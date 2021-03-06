// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/logger"
	"github.com/ethereum/go-ethereum/logger/glog"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/pow"
	"gopkg.in/fatih/set.v0"
)

const (
	// must be bumped when consensus algorithm is changed, this forces the upgradedb
	// command to be run (forces the blocks to be imported again using the new algorithm)
	BlockChainVersion = 3
)

type BlockProcessor struct {
	chainDb ethdb.Database
	// Mutex for locking the block processor. Blocks can only be handled one at a time
	mutex sync.Mutex
	// Canonical block chain
	bc *ChainManager
	// non-persistent key/value memory storage
	mem map[string]*big.Int
	// Proof of work used for validating
	Pow pow.PoW

	events event.Subscription

	eventMux *event.TypeMux
}

// TODO: type GasPool big.Int
//
// GasPool is implemented by state.StateObject. This is a historical
// coincidence. Gas tracking should move out of StateObject.

// GasPool tracks the amount of gas available during
// execution of the transactions in a block.
type GasPool interface {
	AddGas(gas, price *big.Int)
	SubGas(gas, price *big.Int) error
}

func NewBlockProcessor(db ethdb.Database, pow pow.PoW, chainManager *ChainManager, eventMux *event.TypeMux) *BlockProcessor {
	sm := &BlockProcessor{
		chainDb:  db,
		mem:      make(map[string]*big.Int),
		Pow:      pow,
		bc:       chainManager,
		eventMux: eventMux,
	}
	return sm
}

func (sm *BlockProcessor) TransitionState(statedb *state.StateDB, parent, block *types.Block, transientProcess bool) (receipts types.Receipts, err error) {
	gp := statedb.GetOrNewStateObject(block.Coinbase())
	gp.SetGasLimit(block.GasLimit())

	// Process the transactions on to parent state
	receipts, err = sm.ApplyTransactions(gp, statedb, block, block.Transactions(), transientProcess)
	if err != nil {
		return nil, err
	}

	return receipts, nil
}

func (self *BlockProcessor) ApplyTransaction(gp GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *big.Int, transientProcess bool) (*types.Receipt, *big.Int, error) {
	_, gas, err := ApplyMessage(NewEnv(statedb, self.bc, tx, header), tx, gp)
	if err != nil {
		return nil, nil, err
	}

	// Update the state with pending changes
	statedb.SyncIntermediate()

	usedGas.Add(usedGas, gas)
	receipt := types.NewReceipt(statedb.Root().Bytes(), usedGas)
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = new(big.Int).Set(gas)
	if MessageCreatesContract(tx) {
		from, _ := tx.From()
		receipt.ContractAddress = crypto.CreateAddress(from, tx.Nonce())
	}

	logs := statedb.GetLogs(tx.Hash())
	receipt.SetLogs(logs)
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})

	glog.V(logger.Debug).Infoln(receipt)

	// Notify all subscribers
	if !transientProcess {
		go self.eventMux.Post(TxPostEvent{tx})
		go self.eventMux.Post(logs)
	}

	return receipt, gas, err
}
func (self *BlockProcessor) ChainManager() *ChainManager {
	return self.bc
}

func (self *BlockProcessor) ApplyTransactions(gp GasPool, statedb *state.StateDB, block *types.Block, txs types.Transactions, transientProcess bool) (types.Receipts, error) {
	var (
		receipts      types.Receipts
		totalUsedGas  = big.NewInt(0)
		err           error
		cumulativeSum = new(big.Int)
		header        = block.Header()
	)

	for i, tx := range txs {
		statedb.StartRecord(tx.Hash(), block.Hash(), i)

		receipt, txGas, err := self.ApplyTransaction(gp, statedb, header, tx, totalUsedGas, transientProcess)
		if err != nil {
			return nil, err
		}

		if err != nil {
			glog.V(logger.Core).Infoln("TX err:", err)
		}
		receipts = append(receipts, receipt)

		cumulativeSum.Add(cumulativeSum, new(big.Int).Mul(txGas, tx.GasPrice()))
	}

	if block.GasUsed().Cmp(totalUsedGas) != 0 {
		return nil, ValidationError(fmt.Sprintf("gas used error (%v / %v)", block.GasUsed(), totalUsedGas))
	}

	if transientProcess {
		go self.eventMux.Post(PendingBlockEvent{block, statedb.Logs()})
	}

	return receipts, err
}

func (sm *BlockProcessor) RetryProcess(block *types.Block) (logs state.Logs, err error) {
	// Processing a blocks may never happen simultaneously
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if !sm.bc.HasBlock(block.ParentHash()) {
		return nil, ParentError(block.ParentHash())
	}
	parent := sm.bc.GetBlock(block.ParentHash())

	// FIXME Change to full header validation. See #1225
	errch := make(chan bool)
	go func() { errch <- sm.Pow.Verify(block) }()

	logs, _, err = sm.processWithParent(block, parent)
	if !<-errch {
		return nil, ValidationError("Block's nonce is invalid (= %x)", block.Nonce)
	}

	return logs, err
}

// Process block will attempt to process the given block's transactions and applies them
// on top of the block's parent state (given it exists) and will return wether it was
// successful or not.
func (sm *BlockProcessor) Process(block *types.Block) (logs state.Logs, receipts types.Receipts, err error) {
	// Processing a blocks may never happen simultaneously
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if sm.bc.HasBlock(block.Hash()) {
		return nil, nil, &KnownBlockError{block.Number(), block.Hash()}
	}

	if !sm.bc.HasBlock(block.ParentHash()) {
		return nil, nil, ParentError(block.ParentHash())
	}
	parent := sm.bc.GetBlock(block.ParentHash())
	return sm.processWithParent(block, parent)
}

func (sm *BlockProcessor) processWithParent(block, parent *types.Block) (logs state.Logs, receipts types.Receipts, err error) {
	// Create a new state based on the parent's root (e.g., create copy)
	state := state.New(parent.Root(), sm.chainDb)
	header := block.Header()
	uncles := block.Uncles()
	txs := block.Transactions()

	// Block validation
	if err = ValidateHeader(sm.Pow, header, parent.Header(), false, false); err != nil {
		return
	}

	// There can be at most two uncles
	if len(uncles) > 2 {
		return nil, nil, ValidationError("Block can only contain maximum 2 uncles (contained %v)", len(uncles))
	}

	receipts, err = sm.TransitionState(state, parent, block, false)
	if err != nil {
		return
	}

	// Validate the received block's bloom with the one derived from the generated receipts.
	// For valid blocks this should always validate to true.
	rbloom := types.CreateBloom(receipts)
	if rbloom != header.Bloom {
		err = fmt.Errorf("unable to replicate block's bloom=%x", rbloom)
		return
	}

	// The transactions Trie's root (R = (Tr [[i, RLP(T1)], [i, RLP(T2)], ... [n, RLP(Tn)]]))
	// can be used by light clients to make sure they've received the correct Txs
	txSha := types.DeriveSha(txs)
	if txSha != header.TxHash {
		err = fmt.Errorf("invalid transaction root hash. received=%x calculated=%x", header.TxHash, txSha)
		return
	}

	// Tre receipt Trie's root (R = (Tr [[H1, R1], ... [Hn, R1]]))
	receiptSha := types.DeriveSha(receipts)
	if receiptSha != header.ReceiptHash {
		err = fmt.Errorf("invalid receipt root hash. received=%x calculated=%x", header.ReceiptHash, receiptSha)
		return
	}

	// Verify UncleHash before running other uncle validations
	unclesSha := types.CalcUncleHash(uncles)
	if unclesSha != header.UncleHash {
		err = fmt.Errorf("invalid uncles root hash. received=%x calculated=%x", header.UncleHash, unclesSha)
		return
	}

	// Verify uncles
	if err = sm.VerifyUncles(state, block, parent); err != nil {
		return
	}
	// Accumulate static rewards; block reward, uncle's and uncle inclusion.
	AccumulateRewards(state, header, uncles)

	// Commit state objects/accounts to a temporary trie (does not save)
	// used to calculate the state root.
	state.SyncObjects()
	if header.Root != state.Root() {
		err = fmt.Errorf("invalid merkle root. received=%x got=%x", header.Root, state.Root())
		return
	}

	// Sync the current block's state to the database
	state.Sync()

	return state.Logs(), receipts, nil
}

var (
	big8  = big.NewInt(8)
	big32 = big.NewInt(32)
)

// AccumulateRewards credits the coinbase of the given block with the
// mining reward. The total reward consists of the static block reward
// and rewards for included uncles. The coinbase of each uncle block is
// also rewarded.
func AccumulateRewards(statedb *state.StateDB, header *types.Header, uncles []*types.Header) {
	reward := new(big.Int).Set(BlockReward)
	r := new(big.Int)
	for _, uncle := range uncles {
		r.Add(uncle.Number, big8)
		r.Sub(r, header.Number)
		r.Mul(r, BlockReward)
		r.Div(r, big8)
		statedb.AddBalance(uncle.Coinbase, r)

		r.Div(BlockReward, big32)
		reward.Add(reward, r)
	}
	statedb.AddBalance(header.Coinbase, reward)
}

func (sm *BlockProcessor) VerifyUncles(statedb *state.StateDB, block, parent *types.Block) error {
	uncles := set.New()
	ancestors := make(map[common.Hash]*types.Block)
	for _, ancestor := range sm.bc.GetBlocksFromHash(block.ParentHash(), 7) {
		ancestors[ancestor.Hash()] = ancestor
		// Include ancestors uncles in the uncle set. Uncles must be unique.
		for _, uncle := range ancestor.Uncles() {
			uncles.Add(uncle.Hash())
		}
	}
	ancestors[block.Hash()] = block
	uncles.Add(block.Hash())

	for i, uncle := range block.Uncles() {
		hash := uncle.Hash()
		if uncles.Has(hash) {
			// Error not unique
			return UncleError("uncle[%d](%x) not unique", i, hash[:4])
		}
		uncles.Add(hash)

		if ancestors[hash] != nil {
			branch := fmt.Sprintf("  O - %x\n  |\n", block.Hash())
			for h := range ancestors {
				branch += fmt.Sprintf("  O - %x\n  |\n", h)
			}
			glog.Infoln(branch)
			return UncleError("uncle[%d](%x) is ancestor", i, hash[:4])
		}

		if ancestors[uncle.ParentHash] == nil || uncle.ParentHash == parent.Hash() {
			return UncleError("uncle[%d](%x)'s parent is not ancestor (%x)", i, hash[:4], uncle.ParentHash[0:4])
		}

		if err := ValidateHeader(sm.Pow, uncle, ancestors[uncle.ParentHash].Header(), true, true); err != nil {
			return ValidationError(fmt.Sprintf("uncle[%d](%x) header invalid: %v", i, hash[:4], err))
		}
	}

	return nil
}

// GetBlockReceipts returns the receipts beloniging to the block hash
func (sm *BlockProcessor) GetBlockReceipts(bhash common.Hash) types.Receipts {
	if block := sm.ChainManager().GetBlock(bhash); block != nil {
		return GetBlockReceipts(sm.chainDb, block.Hash())
	}

	return nil
}

// GetLogs returns the logs of the given block. This method is using a two step approach
// where it tries to get it from the (updated) method which gets them from the receipts or
// the depricated way by re-processing the block.
func (sm *BlockProcessor) GetLogs(block *types.Block) (logs state.Logs, err error) {
	receipts := GetBlockReceipts(sm.chainDb, block.Hash())
	// coalesce logs
	for _, receipt := range receipts {
		logs = append(logs, receipt.Logs()...)
	}
	return logs, nil
}

// See YP section 4.3.4. "Block Header Validity"
// Validates a header. Returns an error if the header is invalid.
func ValidateHeader(pow pow.PoW, header *types.Header, parent *types.Header, checkPow, uncle bool) error {
	if big.NewInt(int64(len(header.Extra))).Cmp(params.MaximumExtraDataSize) == 1 {
		return fmt.Errorf("Header extra data too long (%d)", len(header.Extra))
	}

	if uncle {
		if header.Time.Cmp(common.MaxBig) == 1 {
			return BlockTSTooBigErr
		}
	} else {
		if header.Time.Cmp(big.NewInt(time.Now().Unix())) == 1 {
			return BlockFutureErr
		}
	}
	if header.Time.Cmp(parent.Time) != 1 {
		return BlockEqualTSErr
	}

	expd := CalcDifficulty(header.Time.Uint64(), parent.Time.Uint64(), parent.Number, parent.Difficulty)
	if expd.Cmp(header.Difficulty) != 0 {
		return fmt.Errorf("Difficulty check failed for header %v, %v", header.Difficulty, expd)
	}

	a := new(big.Int).Set(parent.GasLimit)
	a = a.Sub(a, header.GasLimit)
	a.Abs(a)
	b := new(big.Int).Set(parent.GasLimit)
	b = b.Div(b, params.GasLimitBoundDivisor)
	if !(a.Cmp(b) < 0) || (header.GasLimit.Cmp(params.MinGasLimit) == -1) {
		return fmt.Errorf("GasLimit check failed for header %v (%v > %v)", header.GasLimit, a, b)
	}

	num := new(big.Int).Set(parent.Number)
	num.Sub(header.Number, num)
	if num.Cmp(big.NewInt(1)) != 0 {
		return BlockNumberErr
	}

	if checkPow {
		// Verify the nonce of the header. Return an error if it's not valid
		if !pow.Verify(types.NewBlockWithHeader(header)) {
			return ValidationError("Header's nonce is invalid (= %x)", header.Nonce)
		}
	}
	return nil
}
