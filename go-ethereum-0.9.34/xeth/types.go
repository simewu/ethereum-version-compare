package xeth

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rlp"
)

type Object struct {
	*state.StateObject
}

func NewObject(state *state.StateObject) *Object {
	return &Object{state}
}

func (self *Object) StorageString(str string) []byte {
	if common.IsHex(str) {
		return self.storage(common.Hex2Bytes(str[2:]))
	} else {
		return self.storage(common.RightPadBytes([]byte(str), 32))
	}
}

func (self *Object) StorageValue(addr *common.Value) []byte {
	return self.storage(addr.Bytes())
}

func (self *Object) storage(addr []byte) []byte {
	return self.StateObject.GetState(common.BytesToHash(addr)).Bytes()
}

func (self *Object) Storage() (storage map[string]string) {
	storage = make(map[string]string)

	it := self.StateObject.Trie().Iterator()
	for it.Next() {
		var data []byte
		rlp.Decode(bytes.NewReader(it.Value), &data)
		storage[common.ToHex(self.Trie().GetKey(it.Key))] = common.ToHex(data)
	}

	return
}

// Block interface exposed to QML
type Block struct {
	//Transactions string `json:"transactions"`
	ref          *types.Block
	Size         string       `json:"size"`
	Number       int          `json:"number"`
	Hash         string       `json:"hash"`
	Transactions *common.List `json:"transactions"`
	Uncles       *common.List `json:"uncles"`
	Time         int64        `json:"time"`
	Coinbase     string       `json:"coinbase"`
	Name         string       `json:"name"`
	GasLimit     string       `json:"gasLimit"`
	GasUsed      string       `json:"gasUsed"`
	PrevHash     string       `json:"prevHash"`
	Bloom        string       `json:"bloom"`
	Raw          string       `json:"raw"`
}

// Creates a new QML Block from a chain block
func NewBlock(block *types.Block) *Block {
	if block == nil {
		return &Block{}
	}

	ptxs := make([]*Transaction, len(block.Transactions()))
	/*
		for i, tx := range block.Transactions() {
			ptxs[i] = NewTx(tx)
		}
	*/
	txlist := common.NewList(ptxs)

	puncles := make([]*Block, len(block.Uncles()))
	/*
		for i, uncle := range block.Uncles() {
			puncles[i] = NewBlock(types.NewBlockWithHeader(uncle))
		}
	*/
	ulist := common.NewList(puncles)

	return &Block{
		ref: block, Size: block.Size().String(),
		Number: int(block.NumberU64()), GasUsed: block.GasUsed().String(),
		GasLimit: block.GasLimit().String(), Hash: block.Hash().Hex(),
		Transactions: txlist, Uncles: ulist,
		Time:     block.Time(),
		Coinbase: block.Coinbase().Hex(),
		PrevHash: block.ParentHash().Hex(),
		Bloom:    common.ToHex(block.Bloom().Bytes()),
		Raw:      block.String(),
	}
}

func (self *Block) ToString() string {
	if self.ref != nil {
		return self.ref.String()
	}

	return ""
}

func (self *Block) GetTransaction(hash string) *Transaction {
	tx := self.ref.Transaction(common.HexToHash(hash))
	if tx == nil {
		return nil
	}

	return NewTx(tx)
}

type Transaction struct {
	ref *types.Transaction

	Value           string `json:"value"`
	Gas             string `json:"gas"`
	GasPrice        string `json:"gasPrice"`
	Hash            string `json:"hash"`
	Address         string `json:"address"`
	Sender          string `json:"sender"`
	RawData         string `json:"rawData"`
	Data            string `json:"data"`
	Contract        bool   `json:"isContract"`
	CreatesContract bool   `json:"createsContract"`
	Confirmations   int    `json:"confirmations"`
}

func NewTx(tx *types.Transaction) *Transaction {
	sender, err := tx.From()
	if err != nil {
		return nil
	}
	hash := tx.Hash().Hex()

	var receiver string
	if to := tx.To(); to != nil {
		receiver = to.Hex()
	} else {
		receiver = core.AddressFromMessage(tx).Hex()
	}
	createsContract := core.MessageCreatesContract(tx)

	var data string
	if createsContract {
		data = strings.Join(core.Disassemble(tx.Data()), "\n")
	} else {
		data = common.ToHex(tx.Data())
	}

	return &Transaction{ref: tx, Hash: hash, Value: common.CurrencyToString(tx.Value()), Address: receiver, Contract: createsContract, Gas: tx.Gas().String(), GasPrice: tx.GasPrice().String(), Data: data, Sender: sender.Hex(), CreatesContract: createsContract, RawData: common.ToHex(tx.Data())}
}

func (self *Transaction) ToString() string {
	return self.ref.String()
}

type Key struct {
	Address    string `json:"address"`
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

func NewKey(key *crypto.KeyPair) *Key {
	return &Key{common.ToHex(key.Address()), common.ToHex(key.PrivateKey), common.ToHex(key.PublicKey)}
}

type PReceipt struct {
	CreatedContract bool   `json:"createdContract"`
	Address         string `json:"address"`
	Hash            string `json:"hash"`
	Sender          string `json:"sender"`
}

func NewPReciept(contractCreation bool, creationAddress, hash, address []byte) *PReceipt {
	return &PReceipt{
		contractCreation,
		common.ToHex(creationAddress),
		common.ToHex(hash),
		common.ToHex(address),
	}
}

// Peer interface exposed to QML

type Peer struct {
	ref     *p2p.Peer
	Ip      string `json:"ip"`
	Version string `json:"version"`
	Caps    string `json:"caps"`
}

func NewPeer(peer *p2p.Peer) *Peer {
	var caps []string
	for _, cap := range peer.Caps() {
		caps = append(caps, fmt.Sprintf("%s/%d", cap.Name, cap.Version))
	}

	return &Peer{
		ref:     peer,
		Ip:      fmt.Sprintf("%v", peer.RemoteAddr()),
		Version: fmt.Sprintf("%v", peer.ID()),
		Caps:    fmt.Sprintf("%v", caps),
	}
}

type Receipt struct {
	CreatedContract bool   `json:"createdContract"`
	Address         string `json:"address"`
	Hash            string `json:"hash"`
	Sender          string `json:"sender"`
}

func NewReciept(contractCreation bool, creationAddress, hash, address []byte) *Receipt {
	return &Receipt{
		contractCreation,
		common.ToHex(creationAddress),
		common.ToHex(hash),
		common.ToHex(address),
	}
}
