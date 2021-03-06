// Copyright 2015 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with go-ethereum.  If not, see <http://www.gnu.org/licenses/>.

package natspec

import (
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/docserver"
	"github.com/ethereum/go-ethereum/common/registrar"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth"
	xe "github.com/ethereum/go-ethereum/xeth"
)

const (
	testBalance = "10000000000000000000"

	testFileName = "long_file_name_for_testing_registration_of_URLs_longer_than_32_bytes.content"

	testNotice = "Register key `utils.toHex(_key)` <- content `utils.toHex(_content)`"

	testExpNotice = "Register key 0xadd1a7d961cff0242089674ec2ef6fca671ab15e1fe80e38859fc815b98d88ab <- content 0xb3a2dea218de5d8bbe6c4645aadbf67b5ab00ecb1a9ec95dbdad6a0eed3e41a7"

	testExpNotice2 = `About to submit transaction (NatSpec notice error: abi key does not match any method): {"params":[{"to":"%s","data": "0x31e12c20"}]}`

	testExpNotice3 = `About to submit transaction (no NatSpec info found for contract: content hash not found for '0x1392c62d05b2d149e22a339c531157ae06b44d39a674cce500064b12b9aeb019'): {"params":[{"to":"%s","data": "0x300a3bbfb3a2dea218de5d8bbe6c4645aadbf67b5ab00ecb1a9ec95dbdad6a0eed3e41a7000000000000000000000000000000000000000000000000000000000000000000000000000000000000000066696c653a2f2f2f746573742e636f6e74656e74"}]}`
)

const (
	testUserDoc = `
{
  "methods": {
    "register(uint256,uint256)": {
      "notice":  "` + testNotice + `"
    }
  },
  "invariants": [
    { "notice": "" }
  ],
  "construction": [
    { "notice": "" }
  ]
}
`
	testAbiDefinition = `
[{
  "name": "register",
  "constant": false,
  "type": "function",
  "inputs": [{
    "name": "_key",
    "type": "uint256"
  }, {
    "name": "_content",
    "type": "uint256"
  }],
  "outputs": []
}]
`

	testContractInfo = `
{
	"userDoc": ` + testUserDoc + `,
	"abiDefinition": ` + testAbiDefinition + `
}
`
)

type testFrontend struct {
	t           *testing.T
	ethereum    *eth.Ethereum
	xeth        *xe.XEth
	wait        chan *big.Int
	lastConfirm string
	wantNatSpec bool
}

func (self *testFrontend) UnlockAccount(acc []byte) bool {
	self.ethereum.AccountManager().Unlock(common.BytesToAddress(acc), "password")
	return true
}

func (self *testFrontend) ConfirmTransaction(tx string) bool {
	if self.wantNatSpec {
		ds := docserver.New("/tmp/")
		self.lastConfirm = GetNotice(self.xeth, tx, ds)
	}
	return true
}

func testEth(t *testing.T) (ethereum *eth.Ethereum, err error) {

	os.RemoveAll("/tmp/eth-natspec/")

	err = os.MkdirAll("/tmp/eth-natspec/keystore", os.ModePerm)
	if err != nil {
		panic(err)
	}

	// create a testAddress
	ks := crypto.NewKeyStorePassphrase("/tmp/eth-natspec/keystore")
	am := accounts.NewManager(ks)
	testAccount, err := am.NewAccount("password")
	if err != nil {
		panic(err)
	}
	testAddress := strings.TrimPrefix(testAccount.Address.Hex(), "0x")

	// set up mock genesis with balance on the testAddress
	core.GenesisAccounts = []byte(`{
	"` + testAddress + `": {"balance": "` + testBalance + `"}
	}`)

	// only use minimalistic stack with no networking
	ethereum, err = eth.New(&eth.Config{
		DataDir:        "/tmp/eth-natspec",
		AccountManager: am,
		MaxPeers:       0,
		PowTest:        true,
		Etherbase:      common.HexToAddress(testAddress),
	})

	if err != nil {
		panic(err)
	}

	return
}

func testInit(t *testing.T) (self *testFrontend) {
	// initialise and start minimal ethereum stack
	ethereum, err := testEth(t)
	if err != nil {
		t.Errorf("error creating ethereum: %v", err)
		return
	}
	err = ethereum.Start()
	if err != nil {
		t.Errorf("error starting ethereum: %v", err)
		return
	}

	// mock frontend
	self = &testFrontend{t: t, ethereum: ethereum}
	self.xeth = xe.New(ethereum, self)
	self.wait = self.xeth.UpdateState()
	addr, _ := self.ethereum.Etherbase()

	// initialise the registry contracts
	reg := registrar.New(self.xeth)
	var registrarTxhash, hashRegTxhash, urlHintTxhash string
	registrarTxhash, err = reg.SetGlobalRegistrar("", addr)
	if err != nil {
		t.Errorf("error creating GlobalRegistrar: %v", err)
	}

	hashRegTxhash, err = reg.SetHashReg("", addr)
	if err != nil {
		t.Errorf("error creating HashReg: %v", err)
	}
	urlHintTxhash, err = reg.SetUrlHint("", addr)
	if err != nil {
		t.Errorf("error creating UrlHint: %v", err)
	}
	if !processTxs(self, t, 3) {
		t.Errorf("error mining txs")
	}
	_ = registrarTxhash
	_ = hashRegTxhash
	_ = urlHintTxhash

	/* TODO:
	* lookup receipt and contract addresses by tx hash
	* name registration for HashReg and UrlHint addresses
	* mine those transactions
	* then set once more SetHashReg SetUrlHint
	 */

	return

}

// end to end test
func TestNatspecE2E(t *testing.T) {
	t.Skip()

	tf := testInit(t)
	defer tf.ethereum.Stop()
	addr, _ := tf.ethereum.Etherbase()

	// create a contractInfo file (mock cloud-deployed contract metadocs)
	// incidentally this is the info for the registry contract itself
	ioutil.WriteFile("/tmp/"+testFileName, []byte(testContractInfo), os.ModePerm)
	dochash := crypto.Sha3Hash([]byte(testContractInfo))

	// take the codehash for the contract we wanna test
	codeb := tf.xeth.CodeAtBytes(registrar.HashRegAddr)
	codehash := crypto.Sha3Hash(codeb)

	// use resolver to register codehash->dochash->url
	// test if globalregistry works
	// registrar.HashRefAddr = "0x0"
	// registrar.UrlHintAddr = "0x0"
	reg := registrar.New(tf.xeth)
	_, err := reg.SetHashToHash(addr, codehash, dochash)
	if err != nil {
		t.Errorf("error registering: %v", err)
	}
	_, err = reg.SetUrlToHash(addr, dochash, "file:///"+testFileName)
	if err != nil {
		t.Errorf("error registering: %v", err)
	}
	if !processTxs(tf, t, 5) {
		return
	}

	// NatSpec info for register method of HashReg contract installed
	// now using the same transactions to check confirm messages

	tf.wantNatSpec = true // this is set so now the backend uses natspec confirmation
	_, err = reg.SetHashToHash(addr, codehash, dochash)
	if err != nil {
		t.Errorf("error calling contract registry: %v", err)
	}

	fmt.Printf("GlobalRegistrar: %v, HashReg: %v, UrlHint: %v\n", registrar.GlobalRegistrarAddr, registrar.HashRegAddr, registrar.UrlHintAddr)
	if tf.lastConfirm != testExpNotice {
		t.Errorf("Wrong confirm message. expected\n'%v', got\n'%v'", testExpNotice, tf.lastConfirm)
	}

	// test unknown method
	exp := fmt.Sprintf(testExpNotice2, registrar.HashRegAddr)
	_, err = reg.SetOwner(addr)
	if err != nil {
		t.Errorf("error setting owner: %v", err)
	}

	if tf.lastConfirm != exp {
		t.Errorf("Wrong confirm message, expected\n'%v', got\n'%v'", exp, tf.lastConfirm)
	}

	// test unknown contract
	exp = fmt.Sprintf(testExpNotice3, registrar.UrlHintAddr)

	_, err = reg.SetUrlToHash(addr, dochash, "file:///test.content")
	if err != nil {
		t.Errorf("error registering: %v", err)
	}

	if tf.lastConfirm != exp {
		t.Errorf("Wrong confirm message, expected '%v', got '%v'", exp, tf.lastConfirm)
	}

}

func pendingTransactions(repl *testFrontend, t *testing.T) (txc int64, err error) {
	txs := repl.ethereum.TxPool().GetTransactions()
	return int64(len(txs)), nil
}

func processTxs(repl *testFrontend, t *testing.T, expTxc int) bool {
	var txc int64
	var err error
	for i := 0; i < 50; i++ {
		txc, err = pendingTransactions(repl, t)
		if err != nil {
			t.Errorf("unexpected error checking pending transactions: %v", err)
			return false
		}
		if expTxc < int(txc) {
			t.Errorf("too many pending transactions: expected %v, got %v", expTxc, txc)
			return false
		} else if expTxc == int(txc) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if int(txc) != expTxc {
		t.Errorf("incorrect number of pending transactions, expected %v, got %v", expTxc, txc)
		return false
	}

	err = repl.ethereum.StartMining(runtime.NumCPU())
	if err != nil {
		t.Errorf("unexpected error mining: %v", err)
		return false
	}
	defer repl.ethereum.StopMining()

	timer := time.NewTimer(100 * time.Second)
	height := new(big.Int).Add(repl.xeth.CurrentBlock().Number(), big.NewInt(1))
	repl.wait <- height
	select {
	case <-timer.C:
		// if times out make sure the xeth loop does not block
		go func() {
			select {
			case repl.wait <- nil:
			case <-repl.wait:
			}
		}()
	case <-repl.wait:
	}
	txc, err = pendingTransactions(repl, t)
	if err != nil {
		t.Errorf("unexpected error checking pending transactions: %v", err)
		return false
	}
	if txc != 0 {
		t.Errorf("%d trasactions were not mined", txc)
		return false
	}
	return true
}
