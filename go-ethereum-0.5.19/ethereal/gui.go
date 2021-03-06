package main

import (
	"bytes"
	"fmt"
	"github.com/ethereum/eth-go"
	"github.com/ethereum/eth-go/ethchain"
	"github.com/ethereum/eth-go/ethdb"
	"github.com/ethereum/eth-go/ethlog"
	"github.com/ethereum/eth-go/ethminer"
	"github.com/ethereum/eth-go/ethpub"
	"github.com/ethereum/eth-go/ethutil"
	"github.com/ethereum/eth-go/ethwire"
	"github.com/ethereum/go-ethereum/utils"
	"github.com/go-qml/qml"
	"math/big"
	"strconv"
	"strings"
	"time"
)

var logger = ethlog.NewLogger("GUI")

type Gui struct {
	// The main application window
	win *qml.Window
	// QML Engine
	engine    *qml.Engine
	component *qml.Common
	// The ethereum interface
	eth *eth.Ethereum

	// The public Ethereum library
	uiLib *UiLib

	txDb *ethdb.LDBDatabase

	pub      *ethpub.PEthereum
	logLevel ethlog.LogLevel
	open     bool

	Session        string
	clientIdentity *ethwire.SimpleClientIdentity
	config         *ethutil.ConfigManager

	miner *ethminer.Miner
}

// Create GUI, but doesn't start it
func NewWindow(ethereum *eth.Ethereum, config *ethutil.ConfigManager, clientIdentity *ethwire.SimpleClientIdentity, session string, logLevel int) *Gui {
	db, err := ethdb.NewLDBDatabase("tx_database")
	if err != nil {
		panic(err)
	}

	pub := ethpub.NewPEthereum(ethereum)

	return &Gui{eth: ethereum, txDb: db, pub: pub, logLevel: ethlog.LogLevel(logLevel), Session: session, open: false, clientIdentity: clientIdentity, config: config}
}

func (gui *Gui) Start(assetPath string) {

	defer gui.txDb.Close()

	// Register ethereum functions
	qml.RegisterTypes("Ethereum", 1, 0, []qml.TypeSpec{{
		Init: func(p *ethpub.PBlock, obj qml.Object) { p.Number = 0; p.Hash = "" },
	}, {
		Init: func(p *ethpub.PTx, obj qml.Object) { p.Value = ""; p.Hash = ""; p.Address = "" },
	}, {
		Init: func(p *ethpub.KeyVal, obj qml.Object) { p.Key = ""; p.Value = "" },
	}})

	// Create a new QML engine
	gui.engine = qml.NewEngine()
	context := gui.engine.Context()

	// Expose the eth library and the ui library to QML
	context.SetVar("eth", gui)
	context.SetVar("pub", gui.pub)
	gui.uiLib = NewUiLib(gui.engine, gui.eth, assetPath)
	context.SetVar("ui", gui.uiLib)

	// Load the main QML interface
	data, _ := ethutil.Config.Db.Get([]byte("KeyRing"))

	var win *qml.Window
	var err error
	var addlog = false
	if len(data) == 0 {
		win, err = gui.showKeyImport(context)
	} else {
		win, err = gui.showWallet(context)
		addlog = true
	}
	if err != nil {
		logger.Errorln("asset not found: you can set an alternative asset path on the command line using option 'asset_path'", err)

		panic(err)
	}

	logger.Infoln("Starting GUI")
	gui.open = true
	win.Show()
	// only add the gui logger after window is shown otherwise slider wont be shown
	if addlog {
		ethlog.AddLogSystem(gui)
	}
	win.Wait()
	// need to silence gui logger after window closed otherwise logsystem hangs (but do not save loglevel)
	gui.logLevel = ethlog.Silence
	gui.open = false
}

func (gui *Gui) Stop() {
	if gui.open {
		gui.logLevel = ethlog.Silence
		gui.open = false
		gui.win.Hide()
	}
	logger.Infoln("Stopped")
}

func (gui *Gui) ToggleMining() {
	var txt string
	if gui.eth.Mining {
		utils.StopMining(gui.eth)
		txt = "Start mining"
	} else {
		utils.StartMining(gui.eth)
		gui.miner = utils.GetMiner()
		txt = "Stop mining"
	}

	gui.win.Root().Set("miningButtonText", txt)
}

func (gui *Gui) showWallet(context *qml.Context) (*qml.Window, error) {
	component, err := gui.engine.LoadFile(gui.uiLib.AssetPath("qml/wallet.qml"))
	if err != nil {
		return nil, err
	}

	win := gui.createWindow(component)

	gui.setInitialBlockChain()
	gui.loadAddressBook()
	gui.readPreviousTransactions()
	gui.setPeerInfo()

	go gui.update()

	return win, nil
}

func (gui *Gui) showKeyImport(context *qml.Context) (*qml.Window, error) {
	context.SetVar("lib", gui)
	component, err := gui.engine.LoadFile(gui.uiLib.AssetPath("qml/first_run.qml"))
	if err != nil {
		return nil, err
	}
	return gui.createWindow(component), nil
}

func (gui *Gui) createWindow(comp qml.Object) *qml.Window {
	win := comp.CreateWindow(nil)

	gui.win = win
	gui.uiLib.win = win

	return gui.win
}

func (gui *Gui) ImportAndSetPrivKey(secret string) bool {
	err := gui.eth.KeyManager().InitFromString(gui.Session, 0, secret)
	if err != nil {
		logger.Errorln("unable to import: ", err)
		return false
	}
	logger.Errorln("successfully imported: ", err)
	return true
}

func (gui *Gui) CreateAndSetPrivKey() (string, string, string, string) {
	err := gui.eth.KeyManager().Init(gui.Session, 0, true)
	if err != nil {
		logger.Errorln("unable to create key: ", err)
		return "", "", "", ""
	}
	return gui.eth.KeyManager().KeyPair().AsStrings()
}

func (gui *Gui) setInitialBlockChain() {
	sBlk := gui.eth.BlockChain().LastBlockHash
	blk := gui.eth.BlockChain().GetBlock(sBlk)
	for ; blk != nil; blk = gui.eth.BlockChain().GetBlock(sBlk) {
		sBlk = blk.PrevHash
		addr := gui.address()

		// Loop through all transactions to see if we missed any while being offline
		for _, tx := range blk.Transactions() {
			if bytes.Compare(tx.Sender(), addr) == 0 || bytes.Compare(tx.Recipient, addr) == 0 {
				if ok, _ := gui.txDb.Get(tx.Hash()); ok == nil {
					gui.txDb.Put(tx.Hash(), tx.RlpEncode())
				}

			}
		}

		gui.processBlock(blk, true)
	}
}

type address struct {
	Name, Address string
}

func (gui *Gui) loadAddressBook() {
	gui.win.Root().Call("clearAddress")

	nameReg := ethpub.EthereumConfig(gui.eth.StateManager()).NameReg()
	if nameReg != nil {
		nameReg.State().EachStorage(func(name string, value *ethutil.Value) {
			if name[0] != 0 {
				gui.win.Root().Call("addAddress", struct{ Name, Address string }{name, ethutil.Bytes2Hex(value.Bytes())})
			}
		})
	}
}

func (gui *Gui) readPreviousTransactions() {
	it := gui.txDb.Db().NewIterator(nil, nil)
	addr := gui.address()
	for it.Next() {
		tx := ethchain.NewTransactionFromBytes(it.Value())

		var inout string
		if bytes.Compare(tx.Sender(), addr) == 0 {
			inout = "send"
		} else {
			inout = "recv"
		}

		gui.win.Root().Call("addTx", ethpub.NewPTx(tx), inout)

	}
	it.Release()
}

func (gui *Gui) processBlock(block *ethchain.Block, initial bool) {
	name := ethpub.FindNameInNameReg(gui.eth.StateManager(), block.Coinbase)
	b := ethpub.NewPBlock(block)
	b.Name = name

	gui.win.Root().Call("addBlock", b, initial)
}

func (gui *Gui) setWalletValue(amount, unconfirmedFunds *big.Int) {
	var str string
	if unconfirmedFunds != nil {
		pos := "+"
		if unconfirmedFunds.Cmp(big.NewInt(0)) < 0 {
			pos = "-"
		}
		val := ethutil.CurrencyToString(new(big.Int).Abs(ethutil.BigCopy(unconfirmedFunds)))
		str = fmt.Sprintf("%v (%s %v)", ethutil.CurrencyToString(amount), pos, val)
	} else {
		str = fmt.Sprintf("%v", ethutil.CurrencyToString(amount))
	}

	gui.win.Root().Call("setWalletValue", str)
}

func (self *Gui) getObjectByName(objectName string) qml.Object {
	return self.win.Root().ObjectByName(objectName)
}

// Simple go routine function that updates the list of peers in the GUI
func (gui *Gui) update() {
	reactor := gui.eth.Reactor()

	var (
		blockChan     = make(chan ethutil.React, 1)
		txChan        = make(chan ethutil.React, 1)
		objectChan    = make(chan ethutil.React, 1)
		peerChan      = make(chan ethutil.React, 1)
		chainSyncChan = make(chan ethutil.React, 1)
		miningChan    = make(chan ethutil.React, 1)
	)

	reactor.Subscribe("newBlock", blockChan)
	reactor.Subscribe("newTx:pre", txChan)
	reactor.Subscribe("newTx:post", txChan)
	reactor.Subscribe("chainSync", chainSyncChan)
	reactor.Subscribe("miner:start", miningChan)
	reactor.Subscribe("miner:stop", miningChan)

	nameReg := ethpub.EthereumConfig(gui.eth.StateManager()).NameReg()
	if nameReg != nil {
		reactor.Subscribe("object:"+string(nameReg.Address()), objectChan)
	}
	reactor.Subscribe("peerList", peerChan)

	peerUpdateTicker := time.NewTicker(5 * time.Second)
	generalUpdateTicker := time.NewTicker(1 * time.Second)

	state := gui.eth.StateManager().TransState()

	unconfirmedFunds := new(big.Int)
	gui.win.Root().Call("setWalletValue", fmt.Sprintf("%v", ethutil.CurrencyToString(state.GetAccount(gui.address()).Amount)))
	gui.getObjectByName("syncProgressIndicator").Set("visible", !gui.eth.IsUpToDate())

	lastBlockLabel := gui.getObjectByName("lastBlockLabel")

	for {
		select {
		case b := <-blockChan:
			block := b.Resource.(*ethchain.Block)
			gui.processBlock(block, false)
			if bytes.Compare(block.Coinbase, gui.address()) == 0 {
				gui.setWalletValue(gui.eth.StateManager().CurrentState().GetAccount(gui.address()).Amount, nil)
			}

		case txMsg := <-txChan:
			tx := txMsg.Resource.(*ethchain.Transaction)

			if txMsg.Event == "newTx:pre" {
				object := state.GetAccount(gui.address())

				if bytes.Compare(tx.Sender(), gui.address()) == 0 {
					gui.win.Root().Call("addTx", ethpub.NewPTx(tx), "send")
					gui.txDb.Put(tx.Hash(), tx.RlpEncode())

					unconfirmedFunds.Sub(unconfirmedFunds, tx.Value)
				} else if bytes.Compare(tx.Recipient, gui.address()) == 0 {
					gui.win.Root().Call("addTx", ethpub.NewPTx(tx), "recv")
					gui.txDb.Put(tx.Hash(), tx.RlpEncode())

					unconfirmedFunds.Add(unconfirmedFunds, tx.Value)
				}

				gui.setWalletValue(object.Amount, unconfirmedFunds)
			} else {
				object := state.GetAccount(gui.address())
				if bytes.Compare(tx.Sender(), gui.address()) == 0 {
					object.SubAmount(tx.Value)
				} else if bytes.Compare(tx.Recipient, gui.address()) == 0 {
					object.AddAmount(tx.Value)
				}

				gui.setWalletValue(object.Amount, nil)

				state.UpdateStateObject(object)
			}
		case msg := <-chainSyncChan:
			sync := msg.Resource.(bool)
			gui.win.Root().ObjectByName("syncProgressIndicator").Set("visible", sync)

		case <-objectChan:
			gui.loadAddressBook()
		case <-peerChan:
			gui.setPeerInfo()
		case <-peerUpdateTicker.C:
			gui.setPeerInfo()
		case msg := <-miningChan:
			if msg.Event == "miner:start" {
				gui.miner = msg.Resource.(*ethminer.Miner)
			} else {
				gui.miner = nil
			}

		case <-generalUpdateTicker.C:
			statusText := "#" + gui.eth.BlockChain().CurrentBlock.Number.String()
			if gui.miner != nil {
				pow := gui.miner.GetPow()
				if pow.GetHashrate() != 0 {
					statusText = "Mining @ " + strconv.FormatInt(pow.GetHashrate(), 10) + "Khash - " + statusText
				}
			}
			lastBlockLabel.Set("text", statusText)
		}
	}
}

func (gui *Gui) setPeerInfo() {
	gui.win.Root().Call("setPeers", fmt.Sprintf("%d / %d", gui.eth.PeerCount(), gui.eth.MaxPeers))

	gui.win.Root().Call("resetPeers")
	for _, peer := range gui.pub.GetPeers() {
		gui.win.Root().Call("addPeer", peer)
	}
}

func (gui *Gui) privateKey() string {
	return ethutil.Bytes2Hex(gui.eth.KeyManager().PrivateKey())
}

func (gui *Gui) address() []byte {
	return gui.eth.KeyManager().Address()
}

func (gui *Gui) RegisterName(name string) {
	name = fmt.Sprintf("\"register\"\n\"%s\"", name)

	gui.pub.Transact(gui.privateKey(), "NameReg", "", "10000", "10000000000000", name)
}

func (gui *Gui) Transact(recipient, value, gas, gasPrice, data string) (*ethpub.PReceipt, error) {
	return gui.pub.Transact(gui.privateKey(), recipient, value, gas, gasPrice, data)
}

func (gui *Gui) Create(recipient, value, gas, gasPrice, data string) (*ethpub.PReceipt, error) {
	return gui.pub.Transact(gui.privateKey(), recipient, value, gas, gasPrice, data)
}

func (gui *Gui) SetCustomIdentifier(customIdentifier string) {
	gui.clientIdentity.SetCustomIdentifier(customIdentifier)
	gui.config.Save("id", customIdentifier)
}

func (gui *Gui) GetCustomIdentifier() string {
	return gui.clientIdentity.GetCustomIdentifier()
}

// functions that allow Gui to implement interface ethlog.LogSystem
func (gui *Gui) SetLogLevel(level ethlog.LogLevel) {
	gui.logLevel = level
	gui.config.Save("loglevel", level)
}

func (gui *Gui) GetLogLevel() ethlog.LogLevel {
	return gui.logLevel
}

// this extra function needed to give int typecast value to gui widget
// that sets initial loglevel to default
func (gui *Gui) GetLogLevelInt() int {
	return int(gui.logLevel)
}

func (gui *Gui) Println(v ...interface{}) {
	gui.printLog(fmt.Sprintln(v...))
}

func (gui *Gui) Printf(format string, v ...interface{}) {
	gui.printLog(fmt.Sprintf(format, v...))
}

// Print function that logs directly to the GUI
func (gui *Gui) printLog(s string) {
	str := strings.TrimRight(s, "\n")
	lines := strings.Split(str, "\n")
	for _, line := range lines {
		gui.win.Root().Call("addLog", line)
	}
}
