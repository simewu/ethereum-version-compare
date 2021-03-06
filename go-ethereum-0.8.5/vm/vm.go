package vm

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethutil"
	"github.com/ethereum/go-ethereum/state"
)

type Vm struct {
	env Environment

	logTy  byte
	logStr string

	err error

	Dbg Debugger

	BreakPoints []int64
	Stepping    bool
	Fn          string

	Recoverable bool
}

func New(env Environment) *Vm {
	lt := LogTyPretty
	if ethutil.Config.Diff {
		lt = LogTyDiff
	}

	return &Vm{env: env, logTy: lt, Recoverable: true}
}

func (self *Vm) Run(me, caller ContextRef, code []byte, value, gas, price *big.Int, callData []byte) (ret []byte, err error) {
	self.env.SetDepth(self.env.Depth() + 1)

	context := NewContext(caller, me, code, gas, price)

	vmlogger.Debugf("(%d) (%x) %x (code=%d) gas: %v (d) %x\n", self.env.Depth(), caller.Address()[:4], context.Address(), len(code), context.Gas, callData)

	if self.Recoverable {
		// Recover from any require exception
		defer func() {
			if r := recover(); r != nil {
				self.Printf(" %v", r).Endl()

				context.UseGas(context.Gas)

				ret = context.Return(nil)

				err = fmt.Errorf("%v", r)

			}
		}()
	}

	if p := Precompiled[string(me.Address())]; p != nil {
		return self.RunPrecompiled(p, callData, context)
	}

	var (
		op OpCode

		destinations        = analyseJumpDests(context.Code)
		mem                 = NewMemory()
		stack               = NewStack()
		pc           uint64 = 0
		step                = 0
		prevStep            = 0
		statedb             = self.env.State()

		jump = func(from uint64, to *big.Int) {
			p := to.Uint64()

			nop := context.GetOp(p)
			if !destinations.Has(p) {
				panic(fmt.Sprintf("invalid jump destination (%v) %v", nop, p))
			}

			self.Printf(" ~> %v", to)
			pc = to.Uint64()

			self.Endl()
		}
	)

	// Don't bother with the execution if there's no code.
	if len(code) == 0 {
		return context.Return(nil), nil
	}

	for {
		prevStep = step
		// The base for all big integer arithmetic
		base := new(big.Int)

		step++
		// Get the memory location of pc
		op = context.GetOp(pc)

		self.Printf("(pc) %-3d -o- %-14s (m) %-4d (s) %-4d ", pc, op.String(), mem.Len(), stack.Len())
		if self.Dbg != nil {
			//self.Dbg.Step(self, op, mem, stack, context)
		}

		newMemSize, gas := self.calculateGasAndSize(context, caller, op, statedb, mem, stack)

		self.Printf("(g) %-3v (%v)", gas, context.Gas)

		if !context.UseGas(gas) {
			self.Endl()

			tmp := new(big.Int).Set(context.Gas)

			context.UseGas(context.Gas)

			return context.Return(nil), OOG(gas, tmp)
		}

		mem.Resize(newMemSize.Uint64())

		switch op {
		// 0x20 range
		case ADD:
			x, y := stack.Popn()
			self.Printf(" %v + %v", y, x)

			base.Add(y, x)

			U256(base)

			self.Printf(" = %v", base)
			// Pop result back on the stack
			stack.Push(base)
		case SUB:
			x, y := stack.Popn()
			self.Printf(" %v - %v", y, x)

			base.Sub(y, x)

			U256(base)

			self.Printf(" = %v", base)
			// Pop result back on the stack
			stack.Push(base)
		case MUL:
			x, y := stack.Popn()
			self.Printf(" %v * %v", y, x)

			base.Mul(y, x)

			U256(base)

			self.Printf(" = %v", base)
			// Pop result back on the stack
			stack.Push(base)
		case DIV:
			x, y := stack.Pop(), stack.Pop()
			self.Printf(" %v / %v", x, y)

			if y.Cmp(ethutil.Big0) != 0 {
				base.Div(x, y)
			}

			U256(base)

			self.Printf(" = %v", base)
			// Pop result back on the stack
			stack.Push(base)
		case SDIV:
			x, y := S256(stack.Pop()), S256(stack.Pop())

			self.Printf(" %v / %v", x, y)

			if y.Cmp(ethutil.Big0) == 0 {
				base.Set(ethutil.Big0)
			} else {
				n := new(big.Int)
				if new(big.Int).Mul(x, y).Cmp(ethutil.Big0) < 0 {
					n.SetInt64(-1)
				} else {
					n.SetInt64(1)
				}

				base.Div(x.Abs(x), y.Abs(y)).Mul(base, n)

				U256(base)
			}

			self.Printf(" = %v", base)
			stack.Push(base)
		case MOD:
			x, y := stack.Pop(), stack.Pop()

			self.Printf(" %v %% %v", x, y)

			if y.Cmp(ethutil.Big0) == 0 {
				base.Set(ethutil.Big0)
			} else {
				base.Mod(x, y)
			}

			U256(base)

			self.Printf(" = %v", base)
			stack.Push(base)
		case SMOD:
			x, y := S256(stack.Pop()), S256(stack.Pop())

			self.Printf(" %v %% %v", x, y)

			if y.Cmp(ethutil.Big0) == 0 {
				base.Set(ethutil.Big0)
			} else {
				n := new(big.Int)
				if x.Cmp(ethutil.Big0) < 0 {
					n.SetInt64(-1)
				} else {
					n.SetInt64(1)
				}

				base.Mod(x.Abs(x), y.Abs(y)).Mul(base, n)

				U256(base)
			}

			self.Printf(" = %v", base)
			stack.Push(base)

		case EXP:
			x, y := stack.Popn()

			self.Printf(" %v ** %v", y, x)

			base.Exp(y, x, Pow256)

			U256(base)

			self.Printf(" = %v", base)

			stack.Push(base)
		case SIGNEXTEND:
			back := stack.Pop().Uint64()
			if back < 31 {
				bit := uint(back*8 + 7)
				num := stack.Pop()
				mask := new(big.Int).Lsh(ethutil.Big1, bit)
				mask.Sub(mask, ethutil.Big1)
				if ethutil.BitTest(num, int(bit)) {
					num.Or(num, mask.Not(mask))
				} else {
					num.And(num, mask)
				}

				num = U256(num)

				self.Printf(" = %v", num)

				stack.Push(num)
			}
		case NOT:
			base.Sub(Pow256, stack.Pop()).Sub(base, ethutil.Big1)

			// Not needed
			base = U256(base)

			stack.Push(base)
		case LT:
			x, y := stack.Popn()
			self.Printf(" %v < %v", y, x)
			// x < y
			if y.Cmp(x) < 0 {
				stack.Push(ethutil.BigTrue)
			} else {
				stack.Push(ethutil.BigFalse)
			}
		case GT:
			x, y := stack.Popn()
			self.Printf(" %v > %v", y, x)

			// x > y
			if y.Cmp(x) > 0 {
				stack.Push(ethutil.BigTrue)
			} else {
				stack.Push(ethutil.BigFalse)
			}

		case SLT:
			y, x := S256(stack.Pop()), S256(stack.Pop())
			self.Printf(" %v < %v", y, x)
			// x < y
			if y.Cmp(S256(x)) < 0 {
				stack.Push(ethutil.BigTrue)
			} else {
				stack.Push(ethutil.BigFalse)
			}
		case SGT:
			y, x := S256(stack.Pop()), S256(stack.Pop())
			self.Printf(" %v > %v", y, x)

			// x > y
			if y.Cmp(x) > 0 {
				stack.Push(ethutil.BigTrue)
			} else {
				stack.Push(ethutil.BigFalse)
			}

		case EQ:
			x, y := stack.Popn()
			self.Printf(" %v == %v", y, x)

			// x == y
			if x.Cmp(y) == 0 {
				stack.Push(ethutil.BigTrue)
			} else {
				stack.Push(ethutil.BigFalse)
			}
		case ISZERO:
			x := stack.Pop()
			if x.Cmp(ethutil.BigFalse) > 0 {
				stack.Push(ethutil.BigFalse)
			} else {
				stack.Push(ethutil.BigTrue)
			}

			// 0x10 range
		case AND:
			x, y := stack.Popn()
			self.Printf(" %v & %v", y, x)

			stack.Push(base.And(y, x))
		case OR:
			x, y := stack.Popn()
			self.Printf(" %v | %v", y, x)

			stack.Push(base.Or(y, x))
		case XOR:
			x, y := stack.Popn()
			self.Printf(" %v ^ %v", y, x)

			stack.Push(base.Xor(y, x))
		case BYTE:
			val, th := stack.Popn()

			if th.Cmp(big.NewInt(32)) < 0 {
				byt := big.NewInt(int64(ethutil.LeftPadBytes(val.Bytes(), 32)[th.Int64()]))

				base.Set(byt)
			} else {
				base.Set(ethutil.BigFalse)
			}

			self.Printf(" => 0x%x", base.Bytes())

			stack.Push(base)
		case ADDMOD:

			x := stack.Pop()
			y := stack.Pop()
			z := stack.Pop()

			add := new(big.Int).Add(x, y)
			if len(z.Bytes()) > 0 { // NOT 0x0
				base.Mod(add, z)

				U256(base)
			}

			self.Printf(" %v + %v %% %v = %v", x, y, z, base)

			stack.Push(base)
		case MULMOD:

			x := stack.Pop()
			y := stack.Pop()
			z := stack.Pop()

			mul := new(big.Int).Mul(x, y)
			if len(z.Bytes()) > 0 { // NOT 0x0
				base.Mod(mul, z)

				U256(base)
			}

			self.Printf(" %v + %v %% %v = %v", x, y, z, base)

			stack.Push(base)

			// 0x20 range
		case SHA3:
			size, offset := stack.Popn()
			data := crypto.Sha3(mem.Get(offset.Int64(), size.Int64()))

			stack.Push(ethutil.BigD(data))

			self.Printf(" => %x", data)
			// 0x30 range
		case ADDRESS:
			stack.Push(ethutil.BigD(context.Address()))

			self.Printf(" => %x", context.Address())
		case BALANCE:

			addr := stack.Pop().Bytes()
			balance := statedb.GetBalance(addr)

			stack.Push(balance)

			self.Printf(" => %v (%x)", balance, addr)
		case ORIGIN:
			origin := self.env.Origin()

			stack.Push(ethutil.BigD(origin))

			self.Printf(" => %x", origin)
		case CALLER:
			caller := context.caller.Address()
			stack.Push(ethutil.BigD(caller))

			self.Printf(" => %x", caller)
		case CALLVALUE:
			stack.Push(value)

			self.Printf(" => %v", value)
		case CALLDATALOAD:
			var (
				offset  = stack.Pop()
				data    = make([]byte, 32)
				lenData = big.NewInt(int64(len(callData)))
			)

			if lenData.Cmp(offset) >= 0 {
				length := new(big.Int).Add(offset, ethutil.Big32)
				length = ethutil.BigMin(length, lenData)

				copy(data, callData[offset.Int64():length.Int64()])
			}

			self.Printf(" => 0x%x", data)

			stack.Push(ethutil.BigD(data))
		case CALLDATASIZE:
			l := int64(len(callData))
			stack.Push(big.NewInt(l))

			self.Printf(" => %d", l)
		case CALLDATACOPY:
			var (
				size = uint64(len(callData))
				mOff = stack.Pop().Uint64()
				cOff = stack.Pop().Uint64()
				l    = stack.Pop().Uint64()
			)

			if cOff > size {
				cOff = 0
				l = 0
			} else if cOff+l > size {
				l = 0
			}

			code := callData[cOff : cOff+l]

			mem.Set(mOff, l, code)

			self.Printf(" => [%v, %v, %v] %x", mOff, cOff, l, callData[cOff:cOff+l])
		case CODESIZE, EXTCODESIZE:
			var code []byte
			if op == EXTCODESIZE {
				addr := stack.Pop().Bytes()

				code = statedb.GetCode(addr)
			} else {
				code = context.Code
			}

			l := big.NewInt(int64(len(code)))
			stack.Push(l)

			self.Printf(" => %d", l)
		case CODECOPY, EXTCODECOPY:
			var code []byte
			if op == EXTCODECOPY {
				code = statedb.GetCode(stack.Pop().Bytes())
			} else {
				code = context.Code
			}
			context := NewContext(nil, nil, code, ethutil.Big0, ethutil.Big0)
			var (
				mOff = stack.Pop().Uint64()
				cOff = stack.Pop().Uint64()
				l    = stack.Pop().Uint64()
			)
			codeCopy := context.GetCode(cOff, l)

			mem.Set(mOff, l, codeCopy)

			self.Printf(" => [%v, %v, %v] %x", mOff, cOff, l, codeCopy)
		case GASPRICE:
			stack.Push(context.Price)

			self.Printf(" => %x", context.Price)

			// 0x40 range
		case BLOCKHASH:
			num := stack.Pop()

			n := new(big.Int).Sub(self.env.BlockNumber(), ethutil.Big257)
			if num.Cmp(n) > 0 && num.Cmp(self.env.BlockNumber()) < 0 {
				stack.Push(ethutil.BigD(self.env.GetHash(num.Uint64())))
			} else {
				stack.Push(ethutil.Big0)
			}

			self.Printf(" => 0x%x", stack.Peek().Bytes())
		case COINBASE:
			coinbase := self.env.Coinbase()

			stack.Push(ethutil.BigD(coinbase))

			self.Printf(" => 0x%x", coinbase)
		case TIMESTAMP:
			time := self.env.Time()

			stack.Push(big.NewInt(time))

			self.Printf(" => 0x%x", time)
		case NUMBER:
			number := self.env.BlockNumber()

			stack.Push(U256(number))

			self.Printf(" => 0x%x", number.Bytes())
		case DIFFICULTY:
			difficulty := self.env.Difficulty()

			stack.Push(difficulty)

			self.Printf(" => 0x%x", difficulty.Bytes())
		case GASLIMIT:
			self.Printf(" => %v", self.env.GasLimit())

			stack.Push(self.env.GasLimit())

			// 0x50 range
		case PUSH1, PUSH2, PUSH3, PUSH4, PUSH5, PUSH6, PUSH7, PUSH8, PUSH9, PUSH10, PUSH11, PUSH12, PUSH13, PUSH14, PUSH15, PUSH16, PUSH17, PUSH18, PUSH19, PUSH20, PUSH21, PUSH22, PUSH23, PUSH24, PUSH25, PUSH26, PUSH27, PUSH28, PUSH29, PUSH30, PUSH31, PUSH32:
			a := uint64(op - PUSH1 + 1)
			byts := context.GetRangeValue(pc+1, a)
			// Push value to stack
			stack.Push(ethutil.BigD(byts))
			pc += a

			step += int(op) - int(PUSH1) + 1

			self.Printf(" => 0x%x", byts)
		case POP:
			stack.Pop()
		case DUP1, DUP2, DUP3, DUP4, DUP5, DUP6, DUP7, DUP8, DUP9, DUP10, DUP11, DUP12, DUP13, DUP14, DUP15, DUP16:
			n := int(op - DUP1 + 1)
			stack.Dupn(n)

			self.Printf(" => [%d] 0x%x", n, stack.Peek().Bytes())
		case SWAP1, SWAP2, SWAP3, SWAP4, SWAP5, SWAP6, SWAP7, SWAP8, SWAP9, SWAP10, SWAP11, SWAP12, SWAP13, SWAP14, SWAP15, SWAP16:
			n := int(op - SWAP1 + 2)
			x, y := stack.Swapn(n)

			self.Printf(" => [%d] %x [0] %x", n, x.Bytes(), y.Bytes())
		case LOG0, LOG1, LOG2, LOG3, LOG4:
			n := int(op - LOG0)
			topics := make([][]byte, n)
			mSize, mStart := stack.Popn()
			for i := 0; i < n; i++ {
				topics[i] = ethutil.LeftPadBytes(stack.Pop().Bytes(), 32)
			}

			data := mem.Get(mStart.Int64(), mSize.Int64())
			log := &Log{context.Address(), topics, data, self.env.BlockNumber().Uint64()}
			self.env.AddLog(log)

			self.Printf(" => %v", log)
		case MLOAD:
			offset := stack.Pop()
			val := ethutil.BigD(mem.Get(offset.Int64(), 32))
			stack.Push(val)

			self.Printf(" => 0x%x", val.Bytes())
		case MSTORE: // Store the value at stack top-1 in to memory at location stack top
			// Pop value of the stack
			val, mStart := stack.Popn()
			mem.Set(mStart.Uint64(), 32, ethutil.BigToBytes(val, 256))

			self.Printf(" => 0x%x", val)
		case MSTORE8:
			off := stack.Pop()
			val := stack.Pop()

			mem.store[off.Int64()] = byte(val.Int64() & 0xff)

			self.Printf(" => [%v] 0x%x", off, val)
		case SLOAD:
			loc := stack.Pop()
			val := ethutil.BigD(statedb.GetState(context.Address(), loc.Bytes()))
			stack.Push(val)

			self.Printf(" {0x%x : 0x%x}", loc.Bytes(), val.Bytes())
		case SSTORE:
			val, loc := stack.Popn()
			statedb.SetState(context.Address(), loc.Bytes(), val)

			self.Printf(" {0x%x : 0x%x}", loc.Bytes(), val.Bytes())
		case JUMP:
			jump(pc, stack.Pop())

			continue
		case JUMPI:
			cond, pos := stack.Popn()

			if cond.Cmp(ethutil.BigTrue) >= 0 {
				jump(pc, pos)

				continue
			}

			self.Printf(" ~> false")

		case JUMPDEST:
		case PC:
			stack.Push(big.NewInt(int64(pc)))
		case MSIZE:
			stack.Push(big.NewInt(int64(mem.Len())))
		case GAS:
			stack.Push(context.Gas)

			self.Printf(" => %x", context.Gas)
			// 0x60 range
		case CREATE:

			var (
				value        = stack.Pop()
				size, offset = stack.Popn()
				input        = mem.Get(offset.Int64(), size.Int64())
				gas          = new(big.Int).Set(context.Gas)
				addr         []byte
			)
			self.Endl()

			context.UseGas(context.Gas)
			ret, suberr, ref := self.env.Create(context, nil, input, gas, price, value)
			if suberr != nil {
				stack.Push(ethutil.BigFalse)

				self.Printf(" (*) 0x0 %v", suberr)
			} else {

				// gas < len(ret) * CreateDataGas == NO_CODE
				dataGas := big.NewInt(int64(len(ret)))
				dataGas.Mul(dataGas, GasCreateByte)
				if context.UseGas(dataGas) {
					ref.SetCode(ret)
				}
				addr = ref.Address()

				stack.Push(ethutil.BigD(addr))

			}

			// Debug hook
			if self.Dbg != nil {
				self.Dbg.SetCode(context.Code)
			}
		case CALL, CALLCODE:
			gas := stack.Pop()
			// Pop gas and value of the stack.
			value, addr := stack.Popn()
			value = U256(value)
			// Pop input size and offset
			inSize, inOffset := stack.Popn()
			// Pop return size and offset
			retSize, retOffset := stack.Popn()

			address := ethutil.Address(addr.Bytes())
			self.Printf(" => %x", address).Endl()

			// Get the arguments from the memory
			args := mem.Get(inOffset.Int64(), inSize.Int64())

			var (
				ret []byte
				err error
			)
			if op == CALLCODE {
				ret, err = self.env.CallCode(context, address, args, gas, price, value)
			} else {
				ret, err = self.env.Call(context, address, args, gas, price, value)
			}

			if err != nil {
				stack.Push(ethutil.BigFalse)

				vmlogger.Debugln(err)
			} else {
				stack.Push(ethutil.BigTrue)

				mem.Set(retOffset.Uint64(), retSize.Uint64(), ret)
			}
			self.Printf("resume %x (%v)", context.Address(), context.Gas)

			// Debug hook
			if self.Dbg != nil {
				self.Dbg.SetCode(context.Code)
			}

		case RETURN:
			size, offset := stack.Popn()
			ret := mem.Get(offset.Int64(), size.Int64())

			self.Printf(" => [%v, %v] (%d) 0x%x", offset, size, len(ret), ret).Endl()

			return context.Return(ret), nil
		case SUICIDE:
			receiver := statedb.GetOrNewStateObject(stack.Pop().Bytes())
			balance := statedb.GetBalance(context.Address())

			self.Printf(" => (%x) %v", receiver.Address()[:4], balance)

			receiver.AddAmount(balance)
			statedb.Delete(context.Address())

			fallthrough
		case STOP: // Stop the context
			self.Endl()

			return context.Return(nil), nil
		default:
			vmlogger.Debugf("(pc) %-3v Invalid opcode %x\n", pc, op)

			panic(fmt.Errorf("Invalid opcode %x", op))
		}

		pc++

		self.Endl()

		if self.Dbg != nil {
			for _, instrNo := range self.Dbg.BreakPoints() {
				if pc == uint64(instrNo) {
					self.Stepping = true

					if !self.Dbg.BreakHook(prevStep, op, mem, stack, statedb.GetStateObject(context.Address())) {
						return nil, nil
					}
				} else if self.Stepping {
					if !self.Dbg.StepHook(prevStep, op, mem, stack, statedb.GetStateObject(context.Address())) {
						return nil, nil
					}
				}
			}
		}

	}
}

func (self *Vm) calculateGasAndSize(context *Context, caller ContextRef, op OpCode, statedb *state.StateDB, mem *Memory, stack *Stack) (*big.Int, *big.Int) {
	gas := new(big.Int)
	addStepGasUsage := func(amount *big.Int) {
		if amount.Cmp(ethutil.Big0) >= 0 {
			gas.Add(gas, amount)
		}
	}

	addStepGasUsage(GasStep)

	var newMemSize *big.Int = ethutil.Big0
	var additionalGas *big.Int = new(big.Int)
	// Stack Check, memory resize & gas phase
	switch op {
	// Stack checks only
	case ISZERO, CALLDATALOAD, POP, JUMP, NOT: // 1
		stack.require(1)
	case JUMPI, ADD, SUB, DIV, SDIV, MOD, SMOD, LT, GT, SLT, SGT, EQ, AND, OR, XOR, BYTE, SIGNEXTEND: // 2
		stack.require(2)
	case ADDMOD, MULMOD: // 3
		stack.require(3)
	case SWAP1, SWAP2, SWAP3, SWAP4, SWAP5, SWAP6, SWAP7, SWAP8, SWAP9, SWAP10, SWAP11, SWAP12, SWAP13, SWAP14, SWAP15, SWAP16:
		n := int(op - SWAP1 + 2)
		stack.require(n)
	case DUP1, DUP2, DUP3, DUP4, DUP5, DUP6, DUP7, DUP8, DUP9, DUP10, DUP11, DUP12, DUP13, DUP14, DUP15, DUP16:
		n := int(op - DUP1 + 1)
		stack.require(n)
	case LOG0, LOG1, LOG2, LOG3, LOG4:
		n := int(op - LOG0)
		stack.require(n + 2)

		gas.Set(GasLog)
		addStepGasUsage(new(big.Int).Mul(big.NewInt(int64(n)), GasLog))

		mSize, mStart := stack.Peekn()
		addStepGasUsage(mSize)

		newMemSize = calcMemSize(mStart, mSize)
	case EXP:
		stack.require(2)

		gas.Set(big.NewInt(int64(len(stack.data[stack.Len()-2].Bytes()) + 1)))
	// Gas only
	case STOP:
		gas.Set(ethutil.Big0)
	case SUICIDE:
		stack.require(1)

		gas.Set(ethutil.Big0)
	case SLOAD:
		stack.require(1)

		gas.Set(GasSLoad)
	// Memory resize & Gas
	case SSTORE:
		stack.require(2)

		var mult *big.Int
		y, x := stack.Peekn()
		val := statedb.GetState(context.Address(), x.Bytes())
		if len(val) == 0 && len(y.Bytes()) > 0 {
			// 0 => non 0
			mult = ethutil.Big3
		} else if len(val) > 0 && len(y.Bytes()) == 0 {
			statedb.Refund(caller.Address(), GasSStoreRefund)

			mult = ethutil.Big0
		} else {
			// non 0 => non 0 (or 0 => 0)
			mult = ethutil.Big1
		}
		gas.Set(new(big.Int).Mul(mult, GasSStore))
	case BALANCE:
		stack.require(1)
		gas.Set(GasBalance)
	case MSTORE:
		stack.require(2)
		newMemSize = calcMemSize(stack.Peek(), u256(32))
	case MLOAD:
		stack.require(1)

		newMemSize = calcMemSize(stack.Peek(), u256(32))
	case MSTORE8:
		stack.require(2)
		newMemSize = calcMemSize(stack.Peek(), u256(1))
	case RETURN:
		stack.require(2)

		newMemSize = calcMemSize(stack.Peek(), stack.data[stack.Len()-2])
	case SHA3:
		stack.require(2)
		gas.Set(GasSha)
		newMemSize = calcMemSize(stack.Peek(), stack.data[stack.Len()-2])
		additionalGas.Set(stack.data[stack.Len()-2])
	case CALLDATACOPY:
		stack.require(2)

		newMemSize = calcMemSize(stack.Peek(), stack.data[stack.Len()-3])
		additionalGas.Set(stack.data[stack.Len()-3])
	case CODECOPY:
		stack.require(3)

		newMemSize = calcMemSize(stack.Peek(), stack.data[stack.Len()-3])
		additionalGas.Set(stack.data[stack.Len()-3])
	case EXTCODECOPY:
		stack.require(4)

		newMemSize = calcMemSize(stack.data[stack.Len()-2], stack.data[stack.Len()-4])
		additionalGas.Set(stack.data[stack.Len()-4])
	case CALL, CALLCODE:
		stack.require(7)
		gas.Set(GasCall)
		addStepGasUsage(stack.data[stack.Len()-1])

		x := calcMemSize(stack.data[stack.Len()-6], stack.data[stack.Len()-7])
		y := calcMemSize(stack.data[stack.Len()-4], stack.data[stack.Len()-5])

		newMemSize = ethutil.BigMax(x, y)
	case CREATE:
		stack.require(3)
		gas.Set(GasCreate)

		newMemSize = calcMemSize(stack.data[stack.Len()-2], stack.data[stack.Len()-3])
	}

	switch op {
	case CALLDATACOPY, CODECOPY, EXTCODECOPY:
		additionalGas.Add(additionalGas, u256(31))
		additionalGas.Div(additionalGas, u256(32))
		addStepGasUsage(additionalGas)
	case SHA3:
		additionalGas.Add(additionalGas, u256(31))
		additionalGas.Div(additionalGas, u256(32))
		additionalGas.Mul(additionalGas, GasSha3Byte)
		addStepGasUsage(additionalGas)
	}

	if newMemSize.Cmp(ethutil.Big0) > 0 {
		newMemSize.Add(newMemSize, u256(31))
		newMemSize.Div(newMemSize, u256(32))
		newMemSize.Mul(newMemSize, u256(32))

		if newMemSize.Cmp(u256(int64(mem.Len()))) > 0 {
			memGasUsage := new(big.Int).Sub(newMemSize, u256(int64(mem.Len())))
			memGasUsage.Mul(GasMemory, memGasUsage)
			memGasUsage.Div(memGasUsage, u256(32))

			addStepGasUsage(memGasUsage)
		}

	}

	return newMemSize, gas
}

func (self *Vm) RunPrecompiled(p *PrecompiledAccount, callData []byte, context *Context) (ret []byte, err error) {
	gas := p.Gas(len(callData))
	if context.UseGas(gas) {
		ret = p.Call(callData)
		self.Printf("NATIVE_FUNC => %x", ret)
		self.Endl()

		return context.Return(ret), nil
	} else {
		self.Printf("NATIVE_FUNC => failed").Endl()

		tmp := new(big.Int).Set(context.Gas)

		panic(OOG(gas, tmp).Error())
	}
}

func (self *Vm) Printf(format string, v ...interface{}) VirtualMachine {
	if self.logTy == LogTyPretty {
		self.logStr += fmt.Sprintf(format, v...)
	}

	return self
}

func (self *Vm) Endl() VirtualMachine {
	if self.logTy == LogTyPretty {
		vmlogger.Debugln(self.logStr)
		self.logStr = ""
	}

	return self
}

func (self *Vm) Env() Environment {
	return self.env
}
