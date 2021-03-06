// Copyright 2016 The go-ethereum Authors
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

package types

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

var ErrInvalidChainId = errors.New("invalid chain id for signer")

// deriveSigner makes a *best* guess about which signer to use.
func deriveSigner(V *big.Int) Signer {
	if V.BitLen() > 0 && isProtectedV(V) {
		return EIP155Signer{chainId: deriveChainId(V)}
	} else {
		return HomesteadSigner{}
	}
}

func pickSigner(rules params.Rules) Signer {
	var signer Signer
	switch {
	case rules.IsEIP155:
		signer = NewEIP155Signer(rules.ChainId)
	case rules.IsHomestead:
		signer = HomesteadSigner{}
	default:
		signer = FrontierSigner{}
	}
	return signer
}

func isProtectedV(V *big.Int) bool {
	if V.BitLen() <= 8 {
		v := V.Uint64()
		return v != 27 && v != 28
	}
	// anything not 27 or 28 are considered unprotected
	return true
}

// MakeSigner returns a Signer based on the given chain config and block number.
func MakeSigner(config *params.ChainConfig, blockNumber *big.Int) Signer {
	var signer Signer
	switch {
	case config.IsEIP155(blockNumber):
		signer = NewEIP155Signer(config.ChainId)
	case config.IsHomestead(blockNumber):
		signer = HomesteadSigner{}
	default:
		signer = FrontierSigner{}
	}
	return signer
}

// SignECDSA signs the transaction using the given signer and private key
func SignECDSA(s Signer, tx *Transaction, prv *ecdsa.PrivateKey) (*Transaction, error) {
	h := s.Hash(tx)
	sig, err := crypto.Sign(h[:], prv)
	if err != nil {
		return nil, err
	}
	return s.WithSignature(tx, sig)
}

// From derives the sender from the tx using the signer derivation
// functions.

// From returns the address derived from the signature (V, R, S) using secp256k1
// elliptic curve and an error if it failed deriving or upon an incorrect
// signature.
//
// From may cache the address, allowing it to be used regardless of
// signing method.
func From(signer Signer, tx *Transaction, cache bool) (common.Address, error) {
	if from := tx.from.Load(); from != nil {
		return from.(common.Address), nil
	}

	pubkey, err := signer.PublicKey(tx)
	if err != nil {
		return common.Address{}, err
	}
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pubkey[1:])[12:])
	if cache {
		tx.from.Store(addr)
	}
	return addr, nil
}

// SignatureValues returns the ECDSA signature values contained in the transaction.
func SignatureValues(signer Signer, tx *Transaction) (v byte, r *big.Int, s *big.Int) {
	return normaliseV(signer, tx.data.V), new(big.Int).Set(tx.data.R), new(big.Int).Set(tx.data.S)
}

type Signer interface {
	// Hash returns the rlp encoded hash for signatures
	Hash(tx *Transaction) common.Hash
	// PubilcKey returns the public key derived from the signature
	PublicKey(tx *Transaction) ([]byte, error)
	// SignECDSA signs the transaction with the given and returns a copy of the tx
	SignECDSA(tx *Transaction, prv *ecdsa.PrivateKey) (*Transaction, error)
	// WithSignature returns a copy of the transaction with the given signature
	WithSignature(tx *Transaction, sig []byte) (*Transaction, error)
}

// EIP155Transaction implements TransactionInterface using the
// EIP155 rules
type EIP155Signer struct {
	HomesteadSigner

	chainId, chainIdMul *big.Int
}

func NewEIP155Signer(chainId *big.Int) EIP155Signer {
	return EIP155Signer{
		chainId:    chainId,
		chainIdMul: new(big.Int).Mul(chainId, big.NewInt(2)),
	}
}

func (s EIP155Signer) SignECDSA(tx *Transaction, prv *ecdsa.PrivateKey) (*Transaction, error) {
	return SignECDSA(s, tx, prv)
}

func (s EIP155Signer) PublicKey(tx *Transaction) ([]byte, error) {
	// if the transaction is not protected fall back to homestead signer
	if !tx.Protected() {
		return (HomesteadSigner{}).PublicKey(tx)
	}
	if tx.ChainId().Cmp(s.chainId) != 0 {
		return nil, ErrInvalidChainId
	}

	V := normaliseV(s, tx.data.V)
	if !crypto.ValidateSignatureValues(V, tx.data.R, tx.data.S, true) {
		return nil, ErrInvalidSig
	}

	// encode the signature in uncompressed format
	R, S := tx.data.R.Bytes(), tx.data.S.Bytes()
	sig := make([]byte, 65)
	copy(sig[32-len(R):32], R)
	copy(sig[64-len(S):64], S)
	sig[64] = V - 27

	// recover the public key from the signature
	hash := s.Hash(tx)
	pub, err := crypto.Ecrecover(hash[:], sig)
	if err != nil {
		return nil, err
	}
	if len(pub) == 0 || pub[0] != 4 {
		return nil, errors.New("invalid public key")
	}
	return pub, nil
}

// WithSignature returns a new transaction with the given signature.
// This signature needs to be formatted as described in the yellow paper (v+27).
func (s EIP155Signer) WithSignature(tx *Transaction, sig []byte) (*Transaction, error) {
	if len(sig) != 65 {
		panic(fmt.Sprintf("wrong size for snature: got %d, want 65", len(sig)))
	}

	cpy := &Transaction{signer: tx.signer, data: tx.data}
	cpy.data.R = new(big.Int).SetBytes(sig[:32])
	cpy.data.S = new(big.Int).SetBytes(sig[32:64])
	cpy.data.V = new(big.Int).SetBytes([]byte{sig[64]})
	if s.chainId.BitLen() > 0 {
		cpy.data.V = big.NewInt(int64(sig[64] + 35))
		cpy.data.V.Add(cpy.data.V, s.chainIdMul)
	}
	return cpy, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s EIP155Signer) Hash(tx *Transaction) common.Hash {
	return rlpHash([]interface{}{
		tx.data.AccountNonce,
		tx.data.Price,
		tx.data.GasLimit,
		tx.data.Recipient,
		tx.data.Amount,
		tx.data.Payload,
		s.chainId, uint(0), uint(0),
	})
}

func (s EIP155Signer) SigECDSA(tx *Transaction, prv *ecdsa.PrivateKey) (*Transaction, error) {
	h := s.Hash(tx)
	sig, err := crypto.Sign(h[:], prv)
	if err != nil {
		return nil, err
	}
	return s.WithSignature(tx, sig)
}

// HomesteadTransaction implements TransactionInterface using the
// homestead rules.
type HomesteadSigner struct{}

// WithSignature returns a new transaction with the given snature.
// This snature needs to be formatted as described in the yellow paper (v+27).
func (hs HomesteadSigner) WithSignature(tx *Transaction, sig []byte) (*Transaction, error) {
	if len(sig) != 65 {
		panic(fmt.Sprintf("wrong size for snature: got %d, want 65", len(sig)))
	}
	cpy := &Transaction{signer: tx.signer, data: tx.data}
	cpy.data.R = new(big.Int).SetBytes(sig[:32])
	cpy.data.S = new(big.Int).SetBytes(sig[32:64])
	cpy.data.V = new(big.Int).SetBytes([]byte{sig[64] + 27})
	return cpy, nil
}

func (hs HomesteadSigner) SignECDSA(tx *Transaction, prv *ecdsa.PrivateKey) (*Transaction, error) {
	h := hs.Hash(tx)
	sig, err := crypto.Sign(h[:], prv)
	if err != nil {
		return nil, err
	}
	return hs.WithSignature(tx, sig)
}

func (hs HomesteadSigner) PublicKey(tx *Transaction) ([]byte, error) {
	if tx.data.V.BitLen() > 8 {
		return nil, ErrInvalidSig
	}
	V := byte(tx.data.V.Uint64())
	if !crypto.ValidateSignatureValues(V, tx.data.R, tx.data.S, true) {
		return nil, ErrInvalidSig
	}
	// encode the snature in uncompressed format
	r, s := tx.data.R.Bytes(), tx.data.S.Bytes()
	sig := make([]byte, 65)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = V - 27

	// recover the public key from the snature
	hash := hs.Hash(tx)
	pub, err := crypto.Ecrecover(hash[:], sig)
	if err != nil {
		return nil, err
	}
	if len(pub) == 0 || pub[0] != 4 {
		return nil, errors.New("invalid public key")
	}
	return pub, nil
}

// Hash returns the hash to be sned by the sender.
// It does not uniquely identify the transaction.
func (hs HomesteadSigner) Hash(tx *Transaction) common.Hash {
	return rlpHash([]interface{}{
		tx.data.AccountNonce,
		tx.data.Price,
		tx.data.GasLimit,
		tx.data.Recipient,
		tx.data.Amount,
		tx.data.Payload,
	})
}

type FrontierSigner struct{}

// WithSignature returns a new transaction with the given snature.
// This snature needs to be formatted as described in the yellow paper (v+27).
func (fs FrontierSigner) WithSignature(tx *Transaction, sig []byte) (*Transaction, error) {
	if len(sig) != 65 {
		panic(fmt.Sprintf("wrong size for snature: got %d, want 65", len(sig)))
	}
	cpy := &Transaction{signer: tx.signer, data: tx.data}
	cpy.data.R = new(big.Int).SetBytes(sig[:32])
	cpy.data.S = new(big.Int).SetBytes(sig[32:64])
	cpy.data.V = new(big.Int).SetBytes([]byte{sig[64] + 27})
	return cpy, nil
}

func (fs FrontierSigner) SignECDSA(tx *Transaction, prv *ecdsa.PrivateKey) (*Transaction, error) {
	h := fs.Hash(tx)
	sig, err := crypto.Sign(h[:], prv)
	if err != nil {
		return nil, err
	}
	return fs.WithSignature(tx, sig)
}

// Hash returns the hash to be sned by the sender.
// It does not uniquely identify the transaction.
func (fs FrontierSigner) Hash(tx *Transaction) common.Hash {
	return rlpHash([]interface{}{
		tx.data.AccountNonce,
		tx.data.Price,
		tx.data.GasLimit,
		tx.data.Recipient,
		tx.data.Amount,
		tx.data.Payload,
	})
}

func (fs FrontierSigner) PublicKey(tx *Transaction) ([]byte, error) {
	if tx.data.V.BitLen() > 8 {
		return nil, ErrInvalidSig
	}

	V := byte(tx.data.V.Uint64())
	if !crypto.ValidateSignatureValues(V, tx.data.R, tx.data.S, false) {
		return nil, ErrInvalidSig
	}
	// encode the snature in uncompressed format
	r, s := tx.data.R.Bytes(), tx.data.S.Bytes()
	sig := make([]byte, 65)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = V - 27

	// recover the public key from the snature
	hash := fs.Hash(tx)
	pub, err := crypto.Ecrecover(hash[:], sig)
	if err != nil {
		return nil, err
	}
	if len(pub) == 0 || pub[0] != 4 {
		return nil, errors.New("invalid public key")
	}
	return pub, nil
}

// normaliseV returns the Ethereum version of the V parameter
func normaliseV(s Signer, v *big.Int) byte {
	if s, ok := s.(EIP155Signer); ok {
		stdV := v.BitLen() <= 8 && (v.Uint64() == 27 || v.Uint64() == 28)
		if s.chainId.BitLen() > 0 && !stdV {
			nv := byte((new(big.Int).Sub(v, s.chainIdMul).Uint64()) - 35 + 27)
			return nv
		}
	}
	return byte(v.Uint64())
}

// deriveChainId derives the chain id from the given v parameter
func deriveChainId(v *big.Int) *big.Int {
	if v.BitLen() <= 64 {
		v := v.Uint64()
		if v == 27 || v == 28 {
			return new(big.Int)
		}
		return new(big.Int).SetUint64((v - 35) / 2)
	}
	v = new(big.Int).Sub(v, big.NewInt(35))
	return v.Div(v, big.NewInt(2))
}
