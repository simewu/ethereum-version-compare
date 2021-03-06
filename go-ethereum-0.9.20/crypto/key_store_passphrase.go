/*
	This file is part of go-ethereum

	go-ethereum is free software: you can redistribute it and/or modify
	it under the terms of the GNU Lesser General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	go-ethereum is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU Lesser General Public License
	along with go-ethereum.  If not, see <http://www.gnu.org/licenses/>.
*/
/**
 * @authors
 * 	Gustav Simonsson <gustav.simonsson@gmail.com>
 * @date 2015
 *
 */

/*

This key store behaves as KeyStorePlain with the difference that
the private key is encrypted and on disk uses another JSON encoding.

Cryptography:

1. Encryption key is first 16 bytes of SHA3-256 of first 16 bytes of
   scrypt derived key from user passphrase. Scrypt parameters
   (work factors) [1][2] are defined as constants below.
2. Scrypt salt is 32 random bytes from CSPRNG.
   It's stored in plain next to ciphertext in key file.
3. MAC is SHA3-256 of concatenation of ciphertext and last 16 bytes of scrypt derived key.
4. Plaintext is the EC private key bytes.
5. Encryption algo is AES 128 CBC [3][4]
6. CBC IV is 16 random bytes from CSPRNG.
   It's stored in plain next to ciphertext in key file.
7. Plaintext padding is PKCS #7 [5][6]

Encoding:

1. On disk, the ciphertext, MAC, salt and IV are encoded in a nested JSON object.
   cat a key file to see the structure.
2. byte arrays are base64 JSON strings.
3. The EC private key bytes are in uncompressed form [7].
   They are a big-endian byte slice of the absolute value of D [8][9].

References:

1. http://www.tarsnap.com/scrypt/scrypt-slides.pdf
2. http://stackoverflow.com/questions/11126315/what-are-optimal-scrypt-work-factors
3. http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
4. http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher-block_chaining_.28CBC.29
5. https://leanpub.com/gocrypto/read#leanpub-auto-block-cipher-modes
6. http://tools.ietf.org/html/rfc2315
7. http://bitcoin.stackexchange.com/questions/3059/what-is-a-compressed-bitcoin-key
8. http://golang.org/pkg/crypto/ecdsa/#PrivateKey
9. https://golang.org/pkg/math/big/#Int.Bytes

*/

package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"code.google.com/p/go-uuid/uuid"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/randentropy"
	"golang.org/x/crypto/scrypt"
)

const (
	keyHeaderVersion = "1"
	keyHeaderKDF     = "scrypt"
	// 2^18 / 8 / 1 uses 256MB memory and approx 1s CPU time on a modern CPU.
	scryptN     = 1 << 18
	scryptr     = 8
	scryptp     = 1
	scryptdkLen = 32
)

type keyStorePassphrase struct {
	keysDirPath string
}

func NewKeyStorePassphrase(path string) KeyStore2 {
	return &keyStorePassphrase{path}
}

func (ks keyStorePassphrase) GenerateNewKey(rand io.Reader, auth string) (key *Key, err error) {
	return GenerateNewKeyDefault(ks, rand, auth)
}

func (ks keyStorePassphrase) GetKey(keyAddr common.Address, auth string) (key *Key, err error) {
	keyBytes, keyId, err := DecryptKey(ks, keyAddr, auth)
	if err != nil {
		return nil, err
	}
	key = &Key{
		Id:         uuid.UUID(keyId),
		Address:    keyAddr,
		PrivateKey: ToECDSA(keyBytes),
	}
	return key, err
}

func (ks keyStorePassphrase) GetKeyAddresses() (addresses []common.Address, err error) {
	return GetKeyAddresses(ks.keysDirPath)
}

func (ks keyStorePassphrase) StoreKey(key *Key, auth string) (err error) {
	authArray := []byte(auth)
	salt := randentropy.GetEntropyCSPRNG(32)
	derivedKey, err := scrypt.Key(authArray, salt, scryptN, scryptr, scryptp, scryptdkLen)
	if err != nil {
		return err
	}

	encryptKey := Sha3(derivedKey[:16])[:16]

	keyBytes := FromECDSA(key.PrivateKey)
	toEncrypt := PKCS7Pad(keyBytes)

	AES128Block, err := aes.NewCipher(encryptKey)
	if err != nil {
		return err
	}

	iv := randentropy.GetEntropyCSPRNG(aes.BlockSize) // 16
	AES128CBCEncrypter := cipher.NewCBCEncrypter(AES128Block, iv)
	cipherText := make([]byte, len(toEncrypt))
	AES128CBCEncrypter.CryptBlocks(cipherText, toEncrypt)

	mac := Sha3(derivedKey[16:32], cipherText)

	scryptParamsJSON := scryptParamsJSON{
		N:     scryptN,
		R:     scryptr,
		P:     scryptp,
		DkLen: scryptdkLen,
		Salt:  hex.EncodeToString(salt),
	}

	cipherParamsJSON := cipherparamsJSON{
		IV: hex.EncodeToString(iv),
	}

	cryptoStruct := cryptoJSON{
		Cipher:       "aes-128-cbc",
		CipherText:   hex.EncodeToString(cipherText),
		CipherParams: cipherParamsJSON,
		KDF:          "scrypt",
		KDFParams:    scryptParamsJSON,
		MAC:          hex.EncodeToString(mac),
		Version:      "1",
	}
	encryptedKeyJSON := encryptedKeyJSON{
		hex.EncodeToString(key.Address[:]),
		cryptoStruct,
		key.Id.String(),
		version,
	}
	keyJSON, err := json.Marshal(encryptedKeyJSON)
	if err != nil {
		return err
	}

	return WriteKeyFile(key.Address, ks.keysDirPath, keyJSON)
}

func (ks keyStorePassphrase) DeleteKey(keyAddr common.Address, auth string) (err error) {
	// only delete if correct passphrase is given
	_, _, err = DecryptKey(ks, keyAddr, auth)
	if err != nil {
		return err
	}

	keyDirPath := filepath.Join(ks.keysDirPath, hex.EncodeToString(keyAddr[:]))
	return os.RemoveAll(keyDirPath)
}

func DecryptKey(ks keyStorePassphrase, keyAddr common.Address, auth string) (keyBytes []byte, keyId []byte, err error) {
	fileContent, err := GetKeyFile(ks.keysDirPath, keyAddr)
	if err != nil {
		return nil, nil, err
	}

	keyProtected := new(encryptedKeyJSON)
	err = json.Unmarshal(fileContent, keyProtected)

	keyId = uuid.Parse(keyProtected.Id)

	mac, err := hex.DecodeString(keyProtected.Crypto.MAC)
	if err != nil {
		return nil, nil, err
	}

	iv, err := hex.DecodeString(keyProtected.Crypto.CipherParams.IV)
	if err != nil {
		return nil, nil, err
	}

	cipherText, err := hex.DecodeString(keyProtected.Crypto.CipherText)
	if err != nil {
		return nil, nil, err
	}

	salt, err := hex.DecodeString(keyProtected.Crypto.KDFParams.Salt)
	if err != nil {
		return nil, nil, err
	}

	n := keyProtected.Crypto.KDFParams.N
	r := keyProtected.Crypto.KDFParams.R
	p := keyProtected.Crypto.KDFParams.P
	dkLen := keyProtected.Crypto.KDFParams.DkLen

	authArray := []byte(auth)
	derivedKey, err := scrypt.Key(authArray, salt, n, r, p, dkLen)
	if err != nil {
		return nil, nil, err
	}

	calculatedMAC := Sha3(derivedKey[16:32], cipherText)
	if !bytes.Equal(calculatedMAC, mac) {
		err = errors.New("Decryption failed: MAC mismatch")
		return nil, nil, err
	}

	plainText, err := aesCBCDecrypt(Sha3(derivedKey[:16])[:16], cipherText, iv)
	if err != nil {
		return nil, nil, err
	}
	return plainText, keyId, err
}
