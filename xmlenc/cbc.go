package xmlenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" // nolint: gas
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/beevik/etree"
)

type cbc struct {
	keySize   int
	algorithm string
	cipher    func([]byte) (cipher.Block, error)
}

func (e cbc) KeySize() int {
	return e.keySize
}

func (e cbc) Algorithm() string {
	return e.algorithm
}

func (e cbc) Encrypt(key interface{}, plaintext []byte) (*etree.Element, error) {
	keyBuf, ok := key.([]byte)
	if !ok {
		return nil, ErrIncorrectKeyType("[]byte")
	}
	if len(keyBuf) != e.keySize {
		return nil, ErrIncorrectKeyLength(e.keySize)
	}

	block, err := e.cipher(keyBuf)
	if err != nil {
		return nil, err
	}
	fmt.Printf("key      : %x\n", keyBuf)
	return cbcEncrypt(
		block,
		e.Algorithm(),
		plaintext)
}

func (e cbc) Decrypt(key interface{}, ciphertext *etree.Element) ([]byte, error) {
	if encryptedKeyEl := ciphertext.FindElement("./KeyInfo/EncryptedKey"); encryptedKeyEl != nil {
		var err error
		key, err = Decrypt(key, encryptedKeyEl)
		if err != nil {
			return nil, err
		}
	}

	keyBuf, ok := key.([]byte)
	if !ok {
		return nil, ErrIncorrectKeyType("[]byte")
	}
	block, err := e.cipher(keyBuf)
	if err != nil {
		return nil, err
	}

	fmt.Printf("key      : %x\n", keyBuf)
	return cbcDecrypt(
		block,
		ciphertext)
}

func cbcEncrypt(block cipher.Block, algorithm string, plaintext []byte) (*etree.Element, error) {
	encryptedDataEl := etree.NewElement("xenc:EncryptedData")
	encryptedDataEl.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	{
		randBuf := make([]byte, 16)
		if _, err := RandReader.Read(randBuf); err != nil {
			return nil, err
		}
		encryptedDataEl.CreateAttr("Id", fmt.Sprintf("_%x", randBuf))
	}
	encryptedDataEl.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")

	em := encryptedDataEl.CreateElement("xenc:EncryptionMethod")
	em.CreateAttr("Algorithm", algorithm)
	em.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")

	// pad the plaintext to an even multiple of the block size
	paddingBytes := block.BlockSize() - (len(plaintext) % block.BlockSize())
	padding := make([]byte, paddingBytes)
	padding[len(padding)-1] = byte(paddingBytes)
	plaintext = append(plaintext, padding...)
	fmt.Printf("padding: %d %x\n", paddingBytes, padding)
	fmt.Printf("plaintext: %x\n", plaintext)

	iv := make([]byte, block.BlockSize())
	if _, err := RandReader.Read(iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)
	fmt.Printf("ciphertxt: %x\n", ciphertext)

	ciphertext = append(iv, ciphertext...)
	fmt.Printf("ciphertext: %x\n", ciphertext)
	cd := encryptedDataEl.CreateElement("xenc:CipherData")
	cd.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	cd.CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(ciphertext))
	return encryptedDataEl, nil
}

func cbcDecrypt(block cipher.Block, encryptedData *etree.Element) ([]byte, error) {
	ciphertext, err := getCiphertext(encryptedData)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < block.BlockSize() {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	fmt.Printf("iv       : %x\n", iv)
	ciphertext = ciphertext[aes.BlockSize:]
	fmt.Printf("ciphertxt: %x\n", ciphertext)
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext) // decrypt in place
	fmt.Printf("plaintext: %x\n", plaintext)

	// expect a padding byte & strip it
	paddingBytes := int(plaintext[len(plaintext)-1])
	if paddingBytes > len(plaintext) {
		fmt.Printf("%d %x\n", len(plaintext), plaintext)
		return nil, errors.New("ciphertext too short for padding")
	}
	plaintext = plaintext[:len(plaintext)-paddingBytes]

	return plaintext, nil
}

var (
	// AES128CBC implements AES128-CBC symetric key mode for encryption and decryption
	AES128CBC BlockCipher = cbc{
		keySize:   16,
		algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
		cipher:    aes.NewCipher,
	}

	// AES192CBC implements AES192-CBC symetric key mode for encryption and decryption
	AES192CBC BlockCipher = cbc{
		keySize:   24,
		algorithm: "http://www.w3.org/2001/04/xmlenc#aes192-cbc",
		cipher:    aes.NewCipher,
	}

	// AES256CBC implements AES256-CBC symetric key mode for encryption and decryption
	AES256CBC BlockCipher = cbc{
		keySize:   32,
		algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
		cipher:    aes.NewCipher,
	}

	// TripleDES implements 3DES in CBC mode for encryption and decryption
	TripleDES BlockCipher = cbc{
		keySize:   8,
		algorithm: "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
		cipher:    des.NewCipher,
	}
)

func init() {
	registerDecrypter(AES128CBC)
	registerDecrypter(AES192CBC)
	registerDecrypter(AES256CBC)
	registerDecrypter(TripleDES)
}
