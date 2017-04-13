package xmlenc

import (
	"crypto/aes"
	"crypto/cipher" // nolint: gas
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/beevik/etree"
)

type gcm struct {
	keySize   int
	algorithm string
	cipher    func([]byte) (cipher.Block, error)
}

func (e gcm) KeySize() int {
	return e.keySize
}

func (e gcm) Algorithm() string {
	return e.algorithm
}

func (e gcm) Encrypt(key interface{}, plaintext []byte) (*etree.Element, error) {
	keyBuf, ok := key.([]byte)
	if !ok {
		return nil, fmt.Errorf("key must be []byte for block cipher")
	}
	if len(keyBuf) != e.keySize {
		return nil, aes.KeySizeError(len(keyBuf))
	}

	block, err := e.cipher(keyBuf)
	if err != nil {
		return nil, err
	}
	return gcmEncrypt(
		block,
		e.Algorithm(),
		plaintext)
}

func (e gcm) Decrypt(key interface{}, ciphertext *etree.Element) ([]byte, error) {
	if encryptedKeyEl := ciphertext.FindElement("./KeyInfo/EncryptedKey"); encryptedKeyEl != nil {
		var err error
		key, err = Decrypt(key, encryptedKeyEl)
		if err != nil {
			return nil, err
		}
	}

	keyBuf, ok := key.([]byte)
	if !ok {
		return nil, errors.New("key must be []byte for block cipher")
	}
	block, err := e.cipher(keyBuf)
	if err != nil {
		return nil, err
	}

	return gcmDecrypt(
		block,
		ciphertext)
}

func gcmEncrypt(block cipher.Block, algorithm string, plaintext []byte) (*etree.Element, error) {
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

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// TODO(ross): the spec (https://www.w3.org/TR/xmlenc-core1/#sec-Alg-Block) says:
	//   For the purposes of this specification, AES-GCM shall be used with a 96 bit Initialization Vector
	//   (IV) and a 128 bit Authentication Tag (T). The cipher text contains the IV first, followed by
	//   the encrypted octets and finally the Authentication tag. No padding should be used during
	//   encryption. During decryption the implementation should compare the authentication tag computed
	//   during decryption with the specified Authentication Tag, and fail if they don't match. For details
	//   on the implementation of AES-GCM, see [SP800-38D].
	// Ensure that we are doing the right thing here.

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := RandReader.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	ciphertext = append(nonce, ciphertext...)

	cd := encryptedDataEl.CreateElement("xenc:CipherData")
	cd.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	cd.CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(ciphertext))
	return encryptedDataEl, nil
}

func gcmDecrypt(block cipher.Block, encryptedData *etree.Element) ([]byte, error) {
	ciphertext, err := getCiphertext(encryptedData)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aesgcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:aesgcm.NonceSize()]
	ciphertext = ciphertext[aesgcm.NonceSize():]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

var (
	// AES128GCM implements the AES128-GCM symetric cipher for encryption and decryption
	AES128GCM BlockCipher = gcm{
		keySize:   16,
		algorithm: "http://www.w3.org/2009/xmlenc11#aes128-gcm",
		cipher:    aes.NewCipher,
	}

	// AES192GCM implements the AES128-GCM symetric cipher for encryption and decryption
	AES192GCM BlockCipher = gcm{
		keySize:   24,
		algorithm: "http://www.w3.org/2009/xmlenc11#aes192-gcm",
		cipher:    aes.NewCipher,
	}

	// AES256GCM implements the AES128-GCM symetric cipher for encryption and decryption
	AES256GCM BlockCipher = gcm{
		keySize:   32,
		algorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm",
		cipher:    aes.NewCipher,
	}
)

func init() {
	registerDecrypter(AES128GCM)
	registerDecrypter(AES192GCM)
	registerDecrypter(AES256GCM)
}
