package xmlenc

import (
	"crypto/rand"
	"io"

	"github.com/beevik/etree"
)

// RandReader is a thunk that allows test to replace the source of randomness used by
// this package. By default it is Reader from crypto/rand.
var RandReader io.Reader = rand.Reader

// Encrypter is an interface that encrypts things. Given a plaintext it returns an
// XML EncryptedData or EncryptedKey element.
type Encrypter interface {
	Encrypt(key interface{}, plaintext []byte) (*etree.Element, error)
}

// Decrypter is an interface that decrypts things. The Decrypt() method returns the
// plaintext version of the EncryptedData or EncryptedKey element passed.
//
// You probably don't have to use this interface directly, instead you may call
// Decrypt() and it will examine the element to determine which Decrypter to use.
type Decrypter interface {
	Algorithm() string
	Decrypt(key interface{}, ciphertextEl *etree.Element) ([]byte, error)
}

var decrypters = map[string]Decrypter{}

func registerDecrypter(d Decrypter) {
	decrypters[d.Algorithm()] = d
}

var digestMethods = map[string]DigestMethod{}

func registerDigestMethod(dm DigestMethod) {
	digestMethods[dm.Algorithm] = dm
}

// BlockCipher implements a cipher with a fixed size key like AES or 3DES.
type BlockCipher interface {
	Encrypter
	Decrypter
	KeySize() int
}
