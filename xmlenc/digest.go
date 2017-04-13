package xmlenc

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/ripemd160"
)

// DigestMethod represents a digest method such as SHA1, etc.
type DigestMethod struct {
	Algorithm string
	Hash      func() hash.Hash
}

var (
	// SHA1 implements the SHA-1 digest method (which is considered insecure)
	SHA1 = DigestMethod{
		Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
		Hash:      sha1.New,
	}

	// SHA256 implements the SHA-256 digest method
	SHA256 = DigestMethod{
		Algorithm: "http://www.w3.org/2000/09/xmldsig#sha256",
		Hash:      sha256.New,
	}

	// SHA512 implements the SHA-512 digest method
	SHA512 = DigestMethod{
		Algorithm: "http://www.w3.org/2000/09/xmldsig#sha512",
		Hash:      sha512.New,
	}

	// RIPEMD160 implements the RIPEMD160 digest method
	RIPEMD160 = DigestMethod{
		Algorithm: "http://www.w3.org/2000/09/xmldsig#ripemd160",
		Hash:      ripemd160.New,
	}
)

func init() {
	registerDigestMethod(SHA1)
	registerDigestMethod(SHA256)
	registerDigestMethod(SHA512)
	registerDigestMethod(RIPEMD160)
}
