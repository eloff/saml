package xmlenc

import (
	"encoding/pem"
	"fmt"
	"math/rand"
	"strings"

	"github.com/beevik/etree"
	"github.com/kr/pretty"
	. "gopkg.in/check.v1"
)

type EncryptTest struct {
}

var _ = Suite(&EncryptTest{})

const (
	testKey            = "-----BEGIN RSA PRIVATE KEY-----\nMIICXgIBAAKBgQDU8wdiaFmPfTyRYuFlVPi866WrH/2JubkHzp89bBQopDaLXYxi\n3PTu3O6Q/KaKxMOFBqrInwqpv/omOGZ4ycQ51O9I+Yc7ybVlW94lTo2gpGf+Y/8E\nPsVbnZaFutRctJ4dVIp9aQ2TpLiGT0xX1OzBO/JEgq9GzDRf+B+eqSuglwIDAQAB\nAoGBAMuy1eN6cgFiCOgBsB3gVDdTKpww87Qk5ivjqEt28SmXO13A1KNVPS6oQ8SJ\nCT5Azc6X/BIAoJCURVL+LHdqebogKljhH/3yIel1kH19vr4E2kTM/tYH+qj8afUS\nJEmArUzsmmK8ccuNqBcllqdwCZjxL4CHDUmyRudFcHVX9oyhAkEA/OV1OkjM3CLU\nN3sqELdMmHq5QZCUihBmk3/N5OvGdqAFGBlEeewlepEVxkh7JnaNXAXrKHRVu/f/\nfbCQxH+qrwJBANeQERF97b9Sibp9xgolb749UWNlAdqmEpmlvmS202TdcaaT1msU\n4rRLiQN3X9O9mq4LZMSVethrQAdX1whawpkCQQDk1yGf7xZpMJ8F4U5sN+F4rLyM\nRq8Sy8p2OBTwzCUXXK+fYeXjybsUUMr6VMYTRP2fQr/LKJIX+E5ZxvcIyFmDAkEA\nyfjNVUNVaIbQTzEbRlRvT6MqR+PTCefC072NF9aJWR93JimspGZMR7viY6IM4lrr\nvBkm0F5yXKaYtoiiDMzlOQJADqmEwXl0D72ZG/2KDg8b4QZEmC9i5gidpQwJXUc6\nhU+IVQoLxRq0fBib/36K9tcrrO5Ba4iEvDcNY+D8yGbUtA==\n-----END RSA PRIVATE KEY-----\n"
	testCertificate    = "-----BEGIN CERTIFICATE-----\nMIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJV\nUzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0\nMB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMx\nCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCB\nnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9\nibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmH\nO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKv\nRsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgk\nakpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeT\nQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvn\nOwJlNCASPZRH/JmF8tX0hoHuAQ==\n-----END CERTIFICATE-----\n"
	expectedCiphertext = `<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Id="_e285ece1511455780875d64ee2d3d0d0" Type="http://www.w3.org/2001/04/xmlenc#Element">
	<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/>
	<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
		<xenc:EncryptedKey Id="_6e4ff95ff662a5eee82abdf44a2d0b75" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
			<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
				<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>
			</xenc:EncryptionMethod>
			<ds:KeyInfo>
				<ds:X509Data>
					<ds:X509Certificate>MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==</ds:X509Certificate>
				</ds:X509Data>
			</ds:KeyInfo>
			<xenc:CipherData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
				<xenc:CipherValue>R9aHQv2U2ZZSuvRaL4/X8TXpm2/1so2IiOz/+NsAzEKoLAg8Sj87Nj5oMrYY2HF5DPQm/N/3+v6wOU9dX62spTzoSWocVzQU+GdTG2DiIIiAAvQwZo1FyUDKS1Fs5voWzgKvs8G43nj68147T96sXY9SyeUBBdhQtXRsEsmKiAs=</xenc:CipherValue>
			</xenc:CipherData>
		</xenc:EncryptedKey>
	</ds:KeyInfo>
	<xenc:CipherData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
		<xenc:CipherValue>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</xenc:CipherValue>
	</xenc:CipherData>
</xenc:EncryptedData>
`
)

func (test *EncryptTest) SetUpTest(c *C) {
	RandReader = rand.New(rand.NewSource(0)) // deterministic random numbers for tests
}

func (test *EncryptTest) TestCanEncryptOAEP(c *C) {
	var err error
	pemBlock, _ := pem.Decode([]byte(testCertificate))
	certificate := []byte(pemBlock.Bytes)

	e := OAEP()
	e.BlockCipher = AES128CBC
	e.DigestMethod = &SHA1

	el, err := e.Encrypt(certificate, []byte(expectedPlaintext))
	c.Assert(err, IsNil)

	doc := etree.NewDocument()
	doc.SetRoot(el)
	doc.IndentTabs()
	ciphertext, _ := doc.WriteToString()

	diff := pretty.Diff(strings.Split(ciphertext, "\n"), strings.Split(expectedCiphertext, "\n"))
	for _, l := range diff {
		fmt.Println(l)
	}
	c.Assert(ciphertext, Equals, expectedCiphertext)
}
