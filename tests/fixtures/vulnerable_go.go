// Fixture: Go code with quantum-vulnerable cryptography.
// Every usage here should trigger at least one finding.

package main

import (
	"crypto/des"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"fmt"
	mathrand "math/rand"
)

func main() {
	// RSA key generation — quantum vulnerable
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	fmt.Println(privateKey)

	// DSA — quantum vulnerable
	var dsaParams dsa.Parameters
	dsa.GenerateParameters(&dsaParams, rand.Reader, dsa.L1024N160)

	// ECDSA — quantum vulnerable
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fmt.Println(ecKey)

	// MD5 — broken hash
	hash := md5.Sum([]byte("data"))
	fmt.Println(hash)

	// SHA-1 — broken hash
	sha1Hash := sha1.Sum([]byte("data"))
	fmt.Println(sha1Hash)

	// DES — broken cipher
	block, _ := des.NewCipher([]byte("12345678"))
	fmt.Println(block)

	// Weak random
	weakKey := mathrand.Intn(1000000)
	fmt.Println(weakKey)
}
