package brainpool_test

import (
	"../brainpool"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// FIXME: find proper test vector
func TestECDSA(t *testing.T) {

	var curves = []elliptic.Curve{
		brainpool.P160t1(),
		brainpool.P192t1(),
		brainpool.P224t1(),
		brainpool.P256t1(),
		brainpool.P320t1(),
		brainpool.P384t1(),
		brainpool.P512t1(),
	}

	var hash = []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}

	for _, curve := range curves {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		r, s, err := ecdsa.Sign(rand.Reader, priv, hash)
		if err != nil {
			t.Fatal(err)
		}

		if !ecdsa.Verify(&priv.PublicKey, hash, r, s) {
			t.Fatal("verification failed")
		}
	}

}
