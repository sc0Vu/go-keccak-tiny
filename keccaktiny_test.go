package keccaktiny

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// hello
var in = []byte{104, 101, 108, 108, 111}

func decodeHex(t *testing.T, src string) []byte {
	out, err := hex.DecodeString(src)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func compare(t *testing.T, a []byte, b []byte) {
	if !bytes.Equal(a, b) {
		t.Fatalf("Hash wern't equal")
	}
}

func TestShake128(t *testing.T) {
	res := decodeHex(t, "8eb4b6a932f280335ee1a279f8c208a349e7bc65daf831d3021c213825292463")
	out, err := Shake128(in)
	if err != nil {
		t.Fatal(err)
	}
	compare(t, out, res)
}

func TestShake256(t *testing.T) {
	res := decodeHex(t, "1234075ae4a1e77316cf2d8000974581a343b9ebbca7e3d1db83394c30f221626f594e4f0de63902349a5ea5781213215813919f92a4d86d127466e3d07e8be3")
	out, err := Shake256(in)
	if err != nil {
		t.Fatal(err)
	}
	compare(t, out, res)
}

func TestSha3_224(t *testing.T) {
	res := decodeHex(t, "b87f88c72702fff1748e58b87e9141a42c0dbedc29a78cb0d4a5cd81")
	out, err := Sha3_224(in)
	if err != nil {
		t.Fatal(err)
	}
	compare(t, out, res)
}

func TestSha3_256(t *testing.T) {
	res := decodeHex(t, "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392")
	out, err := Sha3_256(in)
	if err != nil {
		t.Fatal(err)
	}
	compare(t, out, res)
}

func TestSha3_384(t *testing.T) {
	res := decodeHex(t, "720aea11019ef06440fbf05d87aa24680a2153df3907b23631e7177ce620fa1330ff07c0fddee54699a4c3ee0ee9d887")
	out, err := Sha3_384(in)
	if err != nil {
		t.Fatal(err)
	}
	compare(t, out, res)
}

func TestSha3_512(t *testing.T) {
	res := decodeHex(t, "75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976")
	out, err := Sha3_512(in)
	if err != nil {
		t.Fatal(err)
	}
	compare(t, out, res)
}

func TestKeccak224(t *testing.T) {
	res := decodeHex(t, "45524ec454bcc7d4b8f74350c4a4e62809fcb49bc29df62e61b69fa4")
	out, err := Keccak224(in)
	if err != nil {
		t.Fatal(err)
	}
	compare(t, out, res)
}

func TestKeccak256(t *testing.T) {
	res := decodeHex(t, "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8")
	out, err := Keccak256(in)
	if err != nil {
		t.Fatal(err)
	}
	compare(t, out, res)
}

func TestKeccak384(t *testing.T) {
	res := decodeHex(t, "dcef6fb7908fd52ba26aaba75121526abbf1217f1c0a31024652d134d3e32fb4cd8e9c703b8f43e7277b59a5cd402175")
	out, err := Keccak384(in)
	if err != nil {
		t.Fatal(err)
	}
	compare(t, out, res)
}

func TestKeccak512(t *testing.T) {
	res := decodeHex(t, "52fa80662e64c128f8389c9ea6c73d4c02368004bf4463491900d11aaadca39d47de1b01361f207c512cfa79f0f92c3395c67ff7928e3f5ce3e3c852b392f976")
	out, err := Keccak512(in)
	if err != nil {
		t.Fatal(err)
	}
	compare(t, out, res)
}

func BenchmarkKeccak256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = Keccak256(in)
	}
}
