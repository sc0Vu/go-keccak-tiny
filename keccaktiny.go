package keccaktiny

// build cgo

// #cgo CFLAGS: -I .
// #cgo CFLAGS: -I ./src
// #define USE_NUM_NONE
// #define USE_FIELD_10X26
// #define USE_FIELD_INV_BUILTIN
// #define USE_SCALAR_8X32
// #define USE_SCALAR_INV_BUILTIN
// #define NDEBUG
// #include <./src/keccak-tiny.c>
// #include <./src/keccak-tiny.h>
import "C"

import (
	"fmt"
)

var (
	errEmptySrc = fmt.Errorf("Input cannot be empty")
	errWhenHash = fmt.Errorf("Got error when hash the input")
)

// Shake128 returns shake128 hash of source
func Shake128(src []byte) ([]byte, error) {
	if len(src) <= 0 {
		return nil, errEmptySrc
	}
	out := make([]byte, 32)
	res := C.shake128((*C.uchar)(&out[0]), C.size_t(len(out)), (*C.uchar)(&src[0]), C.size_t(len(src)))
	if res < 0 {
		return nil, errWhenHash
	}
	return out, nil
}

// Shake256 returns shake256 hash of source
func Shake256(src []byte) ([]byte, error) {
	if len(src) <= 0 {
		return nil, errEmptySrc
	}
	out := make([]byte, 64)
	res := C.shake256((*C.uchar)(&out[0]), C.size_t(len(out)), (*C.uchar)(&src[0]), C.size_t(len(src)))
	if res < 0 {
		return nil, errWhenHash
	}
	return out, nil
}

// Sha3_224 returns sha3_224 hash of source
func Sha3_224(src []byte) ([]byte, error) {
	if len(src) <= 0 {
		return nil, errEmptySrc
	}
	out := make([]byte, 28)
	res := C.sha3_224((*C.uchar)(&out[0]), C.size_t(len(out)), (*C.uchar)(&src[0]), C.size_t(len(src)))
	if res < 0 {
		return nil, errWhenHash
	}
	return out, nil
}

// Sha3_256 returns sha3_256 hash of source
func Sha3_256(src []byte) ([]byte, error) {
	if len(src) <= 0 {
		return nil, errEmptySrc
	}
	out := make([]byte, 32)
	res := C.sha3_256((*C.uchar)(&out[0]), C.size_t(len(out)), (*C.uchar)(&src[0]), C.size_t(len(src)))
	if res < 0 {
		return nil, errWhenHash
	}
	return out, nil
}

// Sha3_384 returns sha3_384 hash of source
func Sha3_384(src []byte) ([]byte, error) {
	if len(src) <= 0 {
		return nil, errEmptySrc
	}
	out := make([]byte, 48)
	res := C.sha3_384((*C.uchar)(&out[0]), C.size_t(len(out)), (*C.uchar)(&src[0]), C.size_t(len(src)))
	if res < 0 {
		return nil, errWhenHash
	}
	return out, nil
}

// Sha3_512 returns sha3_512 hash of source
func Sha3_512(src []byte) ([]byte, error) {
	if len(src) <= 0 {
		return nil, errEmptySrc
	}
	out := make([]byte, 64)
	res := C.sha3_512((*C.uchar)(&out[0]), C.size_t(len(out)), (*C.uchar)(&src[0]), C.size_t(len(src)))
	if res < 0 {
		return nil, errWhenHash
	}
	return out, nil
}

// Keccak224 returns keccak224 hash of source
func Keccak224(src []byte) ([]byte, error) {
	if len(src) <= 0 {
		return nil, errEmptySrc
	}
	out := make([]byte, 28)
	res := C.keccak_224((*C.uchar)(&out[0]), C.size_t(len(out)), (*C.uchar)(&src[0]), C.size_t(len(src)))
	if res < 0 {
		return nil, errWhenHash
	}
	return out, nil
}

// Keccak256 returns keccak256 hash of source
func Keccak256(src []byte) ([]byte, error) {
	if len(src) <= 0 {
		return nil, errEmptySrc
	}
	out := make([]byte, 32)
	res := C.keccak_256((*C.uchar)(&out[0]), C.size_t(len(out)), (*C.uchar)(&src[0]), C.size_t(len(src)))
	if res < 0 {
		return nil, errWhenHash
	}
	return out, nil
}

// Keccak384 returns keccak384 hash of source
func Keccak384(src []byte) ([]byte, error) {
	if len(src) <= 0 {
		return nil, errEmptySrc
	}
	out := make([]byte, 48)
	res := C.keccak_384((*C.uchar)(&out[0]), C.size_t(len(out)), (*C.uchar)(&src[0]), C.size_t(len(src)))
	if res < 0 {
		return nil, errWhenHash
	}
	return out, nil
}

// Keccak512 returns keccak512 hash of source
func Keccak512(src []byte) ([]byte, error) {
	if len(src) <= 0 {
		return nil, errEmptySrc
	}
	out := make([]byte, 64)
	res := C.keccak_512((*C.uchar)(&out[0]), C.size_t(len(out)), (*C.uchar)(&src[0]), C.size_t(len(src)))
	if res < 0 {
		return nil, errWhenHash
	}
	return out, nil
}
