package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
)

func littleEndianBytes(destination, value []byte) {
	for index := range value {
		destination[index] = value[len(value)-1-index]
	}
}

func main() {
	output := flag.String("output", "", "destination for the generated test strong-name key")
	flag.Parse()
	if *output == "" {
		fmt.Fprintln(os.Stderr, "-output is required")
		os.Exit(2)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	key.Precompute()
	bits := key.N.BitLen()
	half := bits / 16
	full := bits / 8
	blob := make([]byte, 20+full+half*5+full)
	blob[0], blob[1] = 7, 2                               // PRIVATEKEYBLOB, CUR_BLOB_VERSION
	binary.LittleEndian.PutUint32(blob[4:8], 0x2400)      // CALG_RSA_SIGN
	binary.LittleEndian.PutUint32(blob[8:12], 0x32415352) // RSA2
	binary.LittleEndian.PutUint32(blob[12:16], uint32(bits))
	binary.LittleEndian.PutUint32(blob[16:20], uint32(key.E))

	offset := 20
	parts := []struct {
		value []byte
		size  int
	}{
		{key.N.Bytes(), full},
		{key.Primes[0].Bytes(), half},
		{key.Primes[1].Bytes(), half},
		{key.Precomputed.Dp.Bytes(), half},
		{key.Precomputed.Dq.Bytes(), half},
		{key.Precomputed.Qinv.Bytes(), half},
		{key.D.Bytes(), full},
	}
	for _, part := range parts {
		littleEndianBytes(blob[offset:offset+part.size], part.value)
		offset += part.size
	}
	if err := os.WriteFile(*output, blob, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
