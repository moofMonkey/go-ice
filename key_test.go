package ice

import (
	"encoding/hex"
	"github.com/stretchr/testify/require"
	"math/rand"
	"testing"
	"time"
)

func BenchmarkKey(b *testing.B) {
	rand.Seed(time.Now().UnixNano())
	var seed [8]byte
	rand.Read(seed[:])
	var key Key
	key.SetSeed(seed)
	var data [BlockSize * 1024]byte
	rand.Read(data[:])
	var dst [len(data)]byte
	b.Run("Init", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(16)
		for i := 0; i < b.N; i++ {
			key.SetSeed(seed)
		}
	})
	b.Run("Encrypt", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(BlockSize * 1024)
		for i := 0; i < b.N; i++ {
			for j := 0; j < 1024; j++ {
				key.Encrypt(dst[j*BlockSize:], data[j*BlockSize:])
			}
		}
	})
	b.Run("Decrypt", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(BlockSize * 1024)
		for i := 0; i < b.N; i++ {
			for j := 0; j < 1024; j++ {
				key.Decrypt(dst[j*BlockSize:], data[j*BlockSize:])
			}
		}
	})
}

func TestKey(t *testing.T) {
	var seed [8]byte
	seedParsed, _ := hex.DecodeString("52fdfc072182654f")
	copy(seed[:], seedParsed)
	data, _ := hex.DecodeString("163f5f0f9a621d72")
	encryptedExpect, _ := hex.DecodeString("1fffcd22d2488a39")
	var key Key
	key.SetSeed(seed)
	t.Run("Encrypt", func(t *testing.T) {
		var res [BlockSize]byte
		key.Encrypt(res[:], data)
		require.Equal(t, encryptedExpect, res[:])
	})
	t.Run("Decrypt", func(t *testing.T) {
		var res [BlockSize]byte
		key.Decrypt(res[:], encryptedExpect)
		require.Equal(t, data, res[:])
	})
	t.Run("BlockSize", func(t *testing.T) {
		require.Equal(t, BlockSize, key.BlockSize())
	})
}
