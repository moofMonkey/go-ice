package ice

import (
	"io"
)

type Writer struct {
	dst         io.Writer
	key         *Key
	cachedBytes int
	cache       [BlockSize * 128]byte
}

func (w *Writer) Write(p []byte) (n int, err error) {
	for len(p) > 0 {
		if w.cachedBytes > 0 || len(p) < BlockSize {
			writeSize := BlockSize - w.cachedBytes
			if writeSize > len(p) {
				writeSize = len(p)
			}
			copy(w.cache[w.cachedBytes:], p)
			w.cachedBytes += writeSize
			p = p[writeSize:]
			n += writeSize
			if w.cachedBytes == BlockSize {
				w.cachedBytes = 0
				w.key.Encrypt(w.cache[:])
				_, err = w.dst.Write(w.cache[:BlockSize])
				if err != nil {
					n -= writeSize
					return
				}
			}
			continue
		}

		// fast path for aligned writes
		writeSize := len(p) - (len(p) % BlockSize)
		if writeSize > len(w.cache) {
			writeSize = len(w.cache)
		}
		copy(w.cache[:], p[:writeSize])
		for i := 0; i < writeSize; i += BlockSize {
			w.key.Encrypt(w.cache[i:])
		}
		var actualWrote int
		actualWrote, err = w.dst.Write(w.cache[:writeSize])
		if actualWrote < writeSize {
			writeSize = actualWrote - (actualWrote % BlockSize)
		}
		p = p[writeSize:]
		n += writeSize
		if err != nil {
			return
		}
	}
	return
}

func (w *Writer) Flush() error {
	if w.cachedBytes == 0 {
		return nil
	}
	for i := w.cachedBytes; i < BlockSize; i++ {
		w.cache[i] = 0
	}
	w.cachedBytes = 0
	w.key.Encrypt(w.cache[:])
	_, err := w.dst.Write(w.cache[:BlockSize])
	return err
}

func NewWriter(w io.Writer, key *Key) *Writer {
	return &Writer{
		dst: w,
		key: key,
	}
}
