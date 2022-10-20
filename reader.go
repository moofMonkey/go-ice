package ice

import (
	"crypto/cipher"
	"io"
)

type Reader struct {
	src            io.Reader
	key            cipher.Block
	remainingBytes int
	cache          [BlockSize]byte
}

func (r *Reader) Read(p []byte) (n int, err error) {
	for len(p) > 0 {
		if r.remainingBytes > 0 {
			readSize := r.remainingBytes
			if readSize > len(p) {
				readSize = len(p)
			}
			copy(p, r.cache[len(r.cache)-r.remainingBytes:])
			r.remainingBytes -= readSize
			n += readSize
			p = p[readSize:]
			continue
		}
		// fast path for aligned reads
		if len(p) >= BlockSize {
			readSize := len(p) - (len(p) % BlockSize)
			var actualRead int
			actualRead, err = io.ReadFull(r.src, p[:readSize])
			if actualRead < readSize {
				readSize = actualRead - (actualRead % BlockSize)
			}
			for i := 0; i < readSize; i += BlockSize {
				r.key.Decrypt(p[i:], p[i:])
			}
			p = p[readSize:]
			n += readSize
			if err != nil {
				if readSize > 0 && err == io.ErrUnexpectedEOF {
					err = io.EOF
				}
				return
			}
			continue
		}
		if _, err = io.ReadFull(r.src, r.cache[:]); err != nil {
			return
		}
		r.key.Decrypt(r.cache[:], r.cache[:])
		readSize := len(r.cache)
		if readSize > len(p) {
			readSize = len(p)
		}
		copy(p, r.cache[:])
		r.remainingBytes = len(r.cache) - readSize
		p = p[readSize:]
		n += readSize
	}
	return
}

func NewReader(r io.Reader, key cipher.Block) *Reader {
	return &Reader{
		src: r,
		key: key,
	}
}
