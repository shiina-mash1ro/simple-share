package common

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"net"
	"os"
	"sync"
	"time"
	"unsafe"
)

type EncryptStream struct {
	aead cipher.AEAD
	net.Conn
	nonce    []byte
	WriteBuf []byte
	ReadBuf  []byte
}

const payloadSizeMask = 0x7FFF

func NewAead(password string) cipher.AEAD {
	key, err := GetHkdf(password, 32)
	if err != nil {
		return nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("aes.NewCipher fail")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic("cipher.NewGCM fail")
	}
	return aead
}

func GetHkdf(password string, count uint) ([]byte, error) {
	salt := []byte("share")
	var info []byte
	hkdfReader := hkdf.New(sha256.New, *(*[]byte)(unsafe.Pointer(&password)), salt, info)
	key := make([]byte, count)
	_, err := hkdfReader.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func NewEncryptStream(conn net.Conn, key string) *EncryptStream {
	aead := NewAead(key)
	return &EncryptStream{
		aead:     aead,
		Conn:     conn,
		nonce:    make([]byte, aead.NonceSize()),
		WriteBuf: make([]byte, payloadSizeMask),
		ReadBuf:  make([]byte, payloadSizeMask),
	}
}

func (es *EncryptStream) Read(b []byte) (int, error) {
	sizeBuf := make([]byte, 2)
	//sizeBuf := es.ReadBuf[:2]
	//payloadBuf := es.ReadBuf[2:]
	//_, err := es.Conn.Read(sizeBuf)
	_, err := io.ReadFull(es.Conn, sizeBuf)
	if err != nil {
		return 0, err
	}
	size := int(sizeBuf[0])<<8 + int(sizeBuf[1])
	//fmt.Printf("read %d\n", size)
	if size > 0 {
		//payloadBuf = payloadBuf[:size+es.aead.Overhead()]
		payloadBuf := make([]byte, size+es.aead.Overhead())
		//payloadBuf := make([]byte, size)
		increment(es.nonce)
		//fmt.Printf("%s\n", base64.URLEncoding.EncodeToString(es.nonce))
		_, err := io.ReadFull(es.Conn, payloadBuf)
		if err != nil {
			return 0, err
		}
		es.aead.Open(payloadBuf[:0], es.nonce, payloadBuf, nil)
		copy(b, payloadBuf[:size])
		//fmt.Println(payloadBuf[:size])
		return size, nil
	}
	return size, nil
}

func (es *EncryptStream) Write(b []byte) (n int, err error) {
	buf := bytes.NewBuffer(b)

	for {
		writeInputBuf := es.WriteBuf
		encryptPayload := writeInputBuf[2 : payloadSizeMask-es.aead.Overhead()]
		nr, er := buf.Read(encryptPayload)

		if nr > 0 {
			n += nr
			writeInputBuf[0], writeInputBuf[1] = byte(nr>>8), byte(nr) // big-endian payload size
			increment(es.nonce)
			//fmt.Printf("%s\n", base64.URLEncoding.EncodeToString(es.nonce))
			// dst 传进去必须要 [:0]
			es.aead.Seal(encryptPayload[:0], es.nonce, encryptPayload[:nr], nil)
			_, ew := es.Conn.Write(writeInputBuf[:2+nr+es.aead.Overhead()])
			//_, ew := es.Conn.Write(writeInputBuf[:2+nr])
			//fmt.Printf("write %d, %d / %d\n", nr, n, len(b))
			if ew != nil {
				err = ew
				break
			}
		}

		if er != nil {
			if er != io.EOF { // ignore EOF as per io.ReaderFrom contract
				err = er
			}
			break
		}
	}
	if err != nil {
		fmt.Println(err.Error())
	}
	return n, err

}

func Relay(left, right net.Conn) error {
	var err, err1 error
	var wg sync.WaitGroup
	var wait = 5 * time.Second
	wg.Add(1)
	//logFile, _ := os.OpenFile("relay_log_write.log", os.O_APPEND|os.O_CREATE, 0666)
	//logFile2, _ := os.OpenFile("relay_log_write2.log", os.O_APPEND|os.O_CREATE, 0666)
	go func() {
		defer wg.Done()
		_, err1 = io.Copy(right, left)
		//w := io.MultiWriter(right, logFile)
		//io.Copy(w, left)
		right.SetReadDeadline(time.Now().Add(wait)) // unblock read on right
	}()
	_, err = io.Copy(left, right)
	//w2 := io.MultiWriter(left, logFile2)
	//io.Copy(w2, right)
	left.SetReadDeadline(time.Now().Add(wait)) // unblock read on left
	wg.Wait()
	if err1 != nil && !errors.Is(err1, os.ErrDeadlineExceeded) { // requires Go 1.15+
		return err1
	}
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	return nil
}

func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}
