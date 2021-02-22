package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

type Password [16]byte

func (pwd *Password) String() string {
	return string(pwd[:])
}

func (pwd *Password) Set(value string) error {
	if len(value) == 0 {
		return errors.New("Empty password")
	}

	*pwd = Password(md5.Sum([]byte(value)))

	return nil
}

type Input string

func (in *Input) String() string {
	return string(*in)
}

func (in *Input) Set(value string) error {
	const invalidError = "Input file is invalid"

	if len(value) == 0 {
		return errors.New(invalidError)
	}

	stat, err := os.Stat(value)

	if os.IsNotExist(err) {
		return errors.New("Input file does not exist")
	}

	if stat.IsDir() || stat.Size() <= 0 {
		return errors.New(invalidError)
	}

	*in = Input(value)

	return nil
}

type Output string

func (out *Output) String() string {
	return string(*out)
}

func (out *Output) Set(value string) error {
	const invalidError = "Output file is invalid"

	if len(value) == 0 {
		return errors.New(invalidError)
	}

	stat, err := os.Stat(value)

	if os.IsExist(err) && stat.IsDir() {
		return errors.New(invalidError)
	}

	*out = Output(value)

	return nil
}

type Header struct {
	Signature [8]byte
	FileSize  uint32
	AssocSize uint32
	Nonce     [aes.BlockSize]byte
	Hash      [sha256.Size / 2]byte
}

func (h Header) Size() int {
	return binary.Size(h)
}

func (h Header) EncodedSize() uint32 {
	return h.FileSize - h.AssocSize - uint32(h.Size())
}

type Context struct {
	compress bool
	keysize  int
	password Password
	in       Input
	out      Output
}

func (ctx Context) CompressAndEncode() error {
	in, err := os.Open(ctx.in.String())

	if err != nil {
		return err
	}

	defer in.Close()

	var buf bytes.Buffer

	zw := gzip.NewWriter(&buf)

	defer zw.Close()

	if _, err := io.Copy(zw, in); err != nil {
		return io.ErrUnexpectedEOF
	}

	if err := zw.Close(); err != nil {
		return err
	}

	if err := in.Close(); err != nil {
		return err
	}

	key, _ := hex.DecodeString(secret) // Not expecting an InvalidByteError

	blk, _ := aes.NewCipher(key[:ctx.keysize/8]) // Not expecting a KeySizeError

	nonce := make([]byte, aes.BlockSize)

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ctr := cipher.NewCTR(blk, nonce)

	ciphertxt := make([]byte, buf.Len())

	ctr.XORKeyStream(ciphertxt, buf.Bytes())

	buf.Reset()

	assoctxt := []byte(hex.EncodeToString(ctx.password[:]))

	hdr := Header{}

	copy(hdr.Signature[:], []byte(AEAD10))
	copy(hdr.Nonce[:], nonce)
	copy(hdr.Hash[:], key[:aes.BlockSize])

	hdr.AssocSize = uint32(len(assoctxt))
	hdr.FileSize = hdr.AssocSize + uint32(len(ciphertxt)+hdr.Size())

	binary.Write(&buf, binary.BigEndian, hdr)

	buf.Write(assoctxt)
	buf.Write(ciphertxt)

	hash := sha256.New()

	hash.Write(buf.Bytes()) // Grab the bytes before draining the buffer

	out, err := os.Create(ctx.out.String())

	if err != nil {
		return err
	}

	defer out.Close()

	len := int64(buf.Len())

	if n, err := buf.WriteTo(out); n != len || err != nil { // Drain the buffer
		return err
	}

	out.WriteAt(hash.Sum(nil)[:16], int64(hdr.Size()-binary.Size(hdr.Hash))) // Overwrite key

	if err := out.Sync(); err != nil {
		return err
	}

	if err := out.Close(); err != nil {
		return err
	}

	return nil
}

func (ctx Context) DecodeAndExpand() error {
	txt, err := ioutil.ReadFile(ctx.in.String())

	if err != nil {
		return err
	}

	buf := bytes.NewBuffer(txt)

	hdr := Header{}

	if err := binary.Read(buf, binary.BigEndian, &hdr); err != nil {
		return err
	}

	gsdf := bytes.Compare(hdr.Signature[:], []byte(GSDF10)) == 0

	if !gsdf && bytes.Compare(hdr.Signature[:], []byte(AEAD10)) != 0 {
		return errors.New("Invalid signature")
	}

	hashtxt := make([]byte, sha256.Size/2)

	copy(hashtxt, txt[32:48])

	key, _ := hex.DecodeString(secret)

	copy(txt[32:48], key[:aes.BlockSize])

	hash := sha256.New()

	hash.Write(txt)

	if !bytes.Contains(hash.Sum(nil), hashtxt) {
		return errors.New("Invalid hash")
	}

	assoctxt := make([]byte, hdr.AssocSize) // Admin password MD5

	if n, _ := buf.Read(assoctxt); n != len(assoctxt) {
		return io.ErrUnexpectedEOF
	}

	if !gsdf && string(assoctxt) != hex.EncodeToString(ctx.password[:]) {
		return errors.New("Invalid password")
	}

	ciphertxt := make([]byte, hdr.EncodedSize())

	if n, _ := buf.Read(ciphertxt); n != len(ciphertxt) {
		return io.ErrUnexpectedEOF
	}

	blk, _ := aes.NewCipher(key[:ctx.keysize/8]) // Not expecting a KeySizeError

	ctr := cipher.NewCTR(blk, hdr.Nonce[:])

	ctr.XORKeyStream(ciphertxt, ciphertxt)

	out, err := os.Create(ctx.out.String())

	if err != nil {
		return err
	}

	defer out.Close()

	rdr := bytes.NewReader(ciphertxt) // Really plain-text

	zr, err := gzip.NewReader(rdr)

	if err == nil {
		defer zr.Close()

		for {
			zr.Multistream(false)

			if _, err := io.Copy(out, zr); err != nil {
				return err
			}

			err = zr.Reset(rdr)

			if err == io.EOF {
				break
			}

			if err != nil {
				return err
			}
		}
	} else { // Not gzip'd
		rdr.Reset(ciphertxt)

		if n, err := io.Copy(out, rdr); n != rdr.Size() || err != nil {
			return io.ErrUnexpectedEOF
		}
	}

	if err := out.Sync(); err != nil {
		return err
	}

	if err := out.Close(); err != nil {
		return err
	}

	return nil
}

const (
	GSDF10 = "GSDF 10\000"
	AEAD10 = "AEAD 10\000"
	empty  = ""
	secret = "7da25813dd9d7a153e60a028baddb28800000000000000000000000000000000"
)

var (
	ctx Context
)

func init() {
	flag.BoolVar(&ctx.compress, "c", false, empty)
	flag.IntVar(&ctx.keysize, "keysize", 256, empty)
	flag.IntVar(&ctx.keysize, "k", 256, empty)
	flag.Var(&ctx.password, "password", empty)
	flag.Var(&ctx.password, "p", empty)
	flag.Var(&ctx.in, "input", empty)
	flag.Var(&ctx.in, "in", empty)
	flag.Var(&ctx.out, "output", empty)
	flag.Var(&ctx.out, "out", empty)

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [-c] [-k 128|256] [-p password] <in> <out>\n", flag.CommandLine.Name())
	}
}

func main() {
	flag.Parse()

	for !flag.Parsed() {
	}

	if len(ctx.in) == 0 || len(ctx.out) == 0 {
		if flag.NArg() < 2 {
			flag.Usage()
			os.Exit(1)
		}

		if err := ctx.in.Set(flag.Arg(0)); err != nil {
			log.Fatal(err)
		}

		if err := ctx.out.Set(flag.Arg(1)); err != nil {
			log.Fatal(err)
		}
	}

	switch ctx.keysize {
	case 128, 256:
		break
	default:
		log.Fatal(aes.KeySizeError(ctx.keysize))
	}

	if ctx.compress {
		if err := ctx.CompressAndEncode(); err != nil {
			log.Fatal(err)
		}
	} else {
		if err := ctx.DecodeAndExpand(); err != nil {
			log.Fatal(err)
		}
	}
}
