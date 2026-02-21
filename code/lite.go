// test796b : project USAG YAS-desktop lite
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/k-atusa/USAG-Lib/Bencode"
	"github.com/k-atusa/USAG-Lib/Bencrypt"
	"github.com/k-atusa/USAG-Lib/Opsec"
)

// command line parser
type Config struct {
	Mode      string          // pack unpack send recv genkey sign enc dec
	Output    string          // output path
	Files     []string        // target files
	Text      string          // target text or address
	TypeWords map[string]bool // keyword: webp png bin, zip1 tar1, gcm1 gcmx1, pbk1 arg1, rsa1-2k rsa1-3k rsa1-4k ecc1

	PW      string // password
	KF      []byte // keyfile
	Public  []byte // public key
	Private []byte // private key
	Msg     string // plaintext message
	SMsg    string // secure message
}

func (cfg *Config) Init() {
	defer fmt.Println("configuration completed")
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// basic mode and paths
	fs.StringVar(&cfg.Mode, "m", "", "work mode: pack, unpack, send, recv, genkey, sign, enc, dec")
	fs.StringVar(&cfg.Output, "o", "", "output path")
	fs.StringVar(&cfg.Text, "t", "", "set text input")

	// keywords
	magics := []string{"webp", "png", "bin", "zip1", "tar1", "gcm1", "gcmx1", "pbk1", "arg1", "rsa1-2k", "rsa1-3k", "rsa1-4k", "ecc1"}
	mflags := make([]bool, len(magics))
	for i, r := range magics {
		fs.BoolVar(&mflags[i], r, false, "keyword: "+r)
	}

	// authorization and security
	fs.StringVar(&cfg.PW, "pw", "", "password")
	fs.StringVar(&cfg.Msg, "msg", "", "non-secured message")
	fs.StringVar(&cfg.SMsg, "smsg", "", "secured message")

	// get keyfile
	kfpath := ""
	fs.StringVar(&kfpath, "kf", "", "key file path")

	// get public & private key
	pub, pri := "", ""
	fs.StringVar(&pub, "pub", "", "public key string or path")
	fs.StringVar(&pri, "pri", "", "private key string or path")

	// parse and get target files
	fs.Parse(os.Args[1:])
	cfg.Files = fs.Args()

	// set keywords
	cfg.TypeWords = make(map[string]bool)
	for i, r := range magics {
		if mflags[i] {
			cfg.TypeWords[r] = true
		}
	}

	// set keyfile
	if kfpath == "" {
		cfg.KF = nil
	} else if _, err := os.Stat(kfpath); err == nil { // file
		fmt.Println("reading keyfile")
		cfg.KF, err = os.ReadFile(kfpath)
		if err != nil {
			fmt.Println(err)
			cfg.KF = nil
		}
	}
	if len(cfg.KF) > 1024 {
		fmt.Println("keyfile is truncated to 1024B")
		cfg.KF = cfg.KF[:1024]
	}

	// set public & private key
	preader := func(s string) []byte {
		if _, err := os.Stat(s); err == nil && s != "" { // file
			d, e := os.ReadFile(s)
			if e != nil {
				fmt.Println(e)
			} else {
				s = string(d)
			}
		}
		if s == "" {
			return nil
		}
		d, err := Bencode.Decode(s)
		if err == nil {
			return d
		} else {
			fmt.Println(err)
			return nil
		}
	}
	cfg.Public, cfg.Private = preader(pub), preader(pri)
}

func (cfg *Config) ToPwCplx() *PwCplx {
	c := &PwCplx{PW: cfg.PW, KF: cfg.KF}
	c.AlgoType = "arg1" // default
	switch {
	case cfg.TypeWords["arg1"]:
		c.AlgoType = "arg1"
	case cfg.TypeWords["pbk1"]:
		c.AlgoType = "pbk1"
	}
	return c
}

func (cfg *Config) ToPubCplx() *PubCplx {
	c := &PubCplx{Pub: cfg.Public, Pri: cfg.Private}
	c.AlgoType = "ecc1" // default
	switch {
	case cfg.TypeWords["ecc1"]:
		c.AlgoType = "ecc1"
	case cfg.TypeWords["rsa1-2k"], cfg.TypeWords["rsa1-3k"], cfg.TypeWords["rsa1-4k"]:
		c.AlgoType = "rsa1"
	}
	return c
}

func (cfg *Config) ToEncCplx() *EncCplx {
	c := &EncCplx{Msg: cfg.Msg, Smsg: cfg.SMsg}
	c.ImgType, c.PackType, c.EncType = "webp", "tar1", "gcmx1" // default
	switch {
	case cfg.TypeWords["webp"]:
		c.ImgType = "webp"
	case cfg.TypeWords["png"]:
		c.ImgType = "png"
	case cfg.TypeWords["bin"]:
		c.ImgType = "bin"
	}
	switch {
	case cfg.TypeWords["gcm1"]:
		c.EncType = "gcm1"
	case cfg.TypeWords["gcmx1"]:
		c.EncType = "gcmx1"
	}
	switch {
	case cfg.TypeWords["zip1"]:
		c.PackType = "zip1"
	case cfg.TypeWords["tar1"]:
		c.PackType = "tar1"
	}
	return c
}

// progress printer
type Progress struct {
	bar    int
	drawed int
	cur    float64
}

func (p *Progress) OnStart() {
	p.bar, p.drawed, p.cur = 50, 0, 0.0
	fmt.Print("[")
}

func (p *Progress) OnUpdate(c float64) {
	p.cur = max(p.cur, max(0.0, min(1.0, c)))
	before, after := p.drawed, int(p.cur*float64(p.bar))
	for i := before; i < after; i++ {
		if i != 0 && i%(p.bar/5) == 0 {
			fmt.Print("|") // print every 20%
		}
		fmt.Print("=")
		p.drawed++
	}
}

func (p *Progress) OnEnd() {
	p.OnUpdate(1.0)
	for p.drawed < p.bar {
		fmt.Print("=")
		p.drawed++
	}
	fmt.Println("]")
}

func (p *Progress) OnError(err error) {
	fmt.Printf("//\n[ERROR] %v\n", err)
}

// main functions
func f_pack() error {
	if len(Cfg.Files) == 0 {
		return fmt.Errorf("no target for packing")
	}
	cfg := Cfg.ToEncCplx()
	dst := Cfg.Output
	if dst == "" {
		switch cfg.PackType {
		case "zip1":
			dst = "output.zip"
		case "tar1":
			dst = "output.tar"
		default:
			dst = "output"
		}
	}
	return Pack(Cfg.Files, dst, cfg.PackType)
}

func f_unpack() error {
	if len(Cfg.Files) == 0 {
		return fmt.Errorf("no archive for unpacking")
	}
	dst := Cfg.Output
	if dst == "" {
		dst = "./"
	}
	return Unpack(Cfg.Files[0], dst, Cfg.ToEncCplx().PackType)
}

func f_send() error {
	addr := Cfg.Text
	if addr == "" {
		addr = "127.0.0.1"
	}
	if !strings.Contains(addr, ":") {
		addr += ":8002" // default port
	}
	fmt.Print("Sending: ")
	fromPub, toPub, err := Send(Cfg.Files, Cfg.SMsg, addr, Cfg.ToPubCplx().AlgoType, new(Progress))
	fmt.Printf("[transfer] from %s to %s\n", Opsec.Crc32(fromPub), Opsec.Crc32(toPub))
	return err
}

func f_recv() error {
	port := Cfg.Text
	if port == "" {
		port = "8002" // default port
	}
	dst := Cfg.Output
	if dst == "" {
		dst = "./"
	}
	fmt.Print("Receiving: ")
	fromPub, toPub, smsg, err := Receive(dst, port, new(Progress))
	fmt.Printf("[transfer] from %s to %s\n", Opsec.Crc32(fromPub), Opsec.Crc32(toPub))
	if smsg != "" {
		fmt.Printf("\n[smsg] %s\n", smsg)
	}
	return err
}

func f_genkey() error {
	pubNm, priNm := "", ""
	var pub, pri []byte
	var err error
	switch {
	case Cfg.TypeWords["rsa1-2k"]:
		rsa := new(Bencrypt.RSA1)
		pubNm, priNm = "public_2k.txt", "private_2k.txt"
		pub, pri, err = rsa.Genkey(2048)
	case Cfg.TypeWords["rsa1-3k"]:
		rsa := new(Bencrypt.RSA1)
		pubNm, priNm = "public_3k.txt", "private_3k.txt"
		pub, pri, err = rsa.Genkey(3072)
	case Cfg.TypeWords["rsa1-4k"]:
		rsa := new(Bencrypt.RSA1)
		pubNm, priNm = "public_4k.txt", "private_4k.txt"
		pub, pri, err = rsa.Genkey(4096)
	default: // default ecc1
		ecc := new(Bencrypt.ECC1)
		pubNm, priNm = "public.txt", "private.txt"
		pub, pri, err = ecc.Genkey()
	}
	if err != nil {
		return err
	}
	if err := os.WriteFile(pubNm, []byte(Bencode.Encode(pub)), 0644); err != nil {
		return err
	}
	fmt.Printf("Public key: %s\n", pubNm)
	if err := os.WriteFile(priNm, []byte(Bencode.Encode(pri)), 0644); err != nil {
		return err
	}
	fmt.Printf("Private key: %s\n", priNm)
	return nil
}

func f_sign() error {
	// make sign
	if Cfg.Private != nil {
		if len(Cfg.Files) == 0 {
			return errors.New("no file to sign")
		}
		out := Cfg.Output
		if out == "" {
			out = "./"
		}
		am := new(Bencrypt.AsymMaster)
		if err := am.Init(Cfg.ToPubCplx().AlgoType); err != nil {
			return err
		}
		if err := am.Loadkey(nil, Cfg.Private); err != nil {
			return err
		}
		fmt.Println("Private key loaded")

		for i, f := range Cfg.Files {
			signPath := filepath.Join(out, fmt.Sprintf("sign_%d.txt", i))
			info, err := os.Stat(f)
			if err != nil {
				return err
			}
			if info.IsDir() {
				return fmt.Errorf("file %s is directory", f)
			}
			if info.Size() > 512*1048576 { // 512MB limit
				return fmt.Errorf("file %s is too large", f)
			}
			data, err := os.ReadFile(f)
			if err != nil {
				return err
			}
			sdata, err := am.Sign(data)
			if err != nil {
				return err
			}
			if err := os.WriteFile(signPath, []byte(Bencode.Encode(sdata)), 0644); err != nil {
				return err
			}
			fmt.Printf("Signed %s -> %s\n", f, signPath)
		}
		return nil
	}

	// verify sign
	if Cfg.Public != nil {
		if len(Cfg.Files) < 2 {
			return errors.New("need 2 files (file, sign)")
		}
		info, err := os.Stat(Cfg.Files[0])
		if err != nil {
			return err
		}
		if info.IsDir() {
			return fmt.Errorf("file %s is directory", Cfg.Files[0])
		}
		if info.Size() > 512*1048576 {
			return fmt.Errorf("file %s is too large", Cfg.Files[0])
		}
		data, err := os.ReadFile(Cfg.Files[0])
		if err != nil {
			return err
		}
		sdataRaw, err := os.ReadFile(Cfg.Files[1])
		if err != nil {
			return err
		}
		sdata, err := Bencode.Decode(string(sdataRaw))
		if err != nil {
			return err
		}
		fmt.Println("Target data loaded")

		am := new(Bencrypt.AsymMaster)
		if err := am.Init(Cfg.ToPubCplx().AlgoType); err != nil {
			return err
		}
		if err := am.Loadkey(Cfg.Public, nil); err != nil {
			return err
		}
		fmt.Println("Public key loaded")
		if am.Verify(data, sdata) {
			fmt.Printf("Verification success %s\n", Cfg.Files[0])
		} else {
			fmt.Printf("Invalid sign %s\n", Cfg.Files[0])
		}
		return nil
	}
	return errors.New("no key detected")
}

func f_enc() error {
	pwc, pubc, ec := Cfg.ToPwCplx(), Cfg.ToPubCplx(), Cfg.ToEncCplx()
	if Cfg.Public == nil {
		pubc = nil
	} else {
		pwc = nil
	}
	dst := Cfg.Output
	if dst == "" {
		switch ec.ImgType {
		case "webp":
			dst = "output.webp"
		case "png":
			dst = "output.png"
		case "bin":
			dst = "output.bin"
		default:
			dst = "output"
		}
	}
	fmt.Print("Encrypting: ")

	// msg-only mode
	if len(Cfg.Files) == 0 {
		enc, err := EncMsg(pwc, pubc, ec, new(Progress))
		if err != nil {
			return err
		}
		fmt.Printf("Encrypted successfully:\n\n%s\n\n", Bencode.Encode(enc))
		return nil
	}

	// file mode
	if err := EncFiles(Cfg.Files, dst, pwc, pubc, ec, new(Progress)); err != nil {
		return err
	}
	fmt.Printf("Encrypted successfully: %s\n", dst)
	return nil
}

func f_dec() error {
	if len(Cfg.Files) == 0 && Cfg.Text == "" {
		return errors.New("input source required (file or -t)")
	}
	pwc, pubc := Cfg.ToPwCplx(), Cfg.ToPubCplx()
	if Cfg.Private == nil {
		pubc = nil
	} else {
		pwc = nil
	}
	dst := Cfg.Output
	if dst == "" {
		dst = "./"
	}
	msg, smsg := "", ""
	var data []byte
	var err error

	if len(Cfg.Files) == 0 { // msg-only mode
		data, err = Bencode.Decode(Cfg.Text)
		if err != nil {
			return err
		}
		dst = "(msg-only mode)"
		fmt.Print("Decrypting: ")
		msg, smsg, err = DecMsg(data, pwc, pubc, new(Progress))
	} else { // file mode
		fmt.Print("Decrypting: ")
		msg, smsg, err = DecFile(Cfg.Files[0], dst, pwc, pubc, new(Progress))
	}

	if msg != "" {
		fmt.Printf("\n[msg] %s\n", msg)
	}
	if smsg != "" {
		fmt.Printf("\n[smsg] %s\n", smsg)
	}
	if err == nil {
		fmt.Printf("Decrypted successfully: %s\n", dst)
		return nil
	} else {
		return err
	}
}

// main runtime
var Cfg Config

func main() {
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("[PANIC] %v", err)
		}
	}()
	var err error
	Cfg.Init()
	switch Cfg.Mode {
	case "pack":
		err = f_pack()
	case "unpack":
		err = f_unpack()
	case "send":
		err = f_send()
	case "recv":
		err = f_recv()
	case "genkey":
		err = f_genkey()
	case "sign":
		err = f_sign()
	case "enc":
		err = f_enc()
	case "dec":
		err = f_dec()
	default: // help
		fmt.Println(YAS_VERSION)
		fmt.Println("-m mode [pack unpack send recv genkey sign enc dec]")
		fmt.Println("-o outputDir/Path, -t text/ip:port, -msg message, -smsg securedMessage")
		fmt.Println("-pw password, -kf keyFile, -pub publicKey, -pri privateKey")
		fmt.Println("options: [webp png] [tar1 zip1] [gcmx1 gcm1] [arg1 pbk1] [ecc1 rsa1-2k rsa1-3k rsa1-4k]")
	}
	if err != nil {
		fmt.Printf("\n[ERROR] %v\n", err)
	}
}
