// test796b : project USAG YAS-desktop cli
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/k-atusa/USAG-Lib/Bencode"
	"github.com/k-atusa/USAG-Lib/Bencrypt"
	"github.com/k-atusa/USAG-Lib/Icons"
	"github.com/k-atusa/USAG-Lib/Opsec"
)

// go mod init example.com
// go mod tidy
// go build -ldflags="-s -w" -trimpath -o yascli.exe lib.go main_cli.go

// command line parser
type Config struct {
	Mode    string   // zip unzip send recv genkey sign enc dec version help
	TempDir string   // set temp directory path
	Output  string   // output path
	Files   []string // target files
	Text    string   // target text or address

	PreHead  string // none, zippng, zipwebp, aespng, aeswebp, cloudpng, cloudwebp
	IsLegacy bool   // enables PBKDF2/RSA
	IsZip    bool   // zip or tar (for f_zip)

	PW      string // password
	KF      []byte // keyfile
	Public  []byte // public key
	Private []byte // private key
	Msg     string // plaintext message
	SMsg    string // secure message
	Bits    int    // RSA key bits
}

func (cfg *Config) Init() {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError) // empty string means auto

	// basic mode and paths
	fs.StringVar(&cfg.Mode, "m", "help", "work mode: zip, unzip, send, recv, genkey, sign, enc, dec, version, help")
	fs.StringVar(&cfg.TempDir, "tmp", "", "set temp dir path")
	fs.StringVar(&cfg.Output, "o", "", "output file path")
	fs.StringVar(&cfg.Text, "t", "", "set text input")

	// algorithm and pre-header types
	fs.StringVar(&cfg.PreHead, "pre", "", "PreHeader Type: none, zippng, zipwebp, aespng, aeswebp, cloudpng, cloudwebp")
	fs.BoolVar(&cfg.IsLegacy, "legacy", false, "Enables PBKDF2/RSA")
	fs.BoolVar(&cfg.IsZip, "zip", false, "Enables zip mode")

	// authorization and security
	fs.StringVar(&cfg.PW, "pw", "", "password")
	fs.StringVar(&cfg.Msg, "msg", "", "non-secured message")
	fs.StringVar(&cfg.SMsg, "smsg", "", "secured message")
	fs.IntVar(&cfg.Bits, "bits", 2048, "RSA key bits")

	// get keyfile
	kfpath := ""
	fs.StringVar(&kfpath, "kf", "", "key file path")

	// get public & private key
	b := new(Bencode.Bencode)
	b.Init()
	pub := ""
	pri := ""
	fs.StringVar(&pub, "pub", "", "public key string or path")
	fs.StringVar(&pri, "pri", "", "private key string or path")

	// parse and get target files
	fs.Parse(os.Args[1:])
	cfg.Files = fs.Args()

	// temp path auto setting
	if cfg.TempDir == "" {
		exePath, err := os.Executable()
		if err != nil {
			cfg.TempDir = "."
		} else {
			cfg.TempDir = filepath.Dir(exePath)
		}
	}

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

	if _, err := os.Stat(pub); err == nil && pub != "" { // file
		d, e := os.ReadFile(pub)
		if e != nil {
			fmt.Println(e)
		} else {
			pub = string(d)
		}
	}
	if _, err := os.Stat(pri); err == nil && pri != "" { // file
		d, e := os.ReadFile(pri)
		if e != nil {
			fmt.Println(e)
		} else {
			pri = string(d)
		}
	}
	var err error
	if pub == "" {
		cfg.Public = nil
	} else {
		cfg.Public, err = b.Decode(pub)
		if err != nil {
			fmt.Println(err)
			cfg.Public = nil
		}
	}
	if pri == "" {
		cfg.Private = nil
	} else {
		cfg.Private, err = b.Decode(pri)
		if err != nil {
			fmt.Println(err)
			cfg.Private = nil
		}
	}
}

// progress printer
type Progress struct {
	Now   int64
	Total int64
	Bar   int
}

func (p *Progress) Init(total int64, bar int) {
	p.Now = 0
	p.Total = total
	if bar > 0 {
		p.Bar = bar
	} else {
		p.Bar = 40
	}
}

func (p *Progress) Start(msg string) {
	fmt.Printf("%s: [", msg)
}

func (p *Progress) End() {
	p.Update(p.Total + 1)
	fmt.Println("]")
}

func (p *Progress) Update(now int64) {
	before := int(float64(p.Now) / float64(p.Total) * float64(p.Bar))
	after := min(int(float64(now)/float64(p.Total)*float64(p.Bar)), p.Bar)
	p.Now = now
	for i := before; i < after; i++ {
		if i != 0 && i%(p.Bar/4) == 0 {
			fmt.Print("|")
		}
		fmt.Print("=")
	}
}

// helper functions
func getPrehead() ([]byte, string) {
	if len(Cfg.Files) == 0 { // msg-only mode
		return nil, ""
	}
	ic := new(Icons.Icons)
	var d []byte
	e := ""
	switch Cfg.PreHead {
	case "none":
		d = nil
		e = ""
	case "zippng":
		d, _ = ic.Zip_png()
		e = ".png"
	case "zipwebp":
		d, _ = ic.Zip_webp()
		e = ".webp"
	case "aespng":
		d, _ = ic.Aes_png()
		e = ".png"
	case "aeswebp":
		d, _ = ic.Aes_webp()
		e = ".webp"
	case "cloudpng":
		d, _ = ic.Cloud_png()
		e = ".png"
	case "cloudwebp":
		d, _ = ic.Cloud_webp()
		e = ".webp"
	case "":
		if Cfg.Public == nil { // pw-mode
			d, _ = ic.Aes_webp()
		} else { // pub-mode
			d, _ = ic.Cloud_webp()
		}
		e = ".webp"
	default: // fetch from file
		d, _ = os.ReadFile(Cfg.PreHead)
		e = ".bin"
		if len(d) > 65535 {
			d = d[:65535]
		}
	}
	if len(d)%128 != 0 {
		d = append(d, make([]byte, 128-len(d)%128)...)
	}
	return d, e
}

// main functions
func f_zip() error {
	output := Cfg.Output
	if output == "" {
		if Cfg.IsZip {
			output = "output.zip"
		} else {
			output = "output.tar"
		}
	}
	return DoZip(Cfg.Files, output, Cfg.IsZip)
}

func f_unzip() error {
	return UnZip(Cfg.Files[0], Cfg.Output, Cfg.IsZip)
}

func f_send() error {
	// 1. Validate inputs
	if Cfg.Text == "" { // IP:Port
		return errors.New("receiver address required (-t ip:port)")
	}
	targetAddr := Cfg.Text
	if !strings.Contains(targetAddr, ":") {
		targetAddr += ":8888" // default port
	}

	// 2. zip data
	zipPath := filepath.Join(Cfg.TempDir, "yas2zip.temp")
	defer os.Remove(zipPath)
	fmt.Printf("Packing to %s...\n", zipPath)
	if len(Cfg.Files) == 0 { // msg-only mode
		f, _ := os.Create(zipPath)
		f.Close()
	} else { // zip files
		err := DoZip(Cfg.Files, zipPath, true)
		if err != nil {
			return err
		}
	}

	// 3. Connect to receiver
	fmt.Printf("Connecting to %s...\n", targetAddr)
	conn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	// 4. Initialize Protocol
	var mode uint16 = 0
	if Cfg.IsLegacy {
		mode |= MODE_LEGACY
	}
	if Cfg.Bits >= 4096 {
		mode |= MODE_RSA_4K
	}
	if len(Cfg.Files) == 0 {
		mode |= MODE_MSGONLY // msg-only mode
	}
	p := new(TPprotocol)
	p.Init(uint16(mode), conn)

	// 5. Start prograss bar
	fmt.Printf("Sending data to %s...\n", targetAddr)
	stop := make(chan bool, 1)
	done := make(chan bool, 1)
	go func() {
		defer func() { done <- true }()
		prog := new(Progress)
		isStarted := false
		ticker := time.NewTicker(100 * time.Millisecond) // check every 100ms
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				if isStarted {
					prog.End()
				}
				return
			case <-ticker.C:
				stage, sent, total := p.GetStatus()
				if total > 0 && !isStarted { // start if total exists
					prog.Init(int64(total), 40)
					prog.Start("Sending")
					isStarted = true
				}
				if isStarted { // update progress
					prog.Update(int64(sent))
					if stage == STAGE_ERROR { // halt if error
						return
					}
				}
			}
		}
	}()

	// 6. Send
	sendPath := filepath.Join(Cfg.TempDir, "yas2send.temp")
	err = p.SendFile(zipPath, sendPath, Cfg.SMsg)
	stop <- true
	<-done
	if err != nil {
		return err
	}
	fmt.Println("Session completed successfully")
	return nil
}

func f_recv() error {
	// 1. Setup Listener, print IPs
	port := "8888"
	if Cfg.Text != "" {
		port = Cfg.Text // -t flag used as port
	}

	ips, err := GetIPs(true)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		fmt.Printf("Receiver IP: %s:%s\n", ip, port)
	}

	fmt.Printf("Start listening on port %s...\n", port)
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return err
	}
	defer listener.Close()

	// 2. Accept Connection
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Printf("Connected from %s\n", conn.RemoteAddr().String())

	// 3. Initialize Protocol, prepare paths
	p := new(TPprotocol)
	p.Init(0, conn)
	tempPath := filepath.Join(Cfg.TempDir, "yas2recv.temp")
	zipPath := filepath.Join(Cfg.TempDir, "yas2unzip.temp")
	defer os.Remove(zipPath)

	// 4. Start Progress Bar
	stop := make(chan bool, 1)
	done := make(chan bool, 1)
	go func() {
		defer func() { done <- true }()
		prog := new(Progress)
		isStarted := false
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-stop:
				if isStarted {
					prog.End()
				}
				return
			case <-ticker.C:
				stage, sent, total := p.GetStatus()
				// Start if total size is known (handshake complete)
				if total > 0 && !isStarted {
					prog.Init(int64(total), 40)
					prog.Start("Receiving")
					isStarted = true
				}
				// Update progress
				if isStarted {
					prog.Update(int64(sent))
					if stage == STAGE_ERROR {
						return
					}
				}
			}
		}
	}()

	// 5. Receive archive file
	smsg, err := p.ReceiveFile(zipPath, tempPath)
	stop <- true
	<-done
	if err != nil {
		return err
	}

	// 6. Unzip if required
	if p.Mode&MODE_MSGONLY == 0 {
		output := Cfg.Output
		if output == "" {
			output = "./"
		}
		fmt.Printf("Unpacking data to %s...\n", output)
		err = UnZip(zipPath, output, true)
		if err != nil {
			return err
		}
	}

	// 7. Print Secure Message
	if smsg != "" {
		fmt.Printf("\n[SMSG]: %s\n", smsg)
	}
	fmt.Println("Session completed successfully")
	return nil
}

func f_genkey() error {
	// 1. set key type, generate key
	fmt.Println("Generating key pair...")
	pubNm := ""
	var pub []byte
	priNm := ""
	var pri []byte
	if Cfg.IsLegacy {
		switch Cfg.Bits {
		case 2048:
			pubNm = "public_2k.txt"
			priNm = "private_2k.txt"
			pub, pri, _ = new(Bencrypt.RSA1).Genkey(2048)
		case 3072:
			pubNm = "public_3k.txt"
			priNm = "private_3k.txt"
			pub, pri, _ = new(Bencrypt.RSA1).Genkey(3072)
		case 4096:
			pubNm = "public_4k.txt"
			priNm = "private_4k.txt"
			pub, pri, _ = new(Bencrypt.RSA1).Genkey(4096)
		default:
			return fmt.Errorf("unsupported RSA key size: %d", Cfg.Bits)
		}
	} else {
		pubNm = "public.txt"
		priNm = "private.txt"
		pub, pri, _ = new(Bencrypt.ECC1).Genkey()
	}

	// 2. set output path
	output := Cfg.Output
	if output == "" {
		output = "./"
	}
	pubPath := filepath.Join(output, pubNm)
	priPath := filepath.Join(output, priNm)

	// 3. save keys
	fmt.Println("Saving key pair...")
	b := new(Bencode.Bencode)
	b.Init()
	err := os.WriteFile(pubPath, []byte(b.Encode(pub, true)), 0644)
	if err != nil {
		return err
	}
	fmt.Printf("Public key: %s\n", pubPath)
	err = os.WriteFile(priPath, []byte(b.Encode(pri, true)), 0644)
	if err != nil {
		return err
	}
	fmt.Printf("Private key: %s\n", priPath)
	return nil
}

func f_sign() error {
	if Cfg.Private != nil { // make sign
		// 1. set output path
		if len(Cfg.Files) == 0 {
			return errors.New("no file to sign")
		}
		output := Cfg.Output
		if output == "" {
			output = "./"
		}

		// 2. load key
		fmt.Println("Loading private key...")
		b := new(Bencode.Bencode)
		rsa := new(Bencrypt.RSA1)
		ecc := new(Bencrypt.ECC1)
		var err error
		if Cfg.IsLegacy {
			err = rsa.Loadkey(nil, Cfg.Private)
		} else {
			err = ecc.Loadkey(nil, Cfg.Private)
		}
		if err != nil {
			return err
		}

		// 3. make sign
		for i, f := range Cfg.Files {
			signPath := filepath.Join(output, fmt.Sprintf("sign_%d.txt", i))
			info, err := os.Stat(f)
			if err != nil {
				return err
			}
			if info.IsDir() {
				return fmt.Errorf("file %s is directory", f)
			}
			if info.Size() > 512*1048576 {
				return fmt.Errorf("file %s is too large", f)
			}
			data, err := os.ReadFile(f)
			if err != nil {
				return err
			}

			var sdata []byte
			if Cfg.IsLegacy {
				sdata, err = rsa.Sign(data)
			} else {
				sdata, err = ecc.Sign(data)
			}
			if err != nil {
				return err
			}

			err = os.WriteFile(signPath, []byte(b.Encode(sdata, true)), 0644)
			if err != nil {
				return err
			}
			fmt.Printf("Signed %s -> %s\n", f, signPath)
		}

	} else if Cfg.Public != nil { // verify sign
		// 1. check input paths, load data
		fmt.Println("Loading data...")
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
		sdata, err := os.ReadFile(Cfg.Files[1])
		if err != nil {
			return err
		}

		// 2. load key, transform sdata
		fmt.Println("Loading public key...")
		b := new(Bencode.Bencode)
		b.Init()
		sdata, err = b.Decode(string(sdata))
		if err != nil {
			return err
		}
		rsa := new(Bencrypt.RSA1)
		ecc := new(Bencrypt.ECC1)
		if Cfg.IsLegacy {
			err = rsa.Loadkey(Cfg.Public, nil)
		} else {
			err = ecc.Loadkey(Cfg.Public, nil)
		}
		if err != nil {
			return err
		}

		// 3. verify sign
		c := false
		if Cfg.IsLegacy {
			c = rsa.Verify(data, sdata)
		} else {
			c = ecc.Verify(data, sdata)
		}
		if c {
			fmt.Printf("Verified sussessfully %s\n", Cfg.Files[0])
		} else {
			fmt.Printf("Invalid sign %s\n", Cfg.Files[0])
		}

	} else {
		return errors.New("no key")
	}
	return nil
}

func f_enc() error {
	// 1. prepare settings
	o := new(Opsec.Opsec)
	o.Reset()
	phead, suffix := getPrehead()
	output := Cfg.Output
	if output == "" {
		output = fmt.Sprintf("output%s", suffix)
	}

	// 2. pack file if required
	zipPath := ""
	var zipSize int64
	defer func() {
		if zipPath != "" {
			os.Remove(zipPath)
		}
	}()
	if len(Cfg.Files) > 0 {
		fmt.Println("Packing files...")
		zipPath = filepath.Join(Cfg.TempDir, "yas2tar.temp")
		err := DoZip(Cfg.Files, zipPath, false)
		if err != nil {
			return err
		}
		info, err := os.Stat(zipPath)
		if err != nil {
			return err
		}
		zipSize = info.Size()
	}

	// 3. generate opsec header
	fmt.Println("Generating opsec header...")
	var ohead []byte
	o.Msg = Cfg.Msg
	o.Smsg = Cfg.SMsg
	if len(Cfg.Files) > 0 {
		o.BodyAlgo = "gcmx1"
		o.ContAlgo = "tar1"
	}

	method := ""
	if Cfg.Public == nil { // pw-mode
		if Cfg.IsLegacy {
			method = "pbk1"
		} else {
			method = "arg1"
		}
	} else { // pub-mode
		if Cfg.IsLegacy {
			method = "rsa1"
		} else {
			method = "ecc1"
		}
	}

	var err error
	if len(Cfg.Files) == 0 { // msg-only mode
		if Cfg.Public == nil {
			ohead, err = o.Encpw(method, []byte(Cfg.PW), Cfg.KF)
		} else {
			ohead, err = o.Encpub(method, Cfg.Public, Cfg.Private)
		}

	} else {
		o.Size = AfterSize(zipSize)
		if Cfg.Public == nil {
			ohead, err = o.Encpw(method, []byte(Cfg.PW), Cfg.KF)
		} else {
			ohead, err = o.Encpub(method, Cfg.Public, Cfg.Private)
		}
	}
	if err != nil {
		return err
	}

	// 4. print if msg-only mode
	if len(Cfg.Files) == 0 {
		b := new(Bencode.Bencode)
		b.Init()
		fmt.Printf("Encrypted successfully:\n\n%s\n\n", b.Encode(ohead, true))
		return nil
	}

	// 5. write headers
	fmt.Println("Writing headers...")
	oFile, err := os.Create(output)
	if err != nil {
		return err
	}
	defer oFile.Close()
	oFile.Write(phead)
	err = o.Write(oFile, ohead)
	if err != nil {
		return err
	}

	// 6. Start progress bar
	zf, err := os.Open(zipPath)
	if err != nil {
		return err
	}
	defer zf.Close()
	aes := new(Bencrypt.AES1)
	aes.Init()

	stop := make(chan bool, 1)
	done := make(chan bool, 1)
	go func() {
		defer func() { done <- true }()
		prog := new(Progress)
		prog.Init(zipSize, 40)
		prog.Start("Encrypting")
		ticker := time.NewTicker(100 * time.Millisecond) // check every 100ms
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				prog.End()
				return
			case <-ticker.C:
				prog.Update(aes.Processed())
			}
		}
	}()

	// 7. Encrypt with GCMx
	var key [44]byte
	copy(key[:], o.BodyKey)
	err = aes.EnAESGCMx(key, zf, zipSize, oFile, 0)
	stop <- true
	<-done
	if err != nil {
		return err
	}
	fmt.Printf("Encrypted successfully: %s\n", output)
	return nil
}

func f_dec() error {
	// 1. prerpare input data
	fmt.Println("Loading header...")
	var headBytes []byte
	var inFile *os.File
	if len(Cfg.Files) > 0 {
		f, err := os.Open(Cfg.Files[0])
		if err != nil {
			return err
		}
		defer f.Close()
		inFile = f
		o := new(Opsec.Opsec)
		headBytes, err = o.Read(f, 0)
		if err != nil {
			return err
		}
	} else if Cfg.Text != "" {
		b := new(Bencode.Bencode)
		b.Init()
		var err error
		headBytes, err = b.Decode(Cfg.Text)
		if err != nil {
			return err
		}
	} else {
		return errors.New("input source required (file or -t)")
	}

	// 2. Read opsec header, print msg
	ops := new(Opsec.Opsec)
	ops.View(headBytes)
	if ops.Msg != "" {
		fmt.Printf("\n[MSG]: %s\n\n", ops.Msg)
	}

	// 3. Decrypt opsec header, print smsg
	fmt.Println("Decrypting header...")
	var err error
	switch ops.HeadAlgo {
	case "pbk1", "arg1":
		err = ops.Decpw([]byte(Cfg.PW), Cfg.KF)
	case "rsa1", "ecc1":
		if Cfg.Private == nil {
			return errors.New("private key required (-pri)")
		}
		err = ops.Decpub(Cfg.Private, Cfg.Public)
	default:
		return fmt.Errorf("unknown header algorithm: %s", ops.HeadAlgo)
	}
	if err != nil {
		return err
	}
	if ops.Smsg != "" {
		fmt.Printf("\n[SMSG]: %s\n\n", ops.Smsg)
	}

	// 4. Decrypt body
	if inFile == nil || ops.Size <= 0 {
		fmt.Println("Decrypted successfully: msg-only mode")
		return nil // finish msg-only mode
	}
	aes := new(Bencrypt.AES1)
	aes.Init()
	var key [44]byte
	copy(key[:], ops.BodyKey)
	output := Cfg.Output
	if output == "" {
		output = "./"
	}
	stop := make(chan bool, 1)
	done := make(chan bool, 1)

	switch ops.BodyAlgo {
	case "gcm1": // single file mode
		fmt.Println("Decrypting body...")
		buf := make([]byte, ops.Size)
		_, err = io.ReadFull(inFile, buf)
		if err != nil {
			return err
		}
		dec, err := aes.DeAESGCM(key, buf)
		if err != nil {
			return err
		}
		if ops.Name == "" {
			err = os.WriteFile(filepath.Join(output, "noname.bin"), dec, 0644)
		} else {
			err = os.WriteFile(filepath.Join(output, ops.Name), dec, 0644)
		}
		if err != nil {
			return err
		}
		fmt.Printf("Decrypted successfully: %s\n", output)
		return nil

	case "gcmx1": // packed file mode
		go func() {
			defer func() { done <- true }()
			prog := new(Progress)
			prog.Init(ops.Size, 40)
			prog.Start("Decrypting")
			ticker := time.NewTicker(100 * time.Millisecond) // check every 100ms
			defer ticker.Stop()
			for {
				select {
				case <-stop:
					prog.End()
					return
				case <-ticker.C:
					prog.Update(aes.Processed())
				}
			}
		}()

	default:
		return fmt.Errorf("unknown body algorithm: %s", ops.BodyAlgo)
	}

	// GCMx decryption
	tempPath := filepath.Join(Cfg.TempDir, "yas2untar.temp")
	defer os.Remove(tempPath)
	tFile, err := os.Create(tempPath)
	if err != nil {
		return err
	}
	defer tFile.Close()
	err = aes.DeAESGCMx(key, inFile, ops.Size, tFile, 0)
	stop <- true
	<-done
	if err != nil {
		return err
	}
	tFile.Close() // flush

	// 5. Unpack
	fmt.Printf("Unpacking to %s...\n", output)
	switch ops.ContAlgo {
	case "zip1":
		err = UnZip(tempPath, output, true)
	case "tar1":
		err = UnZip(tempPath, output, false)
	default:
		return fmt.Errorf("unknown container algorithm: %s", ops.ContAlgo)
	}
	if err != nil {
		return err
	}

	fmt.Printf("Decrypted successfully: %s\n", output)
	return nil
}

var Cfg Config

func main() {
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("critical: %v", err)
		}
	}()
	var err error
	Cfg.Init()
	fmt.Println("Configuration completed")
	switch Cfg.Mode {
	case "zip":
		err = f_zip()
	case "unzip":
		err = f_unzip()
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
	case "version":
		fmt.Println("2026 @k-atusa USAG-Yas-cli v0.1")
	default: // help
		fmt.Println("-m mode [zip|unzip|send|recv|genkey|sign|enc|dec|version|help]")
		fmt.Println("-tmp tempDir, -o outputDir/Path, -t text/ip:port")
		fmt.Println("-pre preHead/filePath [none|zippng|zipwebp|aespng|aeswebp|cloudpng|cloudwebp]")
		fmt.Println("-msg message, -smsg securedMessage, -pw password, -kf keyFile, -pub publicKey, -pri privateKey")
		fmt.Println("-legacy : usa RSA, -bits keyBits, -zip : use zip")
	}
	if err != nil {
		fmt.Printf("\nerror: %v\n", err)
	}
}
