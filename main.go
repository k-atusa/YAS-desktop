// test796 : USAG-Yas cli
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/k-atusa/USAG-Lib/Bencode"
	"github.com/k-atusa/USAG-Lib/Bencrypt"
	Icons "github.com/k-atusa/USAG-Lib/Icons"
	Opsec "github.com/k-atusa/USAG-Lib/Opsec"
	Star "github.com/k-atusa/USAG-Lib/Star"
	Szip "github.com/k-atusa/USAG-Lib/Szip"
)

// go mod init example.com
// go mod tidy
// go build -ldflags="-s -w" -trimpath main.go

// command line parser
type Config struct {
	Mode     string   // zip, unzip, enc, dec, view, genkey, hash, sign, send, recv, version, help
	TempPath string   // set temp directory
	Output   string   // output path
	Files    []string // target files
	Text     string   // target text or receiver address

	PreHead string // none, zippng, zipwebp, aespng, aeswebp, cloudpng, cloudwebp
	IsB64   bool   // base64 or base32k
	IsPbk   bool   // PBKDF2 or Argon2
	IsRsa   bool   // RSA or ECC
	IsZip   bool   // zip or tar
	IsGcm   bool   // enables GCM mode
	IsGcmx  bool   // enables GCMx mode

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
	fs.StringVar(&cfg.Mode, "m", "help", "work mode: zip, unzip, enc, dec, view, genkey, send, recv, version, help")
	fs.StringVar(&cfg.TempPath, "tmp", "", "set temp dir path")
	fs.StringVar(&cfg.Output, "o", "", "output file path")
	fs.StringVar(&cfg.Text, "t", "", "set text input")
	if cfg.TempPath == "" { // temp path auto setting
		exePath, err := os.Executable()
		if err != nil {
			cfg.TempPath = "."
		} else {
			cfg.TempPath = filepath.Dir(exePath)
		}
	}

	// algorithm and pre-header types
	fs.StringVar(&cfg.PreHead, "pre", "", "PreHeader Type: none, zippng, zipwebp, aespng, aeswebp, cloudpng, cloudwebp")
	fs.BoolVar(&cfg.IsB64, "b64", false, "Legacy support to Base64")
	fs.BoolVar(&cfg.IsPbk, "pbk", false, "Legacy support to PBKDF2")
	fs.BoolVar(&cfg.IsRsa, "rsa", false, "Legacy support to RSA")
	fs.BoolVar(&cfg.IsZip, "zip", false, "enables zip mode")
	fs.BoolVar(&cfg.IsGcm, "gcm", false, "enables GCM mode")
	fs.BoolVar(&cfg.IsGcmx, "gcmx", false, "enables GCMx mode")

	// authorization and security
	fs.StringVar(&cfg.PW, "pw", "", "password")
	fs.StringVar(&cfg.Msg, "msg", "", "non-secured message")
	fs.StringVar(&cfg.SMsg, "smsg", "", "secured message")
	fs.IntVar(&cfg.Bits, "bits", 2048, "RSA key bits")

	// get keyfile
	kfpath := ""
	fs.StringVar(&kfpath, "kf", "", "key file path")
	if kfpath == "" {
		cfg.KF = nil
	} else if _, err := os.Stat(kfpath); err == nil { // file
		cfg.KF, _ = os.ReadFile(kfpath)
	}
	if len(cfg.KF) > 1024 {
		fmt.Println("keyfile is truncated to 1024B")
		cfg.KF = cfg.KF[:1024]
	}

	// get public & private key
	b := new(Bencode.Bencode)
	b.Init()
	pub := ""
	pri := ""
	fs.StringVar(&pub, "pub", "", "public key string or path")
	fs.StringVar(&pri, "pri", "", "private key string or path")
	if pub == "" {
		cfg.Public = nil
	} else if _, err := os.Stat(pub); err == nil { // file
		temp, _ := os.ReadFile(pub)
		cfg.Public, _ = b.Decode(string(temp))
	} else { // string
		cfg.Public, _ = b.Decode(pub)
	}
	if pri == "" {
		cfg.Private = nil
	} else if _, err := os.Stat(pri); err == nil { // file
		temp, _ := os.ReadFile(pri)
		cfg.Private, _ = b.Decode(string(temp))
	} else { // string
		cfg.Private, _ = b.Decode(pri)
	}

	// parse and get target files
	fs.Parse(os.Args[1:])
	cfg.Files = fs.Args()
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
		if i%(p.Bar/4) == 0 {
			fmt.Print("|")
		}
		fmt.Print("=")
	}
}

func DoZip(files []string, output string, isZip bool) error {
	var err error
	if isZip {
		zw := new(Szip.ZipWriter)
		defer zw.Close()
		if err = zw.Init(output, true); err != nil {
			return err
		}
		for _, root := range files {
			err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				// inner path calculation
				relPath, _ := filepath.Rel(filepath.Dir(root), path)
				relPath = strings.ReplaceAll(relPath, "\\", "/")

				// write directory or file
				if info.IsDir() {
					if !strings.HasSuffix(relPath, "/") {
						relPath += "/"
					}
					return zw.WriteBin(relPath, nil)
				}
				return zw.WriteFile(relPath, path)
			})
			if err != nil {
				break
			}
		}

	} else {
		tw := new(Star.TarWriter)
		defer tw.Close()
		if err = tw.Init(output); err != nil {
			return err
		}
		for _, root := range files {
			err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				// inner path calculation
				relPath, _ := filepath.Rel(filepath.Dir(root), path)
				relPath = strings.ReplaceAll(relPath, "\\", "/")

				// write directory or file
				if info.IsDir() {
					return tw.WriteDir(relPath, 0755)
				}
				return tw.WriteFile(relPath, path, 0644)
			})
			if err != nil {
				break
			}
		}
	}
	return err
}

func UnZip(input string, outputDir string, isZip bool) error {
	// make output dir
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	if isZip {
		zr := new(Szip.ZipReader)
		if err := zr.Init(input); err != nil {
			return err
		}
		defer zr.Close()

		for i, name := range zr.Names {
			// make relative path
			relPath := strings.ReplaceAll(name, "\\", "/")
			destPath := filepath.Join(outputDir, relPath)

			if strings.HasSuffix(relPath, "/") { // directory
				if err := os.MkdirAll(destPath, 0755); err != nil {
					return err
				}
			} else { // file
				if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
					return err
				}
				rc, err := zr.Open(i)
				if err != nil {
					return err
				}
				defer rc.Close()
				f, err := os.Create(destPath)
				if err != nil {
					return err
				}
				defer f.Close()
				if _, err := io.Copy(f, rc); err != nil {
					return err
				}
			}
		}

	} else {
		tr := new(Star.TarReader)
		if err := tr.Init(input); err != nil {
			return err
		}
		defer tr.Close()

		for tr.Next() {
			destPath := filepath.Join(outputDir, strings.ReplaceAll(tr.Name, "\\", "/"))
			if !tr.IsDir {
				if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
					return err
				}
			}
			if err := tr.Mkfile(destPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func f_zip() error {
	output := Cfg.Output
	if output == "" && Cfg.IsZip {
		output = "output.zip"
	} else if output == "" && !Cfg.IsZip {
		output = "output.tar"
	}
	return DoZip(Cfg.Files, output, Cfg.IsZip)
}

func f_unzip() error {
	return UnZip(Cfg.Files[0], Cfg.Output, Cfg.IsZip)
}

func f_enc() error {
	var err error
	o := new(Opsec.Opsec)
	o.Reset()

	// 1. load prehead
	var prehead []byte
	var outputSub string
	ic := new(Icons.Icons)
	switch Cfg.PreHead {
	case "zippng":
		prehead, _ = ic.Zip_png()
		outputSub = ".png"
	case "zipwebp":
		prehead, _ = ic.Zip_webp()
		outputSub = ".webp"
	case "aespng":
		prehead, _ = ic.Aes_png()
		outputSub = ".png"
	case "aeswebp":
		prehead, _ = ic.Aes_webp()
		outputSub = ".webp"
	case "cloudpng":
		prehead, _ = ic.Cloud_png()
		outputSub = ".png"
	case "cloudwebp":
		prehead, _ = ic.Cloud_webp()
		outputSub = ".webp"
	case "none":
		prehead = nil
		outputSub = ".bin"
	case "":
		if len(Cfg.Files) == 0 {
			prehead = nil
			outputSub = ".bin"
		} else if Cfg.Public == nil {
			prehead, _ = ic.Aes_webp()
			outputSub = ".webp"
		} else {
			prehead, _ = ic.Cloud_webp()
			outputSub = ".webp"
		}
	default: // read from file path
		prehead, err = os.ReadFile(Cfg.PreHead)
		outputSub = ".bin"
		if err != nil {
			return err
		}
		if len(prehead) > 65535 {
			return errors.New("prehead too long")
		}
	}

	// 2. select algorithm
	isGCMx := Cfg.IsGcmx
	if !Cfg.IsGcm && !isGCMx {
		isGCMx = true
		if len(Cfg.Files) == 1 {
			info, err := os.Stat(Cfg.Files[0])
			o.Name = filepath.Base(Cfg.Files[0])
			if err == nil && !info.IsDir() && info.Size() <= 10485760 {
				isGCMx = false // small single file
			}
		}
	}

	// 3. archive if file list is not empty and GCMx
	tempArchive := filepath.Join(Cfg.TempPath, "temp")
	defer os.Remove(tempArchive)
	var bodySize int64 = -1
	if len(Cfg.Files) > 0 && isGCMx {
		fmt.Println("Archiving files...")
		err = DoZip(Cfg.Files, tempArchive, Cfg.IsZip)
		if err != nil {
			return err
		}
		info, _ := os.Stat(tempArchive)
		bodySize = info.Size()
	}

	// 4. generate opsec header
	fmt.Println("Generating opsec header...")
	o.Msg = Cfg.Msg
	if Cfg.Public == nil {
		if Cfg.IsPbk {
			o.HeadAlgo = "pbk1"
		} else {
			o.HeadAlgo = "arg1"
		}
	} else {
		if Cfg.IsRsa {
			o.HeadAlgo = "rsa1"
		} else {
			o.HeadAlgo = "ecc1"
		}
	}
	o.Smsg = Cfg.SMsg
	if bodySize < 0 {
		o.Size = -1
	} else if !isGCMx {
		o.Size = bodySize + 16
	} else {
		s0 := bodySize / 1048576
		if bodySize%1048576 == 0 {
			o.Size = bodySize + 16*s0
		} else {
			o.Size = bodySize + 16*s0 + 16
		}
	}
	if len(Cfg.Files) > 0 {
		if isGCMx {
			o.BodyAlgo = "gcmx1"
			if Cfg.IsZip {
				o.ContAlgo = "zip1"
			} else {
				o.ContAlgo = "tar1"
			}
		} else {
			o.BodyAlgo = "gcm1"
		}
	}

	var header []byte
	if Cfg.Public != nil {
		method := "ecc1"
		if Cfg.IsRsa {
			method = "rsa1"
		}
		header, err = o.Encpub(method, []byte(Cfg.Public), []byte(Cfg.Private))
	} else {
		method := "arg1"
		if Cfg.IsPbk {
			method = "pbk1"
		}
		header, err = o.Encpw(method, []byte(Cfg.PW), Cfg.KF)
	}
	if err != nil {
		return err
	}

	// 5. direct print if msg-only mode
	if len(Cfg.Files) == 0 {
		fmt.Println("Encrypted successfully: msg-only mode")
		b := new(Bencode.Bencode)
		b.Init()
		fmt.Println(b.Encode(header, Cfg.IsB64))
		return nil
	}

	// 6. start writing file
	fmt.Println("Writing header...")
	output := Cfg.Output
	if output == "" {
		output = "output" + outputSub
	}
	oFile, err := os.Create(output)
	if err != nil {
		return err
	}
	defer oFile.Close()

	oFile.Write(prehead)
	if len(prehead)%128 != 0 {
		oFile.Write(make([]byte, 128-len(prehead)%128))
	}
	err = o.Write(oFile, header)
	if err != nil {
		return err
	}

	// 7. encrypt body
	if bodySize > 0 {
		aes := new(Bencrypt.AES1)
		aes.Init()
		var key [44]byte
		copy(key[:], o.BodyKey)
		if isGCMx {
			srcF, _ := os.Open(tempArchive)
			defer srcF.Close()

			// start progress bar
			prog := new(Progress)
			prog.Init(bodySize, 40)
			prog.Start("Encrypting")
			endSign := make(chan bool)
			go func() {
				for {
					select {
					case <-endSign:
						prog.End()
						return
					default:
						prog.Update(aes.Processed())
						time.Sleep(100 * time.Millisecond)
					}
				}
			}()

			// encrypt
			err = aes.EnAESGCMx(key, srcF, bodySize, oFile, 0)
			endSign <- true
			time.Sleep(10 * time.Millisecond)

		} else {
			fmt.Println("Encrypting body...")
			tgt, err := os.ReadFile(Cfg.Files[0])
			if err != nil {
				return err
			}
			tgt, err = aes.EnAESGCM(key, tgt)
			if err != nil {
				return err
			}
			_, err = oFile.Write(tgt)
		}
	}
	if err != nil {
		return err
	}

	// 8. close
	fmt.Printf("Encrypted successfully: %s\n", output)
	return nil
}

func f_dec() error {
	var err error
	var rawData []byte
	var f *os.File
	var r io.Reader
	defer f.Close()

	// 1. determine input source
	if len(Cfg.Files) > 0 {
		f, err = os.Open(Cfg.Files[0])
		if err != nil {
			return err
		}
		r = f
	} else if Cfg.Text != "" {
		be := new(Bencode.Bencode)
		be.Init()
		rawData, err = be.Decode(Cfg.Text)
		if err != nil {
			return err
		}
		r = bytes.NewReader(rawData)
	} else {
		return errors.New("no input file or text")
	}

	// 2. read opsec header
	o := new(Opsec.Opsec)
	o.Reset()
	headPayload, err := o.Read(r, 0)
	if err != nil || headPayload == nil {
		return errors.New("failed to read opsec header")
	}
	o.View(headPayload)

	// 3. decrypt header
	switch o.HeadAlgo {
	case "arg1", "pbk1":
		err = o.Decpw([]byte(Cfg.PW), Cfg.KF)
	case "rsa1", "ecc1":
		err = o.Decpub(Cfg.Private, Cfg.Public)
	default:
		return fmt.Errorf("unknown header algorithm: %s", o.HeadAlgo)
	}

	// 4. print messages
	fmt.Printf("Public Message: %s\n", o.Msg)
	fmt.Printf("Secure Message: %s\n", o.Smsg)

	// 5. decrypt body
	if o.Size >= 0 {
		var key [44]byte
		copy(key[:], o.BodyKey)
		aes := new(Bencrypt.AES1)
		aes.Init()

		if o.BodyAlgo == "gcm1" { // direct decrypt
			fmt.Println("Decrypting body...")
			encData, _ := io.ReadAll(r)
			plain, err := aes.DeAESGCM(key, encData)
			if err != nil {
				return err
			}

			outDir := Cfg.Output
			if outDir == "" {
				outDir = "."
			}
			os.MkdirAll(outDir, 0755)
			destPath := filepath.Join(outDir, o.Name)
			err = os.WriteFile(destPath, plain, 0644)
			if err != nil {
				return err
			}
			fmt.Printf("Decrypted successfully: %s\n", destPath)

		} else { // gcmx: temp -> unzip
			tempArchive := filepath.Join(Cfg.TempPath, "temp")
			df, err := os.Create(tempArchive)
			if err != nil {
				return err
			}
			defer os.Remove(tempArchive)

			// progress bar
			prog := new(Progress)
			prog.Init(int64(o.Size), 40)
			prog.Start("Decrypting")
			endSign := make(chan bool)
			go func() {
				for {
					select {
					case <-endSign:
						prog.End()
						return
					default:
						prog.Update(int64(aes.Processed()))
						time.Sleep(100 * time.Millisecond)
					}
				}
			}()

			err = aes.DeAESGCMx(key, r, o.Size, df, 0)
			endSign <- true
			time.Sleep(10 * time.Millisecond)
			df.Close()
			if err != nil {
				return err
			}

			// unzip archive
			outDir := Cfg.Output
			if outDir == "" {
				outDir = "."
			}
			err = UnZip(tempArchive, outDir, o.ContAlgo == "zip1")
			if err != nil {
				return err
			}
			fmt.Printf("Decrypted successfully: %s\n", outDir)
		}
	} else {
		fmt.Println("Decrypted successfully: msg-only mode")
	}
	return nil
}

func f_view() error {
	var err error
	var rawData []byte
	var r io.Reader
	var f *os.File
	defer f.Close()

	// 1. determine input source
	if len(Cfg.Files) > 0 {
		f, err = os.Open(Cfg.Files[0])
		if err != nil {
			return err
		}
		r = f
	} else if Cfg.Text != "" {
		be := new(Bencode.Bencode)
		be.Init()
		rawData, err = be.Decode(Cfg.Text)
		if err != nil {
			return err
		}
		r = bytes.NewReader(rawData)
	} else {
		return errors.New("no input file or text")
	}

	o := new(Opsec.Opsec)
	o.Reset()
	headPayload, err := o.Read(r, 0)
	if err != nil || headPayload == nil {
		return errors.New("failed to read opsec header")
	}

	// load and print outer layer
	o.View(headPayload)
	fmt.Printf("Public Message   : %s\n", o.Msg)
	fmt.Printf("Header Algorithm : %s\n", o.HeadAlgo)
	return nil
}

func f_genkey() error {
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
	switch Cfg.Mode {
	case "zip":
		err = f_zip()
	case "unzip":
		err = f_unzip()
	case "enc":
		err = f_enc()
	case "dec":
		err = f_dec()
	case "view":
		err = f_view()
	case "genkey":
	case "send":
	case "recv":
	case "version":
		fmt.Println("2026 @k-atusa USAG-Yas-cli v0.1")
	default: // help
		fmt.Println("")
	}
	if err != nil {
		fmt.Printf("error: %v\n", err)
	}
}
