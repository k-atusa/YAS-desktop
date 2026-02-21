// test796a : project USAG YAS-desktop library
package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/k-atusa/USAG-Lib/Bencrypt"
	"github.com/k-atusa/USAG-Lib/Icons"
	"github.com/k-atusa/USAG-Lib/Opsec"
	"github.com/k-atusa/USAG-Lib/Star"
	"github.com/k-atusa/USAG-Lib/Szip"
)

var YAS_VERSION string = "2026 @k-atusa [USAG] YAS v0.1.0"

// abstract status indicator
type ProgStatus interface {
	OnStart()
	OnUpdate(p float64)
	OnEnd()
	OnError(err error)
}

// get prehead, keyword: zip, pw, pub, webp, png
func GetPrehead(tp string, img string, ismsg bool) []byte {
	if ismsg {
		return nil
	}
	var ico []byte
	switch {
	case tp == "zip" && img == "webp":
		ico = Icons.ZipWebp
	case tp == "pw" && img == "webp":
		ico = Icons.AesWebp
	case tp == "pub" && img == "webp":
		ico = Icons.CloudWebp
	case tp == "zip" && img == "png":
		ico = Icons.ZipPng
	case tp == "pw" && img == "png":
		ico = Icons.AesPng
	case tp == "pub" && img == "png":
		ico = Icons.CloudPng
	default:
		return nil
	}
	return append(ico, make([]byte, 128-len(ico)%128)...)
}

// retrying delete
func Remove2(path string) {
	for {
		os.Remove(path)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}
}

// password complex
type PwCplx struct {
	AlgoType string // pbk1, arg1
	PW       string
	KF       []byte
}

// public key complex
type PubCplx struct {
	AlgoType string // rsa1, ecc1
	Pub      []byte
	Pri      []byte
}

// encryption config complex
type EncCplx struct {
	ImgType  string // webp, png, bin
	PackType string // zip1, tar1
	EncType  string // gcm1, gcmx1

	Msg  string
	Smsg string
}

// pack targets, keyword: zip1, tar1
func Pack(srcs []string, dst string, tp string) error {
	switch tp {
	case "zip1":
		return Szip.Pack(srcs, dst)
	case "tar1":
		return Star.Pack(srcs, dst)
	default:
		return errors.New("unsupported pack type")
	}
}

// unpack targets, keyword: zip1, tar1
func Unpack(src string, dst string, tp string) error {
	if tp == "" {
		if strings.HasSuffix(src, "zip") {
			tp = "zip1"
		}
		if strings.HasSuffix(src, "tar") {
			tp = "tar1"
		}
	}
	switch tp {
	case "zip1":
		return Szip.Unpack(src, dst)
	case "tar1":
		return Star.Unpack(src, dst)
	default:
		return errors.New("unsupported pack type")
	}
}

// send targets (fromPub, toPub), keyword: rsa1, ecc1, fixed: zip1, gcmx1
func Send(srcs []string, smsg string, addr string, pmode string, pg ProgStatus) ([]byte, []byte, error) {
	// 1. pack targets (zip1)
	pg.OnStart()
	zipPath := TempPath()
	defer Remove2(zipPath)
	if len(srcs) == 0 {
		os.WriteFile(zipPath, nil, 0644)
	} else {
		if err := Pack(srcs, zipPath, "zip1"); err != nil {
			pg.OnError(err)
			return nil, nil, err
		}
	}
	pg.OnUpdate(0.1) // packing is 10%

	// 2. make connection
	sock := new(TCPsocket)
	err := sock.MakeConnection(addr)
	defer sock.Close()
	if err != nil {
		pg.OnError(err)
		return nil, nil, err
	}

	// 3. accept connection
	tp := new(TP1)
	var con uint16 = MODE_GCMX1
	if len(srcs) == 0 {
		con |= MODE_MSGONLY
	}
	switch pmode {
	case "rsa1", "rsa1-2k":
		con |= MODE_RSA1_2K
	case "rsa1-3k":
		con |= MODE_RSA1_3K
	case "rsa1-4k":
		con |= MODE_RSA1_4K
	case "ecc1":
		con |= MODE_ECC1
	}
	tp.Init(con, false, sock.Conn)
	pg.OnUpdate(0.2) // connecting is 10%

	// 4. open packed file
	f, err := os.Open(zipPath)
	if err != nil {
		pg.OnError(err)
		return nil, nil, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		pg.OnError(err)
		return nil, nil, err
	}

	// 5. send
	stop := make(chan bool, 1)
	done := make(chan bool, 1)
	go func() {
		defer func() { done <- true }()
		isStarted := false
		ticker := time.NewTicker(100 * time.Millisecond) // check every 100ms
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				stage, sent, total := tp.GetStatus()
				if total > 0 && !isStarted { // start if total exists
					isStarted = true
					pg.OnUpdate(0.2 + 0.8*float64(sent)/float64(total))
				}
				if isStarted { // update progress
					pg.OnUpdate(0.2 + 0.8*float64(sent)/float64(total))
					if stage == STAGE_ERROR {
						return // halt if error
					}
				}
			}
		}
	}()
	fromPub, toPub, err := tp.Send(f, stat.Size(), smsg)
	stop <- true
	<-done
	if err == nil {
		pg.OnEnd()
	} else {
		pg.OnError(err)
	}
	return fromPub, toPub, err
}

// receive targets (fromPub, toPub), fixed: zip1, gcmx1
func Receive(dst string, port string, pg ProgStatus) ([]byte, []byte, string, error) {
	// 1. make connection
	pg.OnStart()
	sock := new(TCPsocket)
	err := sock.MakeListener(port)
	defer sock.Close()
	if err != nil {
		pg.OnError(err)
		return nil, nil, "", err
	}

	// 2. accept connection, set temp path
	tp := new(TP1)
	tp.Init(0, false, sock.Conn) // listener does not set mode
	pg.OnUpdate(0.1)             // connecting is 10%
	zipPath := TempPath()
	defer Remove2(zipPath)
	f, err := os.Create(zipPath)
	if err != nil {
		pg.OnError(err)
		return nil, nil, "", err
	}

	// 3. receive
	stop := make(chan bool, 1)
	done := make(chan bool, 1)
	go func() {
		defer func() { done <- true }()
		isStarted := false
		ticker := time.NewTicker(100 * time.Millisecond) // check every 100ms
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				stage, sent, total := tp.GetStatus()
				if total > 0 && !isStarted { // start if total exists
					isStarted = true
					pg.OnUpdate(0.1 + 0.8*float64(sent)/float64(total))
				}
				if isStarted { // update progress
					pg.OnUpdate(0.1 + 0.8*float64(sent)/float64(total))
					if stage == STAGE_ERROR {
						return // halt if error
					}
				}
			}
		}
	}()
	fromPub, toPub, smsg, err := tp.Receive(f)
	f.Close()
	stop <- true
	<-done
	pg.OnUpdate(0.9)
	if err != nil {
		pg.OnError(err)
		return nil, nil, "", err
	}

	// 4. unpack if required (zip1)
	if tp.Mode&MODE_MSGONLY == 0 {
		if err := Szip.Unpack(zipPath, dst); err != nil {
			pg.OnError(err)
			return nil, nil, "", err
		}
	}
	pg.OnEnd()
	return fromPub, toPub, smsg, nil
}

// encrypt message
func EncMsg(pwc *PwCplx, pubc *PubCplx, cfg *EncCplx, pg ProgStatus) ([]byte, error) {
	pg.OnStart()
	ops := new(Opsec.Opsec)
	ops.Reset()
	ops.Msg, ops.Smsg = cfg.Msg, cfg.Smsg
	var header []byte
	var err error
	if pwc != nil {
		header, err = ops.Encpw(pwc.AlgoType, []byte(pwc.PW), pwc.KF)
	} else if pubc != nil {
		header, err = ops.Encpub(pubc.AlgoType, pubc.Pub, pubc.Pri)
	} else {
		return nil, errors.New("no password or public key")
	}
	if err == nil {
		w := new(bytes.Buffer)
		err = ops.Write(w, header)
		header = w.Bytes()
	}
	if err == nil {
		pg.OnEnd()
		return header, nil
	} else {
		pg.OnError(err)
		return nil, err
	}
}

// decrypt message
func DecMsg(data []byte, pwc *PwCplx, pubc *PubCplx, pg ProgStatus) (string, string, error) {
	pg.OnStart()
	ops := new(Opsec.Opsec)
	ops.Reset()
	header, err := ops.Read(bytes.NewBuffer(data), 0)
	if err != nil {
		pg.OnError(err)
		return "", "", err
	}
	ops.View(header)
	if pwc != nil {
		err = ops.Decpw([]byte(pwc.PW), pwc.KF)
	} else if pubc != nil {
		err = ops.Decpub(pubc.Pri, pubc.Pub)
	} else {
		return ops.Msg, "", errors.New("no password or public key")
	}
	if err == nil {
		pg.OnEnd()
		return ops.Msg, ops.Smsg, nil
	} else {
		pg.OnError(err)
		return ops.Msg, "", err
	}
}

// encrypt files to file
func EncFiles(srcs []string, dst string, pwc *PwCplx, pubc *PubCplx, cfg *EncCplx, pg ProgStatus) error {
	// 1. pack files
	pg.OnStart()
	zipPath := TempPath()
	defer Remove2(zipPath)
	var err error
	switch cfg.PackType {
	case "zip1":
		err = Szip.Pack(srcs, zipPath)
	case "tar1":
		err = Star.Pack(srcs, zipPath)
	default:
		err = errors.New("unsupported pack type")
	}
	if err != nil {
		pg.OnError(err)
		return err
	}
	pg.OnUpdate(0.1) // packing is 10%

	// 2. make worker, get size
	sm := new(Bencrypt.SymMaster)
	if err := sm.Init(cfg.EncType, make([]byte, 44)); err != nil {
		pg.OnError(err)
		return err
	}
	stat, err := os.Stat(zipPath)
	if err != nil {
		pg.OnError(err)
		return err
	}
	zsize := stat.Size()
	asize := sm.AfterSize(zsize)

	// 3. make header
	ops := new(Opsec.Opsec)
	ops.Reset()
	ops.Msg, ops.Smsg = cfg.Msg, cfg.Smsg
	ops.Size, ops.BodyAlgo, ops.ContAlgo = asize, cfg.EncType, cfg.PackType
	var prehead, header []byte
	if pwc != nil {
		prehead = GetPrehead("pw", cfg.ImgType, false)
		header, err = ops.Encpw(pwc.AlgoType, []byte(pwc.PW), pwc.KF)
	} else if pubc != nil {
		prehead = GetPrehead("pub", cfg.ImgType, false)
		header, err = ops.Encpub(pubc.AlgoType, pubc.Pub, pubc.Pri)
	} else {
		return errors.New("no password or public key")
	}
	if err != nil {
		pg.OnError(err)
		return err
	}

	// 4. write header
	f, err := os.Create(dst)
	if err != nil {
		pg.OnError(err)
		return err
	}
	defer f.Close()
	if _, err := f.Write(prehead); err != nil {
		pg.OnError(err)
		return err
	}
	if err := ops.Write(f, header); err != nil {
		pg.OnError(err)
		return err
	}
	zf, err := os.Open(zipPath)
	if err != nil {
		pg.OnError(err)
		return err
	}
	defer zf.Close()
	pg.OnUpdate(0.2) // header is 10%

	// 5. encrypt
	stop := make(chan bool, 1)
	done := make(chan bool, 1)
	go func() {
		defer func() { done <- true }()
		ticker := time.NewTicker(100 * time.Millisecond) // check every 100ms
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				sent := sm.Processed()
				pg.OnUpdate(0.2 + 0.8*float64(sent)/float64(zsize))
			}
		}
	}()
	if err := sm.Init(sm.Algo, ops.BodyKey); err != nil {
		pg.OnError(err)
		return err
	}
	err = sm.EnFile(zf, zsize, f)
	stop <- true
	<-done
	if err == nil {
		pg.OnEnd()
	} else {
		pg.OnError(err)
	}
	return err
}

// decrypt file to dir
func DecFile(src string, dst string, pwc *PwCplx, pubc *PubCplx, pg ProgStatus) (string, string, error) {
	// 1. read header
	pg.OnStart()
	f, err := os.Open(src)
	if err != nil {
		pg.OnError(err)
		return "", "", err
	}
	defer f.Close()
	ops := new(Opsec.Opsec)
	ops.Reset()
	header, err := ops.Read(f, 0)
	if err != nil {
		pg.OnError(err)
		return "", "", err
	}

	// 2. decrypt header
	ops.View(header)
	if pwc != nil {
		err = ops.Decpw([]byte(pwc.PW), pwc.KF)
	} else if pubc != nil {
		err = ops.Decpub(pubc.Pri, pubc.Pub)
	} else {
		return ops.Msg, "", errors.New("no password or public key")
	}
	if err != nil {
		pg.OnError(err)
		return ops.Msg, "", err
	}
	pg.OnUpdate(0.1) // header is 10%

	// 3. prepare worker
	zipPath := TempPath()
	defer Remove2(zipPath)
	zf, err := os.Create(zipPath)
	if err != nil {
		pg.OnError(err)
		return ops.Msg, ops.Smsg, err
	}
	defer zf.Close()
	sm := new(Bencrypt.SymMaster)
	if err := sm.Init(ops.BodyAlgo, ops.BodyKey); err != nil {
		pg.OnError(err)
		return ops.Msg, ops.Smsg, err
	}

	// 4. decrypt
	stop := make(chan bool, 1)
	done := make(chan bool, 1)
	go func() {
		defer func() { done <- true }()
		ticker := time.NewTicker(100 * time.Millisecond) // check every 100ms
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				sent := sm.Processed()
				pg.OnUpdate(0.1 + 0.8*float64(sent)/float64(ops.Size))
			}
		}
	}()
	err = sm.DeFile(f, ops.Size, zf)
	stop <- true
	<-done
	pg.OnUpdate(0.9)
	if err != nil {
		pg.OnError(err)
		return ops.Msg, ops.Smsg, err
	}

	// 5. unpack
	switch ops.ContAlgo {
	case "zip1":
		zf.Close()
		err = Szip.Unpack(zipPath, dst)
	case "tar1":
		zf.Close()
		err = Star.Unpack(zipPath, dst)
	} // default: no unpack
	if err == nil {
		pg.OnEnd()
		return ops.Msg, ops.Smsg, nil
	} else {
		pg.OnError(err)
		return ops.Msg, ops.Smsg, err
	}
}
