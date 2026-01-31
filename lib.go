// test796a : project USAG YAS-desktop library
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/k-atusa/USAG-Lib/Bencrypt"
	"github.com/k-atusa/USAG-Lib/Opsec"
	"github.com/k-atusa/USAG-Lib/Star"
	"github.com/k-atusa/USAG-Lib/Szip"
)

// Calculates size after AES-GCMx encryption
func AfterSize(n int64) int64 {
	c := n/1048576 + 1
	if n != 0 && n%1048576 == 0 {
		c--
	}
	return n + 16*c
}

// Archive paths to output, zip or tar
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

// Unzip or untar input to output
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

			// check destination path
			chk0, _ := filepath.Abs(destPath)
			chk1, _ := filepath.Abs(outputDir)
			if !strings.HasPrefix(chk0, chk1+string(os.PathSeparator)) {
				return fmt.Errorf("illegal file path: %s", relPath)
			}

			if strings.HasSuffix(relPath, "/") { // directory
				if err := os.MkdirAll(destPath, 0755); err != nil {
					return err
				}
			} else { // file
				if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
					return err
				}
				err := func() error {
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

					_, err = io.Copy(f, rc)
					return err
				}()
				if err != nil {
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
			// make relative path
			destPath := filepath.Join(outputDir, strings.ReplaceAll(tr.Name, "\\", "/"))

			// check destination path
			chk0, _ := filepath.Abs(destPath)
			chk1, _ := filepath.Abs(outputDir)
			if !strings.HasPrefix(chk0, chk1+string(os.PathSeparator)) {
				return fmt.Errorf("illegal file path: %s", tr.Name)
			}

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

// get local IPs
func GetIPs(v4only bool) ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	res := make([]string, 0)
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() { // skip loopback
			if v4only && ipnet.IP.To4() == nil {
				continue
			}
			res = append(res, ipnet.IP.String())
		}
	}
	return res, nil
}

// Mode Flags
const (
	MODE_MSGONLY uint16 = 0x1
	MODE_LEGACY  uint16 = 0x2 // for RSA
	MODE_RSA_4K  uint16 = 0x4 // for RSA

	STAGE_IDLE         int = 0
	STAGE_HANDSHAKE    int = 1
	STAGE_ENCRYPTING   int = 2
	STAGE_TRANSFERRING int = 3
	STAGE_COMPLETE     int = 4
	STAGE_ERROR        int = -1
)

type TPprotocol struct {
	Mode  uint16
	stage int
	sent  uint64
	total uint64
	lock  sync.Mutex
	conn  net.Conn
	magic [4]byte
	zero8 [8]byte
	max8  [8]byte
}

func (p *TPprotocol) Init(mode uint16, conn net.Conn) {
	p.Mode = mode
	p.stage = 0
	p.sent = 0
	p.total = 0
	p.conn = conn
	p.magic = [4]byte{'U', 'T', 'P', '1'}
	p.zero8 = [8]byte{0, 0, 0, 0, 0, 0, 0, 0}
	p.max8 = [8]byte{255, 255, 255, 255, 255, 255, 255, 255}
}

func (p *TPprotocol) GetStatus() (int, uint64, uint64) {
	p.lock.Lock()
	defer p.lock.Unlock()
	return p.stage, p.sent, p.total
}

func (p *TPprotocol) setStage(stage int) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.stage = stage
}

func (p *TPprotocol) setSent(sent uint64) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.sent = sent
}

func (p *TPprotocol) setTotal(total uint64) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.total = total
}

func (p *TPprotocol) syncStatus(stop chan bool) {
	defer func() {
		close(stop)
		if err := recover(); err != nil {
			p.setStage(STAGE_ERROR)
		}
	}()
	for {
		select {
		case s := <-stop:
			if !s {
				p.conn.Write(p.max8[:])
			}
			return
		case <-time.After(1 * time.Second):
			p.conn.Write(p.zero8[:])
		}
	}
}

// handshake with receiver, returns peer (public key, my public key, my private key)
func (p *TPprotocol) handshakeSend() ([]byte, []byte, []byte, error) {
	// 1. Make key pair
	var myPub, myPriv []byte
	var err error
	if p.Mode&MODE_LEGACY != 0 {
		r := new(Bencrypt.RSA1)
		if p.Mode&MODE_RSA_4K != 0 {
			myPub, myPriv, err = r.Genkey(4096)
		} else {
			myPub, myPriv, err = r.Genkey(2048)
		}
	} else {
		e := new(Bencrypt.ECC1)
		myPub, myPriv, err = e.Genkey()
	}
	if err != nil {
		p.setStage(STAGE_ERROR)
		return nil, nil, nil, err
	}

	// 2. Prepare Packet: Magic(4) + Mode(2) + PubSize(2) + PubKey(N)
	buf := make([]byte, 8+len(myPub))
	copy(buf[0:4], p.magic[:])
	pubLen := len(myPub)
	if pubLen > 65535 {
		return nil, nil, nil, errors.New("public key is too long")
	}
	copy(buf[4:6], Opsec.EncodeInt(uint64(p.Mode), 2))
	copy(buf[6:8], Opsec.EncodeInt(uint64(pubLen), 2))
	copy(buf[8:], myPub)

	// 3. Send Packet
	if _, err := p.conn.Write(buf); err != nil {
		return nil, nil, nil, err
	}

	// 4. Receive Response: PubSize(2) + PubKey(M)
	head := make([]byte, 2)
	if _, err := io.ReadFull(p.conn, head); err != nil {
		return nil, nil, nil, err
	}
	peerPubLen := Opsec.DecodeInt(head)
	peerPub := make([]byte, int(peerPubLen))
	if _, err := io.ReadFull(p.conn, peerPub); err != nil {
		return nil, nil, nil, err
	}
	return peerPub, myPub, myPriv, nil
}

// handshake with sender, returns (peer public key, my public key, my private key)
func (p *TPprotocol) handshakeReceive() ([]byte, []byte, []byte, error) {
	// 1. Receive Packet: Magic(4) + Mode(2) + PubSize(2)
	header := make([]byte, 8)
	if _, err := io.ReadFull(p.conn, header); err != nil {
		return nil, nil, nil, err
	}

	// 2. Validate Magic
	if string(header[:4]) != string(p.magic[:]) {
		return nil, nil, nil, errors.New("invalid magic number")
	}

	// 3. Parse Mode & Peer PubKey Length
	p.Mode = uint16(Opsec.DecodeInt(header[4:6])) // Mode (2B)
	peerPubLen := Opsec.DecodeInt(header[6:8])    // PubSize (2B)

	// 4. Receive Peer Public Key
	peerPub := make([]byte, peerPubLen)
	if _, err := io.ReadFull(p.conn, peerPub); err != nil {
		return nil, nil, nil, err
	}

	// 5. Generate My Key Pair based on Mode
	var myPub, myPriv []byte
	var err error
	if p.Mode&MODE_LEGACY != 0 {
		r := new(Bencrypt.RSA1)
		if p.Mode&MODE_RSA_4K != 0 {
			myPub, myPriv, err = r.Genkey(4096)
		} else {
			myPub, myPriv, err = r.Genkey(2048)
		}
	} else {
		e := new(Bencrypt.ECC1)
		myPub, myPriv, err = e.Genkey()
	}
	if err != nil {
		return nil, nil, nil, err
	}

	// 6. Send Response: PubSize(2) + PubKey(M)
	myPubLen := len(myPub)
	if myPubLen > 65535 {
		return nil, nil, nil, errors.New("generated public key is too long")
	}
	resp := make([]byte, 2+myPubLen)
	copy(resp[0:2], Opsec.EncodeInt(uint64(myPubLen), 2))
	copy(resp[2:], myPub)
	if _, err := p.conn.Write(resp); err != nil {
		return nil, nil, nil, err
	}
	return peerPub, myPub, myPriv, nil
}

// Send memory data
func (p *TPprotocol) SendData(data []byte, smsg string) error {
	// 1. Handshake
	p.setStage(STAGE_HANDSHAKE)
	peerPub, _, myPriv, err := p.handshakeSend()
	if err != nil {
		return err
	}
	stop := make(chan bool)
	go p.syncStatus(stop)

	// 2. Make Opsec Header
	p.setStage(STAGE_ENCRYPTING)
	ops := new(Opsec.Opsec)
	ops.Reset()
	ops.Size = int64(len(data)) + 16 // data + tag
	ops.BodyAlgo = "gcm1"
	ops.Smsg = smsg

	var opsHead []byte
	if p.Mode&MODE_LEGACY != 0 {
		opsHead, err = ops.Encpub("rsa1", peerPub, myPriv)
	} else {
		opsHead, err = ops.Encpub("ecc1", peerPub, myPriv)
	}
	if err != nil {
		p.setStage(STAGE_ERROR)
		stop <- false
		return err
	}

	// 3. Encrypt body
	aes := new(Bencrypt.AES1)
	var key [44]byte
	copy(key[:], ops.BodyKey)
	encBody, err := aes.EnAESGCM(key, data)
	if err != nil {
		p.setStage(STAGE_ERROR)
		stop <- false
		return err
	}

	// 4. Build Payload with Framing
	var headerBuf bytes.Buffer
	if err := ops.Write(&headerBuf, opsHead); err != nil {
		p.setStage(STAGE_ERROR)
		stop <- false
		return err
	}
	payload := append(headerBuf.Bytes(), encBody...)
	encBody = nil
	totalSize := uint64(len(payload))
	stop <- true
	p.setStage(STAGE_TRANSFERRING)

	// 5. send total size
	p.setSent(0)
	p.setTotal(totalSize)
	if _, err := p.conn.Write(Opsec.EncodeInt(totalSize, 8)); err != nil {
		p.setStage(STAGE_ERROR)
		return err
	}

	// 6. send payload
	var currentSent uint64 = 0
	for currentSent < totalSize {
		n, err := p.conn.Write(payload[currentSent:min(currentSent+1024, totalSize)])
		if err != nil {
			p.setStage(STAGE_ERROR)
			return err
		}
		currentSent += uint64(n)
		p.setSent(currentSent)
	}

	// 7. Receive Termination
	var term [8]byte
	if _, err := io.ReadFull(p.conn, term[:]); err != nil {
		p.setStage(STAGE_ERROR)
		return err
	}
	if term != p.zero8 {
		p.setStage(STAGE_ERROR)
		return errors.New("abnormal termination signal")
	}
	p.setStage(STAGE_COMPLETE)
	return nil
}

// Receive to memory data
func (p *TPprotocol) ReceiveData() ([]byte, string, error) {
	// 1. Handshake
	p.setStage(STAGE_HANDSHAKE)
	peerPub, _, myPriv, err := p.handshakeReceive()
	if err != nil {
		p.setStage(STAGE_ERROR)
		return nil, "", err
	}

	// 2. Wait for Status (Start Signal)
	p.setStage(STAGE_TRANSFERRING)
	var buf8 [8]byte
	var totalSize uint64
	for {
		if _, err := io.ReadFull(p.conn, buf8[:]); err != nil {
			p.setStage(STAGE_ERROR)
			return nil, "", err
		}

		if buf8 == p.zero8 {
			continue // Still preparing
		} else if buf8 == p.max8 {
			p.setStage(STAGE_ERROR)
			return nil, "", errors.New("remote error reported")
		} else {
			totalSize = Opsec.DecodeInt(buf8[:])
			p.setTotal(totalSize) // Total transmission size (Header + Body)
			break                 // Start transfer
		}
	}

	// 3. Receive All Data to Memory
	payload := make([]byte, totalSize)
	var currentReceived uint64 = 0
	for currentReceived < totalSize {
		n, err := p.conn.Read(payload[currentReceived:])
		if n > 0 {
			currentReceived += uint64(n)
			p.setSent(currentReceived)
		}
		if currentReceived == totalSize {
			break
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			p.setStage(STAGE_ERROR)
			return nil, "", err
		}
	}

	// 4. Parse & Decrypt Header
	bufReader := bytes.NewReader(payload)
	ops := new(Opsec.Opsec)
	headBytes, err := ops.Read(bufReader, 0)
	if err != nil {
		p.setStage(STAGE_ERROR)
		p.conn.Write(p.max8[:])
		return nil, "", err
	}
	ops.View(headBytes)
	if err := ops.Decpub(myPriv, peerPub); err != nil {
		p.setStage(STAGE_ERROR)
		p.conn.Write(p.max8[:])
		return nil, "", err
	}

	// 5. Decrypt Body
	p.setStage(STAGE_ENCRYPTING)
	bodyOffset := totalSize - uint64(bufReader.Len())
	encBody := payload[bodyOffset:]
	if ops.BodyAlgo != "gcm1" {
		p.setStage(STAGE_ERROR)
		p.conn.Write(p.max8[:])
		return nil, "", errors.New("unsupported body algorithm: " + ops.BodyAlgo)
	}
	var key [44]byte
	copy(key[:], ops.BodyKey)
	aes := new(Bencrypt.AES1)
	decBody, err := aes.DeAESGCM(key, encBody)
	if err != nil {
		p.setStage(STAGE_ERROR)
		p.conn.Write(p.max8[:])
		return nil, "", err
	}

	// 6. Send Termination
	if _, err := p.conn.Write(p.zero8[:]); err != nil {
		p.setStage(STAGE_ERROR)
		return nil, "", err
	}
	p.setStage(STAGE_COMPLETE)
	return decBody, ops.Smsg, nil
}

// Send file data
func (p *TPprotocol) SendFile(filePath string, tempPath string, smsg string) error {
	// 1. Handshake
	p.setStage(STAGE_HANDSHAKE)
	peerPub, _, myPriv, err := p.handshakeSend()
	if err != nil {
		return err
	}

	// 2. Prepare Source File
	stop := make(chan bool)
	go p.syncStatus(stop)
	p.setStage(STAGE_ENCRYPTING)

	srcFile, err := os.Open(filePath)
	if err != nil {
		p.setStage(STAGE_ERROR)
		stop <- false
		return err
	}
	defer srcFile.Close()

	// 3. Calculate encrypted body size
	srcInfo, err := srcFile.Stat()
	if err != nil {
		p.setStage(STAGE_ERROR)
		stop <- false
		return err
	}
	originalSize := srcInfo.Size()
	encryptedSize := AfterSize(originalSize)

	// 3. Prepare Opsec Header
	ops := new(Opsec.Opsec)
	ops.Reset()
	ops.Size = encryptedSize
	ops.BodyAlgo = "gcmx1" // File streaming encryption
	ops.ContAlgo = "zip1"
	ops.Smsg = smsg

	// Encrypt Header
	var opsHead []byte
	if p.Mode&MODE_LEGACY != 0 {
		opsHead, err = ops.Encpub("rsa1", peerPub, myPriv)
	} else {
		opsHead, err = ops.Encpub("ecc1", peerPub, myPriv)
	}
	if err != nil {
		p.setStage(STAGE_ERROR)
		stop <- false
		return err
	}

	// 4. Create Temp File & Write Everything (Header + Body)
	tempFile, err := os.Create(tempPath)
	defer os.Remove(tempPath)
	defer tempFile.Close()
	if err != nil {
		p.setStage(STAGE_ERROR)
		stop <- false
		return err
	}

	// Write Opsec Header to Temp File
	if err := ops.Write(tempFile, opsHead); err != nil {
		p.setStage(STAGE_ERROR)
		stop <- false
		return err
	}

	// Encrypt & Append Body to Temp File
	var key [44]byte
	copy(key[:], ops.BodyKey)
	aes := new(Bencrypt.AES1)
	err = aes.EnAESGCMx(key, srcFile, originalSize, tempFile, 0)
	if err != nil {
		p.setStage(STAGE_ERROR)
		stop <- false
		return err
	}

	// 5. Transfer the Entire Temp File
	p.setStage(STAGE_TRANSFERRING)
	stop <- true

	// Get total size (Header + Body)
	tempInfo, err := tempFile.Stat()
	if err != nil {
		p.setStage(STAGE_ERROR)
		return err
	}
	totalSize := uint64(tempInfo.Size())

	// Send Total Size Packet
	p.setSent(0)
	p.setTotal(totalSize)
	if _, err := p.conn.Write(Opsec.EncodeInt(totalSize, 8)); err != nil {
		p.setStage(STAGE_ERROR)
		return err
	}

	// Rewind Temp File to beginning
	if _, err := tempFile.Seek(0, 0); err != nil {
		p.setStage(STAGE_ERROR)
		return err
	}

	// Stream Send
	buf := make([]byte, 1024)
	var currentSent uint64 = 0
	for {
		nr, rErr := tempFile.Read(buf)
		if nr > 0 {
			nw, wErr := p.conn.Write(buf[0:nr])
			if wErr != nil {
				p.setStage(STAGE_ERROR)
				return wErr
			}
			currentSent += uint64(nw)
			p.setSent(currentSent)
		}
		if rErr == io.EOF {
			break
		}
		if rErr != nil {
			p.setStage(STAGE_ERROR)
			return rErr
		}
	}

	// 6. Receive Termination
	var term [8]byte
	if _, err := io.ReadFull(p.conn, term[:]); err != nil {
		p.setStage(STAGE_ERROR)
		return err
	}
	if term != p.zero8 {
		p.setStage(STAGE_ERROR)
		return errors.New("abnormal termination signal")
	}
	p.setStage(STAGE_COMPLETE)
	return nil
}

// Receive to file
func (p *TPprotocol) ReceiveFile(savePath string, tempPath string) (string, error) {
	// 1. Handshake
	p.setStage(STAGE_HANDSHAKE)
	peerPub, _, myPriv, err := p.handshakeReceive()
	if err != nil {
		p.setStage(STAGE_ERROR)
		return "", err
	}

	// 2. Wait for Status (Start Signal)
	p.setStage(STAGE_TRANSFERRING)
	var buf8 [8]byte
	var totalSize uint64
	for {
		if _, err := io.ReadFull(p.conn, buf8[:]); err != nil {
			p.setStage(STAGE_ERROR)
			return "", err
		}

		if buf8 == p.zero8 {
			continue // Still preparing
		} else if buf8 == p.max8 {
			p.setStage(STAGE_ERROR)
			return "", errors.New("remote error reported")
		} else {
			totalSize = Opsec.DecodeInt(buf8[:])
			p.setTotal(totalSize) // Total transmission size (Header + Body)
			break                 // Start transfer
		}
	}

	// 3. Download Stream to Temp File
	tempFile, err := os.Create(tempPath)
	defer os.Remove(tempPath)
	defer tempFile.Close()
	if err != nil {
		p.setStage(STAGE_ERROR)
		return "", err
	}

	// Stream Receive
	p.setSent(0)
	buf := make([]byte, 1024)
	var currentReceived uint64 = 0
	for currentReceived < totalSize {
		toRead := min(uint64(len(buf)), totalSize-currentReceived)

		n, rErr := p.conn.Read(buf[:toRead])
		if n > 0 {
			if _, wErr := tempFile.Write(buf[:n]); wErr != nil {
				p.setStage(STAGE_ERROR)
				return "", wErr
			}
			currentReceived += uint64(n)
			p.setSent(currentReceived)
		}

		if currentReceived == totalSize {
			break
		}
		if rErr != nil {
			if rErr == io.EOF && currentReceived == totalSize {
				break
			}
			p.setStage(STAGE_ERROR)
			return "", rErr
		}
	}

	// 4. Parse & Decrypt Header from Temp File
	if _, err := tempFile.Seek(0, 0); err != nil {
		p.setStage(STAGE_ERROR)
		p.conn.Write(p.max8[:])
		return "", err
	}

	// Read Header, View
	ops := new(Opsec.Opsec)
	headBytes, err := ops.Read(tempFile, 0)
	if err != nil {
		p.setStage(STAGE_ERROR)
		p.conn.Write(p.max8[:])
		return "", err
	}
	ops.View(headBytes)
	if err := ops.Decpub(myPriv, peerPub); err != nil {
		p.setStage(STAGE_ERROR)
		p.conn.Write(p.max8[:])
		return "", err
	}

	// 5. Decrypt Body to Save File
	p.setStage(STAGE_ENCRYPTING)
	outFile, err := os.Create(savePath)
	if err != nil {
		p.setStage(STAGE_ERROR)
		p.conn.Write(p.max8[:])
		return "", err
	}

	// get body key
	defer outFile.Close()
	if ops.BodyAlgo != "gcmx1" {
		p.setStage(STAGE_ERROR)
		p.conn.Write(p.max8[:])
		return "", errors.New("unsupported body algorithm: " + ops.BodyAlgo)
	}
	var key [44]byte
	copy(key[:], ops.BodyKey)
	aes := new(Bencrypt.AES1)

	// decrypt from current pos of tempFile
	err = aes.DeAESGCMx(key, tempFile, ops.Size, outFile, 0)
	if err != nil {
		p.setStage(STAGE_ERROR)
		p.conn.Write(p.max8[:])
		return "", err
	}

	// 6. Send Termination
	if _, err := p.conn.Write(p.zero8[:]); err != nil {
		p.setStage(STAGE_ERROR)
		return "", err
	}
	p.setStage(STAGE_COMPLETE)
	return ops.Smsg, nil
}
