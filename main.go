// test796c : project USAG YAS-desktop gui
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image/color"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/k-atusa/USAG-Lib/Bencode"
	"github.com/k-atusa/USAG-Lib/Bencrypt"
	"github.com/k-atusa/USAG-Lib/Icons"
	"github.com/k-atusa/USAG-Lib/Opsec"
)

// ===== theme =====
var SizeAmpl float32 = 1.0

type U1Theme struct{}

func (m U1Theme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	if name == theme.ColorNameForeground { // change only foreground color
		if variant == theme.VariantDark {
			return color.White
		}
		return color.Black
	}
	return theme.DefaultTheme().Color(name, variant)
}

func (m U1Theme) Font(s fyne.TextStyle) fyne.Resource     { return theme.DefaultTheme().Font(s) }
func (m U1Theme) Icon(n fyne.ThemeIconName) fyne.Resource { return theme.DefaultTheme().Icon(n) }
func (m U1Theme) Size(n fyne.ThemeSizeName) float32       { return theme.DefaultTheme().Size(n) * SizeAmpl }

// ===== config =====
type U1Config struct {
	AutoExpire int      `json:"auto_expire"`
	Size       float32  `json:"size"`
	Accounts   []string `json:"accounts"`
}

func (c *U1Config) GetPath() (string, error) {
	// find actual program path
	exePath, err := os.Executable()
	if err != nil {
		return "./config.json", err
	}
	realPath, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		realPath = exePath
	}
	return filepath.Join(filepath.Dir(realPath), "config.json"), nil
}

func (c *U1Config) Load() error {
	path, err := c.GetPath()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.AutoExpire = 20
			c.Size = 1.0
			c.Accounts = []string{}
			return c.Store()
		}
		return err
	}
	err = json.Unmarshal(data, c)
	SizeAmpl = c.Size
	return err
}

func (c *U1Config) Store() error {
	path, err := c.GetPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// ===== contacts =====
type Contacts struct {
	Datas map[string][]byte `json:"contacts"`
}

func (c *Contacts) GetList() []string {
	keys := make([]string, 0, len(c.Datas))
	for k := range c.Datas {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func (c *Contacts) GetPath() (string, error) {
	// find actual program path
	exePath, err := os.Executable()
	if err != nil {
		return "./contacts.json", err
	}
	realPath, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		realPath = exePath
	}
	return filepath.Join(filepath.Dir(realPath), "contacts.json"), nil
}

func (c *Contacts) Load() error {
	path, err := c.GetPath()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.Datas = make(map[string][]byte)
			return c.Store()
		}
		return err
	}
	return json.Unmarshal(data, c)
}

func (c *Contacts) Store() error {
	path, err := c.GetPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (c *Contacts) Add(name string, keytype string, pub []byte) error {
	key := fmt.Sprintf("%s (%s, %s)", name, keytype, hex.EncodeToString(Opsec.Crc32(pub)))
	c.Datas[key] = pub
	return c.Store()
}

func (c *Contacts) Del(key string) error {
	delete(c.Datas, key)
	return c.Store()
}

// ===== account =====
type Account struct {
	KeyType  string // rsa1, ecc1
	PubKey   []byte
	PriKey   []byte
	KeyFiles map[string][]byte

	Path string
	PW   string
	KF   []byte
	Msg  string
}

func (a *Account) NewKey(bits int) (err error) {
	switch a.KeyType {
	case "rsa1":
		b := new(Bencrypt.RSA1)
		a.PubKey, a.PriKey, err = b.Genkey(bits)
	case "ecc1":
		b := new(Bencrypt.ECC1)
		a.PubKey, a.PriKey, err = b.Genkey()
	}
	return err
}

func (a *Account) Load() error {
	// 1. read header
	f, err := os.Open(a.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	o := new(Opsec.Opsec)
	o.Reset()
	header, err := o.Read(f, 0)
	if err != nil {
		return err
	}

	// 2. decrypt header
	o.View(header)
	a.Msg = o.Msg
	if err := o.Decpw([]byte(a.PW), a.KF); err != nil {
		return err
	}

	// 3. restore key from smsg
	b := new(Bencode.Bencode)
	b.Init()
	parts := strings.Split(o.Smsg, "\n")
	if len(parts) != 3 {
		return errors.New("invalid account format")
	}
	a.KeyType = parts[0]
	a.PubKey, err = b.Decode(parts[1])
	if err != nil {
		return err
	}
	a.PriKey, err = b.Decode(parts[2])
	if err != nil {
		return err
	}

	// 4. read body, set key
	if o.BodyAlgo != "gcm1" {
		return errors.New("invalid body algorithm")
	}
	encBody := make([]byte, o.Size)
	_, err = io.ReadFull(f, encBody)
	if err != nil {
		return err
	}
	var key [44]byte
	copy(key[:], o.BodyKey)

	// 5. decrypt body
	es := new(Bencrypt.AES1)
	es.Init()
	plainkf, err := es.DeAESGCM(key, encBody)
	if err != nil {
		return err
	}
	a.KeyFiles = Opsec.DecodeCfg(plainkf)
	return nil
}

func (a *Account) Store() error {
	// 1. make plain data
	b := new(Bencode.Bencode)
	b.Init()
	smsg := strings.Join([]string{a.KeyType, b.Encode(a.PubKey, true), b.Encode(a.PriKey, true)}, "\n")
	plainkf, err := Opsec.EncodeCfg(a.KeyFiles)
	if err != nil {
		return err
	}

	// 2. make header and bodykey
	o := new(Opsec.Opsec)
	o.Reset()
	o.Msg = a.Msg
	o.Smsg = smsg
	o.BodyAlgo = "gcm1"
	o.Size = int64(len(plainkf) + 16)
	m := "arg1"
	if a.KeyType == "rsa1" {
		m = "pbk1"
	}
	header, err := o.Encpw(m, []byte(a.PW), a.KF)
	if err != nil {
		return err
	}
	var key [44]byte
	copy(key[:], o.BodyKey)

	// 3. make file, write prehead
	ic := new(Icons.Icons)
	var prehead []byte
	if strings.HasSuffix(a.Path, ".webp") {
		prehead, _ = ic.Zip_webp()
	} else if strings.HasSuffix(a.Path, ".png") {
		prehead, _ = ic.Zip_png()
	}
	if prehead != nil {
		prehead = append(prehead, make([]byte, 128-len(prehead)%128)...)
	}
	f, err := os.Create(a.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(prehead); err != nil {
		return err
	}

	// 4. write header, encrypt body
	if err := o.Write(f, header); err != nil {
		return err
	}
	es := new(Bencrypt.AES1)
	es.Init()
	enc, err := es.EnAESGCM(key, plainkf)
	if err != nil {
		return err
	}
	_, err = f.Write(enc)
	return err
}

// ===== helper =====
func kfSelect(w fyne.Window, lbl *widget.Label, keyPtr *[]byte) {
	dialog.ShowFileOpen(func(r fyne.URIReadCloser, err error) {
		if err == nil && r != nil {
			// 1. Read file (max 1024 bytes)
			defer r.Close()
			buf := make([]byte, 1024)
			n, _ := io.ReadFull(r, buf)
			data := buf[:n]

			// 2. Set Data & Update UI
			*keyPtr = data
			crc := hex.EncodeToString(Opsec.Crc32(data))
			lbl.SetText(fmt.Sprintf("[%dB, %s] %s", n, crc, r.URI().Name()))
		} else {
			*keyPtr = nil
			lbl.SetText("[0B 00000000] keyfile not selected")
		}
	}, w)
}

func kfReceive(w fyne.Window, lbl *widget.Label, portEnt *widget.Entry, keyPtr *[]byte) {
	// 1. Get IP Address
	ips, err := GetIPs(true)
	if err != nil {
		dialog.ShowError(err, w)
		return
	}
	port := "8001"
	if portEnt.Text != "" {
		port = portEnt.Text
	}
	for i, r := range ips {
		ips[i] = r + ":" + port
	}
	dialog.ShowInformation("IP Address", strings.Join(ips, "\n"), w)

	// 2. Receive KeyFile
	go func() {
		defer func() {
			if r := recover(); r != nil {
				os.WriteFile("yas-panic.txt", []byte(fmt.Sprint(r)), 0644)
			}
		}()

		listener, err := net.Listen("tcp", ":"+port)
		if err != nil {
			fyne.Do(func() { dialog.ShowError(err, w) })
			return
		}
		defer listener.Close()
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(90 * time.Second)) // 90s timeout
		conn, err := listener.Accept()
		if err != nil {
			fyne.Do(func() { dialog.ShowError(err, w) })
			return
		}
		defer conn.Close()

		p := new(TPprotocol)
		p.Init(0, conn)
		fromPub, toPub, data, _, err := p.ReceiveData()
		if err != nil {
			fyne.Do(func() { dialog.ShowError(err, w) })
			return
		}

		// 3. Update UI
		fyne.Do(func() {
			*keyPtr = data
			crc0 := hex.EncodeToString(Opsec.Crc32(data))
			crc1 := hex.EncodeToString(Opsec.Crc32(fromPub))
			crc2 := hex.EncodeToString(Opsec.Crc32(toPub))
			lbl.SetText(fmt.Sprintf("[%dB, %s] from %s to %s", len(data), crc0, crc1, crc2))
		})
	}()
}

func pubSelect(w fyne.Window, lbl *widget.Label, keyPtr *[]byte, basic []byte) {
	dialog.ShowFileOpen(func(r fyne.URIReadCloser, err error) {
		if err == nil && r != nil {
			// 1. Read file (max 1024 bytes)
			defer r.Close()
			buf := make([]byte, 1024)
			n, _ := io.ReadFull(r, buf)
			data := buf[:n]

			// 2. Set Data & Update UI
			*keyPtr = data
			crc := hex.EncodeToString(Opsec.Crc32(data))
			lbl.SetText(fmt.Sprintf("[%dB, %s] %s", n, crc, r.URI().Name()))
		} else {
			*keyPtr = basic
			crc := hex.EncodeToString(Opsec.Crc32(basic))
			lbl.SetText(fmt.Sprintf("[%dB, %s] %s", len(basic), crc, "default"))
		}
	}, w)
}

func pubReceive(w fyne.Window, lbl *widget.Label, portEnt *widget.Entry, keyPtr *[]byte) {
	kfReceive(w, lbl, portEnt, keyPtr)
}

func getPath() string {
	exePath, err := os.Executable()
	if err != nil {
		return "./"
	}
	realPath, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		realPath = exePath
	}
	return filepath.Dir(realPath)
}

func cleanPath(path string) string {
	replaceChars := []string{"\\", "/", ":", "*", "?", "\"", "<", ">", "|"}
	for _, char := range replaceChars {
		path = strings.ReplaceAll(path, char, "_")
	}
	return path
}

func tempPath() string {
	path := filepath.Join(getPath(), hex.EncodeToString(Bencrypt.Random(4))+".temp")
	for {
		if _, err := os.Stat(path); err == nil {
			path = filepath.Join(getPath(), hex.EncodeToString(Bencrypt.Random(4))+".temp")
		} else {
			break
		}
	}
	return path
}

func addFile(w fyne.Window, l *widget.List, tgts *[]string) {
	dialog.ShowFileOpen(func(r fyne.URIReadCloser, err error) {
		defer l.Refresh()
		if err == nil && r != nil {
			path := r.URI().Path()
			if slices.Contains(*tgts, path) {
				return
			}
			*tgts = append(*tgts, path)
		}
	}, w)
}

func addFolder(w fyne.Window, l *widget.List, tgts *[]string) {
	dialog.ShowFolderOpen(func(lu fyne.ListableURI, err error) {
		defer l.Refresh()
		if err == nil && lu != nil {
			path := lu.Path()
			if slices.Contains(*tgts, path) {
				return
			}
			*tgts = append(*tgts, path)
		}
	}, w)
}

func delTgt(l *widget.List, tgts *[]string, idx int) {
	defer l.Refresh()
	if idx < 0 || idx > len(*tgts) {
		return
	}
	if idx == len(*tgts) {
		*tgts = make([]string, 0)
	} else {
		*tgts = append((*tgts)[:idx], (*tgts)[idx+1:]...)
	}
}

// ===== login =====
type LoginPage struct {
	App      fyne.App
	Window   fyne.Window
	Config   *U1Config
	Contacts *Contacts
	Account  *Account

	AccPath string
	AccKF   []byte
	NewImg  string
	NewType string
}

func (l *LoginPage) Main(c *U1Config, con *Contacts, a *Account) {
	l.Config = c
	l.Contacts = con
	l.Account = a
	e0 := l.Config.Load()
	e1 := l.Contacts.Load()
	l.App = app.New()
	l.App.Settings().SetTheme(&U1Theme{})
	l.Window = l.App.NewWindow("YAS desktop")
	l.Fill()
	l.Window.Resize(fyne.NewSize(720*SizeAmpl, 480*SizeAmpl))
	l.Window.CenterOnScreen()
	if e0 != nil {
		dialog.ShowError(fmt.Errorf("Config Load Fail: %s", e0), l.Window)
	}
	if e1 != nil {
		dialog.ShowError(fmt.Errorf("Contacts Load Fail: %s", e1), l.Window)
	}
	l.Window.ShowAndRun()
}

func (l *LoginPage) Fill() {
	// group0: account select
	lbl0 := widget.NewLabel("Msg:")
	sel0 := widget.NewSelect(l.Config.Accounts, func(s string) {
		l.AccPath = s
		l.Account.Path = s
		lbl0.SetText(s)
		l.Account.Load()
		lbl0.SetText("Msg: " + l.Account.Msg)
	})
	sel0.PlaceHolder = "Select Account"

	// group1: keyfile selection
	lbl1 := widget.NewLabel("[0B 00000000] keyfile not selected")
	btn1a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() {
		kfSelect(l.Window, lbl1, &l.AccKF)
	})
	ent1 := widget.NewEntry()
	ent1.SetPlaceHolder("port: 8001")
	btn1b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() {
		kfReceive(l.Window, lbl1, ent1, &l.AccKF)
	})
	box1 := container.NewBorder(nil, nil, container.NewHBox(btn1a, btn1b), nil, ent1)

	// group2: password and login
	ent2 := widget.NewPasswordEntry()
	ent2.SetPlaceHolder("Password")
	btn2 := widget.NewButtonWithIcon("Login", theme.LoginIcon(), func() {
		if l.AccPath == "" {
			dialog.ShowError(fmt.Errorf("Account not selected"), l.Window)
			return
		}
		l.Account.PW, l.Account.KF = ent2.Text, l.AccKF
		err := l.Account.Load()
		if err != nil {
			dialog.ShowError(err, l.Window)
			return
		}
		l.AccKF = nil
		l.switchToMain()
	})
	btn2.Importance = widget.HighImportance

	// guoup3: left box
	box3 := container.NewVBox(
		lbl0, sel0,
		widget.NewSeparator(),
		lbl1, box1,
		layout.NewSpacer(),
		ent2, btn2,
	)

	// group4: new account config
	lbl4a := widget.NewLabel("Password and KeyFile are loaded from left card")
	ent4b := widget.NewEntry()
	ent4b.SetPlaceHolder("Public message")
	sel4c := widget.NewSelect([]string{"webp", "png", "bin"}, func(s string) { l.NewImg = s })
	sel4c.SetSelected("webp")
	l.NewImg = "webp"
	sel4d := widget.NewSelect([]string{"ecc1", "rsa1-2k", "rsa1-3k", "rsa1-4k"}, func(s string) { l.NewType = s })
	sel4d.SetSelected("ecc1")
	l.NewType = "ecc1"

	// group5: make new account
	ent5 := widget.NewEntry()
	ent5.SetPlaceHolder("Account name")
	btn5 := widget.NewButtonWithIcon("Generate", theme.ContentAddIcon(), func() {
		// 1. sanitize name
		name := cleanPath(ent5.Text)
		if name == "" {
			dialog.ShowError(fmt.Errorf("Account name is empty"), l.Window)
			return
		}

		// 2. check path
		l.Account.Path = filepath.Join(getPath(), name+"."+l.NewImg)
		if _, err := os.Stat(l.Account.Path); err == nil {
			dialog.ShowError(fmt.Errorf("Account already exists"), l.Window)
			return
		}

		// 3. make key, save
		switch l.NewType {
		case "ecc1":
			l.Account.KeyType = "ecc1"
			if err := l.Account.NewKey(0); err != nil {
				dialog.ShowError(err, l.Window)
				return
			}
		case "rsa1-2k":
			l.Account.KeyType = "rsa1"
			if err := l.Account.NewKey(2048); err != nil {
				dialog.ShowError(err, l.Window)
				return
			}
		case "rsa1-3k":
			l.Account.KeyType = "rsa1"
			if err := l.Account.NewKey(3072); err != nil {
				dialog.ShowError(err, l.Window)
				return
			}
		case "rsa1-4k":
			l.Account.KeyType = "rsa1"
			if err := l.Account.NewKey(4096); err != nil {
				dialog.ShowError(err, l.Window)
				return
			}
		default:
			dialog.ShowError(fmt.Errorf("Unknown key type: %s", l.NewType), l.Window)
			return
		}
		l.Account.PW, l.Account.KF, l.Account.Msg = ent2.Text, l.AccKF, ent4b.Text
		if err := l.Account.Store(); err != nil {
			dialog.ShowError(err, l.Window)
			return
		}

		// 4. update account list
		l.Config.Accounts = append(l.Config.Accounts, l.Account.Path)
		if err := l.Config.Store(); err != nil {
			dialog.ShowError(err, l.Window)
			return
		}
		sel0.Options = l.Config.Accounts
		sel0.Refresh()
		dialog.ShowInformation("Success", "Account created successfully", l.Window)
	})
	btn5.Importance = widget.HighImportance

	// group6: right box
	box6 := container.NewVBox(
		lbl4a, ent4b,
		container.NewBorder(nil, nil, widget.NewLabel("Image Format"), sel4c),
		container.NewBorder(nil, nil, widget.NewLabel("Key Type"), sel4d),
		layout.NewSpacer(),
		ent5, btn5,
	)

	// group7: main grid
	box7 := container.NewGridWithColumns(2,
		widget.NewCard("Login Existing", "기존 계정 로그인", box3),
		widget.NewCard("Create New", "새로운 계정 생성", box6),
	)
	l.Window.SetContent(container.NewPadded(box7))
}

func (l *LoginPage) switchToMain() {
	m := new(MainPage)
	m.App = l.App
	m.Main(l.Config, l.Contacts, l.Account)
	l.Window.Close()
}

// ===== main =====
type MainPage struct {
	App      fyne.App
	Window   fyne.Window
	Config   *U1Config
	Contacts *Contacts
	Account  *Account

	Mode        int
	ContentArea *fyne.Container
	LblArea     *widget.Label

	LogoutTimer *time.Timer
	LogoutTime  time.Time
	LblTimer    *widget.Label

	Pg0 *Page0
	Pg1 *Page1
	Pg2 *Page2
	Pg3 *Page3
	Pg4 *Page4
	Pg5 *Page5
	Pg6 *Page6
	Pg7 *Page7
}

func (m *MainPage) Main(c *U1Config, con *Contacts, a *Account) {
	m.Config = c
	m.Contacts = con
	m.Account = a
	m.Pg0 = new(Page0)
	m.Pg1 = new(Page1)
	m.Pg2 = new(Page2)
	m.Pg3 = new(Page3)
	m.Pg4 = new(Page4)
	m.Pg5 = new(Page5)
	m.Pg6 = new(Page6)
	m.Pg7 = new(Page7)

	m.Window = m.App.NewWindow("YAS desktop")
	m.Fill()
	m.Window.Resize(fyne.NewSize(800*SizeAmpl, 480*SizeAmpl))
	m.Window.CenterOnScreen()
	m.Pg0.Init(m.Window, c, con, a, m.ContentArea)
	m.Pg2.Init(m.Window, c, con, a, m.ContentArea)
	m.Pg3.Init(m.Window, c, con, a, m.ContentArea)

	if m.Config.AutoExpire > 0 {
		m.ResetTimer()
		go m.UpdateTimerLoop()
	}
	m.ModeClick(7)
	m.Window.Show()
}

func (m *MainPage) Fill() {
	// group0: top toolbar
	box0 := widget.NewToolbar(
		widget.NewToolbarAction(theme.MailAttachmentIcon(), func() { m.ModeClick(0) }),
		widget.NewToolbarAction(theme.DocumentCreateIcon(), func() { m.ModeClick(1) }),
		widget.NewToolbarSeparator(),
		widget.NewToolbarAction(theme.UploadIcon(), func() { m.ModeClick(2) }),
		widget.NewToolbarAction(theme.DownloadIcon(), func() { m.ModeClick(3) }),
		widget.NewToolbarSeparator(),
		widget.NewToolbarAction(theme.CheckButtonIcon(), func() { m.ModeClick(4) }),
		widget.NewToolbarAction(theme.BrokenImageIcon(), func() { m.ModeClick(5) }),
		widget.NewToolbarSpacer(),
		widget.NewToolbarAction(theme.MailComposeIcon(), func() { m.ModeClick(6) }),
		widget.NewToolbarAction(theme.AccountIcon(), func() { m.ModeClick(7) }),
	)

	// group1: center area
	m.ContentArea = container.NewStack()

	// group2: bottom bar
	m.LblArea = widget.NewLabel(fmt.Sprintf("%s | %s", m.Account.Path, m.Account.KeyType))
	var box2 []fyne.CanvasObject = []fyne.CanvasObject{m.LblArea, layout.NewSpacer()}
	if m.Config.AutoExpire > 0 {
		m.LblTimer = widget.NewLabel("Expire in 00:00")
		btnExtend := widget.NewButton("Extend", func() { m.ResetTimer() })
		btnExtend.Importance = widget.HighImportance
		box2 = append(box2, m.LblTimer, btnExtend)
	}
	btn2 := widget.NewButtonWithIcon("Logout", theme.LogoutIcon(), func() {
		dialog.ShowConfirm("Logout", "Logout Now?", func(b bool) {
			if b {
				m.Account = nil
				m.Window.Close()
			}
		}, m.Window)
	})
	btn2.Importance = widget.DangerImportance
	box2 = append(box2, btn2)

	// group3: main layout
	box3 := container.NewBorder(box0, container.NewHBox(box2...), nil, nil, m.ContentArea)
	m.Window.SetContent(box3)
}

func (m *MainPage) ResetTimer() {
	if m.Config.AutoExpire <= 0 {
		return
	}
	if m.LogoutTimer != nil {
		m.LogoutTimer.Stop()
	}
	m.LogoutTime = time.Now().Add(time.Duration(m.Config.AutoExpire) * time.Minute)
	m.LogoutTimer = time.AfterFunc(time.Duration(m.Config.AutoExpire)*time.Minute, func() {
		fyne.Do(func() {
			m.Account = nil
			m.Window.Close()
		})
	})
}

func (m *MainPage) UpdateTimerLoop() {
	for {
		time.Sleep(1 * time.Second)
		remaining := time.Until(m.LogoutTime)
		if remaining <= 0 || m.Account == nil {
			break
		}
		if m.LblTimer != nil {
			fyne.Do(func() {
				m.LblTimer.SetText(fmt.Sprintf("Expire in %02d:%02d", int(remaining.Minutes()), int(remaining.Seconds())%60))
			})
		}
	}
}

func (m *MainPage) ModeClick(mode int) {
	defer m.ContentArea.Refresh()
	m.Mode = mode
	switch mode {
	case 0:
		m.LblArea.SetText(fmt.Sprintf("%s | %s | Pack/Unpack", m.Account.Path, m.Account.KeyType))
		m.Pg0.Fill()
	case 1:
		m.LblArea.SetText(fmt.Sprintf("%s | %s | Sign/Verify", m.Account.Path, m.Account.KeyType))
	case 2:
		m.LblArea.SetText(fmt.Sprintf("%s | %s | Send", m.Account.Path, m.Account.KeyType))
		m.Pg2.Fill()
	case 3:
		m.LblArea.SetText(fmt.Sprintf("%s | %s | Receive", m.Account.Path, m.Account.KeyType))
		m.Pg3.Fill()
	case 4:
		m.LblArea.SetText(fmt.Sprintf("%s | %s | Encrypt", m.Account.Path, m.Account.KeyType))
	case 5:
		m.LblArea.SetText(fmt.Sprintf("%s | %s | Decrypt", m.Account.Path, m.Account.KeyType))
	case 6:
		m.LblArea.SetText(fmt.Sprintf("%s | %s | Contacts", m.Account.Path, m.Account.KeyType))
	case 7:
		m.LblArea.SetText(fmt.Sprintf("%s | %s | Account", m.Account.Path, m.Account.KeyType))
	}
}

// ===== mode 0: zip/unzip =====
type Page0 struct {
	Window   fyne.Window
	Content  *fyne.Container
	Config   *U1Config
	Contacts *Contacts
	Account  *Account

	list      *widget.List
	selected  int
	status    *widget.Label
	isWorking bool
	Targets   []string
	ZipType   string
}

func (p *Page0) Init(w fyne.Window, c *U1Config, con *Contacts, a *Account, ca *fyne.Container) {
	p.Window = w
	p.Config = c
	p.Contacts = con
	p.Account = a
	p.Content = ca
	p.isWorking = false
	p.Targets = make([]string, 0)
}

func (p *Page0) Fill() {
	// group0: file list
	p.list = widget.NewList(
		func() int { return len(p.Targets) },
		func() fyne.CanvasObject { return widget.NewLabel("template path") },
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			obj.(*widget.Label).SetText(p.Targets[id])
		},
	)
	p.selected = -1
	p.list.OnSelected = func(id widget.ListItemID) {
		p.selected = id
	}

	// group1: file management buttons
	btn1a := widget.NewButtonWithIcon("Add file", theme.FileIcon(), func() { addFile(p.Window, p.list, &p.Targets) })
	btn1b := widget.NewButtonWithIcon("Add folder", theme.FolderIcon(), func() { addFolder(p.Window, p.list, &p.Targets) })
	btn1c := widget.NewButtonWithIcon("Del path", theme.DeleteIcon(), func() { delTgt(p.list, &p.Targets, p.selected); p.selected = -1 })
	btn1d := widget.NewButtonWithIcon("Reset all", theme.ContentClearIcon(), func() { delTgt(p.list, &p.Targets, len(p.Targets)); p.selected = -1 })
	box1a := container.NewHBox(btn1a, btn1b, btn1c, btn1d)
	box1b := container.NewBorder(nil, box1a, nil, nil, p.list)

	// group2: right config
	p.status = widget.NewLabel("Idle")
	if p.isWorking {
		p.status.SetText("Working...")
	}
	ent2 := widget.NewEntry()
	ent2.SetPlaceHolder("output")
	sel2 := widget.NewSelect([]string{"zip1", "tar1"}, func(s string) { p.ZipType = s })
	sel2.SetSelected("zip1")
	p.ZipType = "zip1"

	// group3: right action
	btn3a := widget.NewButtonWithIcon("Pack", theme.ViewRestoreIcon(), func() {
		if p.isWorking {
			return
		}
		go p.Pack(ent2.Text)
	})
	btn3b := widget.NewButtonWithIcon("Unpack", theme.ViewFullScreenIcon(), func() {
		if p.isWorking || p.selected < 0 || p.selected >= len(p.Targets) {
			return
		}
		go p.Unpack(ent2.Text)
	})
	box3 := container.NewVBox(
		widget.NewLabelWithStyle("Work menus", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		p.status, widget.NewSeparator(),
		widget.NewForm(
			widget.NewFormItem("Output name", ent2),
			widget.NewFormItem("Pack type", sel2),
		),
		layout.NewSpacer(),
		container.NewGridWithColumns(2, btn3a, btn3b),
	)

	// group4: main layout
	box4 := container.NewHSplit(box1b, box3)
	box4.Offset = 0.6
	p.Content.Objects = []fyne.CanvasObject{box4}
}

func (p *Page0) Pack(output string) {
	var err error
	p.isWorking = true
	fyne.Do(func() { p.status.SetText("Working...") })
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
		}
		p.isWorking = false
		fyne.Do(func() {
			p.status.SetText("Idle")
			if err == nil {
				dialog.ShowInformation("Success", "Packed successfully", p.Window)
			} else {
				dialog.ShowError(err, p.Window)
			}
		})
	}()

	tgts := make([]string, len(p.Targets))
	copy(tgts, p.Targets)
	output = cleanPath(output)
	if output == "" {
		output = "output"
	}
	switch p.ZipType {
	case "zip1":
		err = DoZip(tgts, output+".zip", true)
	case "tar1":
		err = DoZip(tgts, output+".tar", false)
	default:
		err = errors.New("invalid packing type")
	}
}

func (p *Page0) Unpack(output string) {
	var err error
	p.isWorking = true
	fyne.Do(func() { p.status.SetText("Working...") })
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
		}
		p.isWorking = false
		fyne.Do(func() {
			p.status.SetText("Idle")
			if err == nil {
				dialog.ShowInformation("Success", "Unpacked successfully", p.Window)
			} else {
				dialog.ShowError(err, p.Window)
			}
		})
	}()

	tgt := p.Targets[p.selected]
	output = cleanPath(output)
	if output == "" {
		output = "output"
	}
	switch p.ZipType {
	case "zip1":
		err = UnZip(tgt, output, true)
	case "tar1":
		err = UnZip(tgt, output, false)
	default:
		err = errors.New("invalid unpacking type")
	}
}

// ===== mode 1: sign/verify =====
type Page1 struct {
	Targets []string
	Sign    string
}

// ===== mode 2: send =====
type Page2 struct {
	Window   fyne.Window
	Content  *fyne.Container
	Config   *U1Config
	Contacts *Contacts
	Account  *Account

	list      *widget.List
	selected  int
	status    *widget.Label
	progbar   *widget.ProgressBar
	isWorking bool
	Targets   []string
	SendType  string
}

func (p *Page2) Init(w fyne.Window, c *U1Config, con *Contacts, a *Account, ca *fyne.Container) {
	p.Window = w
	p.Config = c
	p.Contacts = con
	p.Account = a
	p.Content = ca
	p.isWorking = false
	p.Targets = make([]string, 0)
}

func (p *Page2) Fill() {
	// group0: file list
	p.list = widget.NewList(
		func() int { return len(p.Targets) },
		func() fyne.CanvasObject { return widget.NewLabel("template path") },
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			obj.(*widget.Label).SetText(p.Targets[id])
		},
	)
	p.selected = -1
	p.list.OnSelected = func(id widget.ListItemID) {
		p.selected = id
	}

	// group1: file management buttons
	btn1a := widget.NewButtonWithIcon("Add file", theme.FileIcon(), func() { addFile(p.Window, p.list, &p.Targets) })
	btn1b := widget.NewButtonWithIcon("Add folder", theme.FolderIcon(), func() { addFolder(p.Window, p.list, &p.Targets) })
	btn1c := widget.NewButtonWithIcon("Del path", theme.DeleteIcon(), func() { delTgt(p.list, &p.Targets, p.selected); p.selected = -1 })
	btn1d := widget.NewButtonWithIcon("Reset all", theme.ContentClearIcon(), func() { delTgt(p.list, &p.Targets, len(p.Targets)); p.selected = -1 })
	box1a := container.NewHBox(btn1a, btn1b, btn1c, btn1d)
	box1b := container.NewBorder(nil, box1a, nil, nil, p.list)

	// group2: right config
	p.status = widget.NewLabel("Idle")
	if p.isWorking {
		p.status.SetText("Working...")
	}
	p.progbar = widget.NewProgressBar()
	ent2a := widget.NewEntry()
	ent2a.SetPlaceHolder("127.0.0.1:8002")
	ent2b := widget.NewMultiLineEntry()
	ent2b.SetPlaceHolder("secure message")
	sel2 := widget.NewSelect([]string{"ecc1", "rsa1-2k", "rsa1-4k"}, func(s string) { p.SendType = s })
	sel2.SetSelected("ecc1")
	p.SendType = "ecc1"

	// group3: right action
	btn3 := widget.NewButtonWithIcon("Send", theme.ConfirmIcon(), func() {
		if p.isWorking {
			return
		}
		go p.Send(ent2a.Text, ent2b.Text)
	})
	btn3.Importance = widget.HighImportance
	box3 := container.NewVBox(
		widget.NewLabelWithStyle("Work menus", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		p.status, p.progbar, widget.NewSeparator(),
		widget.NewForm(
			widget.NewFormItem("Peer", ent2a),
			widget.NewFormItem("Message", ent2b),
			widget.NewFormItem("Type", sel2),
		),
		layout.NewSpacer(),
		btn3,
	)

	// group4: main layout
	box4 := container.NewHSplit(box1b, box3)
	box4.Offset = 0.6
	p.Content.Objects = []fyne.CanvasObject{box4}
}

func (p *Page2) Send(tgt string, smsg string) {
	var err error
	var fromPub, toPub []byte
	p.isWorking = true
	fyne.Do(func() { p.status.SetText("Working...") })
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
		}
		p.isWorking = false
		fyne.Do(func() {
			p.status.SetText("Idle")
			if err == nil {
				dialog.ShowInformation("Success", fmt.Sprintf("Transfer: from %s to %s", hex.EncodeToString(Opsec.Crc32(fromPub)), hex.EncodeToString(Opsec.Crc32(toPub))), p.Window)
				p.progbar.SetValue(1.0)
			} else {
				dialog.ShowError(err, p.Window)
				p.progbar.SetValue(0.0)
			}
		})
	}()

	// 1. get target address
	targetAddr := tgt // IP:Port
	if targetAddr == "" {
		targetAddr = "127.0.0.1"
	}
	if !strings.Contains(targetAddr, ":") {
		targetAddr += ":8002" // default port
	}
	fyne.Do(func() { p.progbar.SetValue(0.0) })

	// 2. zip data
	targetPaths := make([]string, len(p.Targets))
	copy(targetPaths, p.Targets)
	zipPath := tempPath()
	defer os.Remove(zipPath)
	if len(targetPaths) == 0 { // msg-only mode
		f, _ := os.Create(zipPath)
		f.Close()
	} else { // zip files
		err = DoZip(targetPaths, zipPath, true)
		if err != nil {
			return
		}
	}
	fyne.Do(func() { p.progbar.SetValue(0.1) })

	// 3. Connect to receiver
	var conn net.Conn
	for range 5 { // 5 attempts
		conn, err = net.DialTimeout("tcp", targetAddr, 10*time.Second)
		if err == nil {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		return
	}
	defer conn.Close()
	fyne.Do(func() { p.progbar.SetValue(0.2) })

	// 4. Initialize Protocol
	var mode uint16 = 0
	switch p.SendType {
	case "ecc1":
		mode = 0
	case "rsa1-2k":
		mode = MODE_LEGACY
	case "rsa1-4k":
		mode = MODE_LEGACY | MODE_RSA_4K
	}
	if len(targetPaths) == 0 {
		mode |= MODE_MSGONLY // msg-only mode
	}
	tp := new(TPprotocol)
	tp.Init(uint16(mode), conn)

	// 5. Start prograss bar
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
				if isStarted {
					p.progbar.SetValue(1.0)
				}
				return
			case <-ticker.C:
				stage, sent, total := tp.GetStatus()
				if total > 0 && !isStarted { // start if total exists
					isStarted = true
				}
				if isStarted { // update progress
					p.progbar.SetValue(0.2 + 0.8*float64(sent)/float64(total))
					if stage == STAGE_ERROR { // halt if error
						return
					}
				}
			}
		}
	}()

	// 6. Send
	fromPub, toPub, err = tp.SendFile(zipPath, tempPath(), smsg)
	stop <- true
	<-done
}

// ===== mode 3: receive =====
type Page3 struct {
	Window   fyne.Window
	Content  *fyne.Container
	Config   *U1Config
	Contacts *Contacts
	Account  *Account

	list      *widget.List
	msgview   *widget.Entry
	status    *widget.Label
	progbar   *widget.ProgressBar
	isWorking bool
	IPs       []string
}

func (p *Page3) Init(w fyne.Window, c *U1Config, con *Contacts, a *Account, ca *fyne.Container) {
	p.Window = w
	p.Config = c
	p.Contacts = con
	p.Account = a
	p.Content = ca
	p.isWorking = false
	p.IPs = make([]string, 0)
}

func (p *Page3) Fill() {
	// group1: IP list
	p.list = widget.NewList(
		func() int { return len(p.IPs) },
		func() fyne.CanvasObject { return widget.NewLabel("template path") },
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			obj.(*widget.Label).SetText(p.IPs[id])
		},
	)

	// group1: right config
	p.status = widget.NewLabel("Idle")
	if p.isWorking {
		p.status.SetText("Working...")
	}
	p.progbar = widget.NewProgressBar()
	ent1 := widget.NewEntry()
	ent1.SetPlaceHolder("8002")
	p.msgview = widget.NewMultiLineEntry()
	p.msgview.SetPlaceHolder("secure message")

	// group2: right action
	btn2 := widget.NewButtonWithIcon("Receive", theme.ConfirmIcon(), func() {
		if p.isWorking {
			return
		}
		go p.Recv(ent1.Text)
	})
	btn2.Importance = widget.HighImportance
	box2 := container.NewVBox(
		widget.NewLabelWithStyle("Work menus", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		p.status, p.progbar, widget.NewSeparator(),
		widget.NewForm(
			widget.NewFormItem("Port", ent1),
			widget.NewFormItem("Message", p.msgview),
		),
		layout.NewSpacer(),
		btn2,
	)

	// group3: main layout
	box3 := container.NewHSplit(p.list, box2)
	box3.Offset = 0.4
	p.Content.Objects = []fyne.CanvasObject{box3}
}

func (p *Page3) Recv(port string) {
	var err error
	var fromPub, toPub []byte
	p.isWorking = true
	fyne.Do(func() { p.status.SetText("Working...") })
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
		}
		p.isWorking = false
		fyne.Do(func() {
			p.status.SetText("Idle")
			if err == nil {
				dialog.ShowInformation("Success", fmt.Sprintf("Transfer: from %s to %s", hex.EncodeToString(Opsec.Crc32(fromPub)), hex.EncodeToString(Opsec.Crc32(toPub))), p.Window)
				p.progbar.SetValue(1.0)
			} else {
				dialog.ShowError(err, p.Window)
				p.progbar.SetValue(0.0)
			}
		})
	}()

	// 1. Setup Listener, print IPs
	tgtPort := "8002"
	if port != "" {
		tgtPort = port
	}
	p.IPs, err = GetIPs(true)
	if err != nil {
		return
	}
	for i, ip := range p.IPs {
		p.IPs[i] = ip + ":" + tgtPort
	}
	fyne.Do(func() { p.list.Refresh() })
	listener, e := net.Listen("tcp", ":"+tgtPort)
	if e != nil {
		err = e
		return
	}
	defer listener.Close()
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(90 * time.Second)) // 90s timeout
	fyne.Do(func() { p.progbar.SetValue(0.0) })

	// 2. Accept Connection
	conn, e := listener.Accept()
	if e != nil {
		err = e
		return
	}
	defer conn.Close()
	fyne.Do(func() { p.progbar.SetValue(0.1) })

	// 3. Initialize Protocol, prepare paths
	tp := new(TPprotocol)
	tp.Init(0, conn)
	zipPath := tempPath()
	defer os.Remove(zipPath)

	// 4. Start Progress Bar
	stop := make(chan bool, 1)
	done := make(chan bool, 1)
	go func() {
		defer func() { done <- true }()
		isStarted := false
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-stop:
				if isStarted {
					fyne.Do(func() { p.progbar.SetValue(0.9) })
				}
				return
			case <-ticker.C:
				stage, sent, total := tp.GetStatus()
				// Start if total size is known (handshake complete)
				if total > 0 && !isStarted {
					isStarted = true
				}
				// Update progress
				if isStarted {
					fyne.Do(func() { p.progbar.SetValue(0.1 + 0.8*float64(sent)/float64(total)) })
					if stage == STAGE_ERROR {
						return
					}
				}
			}
		}
	}()

	// 5. Receive archive file
	smsg := ""
	fromPub, toPub, smsg, err = tp.ReceiveFile(zipPath, tempPath())
	stop <- true
	<-done
	fyne.Do(func() { p.msgview.SetText(smsg) })
	if err != nil {
		return
	}

	// 6. Unzip if required
	if tp.Mode&MODE_MSGONLY == 0 {
		err = UnZip(zipPath, "./", true)
		if err != nil {
			return
		}
	}
	fyne.Do(func() { p.progbar.SetValue(1.0) })
}

// ===== mode 4: encrypt =====
type Page4 struct {
	Targets     []string
	Prehead     string
	RandName    bool
	IsZip       bool
	SplitTarget bool
}

// ===== mode 5: decrypt =====
type Page5 struct {
	Targets []string
}

// ===== mode 6: contacts =====
type Page6 struct {
	Names   []string
	Types   []string
	PubKeys [][]byte
}

// ===== mode 7: account =====
type Page7 struct {
	Account *Account
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			os.WriteFile("yas-panic.txt", []byte(fmt.Sprint(r)), 0644)
		}
	}()
	var p LoginPage
	p.Main(new(U1Config), new(Contacts), new(Account))
}
