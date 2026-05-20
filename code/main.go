// test796c : project USAG YAS-desktop gui
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"github.com/k-atusa/USAG-Lib/Opsec"
	"github.com/taewook427/USAG-KOX/BaseUI"
	"github.com/taewook427/USAG-KOX/TP1"
)

// save data to file
func savemem(name string, data []byte) {
	path, err := BaseUI.ZenityFolder("")
	if err == nil {
		os.WriteFile(filepath.Join(path, TP1.CleanPath(name)), data, 0644)
	}
}

// ===== config =====
type U1Config struct {
	AutoExpire int               `json:"expire"`
	Size       float32           `json:"size"`
	DoPad      bool              `json:"dopad"`
	InitDir    string            `json:"initdir"`
	Accounts   []string          `json:"accounts"`
	IPs        []string          `json:"ips"`
	PublicKeys map[string][]byte `json:"pubkeys"`
}

func (c *U1Config) Load() error {
	data, err := os.ReadFile(filepath.Join(TP1.GetPath(), "config.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.AutoExpire = 20
			c.Size = 1.0
			c.DoPad = true
			c.InitDir = ""
			c.Accounts = []string{}
			c.IPs = []string{"127.0.0.1"}
			c.PublicKeys = map[string][]byte{}
			return c.Store()
		}
		return err
	}
	err = json.Unmarshal(data, c)
	BaseUI.FyneSize = c.Size
	return err
}

func (c *U1Config) Store() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(TP1.GetPath(), "config.json"), data, 0644)
}

// get public key name list
func (c *U1Config) GetPub() []string {
	keys := make([]string, 0, len(c.PublicKeys))
	for k := range c.PublicKeys {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// add public key
func (c *U1Config) AddPub(name string, keytype string, pub []byte) error {
	key := fmt.Sprintf("%s (%s, %s)", name, keytype, Opsec.Crc32(pub))
	c.PublicKeys[key] = pub
	return c.Store()
}

// delete public key
func (c *U1Config) DelPub(key string) error {
	delete(c.PublicKeys, key)
	return c.Store()
}

// ===== account =====
type Account struct {
	KeyType  string // rsa1, rsa2, ecc1, pqc1
	PubKey   []byte
	PriKey   []byte            // masked
	KeyFiles map[string][]byte // masked

	Path  string
	PW    []byte // masked
	KF    []byte // masked
	Msg   string
	DoPad bool

	Mask *Bencrypt.Masker
}

func (a *Account) NewKey() error {
	am := new(Bencrypt.AsymMaster)
	err := am.Init(a.KeyType)
	if err == nil {
		var priv []byte
		a.PubKey, priv, err = am.Genkey()
		if err == nil {
			a.PriKey, err = a.Mask.XOR(priv)
		}
		sclear(priv)
	}
	if err == nil {
		err = a.Store()
	}
	return err
}

func (a *Account) GetList() []string {
	list := make([]string, 0)
	for nm := range a.KeyFiles {
		list = append(list, nm)
	}
	slices.Sort(list)
	return list
}

func (a *Account) Load() error {
	// 1. read header
	f, err := os.Open(a.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	o := new(Opsec.Opsec)
	defer func() {
		o.Smsg = ""
		sclear(o.BodyKey)
	}()
	o.Reset()
	header, err := o.Read(f, 0)
	if err != nil {
		return err
	}

	// 2. decrypt header
	o.View(header)
	a.Msg = o.Msg
	pw, _ := a.Mask.XOR(a.PW)
	defer sclear(pw)
	kf, _ := a.Mask.XOR(a.KF)
	defer sclear(kf)
	if err := o.Decpw(pw, kf); err != nil {
		return err
	}

	// 3. restore key from smsg
	parts := strings.Split(o.Smsg, "\n")
	if len(parts) != 3 {
		return errors.New("invalid account format")
	}
	a.KeyType = parts[0]
	a.PubKey, err = Bencode.Decode64(parts[1], "") // pure base64
	if err != nil {
		return err
	}
	var priv []byte
	defer func() { sclear(priv) }()
	priv, err = Bencode.Decode64(parts[2], "") // pure base64
	parts[2] = ""
	if err == nil {
		a.PriKey, err = a.Mask.XOR(priv)
	}
	if err != nil {
		return err
	}

	// 4. read body, decrypt body
	sm := new(Bencrypt.SymMaster)
	defer func() { sclear(sm.Key) }()
	if err := sm.Init(o.BodyAlgo, o.BodyKey); err != nil {
		return err
	}
	if o.BodySize > LIMIT_BIG {
		return errors.New("body is too large")
	}
	enc := make([]byte, o.BodySize)
	_, err = io.ReadFull(f, enc)
	if err != nil {
		return err
	}
	plainkf, err := sm.DeBin(enc)
	defer sclear(plainkf)
	if err != nil {
		return err
	}

	// 5. mask key files
	a.KeyFiles = make(map[string][]byte)
	for name, data := range Opsec.DecodeCfg(plainkf) {
		a.KeyFiles[name], err = a.Mask.XOR(data)
		sclear(data)
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *Account) Store() error {
	// 1. make plain data, make worker
	priv, err := a.Mask.XOR(a.PriKey)
	defer sclear(priv)
	if err != nil {
		return err
	}
	smsg := strings.Join([]string{a.KeyType, Bencode.Encode64h(a.PubKey), Bencode.Encode64h(priv)}, "\n")
	tempKF := make(map[string][]byte)
	defer func() {
		for _, v := range tempKF {
			sclear(v)
		}
		tempKF = nil
	}()
	for name, data := range a.KeyFiles {
		tempKF[name], err = a.Mask.XOR(data)
		if err != nil {
			return err
		}
	}
	plainkf, err := Opsec.EncodeCfg(tempKF)
	defer sclear(plainkf)
	if err != nil {
		return err
	}
	sm := new(Bencrypt.SymMaster)
	defer func() { sclear(sm.Key) }()
	if err := sm.Init("gcm1", make([]byte, 44)); err != nil {
		return err
	}

	// 2. make header and bodykey
	o := new(Opsec.Opsec)
	defer func() {
		o.Smsg = ""
		sclear(o.BodyKey)
	}()
	o.Reset()
	o.Msg, o.Smsg, o.BodySize, o.BodyAlgo = a.Msg, smsg, sm.AfterSize(int64(len(plainkf))), sm.Algo
	var header []byte
	pw, _ := a.Mask.XOR(a.PW)
	defer sclear(pw)
	kf, _ := a.Mask.XOR(a.KF)
	defer sclear(kf)
	switch a.KeyType {
	case "rsa1", "rsa2":
		header, err = o.Encpw("pbk2", pw, kf)
	case "ecc1", "pqc1":
		header, err = o.Encpw("arg2", pw, kf)
	default:
		return errors.New("unsupported account type")
	}
	if err == nil {
		err = sm.Init(sm.Algo, o.BodyKey)
	}
	if err != nil {
		return err
	}

	// 3. make file, write header
	f, err := os.Create(a.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	var writed int64 = 0
	switch {
	case strings.HasSuffix(a.Path, ".webp"):
		tb := GetPrehead("zip", "webp", false)
		writed += int64(len(tb))
		_, err = f.Write(tb)
	case strings.HasSuffix(a.Path, ".png"):
		tb := GetPrehead("zip", "png", false)
		writed += int64(len(tb))
		_, err = f.Write(tb)
	}
	if err == nil {
		writed += int64(len(header)) + 6 // Opsec magic
		if len(header) >= 65535 {
			writed += 2
		}
		err = o.Write(f, header)
	}
	if err != nil {
		return err
	}

	// 4. encrypt body
	enc, err := sm.EnBin(plainkf)
	if err != nil {
		return err
	}
	writed += int64(len(enc))
	_, err = f.Write(enc)
	if err != nil {
		return err
	}

	// 5. pad tail if required
	if a.DoPad {
		padLen := Opsec.PadLen(writed)
		writed += padLen
		err = Opsec.PadFile(f, padLen)
	}
	return err
}

// ===== progress bar =====
type Progress struct {
	Window fyne.Window
	Bar    *widget.ProgressBar
	Result *error
}

func (p *Progress) Init(w fyne.Window, b *widget.ProgressBar, r *error) {
	p.Window = w
	p.Bar = b
	p.Result = r
}

func (p *Progress) OnStart() {
	fyne.Do(func() { p.Bar.SetValue(0.0) })
}

func (p *Progress) OnUpdate(c float64) {
	fyne.Do(func() { p.Bar.SetValue(max(0.0, min(1.0, c))) })
}

func (p *Progress) OnEnd() {
	fyne.Do(func() { p.Bar.SetValue(1.0) })
}

func (p *Progress) OnError(err error) {
	fyne.Do(func() { p.Bar.SetValue(0.0) })
	*p.Result = err
}

// ===== login =====
type LoginPage struct {
	Window  fyne.Window
	Config  *U1Config
	Account *Account

	Mask    *Bencrypt.Masker
	AccPath string
	AccKF   []byte // masked
	NewImg  string
	NewType string
}

func (l *LoginPage) Main(c *U1Config, a *Account) {
	l.Config = c
	l.Account = a
	l.Account.Mask = Bencrypt.GetMasker(-1)
	l.Mask = l.Account.Mask
	err := l.Config.Load()

	l.Window = MainApp.NewWindow("YAS desktop")
	l.Fill()
	l.Window.Resize(fyne.NewSize(720*BaseUI.FyneSize, 480*BaseUI.FyneSize))
	l.Window.CenterOnScreen()
	if err != nil {
		dialog.ShowError(fmt.Errorf("Config Load Fail: %s", err), l.Window)
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
	btn1a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { BaseUI.SelectKF(lbl1, &l.AccKF, l.Mask) })
	ent1 := widget.NewEntry()
	ent1.SetPlaceHolder("port/secret: 8001/...")
	btn1b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { BaseUI.ReceiveKF(l.Window, lbl1, ent1, &l.AccKF, l.Mask) })
	box1 := container.NewBorder(nil, nil, container.NewHBox(btn1a, btn1b), nil, ent1)

	// group2: password and login
	ent2 := widget.NewPasswordEntry()
	ent2.SetPlaceHolder("Password")
	btn2 := widget.NewButtonWithIcon("Login", theme.LoginIcon(), func() {
		if l.AccPath == "" {
			dialog.ShowError(fmt.Errorf("Account not selected"), l.Window)
			return
		}
		pw := Bencode.NormPW(ent2.Text)
		pwm, _ := l.Mask.XOR(pw)
		ent2.SetText("")
		sclear(pw)
		l.Account.PW, l.Account.KF, l.Account.DoPad = pwm, l.AccKF, l.Config.DoPad
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
	sel4d := widget.NewSelect([]string{"rsa1", "rsa2", "ecc1", "pqc1"}, func(s string) { l.NewType = s })
	sel4d.SetSelected("pqc1")
	l.NewType = "pqc1"

	// group5: make new account
	ent5 := widget.NewEntry()
	ent5.SetPlaceHolder("Account name")
	btn5 := widget.NewButtonWithIcon("Generate", theme.ContentAddIcon(), func() {
		// 1. sanitize name, check path
		name := TP1.CleanPath(ent5.Text)
		if name == "" {
			dialog.ShowError(fmt.Errorf("Account name is empty"), l.Window)
			return
		}
		l.Account.Path = filepath.Join(TP1.GetPath(), name+"."+l.NewImg)
		if _, err := os.Stat(l.Account.Path); err == nil {
			dialog.ShowError(fmt.Errorf("Account already exists"), l.Window)
			return
		}

		// 3. make account
		pw := Bencode.NormPW(ent2.Text)
		pwm, _ := l.Mask.XOR(pw)
		ent2.SetText("")
		sclear(pw)
		l.Account.KeyType, l.Account.PW, l.Account.KF, l.Account.Msg, l.Account.DoPad = l.NewType, pwm, l.AccKF, ent4b.Text, l.Config.DoPad
		if err := l.Account.NewKey(); err != nil {
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
		dialog.ShowInformation("Success", fmt.Sprintf("Account created successfully\nPW: %d bytes, KF: %d bytes", len(l.Account.PW), len(l.Account.KF)), l.Window)
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
	if l.Config.InitDir != "" {
		os.Chdir(l.Config.InitDir)
	}
	m := new(MainPage)
	m.Main(l.Config, l.Account)
	l.Window.Close()
}

// ===== main =====
type FuncPage interface {
	Main(w fyne.Window, co *fyne.Container, c *U1Config, a *Account)
	Fill()
}

type MainPage struct {
	Window  fyne.Window
	Config  *U1Config
	Account *Account

	Mode        int
	Pages       []FuncPage
	ContentArea *fyne.Container
	LblArea     *widget.Label

	LogoutTimer *time.Timer
	LogoutTime  time.Time
	LblTimer    *widget.Label
}

func (m *MainPage) Main(c *U1Config, a *Account) {
	m.Config = c
	m.Account = a
	m.Window = MainApp.NewWindow("YAS desktop")
	m.Fill()
	m.Window.Resize(fyne.NewSize(800*BaseUI.FyneSize, 480*BaseUI.FyneSize))
	m.Window.CenterOnScreen()

	m.Mode = -1
	m.Pages = make([]FuncPage, 10)
	m.Pages[0] = new(Page0)
	m.Pages[1] = new(Page1)
	m.Pages[2] = new(Page2)
	m.Pages[3] = new(Page3)
	m.Pages[4] = new(Page4)
	m.Pages[5] = new(Page5)
	m.Pages[6] = new(Page6)
	m.Pages[7] = new(Page7)
	m.Pages[8] = new(Page8)
	m.Pages[9] = new(Page9)
	for _, pg := range m.Pages {
		pg.Main(m.Window, m.ContentArea, m.Config, m.Account)
	}

	if m.Config.AutoExpire > 0 {
		m.ResetTimer()
		go m.UpdateTimerLoop()
	}
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
		widget.NewToolbarAction(theme.CheckButtonCheckedIcon(), func() { m.ModeClick(4) }),
		widget.NewToolbarAction(theme.BrokenImageIcon(), func() { m.ModeClick(5) }),
		widget.NewToolbarAction(theme.CheckButtonCheckedIcon(), func() { m.ModeClick(6) }),
		widget.NewToolbarAction(theme.BrokenImageIcon(), func() { m.ModeClick(7) }),
		widget.NewToolbarSpacer(),
		widget.NewToolbarAction(theme.MailComposeIcon(), func() { m.ModeClick(8) }),
		widget.NewToolbarAction(theme.AccountIcon(), func() { m.ModeClick(9) }),
	)

	// group1: center area
	m.ContentArea = container.NewStack(widget.NewLabelWithStyle(YAS_VERSION, fyne.TextAlignCenter, fyne.TextStyle{Bold: true}))

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
				sclear(m.Account.PW)
				sclear(m.Account.KF)
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
			sclear(m.Account.PW)
			sclear(m.Account.KF)
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
	lbltxt := []string{"Pack/Unpack", "Sign/Verify", "Send", "Receive", "Encrypt", "Decrypt", "Encrypt", "Decrypt", "Contacts", "Account"}
	defer m.ContentArea.Refresh()
	m.Mode = mode
	m.LblArea.SetText(fmt.Sprintf("%s | %s | %s", m.Account.Path, m.Account.KeyType, lbltxt[m.Mode]))
	m.Pages[m.Mode].Fill()
}

var MainApp fyne.App

func main() {
	defer func() {
		if r := recover(); r != nil {
			os.WriteFile("panic-log.txt", []byte(fmt.Sprintf("panic while main.main: %v", r)), 0644)
		}
	}()
	MainApp = app.New()
	MainApp.Settings().SetTheme(new(BaseUI.U1Theme))
	var p LoginPage
	p.Main(new(U1Config), new(Account))
}
