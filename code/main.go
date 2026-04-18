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
	"github.com/k-atusa/USAG-Lib/Star"
	"github.com/k-atusa/USAG-Lib/Szip"
)

// ===== config =====
type U1Config struct {
	AutoExpire int               `json:"expire"`
	Size       float32           `json:"size"`
	Limit      int64             `json:"limit"`
	OpsecPad   int64             `json:"opsecpad"`
	JoinInput  bool              `json:"joininput"`
	InitDir    string            `json:"initdir"`
	Accounts   []string          `json:"accounts"`
	IPs        []string          `json:"ips"`
	PublicKeys map[string][]byte `json:"pubkeys"`
}

func (c *U1Config) Load() error {
	data, err := os.ReadFile(filepath.Join(GetPath(), "config.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.AutoExpire = 20
			c.Size = 1.0
			c.Limit = 512 * 1048576
			c.OpsecPad = 0
			c.JoinInput = true
			c.InitDir = GetPath()
			c.Accounts = []string{}
			c.IPs = []string{"127.0.0.1"}
			c.PublicKeys = map[string][]byte{}
			return c.Store()
		}
		return err
	}
	err = json.Unmarshal(data, c)
	FyneSize = c.Size
	return err
}

func (c *U1Config) Store() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(GetPath(), "config.json"), data, 0644)
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
	PriKey   []byte
	KeyFiles map[string][]byte

	Path string
	PW   string
	KF   []byte
	Msg  string
}

func (a *Account) NewKey() error {
	am := new(Bencrypt.AsymMaster)
	err := am.Init(a.KeyType)
	if err == nil {
		a.PubKey, a.PriKey, err = am.Genkey()
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
	parts := strings.Split(o.Smsg, "\n")
	if len(parts) != 3 {
		return errors.New("invalid account format")
	}
	a.KeyType = parts[0]
	a.PubKey, err = Bencode.Decode64(parts[1], "") // pure base64
	if err != nil {
		return err
	}
	a.PriKey, err = Bencode.Decode64(parts[2], "") // pure base64
	if err != nil {
		return err
	}

	// 4. read body, decrypt body
	sm := new(Bencrypt.SymMaster)
	if err := sm.Init(o.BodyAlgo, o.BodyKey); err != nil {
		return err
	}
	if o.BodySize > 512*1048576 {
		return errors.New("body is too large")
	}
	enc := make([]byte, o.BodySize)
	_, err = io.ReadFull(f, enc)
	if err != nil {
		return err
	}
	plainkf, err := sm.DeBin(enc)
	if err != nil {
		return err
	}
	a.KeyFiles = Opsec.DecodeCfg(plainkf)
	return nil
}

func (a *Account) Store() error {
	// 1. make plain data, make worker
	var err error
	pub, err := Bencode.Encode64(a.PubKey, "", 0, 0) // pure base64
	if err != nil {
		return err
	}
	pri, err := Bencode.Encode64(a.PriKey, "", 0, 0) // pure base64
	if err != nil {
		return err
	}
	smsg := strings.Join([]string{a.KeyType, pub, pri}, "\n")
	plainkf, err := Opsec.EncodeCfg(a.KeyFiles)
	if err != nil {
		return err
	}
	sm := new(Bencrypt.SymMaster)
	if err := sm.Init("gcm1", make([]byte, 44)); err != nil {
		return err
	}

	// 2. make header and bodykey
	o := new(Opsec.Opsec)
	o.Reset()
	o.Msg, o.Smsg, o.BodySize, o.BodyAlgo = a.Msg, smsg, sm.AfterSize(int64(len(plainkf))), sm.Algo
	var header []byte
	switch a.KeyType {
	case "rsa1", "rsa2":
		header, err = o.Encpw("pbk2", []byte(a.PW), a.KF)
	case "ecc1", "pqc1":
		header, err = o.Encpw("arg2", []byte(a.PW), a.KF)
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
	switch {
	case strings.HasSuffix(a.Path, ".webp"):
		_, err = f.Write(GetPrehead("zip", "webp", false))
	case strings.HasSuffix(a.Path, ".png"):
		_, err = f.Write(GetPrehead("zip", "png", false))
	}
	if err == nil {
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
	_, err = f.Write(enc)
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
	App     fyne.App
	Window  fyne.Window
	Config  *U1Config
	Account *Account

	AccPath string
	AccKF   []byte
	NewImg  string
	NewType string
}

func (l *LoginPage) Main(c *U1Config, a *Account) {
	l.Config = c
	l.Account = a
	err := l.Config.Load()
	l.App = app.New()
	l.App.Settings().SetTheme(&U1Theme{})
	l.Window = l.App.NewWindow("YAS desktop")
	l.Fill()
	l.Window.Resize(fyne.NewSize(720*FyneSize, 480*FyneSize))
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
	btn1a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { SelectKF(lbl1, &l.AccKF) })
	ent1 := widget.NewEntry()
	ent1.SetPlaceHolder("port/secret: 8001/...")
	btn1b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { ReceiveKF(l.Window, lbl1, ent1, &l.AccKF) })
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
	sel4d := widget.NewSelect([]string{"rsa1", "rsa2", "ecc1", "pqc1"}, func(s string) { l.NewType = s })
	sel4d.SetSelected("pqc1")
	l.NewType = "pqc1"

	// group5: make new account
	ent5 := widget.NewEntry()
	ent5.SetPlaceHolder("Account name")
	btn5 := widget.NewButtonWithIcon("Generate", theme.ContentAddIcon(), func() {
		// 1. sanitize name, check path
		name := CleanPath(ent5.Text)
		if name == "" {
			dialog.ShowError(fmt.Errorf("Account name is empty"), l.Window)
			return
		}
		l.Account.Path = filepath.Join(GetPath(), name+"."+l.NewImg)
		if _, err := os.Stat(l.Account.Path); err == nil {
			dialog.ShowError(fmt.Errorf("Account already exists"), l.Window)
			return
		}

		// 3. make account
		l.Account.KeyType, l.Account.PW, l.Account.KF, l.Account.Msg = l.NewType, ent2.Text, l.AccKF, ent4b.Text
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
	if l.Config.InitDir != "" {
		os.Chdir(l.Config.InitDir)
	}
	m := new(MainPage)
	m.App = l.App
	m.Main(l.Config, l.Account)
	l.Window.Close()
}

// ===== main =====
type FuncPage interface {
	Main(w fyne.Window, co *fyne.Container, c *U1Config, a *Account)
	Fill()
}

type MainPage struct {
	App     fyne.App
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
	m.Window = m.App.NewWindow("YAS desktop")
	m.Fill()
	m.Window.Resize(fyne.NewSize(800*FyneSize, 480*FyneSize))
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
	lbltxt := []string{"Pack/Unpack", "Sign/Verify", "Send", "Receive", "Encrypt", "Decrypt", "Encrypt", "Decrypt", "Contacts", "Account"}
	defer m.ContentArea.Refresh()
	m.Mode = mode
	m.LblArea.SetText(fmt.Sprintf("%s | %s | %s", m.Account.Path, m.Account.KeyType, lbltxt[m.Mode]))
	m.Pages[m.Mode].Fill()
}

// ===== mode 0: zip/unzip =====
type Page0 struct {
	Window  fyne.Window
	Content *fyne.Container
	Config  *U1Config
	Account *Account

	Targets  []string
	list     *widget.List
	selected int

	isWorking bool
	status    *widget.Label
	PackType  string
}

func (p *Page0) Main(w fyne.Window, co *fyne.Container, c *U1Config, a *Account) {
	p.Window, p.Content, p.Config, p.Account = w, co, c, a
	p.Targets = make([]string, 0)
	p.isWorking = false
}

func (p *Page0) Fill() {
	// group0: file list
	p.list = widget.NewList(
		func() int { return len(p.Targets) },
		func() fyne.CanvasObject { return widget.NewLabel("template path") },
		func(id widget.ListItemID, obj fyne.CanvasObject) { obj.(*widget.Label).SetText(p.Targets[id]) },
	)
	p.selected = -1
	p.list.OnSelected = func(id widget.ListItemID) { p.selected = id }

	// group1: file management buttons
	btn1a := widget.NewButtonWithIcon("Add file", theme.FileIcon(), func() { ListAddFile(p.list, &p.Targets) })
	btn1b := widget.NewButtonWithIcon("Add folder", theme.FolderIcon(), func() { ListAddFolder(p.list, &p.Targets) })
	btn1c := widget.NewButtonWithIcon("Del path", theme.DeleteIcon(), func() { ListDelTgt(p.list, &p.Targets, p.selected); p.selected = -1 })
	btn1d := widget.NewButtonWithIcon("Reset all", theme.ContentClearIcon(), func() { ListDelTgt(p.list, &p.Targets, len(p.Targets)); p.selected = -1 })
	box1a := container.NewHBox(btn1a, btn1b, btn1c, btn1d)
	box1b := container.NewBorder(nil, box1a, nil, nil, p.list)

	// group2: right config
	p.status = widget.NewLabel("Idle")
	if p.isWorking {
		p.status.SetText("Working...")
	}
	ent2 := widget.NewEntry()
	ent2.SetPlaceHolder("output")
	sel2 := widget.NewSelect([]string{"zip1", "tar1"}, func(s string) { p.PackType = s })
	sel2.SetSelected("zip1")
	p.PackType = "zip1"

	// group3: right action
	btn3a := widget.NewButtonWithIcon("Pack", theme.ViewRestoreIcon(), func() {
		if p.isWorking || len(p.Targets) == 0 {
			return
		}
		go p.Pack(ent2.Text)
	})
	btn3a.Importance = widget.HighImportance
	btn3b := widget.NewButtonWithIcon("Unpack", theme.ViewFullScreenIcon(), func() {
		if p.isWorking || p.selected < 0 || p.selected >= len(p.Targets) {
			return
		}
		go p.Unpack(ent2.Text)
	})
	btn3b.Importance = widget.HighImportance
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
	output = CleanPath(output)
	if output == "" {
		output = "output"
	}
	switch p.PackType {
	case "zip1":
		err = Szip.Pack(tgts, output+".zip")
	case "tar1":
		err = Star.Pack(tgts, output+".tar")
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
	output = CleanPath(output)
	if output == "" {
		output = "output"
	}
	err = os.MkdirAll(output, 0644)
	if err != nil {
		return
	}
	switch p.PackType {
	case "zip1":
		err = Szip.Unpack(tgt, output)
	case "tar1":
		err = Star.Unpack(tgt, output)
	default:
		err = errors.New("invalid unpacking type")
	}
}

// ===== mode 1: sign/verify =====
type Page1 struct {
	Window  fyne.Window
	Content *fyne.Container
	Config  *U1Config
	Account *Account

	isWorking bool
	status    *widget.Label
	Target    string
	SignData  string
	signview  *widget.Entry
	KeyData   []byte
}

func (p *Page1) Main(w fyne.Window, co *fyne.Container, c *U1Config, a *Account) {
	p.Window, p.Content, p.Config, p.Account = w, co, c, a
	p.Target = ""
	p.SignData = ""
	p.KeyData = nil
	p.isWorking = false
}

func (p *Page1) Fill() {
	// group0: sign target
	lbl0 := widget.NewLabel("No file selected")
	if p.Target != "" {
		lbl0.SetText(p.Target)
	}
	btn0 := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() {
		path, err := ZenityFile("")
		if err == nil {
			p.Target = path
			lbl0.SetText(p.Target)
		} else {
			p.Target = ""
			lbl0.SetText("No file selected")
		}
	})
	box0 := container.NewHBox(widget.NewLabel("Sign target:"), btn0, lbl0)

	// group1: sign result
	p.signview = widget.NewMultiLineEntry()
	p.signview.SetPlaceHolder("Signature data")
	if p.SignData != "" {
		p.signview.SetText(p.SignData)
	}
	btn1a := widget.NewButtonWithIcon("Download", theme.DownloadIcon(), func() {
		if err := os.WriteFile("yas-sign.txt", []byte(p.SignData), 0644); err != nil {
			dialog.ShowError(err, p.Window)
		} else {
			dialog.ShowInformation("Success", "Signature data downloaded to yas-sign.txt", p.Window)
		}
	})
	btn1b := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() {
		path, err := ZenityFile("")
		if err == nil {
			var stat os.FileInfo
			stat, err = os.Stat(path)
			if err == nil && stat.Size() > p.Config.Limit {
				err = errors.New("Signature data is too large")
			}
		}
		var data []byte
		if err == nil {
			data, err = os.ReadFile(path)
		}
		if err != nil {
			dialog.ShowError(err, p.Window)
			return
		}
		p.SignData = string(data)
		p.signview.SetText(p.SignData)
		dialog.ShowInformation("Success", "Signature data loaded", p.Window)
	})
	btn1c := widget.NewButtonWithIcon("Fetch", theme.ContentPasteIcon(), func() {
		p.SignData = p.signview.Text
		dialog.ShowInformation("Success", "Signature data fetched from editor", p.Window)
	})
	box1 := container.NewVBox(container.NewHBox(widget.NewLabel("Signature data:"), btn1a, btn1b, btn1c), p.signview)

	// group2: key config
	p.KeyData = p.Account.PriKey
	lbl2 := widget.NewLabel(fmt.Sprintf("[%dB %s] default", len(p.KeyData), Opsec.Crc32(p.KeyData)))
	sel2 := widget.NewSelect(p.Config.GetPub(), func(s string) { ChooseKF(lbl2, &p.KeyData, s, p.Config.PublicKeys) })
	sel2.PlaceHolder = "Select from Contacts"
	btn2a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { SelectPub(lbl2, &p.KeyData, p.Account.PriKey) })
	ent2 := widget.NewEntry()
	ent2.SetPlaceHolder("port/secret: 8001/...")
	btn2b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { ReceivePub(p.Window, lbl2, ent2, &p.KeyData) })
	box2 := container.NewVBox(
		container.NewHBox(widget.NewLabel("Public/Private key (default=MyPriv):"), sel2),
		container.NewBorder(nil, nil, container.NewHBox(btn2a, btn2b), nil, ent2),
		lbl2,
	)

	// group3: functions
	btn3a := widget.NewButtonWithIcon("Sign", theme.DocumentIcon(), func() {
		if p.isWorking {
			return
		}
		go p.Sign()
	})
	btn3a.Importance = widget.HighImportance
	btn3b := widget.NewButtonWithIcon("Verify", theme.SearchIcon(), func() {
		if p.isWorking {
			return
		}
		go p.Verify()
	})
	btn3b.Importance = widget.HighImportance
	box3 := container.NewGridWithColumns(2, btn3a, btn3b)

	// group4: main layout
	p.status = widget.NewLabel("Idle")
	if p.isWorking {
		p.status.SetText("Working...")
	}
	box4 := container.NewVBox(
		container.NewBorder(nil, nil, widget.NewLabelWithStyle("Sign/Verify with "+p.Account.KeyType, fyne.TextAlignCenter, fyne.TextStyle{Bold: true}), p.status),
		box0, widget.NewSeparator(),
		box1, widget.NewSeparator(),
		box2, layout.NewSpacer(),
		box3)
	p.Content.Objects = []fyne.CanvasObject{box4}
}

func (p *Page1) Sign() {
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
				dialog.ShowInformation("Success", "Signed successfully", p.Window)
			} else {
				dialog.ShowError(err, p.Window)
			}
		})
	}()

	// 1. check parameters, read target file
	if p.Target == "" || p.KeyData == nil {
		err = errors.New("No target file or private key")
		return
	}
	info, err := os.Stat(p.Target)
	if err != nil {
		return
	}
	if info.Size() > p.Config.Limit {
		err = errors.New("Target file is too large")
		return
	}
	data, err := os.ReadFile(p.Target)
	if err != nil {
		return
	}

	// 2. sign
	var sign []byte
	am := new(Bencrypt.AsymMaster)
	err = am.Init(p.Account.KeyType)
	if err == nil {
		err = am.Loadkey(nil, p.KeyData)
	}
	if err == nil {
		sign, err = am.Sign(data)
	}
	if err != nil {
		return
	}

	// 3. update UI
	fyne.Do(func() {
		p.SignData, _ = Bencode.Encode64(sign, "#", 80, 10)
		p.signview.SetText(p.SignData)
	})
}

func (p *Page1) Verify() {
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
				dialog.ShowInformation("Success", "Signature verified successfully", p.Window)
			} else {
				dialog.ShowError(err, p.Window)
			}
		})
	}()

	// 1. check parameters, read target file
	if p.Target == "" || p.SignData == "" || p.KeyData == nil {
		err = errors.New("No target file, sign data, or public key")
		return
	}
	info, err := os.Stat(p.Target)
	if err != nil {
		return
	}
	if info.Size() > p.Config.Limit {
		err = errors.New("Target file is too large")
		return
	}
	data, err := os.ReadFile(p.Target)
	if err != nil {
		return
	}
	var sign []byte
	if strings.Contains(p.SignData, "#") {
		sign, err = Bencode.Decode64(p.SignData, "#")
	} else {
		sign, err = Bencode.Decode64(p.SignData, "")
	}
	if err != nil {
		return
	}

	// 2. verify
	am := new(Bencrypt.AsymMaster)
	err = am.Init(p.Account.KeyType)
	if err == nil {
		err = am.Loadkey(p.KeyData, nil)
	}
	if err == nil {
		if !am.Verify(data, sign) {
			err = errors.New("Signature verification failed")
		}
	}
}

// ===== mode2: send =====
type Page2 struct {
	Window  fyne.Window
	Content *fyne.Container
	Config  *U1Config
	Account *Account

	Targets  []string
	list     *widget.List
	selected int

	isWorking bool
	status    *widget.Label
	progbar   *widget.ProgressBar
	IPtgt     string
}

func (p *Page2) Main(w fyne.Window, co *fyne.Container, c *U1Config, a *Account) {
	p.Window, p.Content, p.Config, p.Account = w, co, c, a
	p.Targets = make([]string, 0)
	p.isWorking = false
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
	btn1a := widget.NewButtonWithIcon("Add file", theme.FileIcon(), func() { ListAddFile(p.list, &p.Targets) })
	btn1b := widget.NewButtonWithIcon("Add folder", theme.FolderIcon(), func() { ListAddFolder(p.list, &p.Targets) })
	btn1c := widget.NewButtonWithIcon("Del path", theme.DeleteIcon(), func() { ListDelTgt(p.list, &p.Targets, p.selected); p.selected = -1 })
	btn1d := widget.NewButtonWithIcon("Reset all", theme.ContentClearIcon(), func() { ListDelTgt(p.list, &p.Targets, len(p.Targets)); p.selected = -1 })
	box1a := container.NewHBox(btn1a, btn1b, btn1c, btn1d)
	box1b := container.NewBorder(nil, box1a, nil, nil, p.list)

	// group2: right config
	p.status = widget.NewLabel("Idle")
	if p.isWorking {
		p.status.SetText("Working...")
	}
	p.progbar = widget.NewProgressBar()
	sel2 := widget.NewSelect(p.Config.IPs, func(s string) { p.IPtgt = s })
	sel2.PlaceHolder = "Address list"
	p.IPtgt = ""
	ent2a := widget.NewEntry()
	ent2a.SetPlaceHolder("127.0.0.1:8002")
	ent2b := widget.NewPasswordEntry()
	ent2b.SetPlaceHolder("shared secret")
	ent2c := widget.NewMultiLineEntry()
	ent2c.SetPlaceHolder("secure message")

	// group3: right action
	btn3 := widget.NewButtonWithIcon("Send", theme.ConfirmIcon(), func() {
		if p.isWorking {
			return
		}
		if ent2a.Text != "" {
			p.IPtgt = ent2a.Text
		}
		addr := p.IPtgt
		if addr == "" {
			addr = "127.0.0.1"
		}
		if !strings.Contains(addr, ":") {
			addr += ":8002" // default port
		}
		go p.Send(addr, ent2b.Text, ent2c.Text)
	})
	btn3.Importance = widget.HighImportance
	box3 := container.NewVBox(
		widget.NewLabelWithStyle("Work menus", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		p.status, p.progbar, widget.NewSeparator(),
		widget.NewForm(
			widget.NewFormItem("Peer IP", sel2),
			widget.NewFormItem("Manual", ent2a),
			widget.NewFormItem("Context", ent2b),
			widget.NewFormItem("Message", ent2c),
		),
		layout.NewSpacer(),
		btn3,
	)

	// group4: main layout
	box4 := container.NewHSplit(box1b, box3)
	box4.Offset = 0.6
	p.Content.Objects = []fyne.CanvasObject{box4}
}

func (p *Page2) Send(addr string, secret string, smsg string) {
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
				dialog.ShowInformation("Success", fmt.Sprintf("Transfer: from %s to %s", Opsec.Crc32(fromPub), Opsec.Crc32(toPub)), p.Window)
			} else {
				dialog.ShowError(err, p.Window)
			}
		})
	}()
	tgts := make([]string, len(p.Targets))
	copy(tgts, p.Targets)
	pg := new(Progress)
	pg.Init(p.Window, p.progbar, &err)
	switch p.Account.KeyType {
	case "rsa1", "rsa2":
		fromPub, toPub, err = Send(tgts, smsg, addr, secret, "pbk2", p.Account.KeyType, pg)
	case "ecc1", "pqc1":
		fromPub, toPub, err = Send(tgts, smsg, addr, secret, "arg2", p.Account.KeyType, pg)
	default:
		err = errors.New("Unsupported key type")
	}
}

// ===== mode3: receive =====
type Page3 struct {
	Window  fyne.Window
	Content *fyne.Container
	Config  *U1Config
	Account *Account

	isWorking bool
	status    *widget.Label
	progbar   *widget.ProgressBar

	portTgt string
	msgview *widget.Entry
}

func (p *Page3) Main(w fyne.Window, co *fyne.Container, c *U1Config, a *Account) {
	p.Window, p.Content, p.Config, p.Account = w, co, c, a
	p.isWorking = false
}

func (p *Page3) Fill() {
	// group1: IP list
	ips := make([]string, 0)
	list0 := widget.NewList(
		func() int { return len(ips) },
		func() fyne.CanvasObject { return widget.NewLabel("template path") },
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			obj.(*widget.Label).SetText(ips[id])
		},
	)

	// group1: right config
	p.status = widget.NewLabel("Idle")
	if p.isWorking {
		p.status.SetText("Working...")
	}
	p.progbar = widget.NewProgressBar()
	sel1 := widget.NewSelect(p.Config.IPs, func(s string) { p.portTgt = s })
	sel1.PlaceHolder = "Address list"
	p.portTgt = ""
	ent1a := widget.NewEntry()
	ent1a.SetPlaceHolder("8002")
	ent1b := widget.NewPasswordEntry()
	ent1b.SetPlaceHolder("shared secret")
	p.msgview = widget.NewMultiLineEntry()
	p.msgview.SetPlaceHolder("secure message")

	// group2: right action
	btn2 := widget.NewButtonWithIcon("Receive", theme.ConfirmIcon(), func() {
		if p.isWorking {
			return
		}
		if ent1a.Text != "" {
			p.portTgt = ent1a.Text
		}
		port := p.portTgt
		if port == "" {
			port = "8002"
		}
		t, e := GetIPs(true)
		if e != nil {
			dialog.ShowError(e, p.Window)
			return
		}
		for i, r := range t {
			t[i] = r + ":" + port
		}
		ips = t
		list0.Refresh()
		go p.Recv(port, ent1b.Text)
	})
	btn2.Importance = widget.HighImportance
	box2 := container.NewVBox(
		widget.NewLabelWithStyle("Work menus", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		p.status, p.progbar, widget.NewSeparator(),
		widget.NewForm(
			widget.NewFormItem("Peer port", sel1),
			widget.NewFormItem("Manual", ent1a),
			widget.NewFormItem("Context", ent1b),
			widget.NewFormItem("Message", p.msgview),
		),
		layout.NewSpacer(),
		btn2,
	)

	// group3: main layout
	box3 := container.NewHSplit(list0, box2)
	box3.Offset = 0.4
	p.Content.Objects = []fyne.CanvasObject{box3}
}

func (p *Page3) Recv(port string, secret string) {
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
				dialog.ShowInformation("Success", fmt.Sprintf("Transfer: from %s to %s", Opsec.Crc32(fromPub), Opsec.Crc32(toPub)), p.Window)
			} else {
				dialog.ShowError(err, p.Window)
			}
		})
	}()
	smsg := ""
	pg := new(Progress)
	pg.Init(p.Window, p.progbar, &err)
	fromPub, toPub, smsg, err = Receive("./", port, secret, pg)
	fyne.Do(func() { p.msgview.SetText(smsg) })
}

// ===== mode4: encrypt pw =====
type Page4 struct {
	Window  fyne.Window
	Content *fyne.Container
	Config  *U1Config
	Account *Account

	textResult *widget.Entry
	Targets    []string
	list       *widget.List
	selected   int

	isWorking bool
	status    *widget.Label
	progbar   *widget.ProgressBar

	imgType  string
	packType string
	encType  string
	kf       []byte
}

func (p *Page4) Main(w fyne.Window, co *fyne.Container, c *U1Config, a *Account) {
	p.Window, p.Content, p.Config, p.Account = w, co, c, a
	p.Targets = make([]string, 0)
	p.isWorking = false
}

func (p *Page4) Fill() {
	// group0: smsg input, msg output
	ent0 := widget.NewMultiLineEntry()
	ent0.SetPlaceHolder("Secure message\n(Input)")
	p.textResult = widget.NewMultiLineEntry()
	p.textResult.SetPlaceHolder("Msg-mode result\n(Output)")
	btn0a := widget.NewButtonWithIcon("Fetch Input", theme.UploadIcon(), func() {
		path, err := ZenityFile("Load Text File")
		if err != nil {
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		ent0.SetText(string(data))
	})
	btn0b := widget.NewButtonWithIcon("Save Output", theme.DownloadIcon(), func() { os.WriteFile("yas-msg.txt", []byte(p.textResult.Text), 0644) })
	box0 := container.NewVBox(container.NewGridWithColumns(2, ent0, p.textResult), container.NewGridWithColumns(2, btn0a, btn0b))

	// group1: file management
	p.list = widget.NewList(
		func() int { return len(p.Targets) },
		func() fyne.CanvasObject { return widget.NewLabel("template path") },
		func(id widget.ListItemID, obj fyne.CanvasObject) { obj.(*widget.Label).SetText(p.Targets[id]) },
	)
	p.selected = -1
	p.list.OnSelected = func(id widget.ListItemID) { p.selected = id }
	btn1a := widget.NewButtonWithIcon("Add file", theme.FileIcon(), func() { ListAddFile(p.list, &p.Targets) })
	btn1b := widget.NewButtonWithIcon("Add dir", theme.FolderIcon(), func() { ListAddFolder(p.list, &p.Targets) })
	btn1c := widget.NewButtonWithIcon("Del path", theme.DeleteIcon(), func() { ListDelTgt(p.list, &p.Targets, p.selected); p.selected = -1 })
	btn1d := widget.NewButtonWithIcon("Del all", theme.ContentClearIcon(), func() { ListDelTgt(p.list, &p.Targets, len(p.Targets)); p.selected = -1 })
	box1 := container.NewBorder(box0, container.NewHBox(btn1a, btn1b, btn1c, btn1d), nil, nil, p.list)

	// group2: status view
	p.status = widget.NewLabel("Idle")
	if p.isWorking {
		p.status.SetText("Working...")
	}
	p.progbar = widget.NewProgressBar()
	txt := "Encrypt with password"
	switch p.Account.KeyType {
	case "rsa1", "rsa2":
		txt += " | pbk2"
	case "ecc1", "pqc1":
		txt += " | arg2"
	}
	box2 := container.NewVBox(widget.NewLabelWithStyle(txt, fyne.TextAlignCenter, fyne.TextStyle{Bold: true}), p.status, p.progbar)

	// group3: option selection
	sel3a := widget.NewSelect([]string{"webp", "png", "bin"}, func(s string) { p.imgType = s })
	sel3a.SetSelected("webp")
	sel3b := widget.NewSelect([]string{"tar1", "zip1"}, func(s string) { p.packType = s })
	sel3b.SetSelected("tar1")
	sel3c := widget.NewSelect([]string{"gcmx1", "gcm1"}, func(s string) { p.encType = s })
	sel3c.SetSelected("gcmx1")
	box3 := container.NewVBox(
		container.NewBorder(nil, nil, widget.NewLabel("Image type"), sel3a),
		container.NewBorder(nil, nil, widget.NewLabel("Pack type"), sel3b),
		container.NewBorder(nil, nil, widget.NewLabel("Encrypt type"), sel3c),
	)

	// group4: keyfile selection
	p.kf = nil
	lbl4 := widget.NewLabel("[0B 00000000] keyfile not selected")
	sel4 := widget.NewSelect(p.Account.GetList(), func(s string) { ChooseKF(lbl4, &p.kf, s, p.Account.KeyFiles) })
	sel4.PlaceHolder = "Select from Account"
	btn4a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { SelectKF(lbl4, &p.kf) })
	ent4 := widget.NewEntry()
	ent4.SetPlaceHolder("port/secret: 8001/...")
	btn4b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { ReceiveKF(p.Window, lbl4, ent4, &p.kf) })
	box4 := container.NewVBox(
		container.NewHBox(widget.NewLabel("KeyFile (default=Null):"), sel4),
		container.NewBorder(nil, nil, container.NewHBox(btn4a, btn4b), nil, ent4),
		lbl4,
	)

	// group5: pw, msg
	ent5a := widget.NewPasswordEntry()
	ent5a.SetPlaceHolder("Password")
	ent5b := widget.NewEntry()
	ent5b.SetPlaceHolder("Public message")
	box5 := container.NewVBox(ent5a, ent5b)

	// group6: output, function
	ent6 := widget.NewEntry()
	ent6.SetPlaceHolder("Output name")
	btn6a := widget.NewButtonWithIcon("Encrypt", theme.ViewRestoreIcon(), func() {
		if p.isWorking {
			return
		}

		// PwCplx
		pwc := new(PwCplx)
		switch p.Account.KeyType {
		case "rsa1", "rsa2":
			pwc.AlgoType = "pbk2"
		case "ecc1", "pqc1":
			pwc.AlgoType = "arg2"
		}
		pwc.PW = ent5a.Text
		pwc.KF = make([]byte, len(p.kf))
		copy(pwc.KF, p.kf)

		// EncCplx
		ec := new(EncCplx)
		ec.ImgType = p.imgType
		ec.PackType = p.packType
		ec.EncType = p.encType
		ec.Msg = ent5b.Text
		ec.Smsg = ent0.Text

		dst := CleanPath(ent6.Text)
		if dst == "" {
			dst = "output"
		}
		var dsts []string
		if p.Config.JoinInput {
			dsts = append(dsts, dst)
		} else {
			for _, tgt := range p.Targets {
				dsts = append(dsts, filepath.Base(tgt))
			}
		}
		for i := range dsts {
			dsts[i] += "." + ec.ImgType
		}
		go p.Encrypt(dsts, pwc, ec)
	})
	btn6a.Importance = widget.HighImportance
	box6 := container.NewBorder(nil, nil, nil, btn6a, ent6)

	// group7: main layout
	box7a := container.NewVBox(
		box2, widget.NewSeparator(),
		box3, widget.NewSeparator(),
		box4, widget.NewSeparator(),
		box5, widget.NewSeparator(),
		box6,
	)
	box7b := container.NewHSplit(box1, container.NewScroll(box7a))
	box7b.Offset = 0.4
	p.Content.Objects = []fyne.CanvasObject{box7b}
}

func (p *Page4) Encrypt(dsts []string, pwc *PwCplx, ec *EncCplx) {
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
				dialog.ShowInformation("Success", "Encrypted successfully", p.Window)
			} else {
				dialog.ShowError(err, p.Window)
			}
		})
	}()
	tgts := make([]string, len(p.Targets))
	copy(tgts, p.Targets)
	pg := new(Progress)
	pg.Init(p.Window, p.progbar, &err)
	if len(tgts) == 0 {
		var res []byte
		res, err = EncMsg(pwc, nil, ec, pg)
		var txtRes string
		if err == nil {
			txtRes, err = Bencode.Encode64(res, "#", 0, 0)
		}
		fyne.Do(func() { p.textResult.SetText(txtRes) })
	} else if p.Config.JoinInput { // join input files
		err = EncFiles(tgts, dsts[0], pwc, nil, ec, pg)
	} else { // separate files
		for i, tgt := range tgts {
			err = EncFiles([]string{tgt}, dsts[i], pwc, nil, ec, pg)
			if err != nil {
				break
			}
		}
	}
}

// ===== mode5: decrypt pw =====
type Page5 struct {
	Window  fyne.Window
	Content *fyne.Container
	Config  *U1Config
	Account *Account

	textResult *widget.Entry
	Targets    []string
	list       *widget.List
	selected   int

	isWorking bool
	status    *widget.Label
	progbar   *widget.ProgressBar

	msgView *widget.Entry
	kf      []byte
}

func (p *Page5) Main(w fyne.Window, co *fyne.Container, c *U1Config, a *Account) {
	p.Window, p.Content, p.Config, p.Account = w, co, c, a
	p.Targets = make([]string, 0)
	p.isWorking = false
}

func (p *Page5) Fill() {
	// group0: text input, smsg output
	ent0 := widget.NewMultiLineEntry()
	ent0.SetPlaceHolder("Text data\n(Input)")
	p.textResult = widget.NewMultiLineEntry()
	p.textResult.SetPlaceHolder("Secure message\n(Output)")
	btn0a := widget.NewButtonWithIcon("Fetch Input", theme.UploadIcon(), func() {
		path, err := ZenityFile("Load Text File")
		if err != nil {
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		ent0.SetText(string(data))
	})
	btn0b := widget.NewButtonWithIcon("Save Output", theme.DownloadIcon(), func() { os.WriteFile("yas-msg.txt", []byte(p.textResult.Text), 0644) })
	box0 := container.NewVBox(container.NewGridWithColumns(2, ent0, p.textResult), container.NewGridWithColumns(2, btn0a, btn0b))

	// group1: file management
	p.list = widget.NewList(
		func() int { return len(p.Targets) },
		func() fyne.CanvasObject { return widget.NewLabel("template path") },
		func(id widget.ListItemID, obj fyne.CanvasObject) { obj.(*widget.Label).SetText(p.Targets[id]) },
	)
	p.selected = -1
	p.list.OnSelected = func(id widget.ListItemID) {
		p.selected = id
		p.msgView.SetText("Msg: " + p.View())
	}
	btn1a := widget.NewButtonWithIcon("Add file", theme.FileIcon(), func() { ListAddFile(p.list, &p.Targets) })
	btn1b := widget.NewButtonWithIcon("Add dir", theme.FolderIcon(), func() { ListAddFolder(p.list, &p.Targets) })
	btn1c := widget.NewButtonWithIcon("Del path", theme.DeleteIcon(), func() { ListDelTgt(p.list, &p.Targets, p.selected); p.selected = -1 })
	btn1d := widget.NewButtonWithIcon("Del all", theme.ContentClearIcon(), func() { ListDelTgt(p.list, &p.Targets, len(p.Targets)); p.selected = -1 })
	box1 := container.NewBorder(box0, container.NewHBox(btn1a, btn1b, btn1c, btn1d), nil, nil, p.list)

	// group2: status view
	p.status = widget.NewLabel("Idle")
	if p.isWorking {
		p.status.SetText("Working...")
	}
	p.progbar = widget.NewProgressBar()
	box2 := container.NewVBox(widget.NewLabelWithStyle("Decrypt with password", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}), p.status, p.progbar)

	// group4: keyfile selection
	p.kf = nil
	lbl4 := widget.NewLabel("[0B 00000000] keyfile not selected")
	sel4 := widget.NewSelect(p.Account.GetList(), func(s string) { ChooseKF(lbl4, &p.kf, s, p.Account.KeyFiles) })
	sel4.PlaceHolder = "Select from Account"
	btn4a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { SelectKF(lbl4, &p.kf) })
	ent4 := widget.NewEntry()
	ent4.SetPlaceHolder("port/secret: 8001/...")
	btn4b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { ReceiveKF(p.Window, lbl4, ent4, &p.kf) })
	box4 := container.NewVBox(
		container.NewHBox(widget.NewLabel("KeyFile (default=Null):"), sel4),
		container.NewBorder(nil, nil, container.NewHBox(btn4a, btn4b), nil, ent4),
		lbl4,
	)

	// group5: pw, msg
	ent5 := widget.NewPasswordEntry()
	ent5.SetPlaceHolder("Password")
	p.msgView = widget.NewEntry()
	p.msgView.SetPlaceHolder("Public message")
	box5 := container.NewVBox(ent5, p.msgView)

	// group6: output, function
	ent6 := widget.NewEntry()
	ent6.SetPlaceHolder("Output name")
	btn6a := widget.NewButtonWithIcon("Decrypt", theme.ViewFullScreenIcon(), func() {
		if p.isWorking {
			return
		}

		// PwCplx
		pwc := new(PwCplx)
		pwc.PW = ent5.Text
		pwc.KF = make([]byte, len(p.kf))
		copy(pwc.KF, p.kf)

		dst := CleanPath(ent6.Text)
		if dst == "" {
			dst = "./"
		}
		os.MkdirAll(dst, 0644)
		go p.Decrypt(ent0.Text, dst, pwc)
	})
	btn6a.Importance = widget.HighImportance
	box6 := container.NewBorder(nil, nil, nil, btn6a, ent6)

	// group7: main layout
	box7a := container.NewVBox(
		box2, widget.NewSeparator(),
		box4, widget.NewSeparator(),
		box5, widget.NewSeparator(),
		box6,
	)
	box7b := container.NewHSplit(box1, container.NewScroll(box7a))
	box7b.Offset = 0.4
	p.Content.Objects = []fyne.CanvasObject{box7b}
}

func (p *Page5) View() string {
	f, err := os.Open(p.Targets[p.selected])
	if err != nil {
		return ""
	}
	defer f.Close()
	ops := new(Opsec.Opsec)
	ops.Reset()
	header, err := ops.Read(f, 0)
	if err != nil {
		return ""
	}
	ops.View(header)
	return ops.Msg
}

func (p *Page5) Decrypt(data string, dst string, pwc *PwCplx) {
	var err error
	msg, smsg := "", ""
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
				dialog.ShowInformation("Success", "Decrypted successfully", p.Window)
			} else {
				dialog.ShowError(err, p.Window)
			}
		})
	}()
	pg := new(Progress)
	pg.Init(p.Window, p.progbar, &err)
	if data != "" { // msg-only mode
		var text []byte
		if strings.Contains(data, "#") {
			text, err = Bencode.Decode64(data, "#")
		} else {
			text, err = Bencode.Decode64(data, "")
		}
		if err != nil {
			return
		}
		msg, smsg, err = DecMsg(text, pwc, nil, pg)
		fyne.Do(func() { p.msgView.SetText(msg); p.textResult.SetText(smsg) })
		return
	}
	if p.selected < 0 || p.selected >= len(p.Targets) {
		err = fmt.Errorf("invalid selection index")
		return
	}
	msg, smsg, err = DecFile(p.Targets[p.selected], dst, pwc, nil, pg)
	fyne.Do(func() { p.msgView.SetText(msg); p.textResult.SetText(smsg) })
	return
}

// ===== mode6: encrypt pub =====
type Page6 struct {
	Window  fyne.Window
	Content *fyne.Container
	Config  *U1Config
	Account *Account

	textResult *widget.Entry
	Targets    []string
	list       *widget.List
	selected   int

	isWorking bool
	status    *widget.Label
	progbar   *widget.ProgressBar

	imgType  string
	packType string
	encType  string
	pub      []byte
	pri      []byte
}

func (p *Page6) Main(w fyne.Window, co *fyne.Container, c *U1Config, a *Account) {
	p.Window, p.Content, p.Config, p.Account = w, co, c, a
	p.Targets = make([]string, 0)
	p.isWorking = false
}

func (p *Page6) Fill() {
	// group0: smsg input, msg output
	ent0 := widget.NewMultiLineEntry()
	ent0.SetPlaceHolder("Secure message\n(Input)")
	p.textResult = widget.NewMultiLineEntry()
	p.textResult.SetPlaceHolder("Msg-mode result\n(Output)")
	btn0a := widget.NewButtonWithIcon("Fetch Input", theme.UploadIcon(), func() {
		path, err := ZenityFile("Load Text File")
		if err != nil {
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		ent0.SetText(string(data))
	})
	btn0b := widget.NewButtonWithIcon("Save Output", theme.DownloadIcon(), func() { os.WriteFile("yas-msg.txt", []byte(p.textResult.Text), 0644) })
	box0 := container.NewVBox(container.NewGridWithColumns(2, ent0, p.textResult), container.NewGridWithColumns(2, btn0a, btn0b))

	// group1: file management
	p.list = widget.NewList(
		func() int { return len(p.Targets) },
		func() fyne.CanvasObject { return widget.NewLabel("template path") },
		func(id widget.ListItemID, obj fyne.CanvasObject) { obj.(*widget.Label).SetText(p.Targets[id]) },
	)
	p.selected = -1
	p.list.OnSelected = func(id widget.ListItemID) { p.selected = id }
	btn1a := widget.NewButtonWithIcon("Add file", theme.FileIcon(), func() { ListAddFile(p.list, &p.Targets) })
	btn1b := widget.NewButtonWithIcon("Add dir", theme.FolderIcon(), func() { ListAddFolder(p.list, &p.Targets) })
	btn1c := widget.NewButtonWithIcon("Del path", theme.DeleteIcon(), func() { ListDelTgt(p.list, &p.Targets, p.selected); p.selected = -1 })
	btn1d := widget.NewButtonWithIcon("Del all", theme.ContentClearIcon(), func() { ListDelTgt(p.list, &p.Targets, len(p.Targets)); p.selected = -1 })
	box1 := container.NewBorder(box0, container.NewHBox(btn1a, btn1b, btn1c, btn1d), nil, nil, p.list)

	// group2: status view
	p.status = widget.NewLabel("Idle")
	if p.isWorking {
		p.status.SetText("Working...")
	}
	p.progbar = widget.NewProgressBar()
	box2 := container.NewVBox(widget.NewLabelWithStyle("Encrypt with public key | "+p.Account.KeyType, fyne.TextAlignCenter, fyne.TextStyle{Bold: true}), p.status, p.progbar)

	// group3: option selection
	sel3a := widget.NewSelect([]string{"webp", "png", "bin"}, func(s string) { p.imgType = s })
	sel3a.SetSelected("webp")
	sel3b := widget.NewSelect([]string{"tar1", "zip1"}, func(s string) { p.packType = s })
	sel3b.SetSelected("tar1")
	sel3c := widget.NewSelect([]string{"gcmx1", "gcm1"}, func(s string) { p.encType = s })
	sel3c.SetSelected("gcmx1")
	box3 := container.NewVBox(
		container.NewBorder(nil, nil, widget.NewLabel("Image type"), sel3a),
		container.NewBorder(nil, nil, widget.NewLabel("Pack type"), sel3b),
		container.NewBorder(nil, nil, widget.NewLabel("Encrypt type"), sel3c),
	)

	// group4: public key
	p.pub = nil
	lbl4 := widget.NewLabel("[0B 00000000] default")
	sel4 := widget.NewSelect(p.Config.GetPub(), func(s string) { ChooseKF(lbl4, &p.pub, s, p.Config.PublicKeys) })
	sel4.PlaceHolder = "Select from Contacts"
	btn4a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { SelectPub(lbl4, &p.pub, nil) })
	ent4 := widget.NewEntry()
	ent4.SetPlaceHolder("port/secret: 8001/...")
	btn4b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { ReceivePub(p.Window, lbl4, ent4, &p.pub) })
	box4 := container.NewVBox(
		container.NewHBox(widget.NewLabel("Peer Public (default=Null):"), sel4),
		container.NewBorder(nil, nil, container.NewHBox(btn4a, btn4b), nil, ent4),
		lbl4,
	)

	// group5: private key
	p.pri = p.Account.PriKey
	lbl5 := widget.NewLabel(fmt.Sprintf("[%dB %s] default", len(p.pri), Opsec.Crc32(p.pri)))
	btn5a := widget.NewButtonWithIcon("Clear", theme.ContentRemoveIcon(), func() { p.pri = nil; lbl5.SetText("[0B 00000000] null") })
	btn5b := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { SelectPub(lbl5, &p.pri, p.Account.PriKey) })
	ent5 := widget.NewEntry()
	ent5.SetPlaceHolder("port/secret: 8001/...")
	btn5c := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { ReceivePub(p.Window, lbl5, ent5, &p.pri) })
	box5 := container.NewVBox(
		container.NewHBox(widget.NewLabel("My Private (default=MyPriv):"), btn5a),
		container.NewBorder(nil, nil, container.NewHBox(btn5b, btn5c), nil, ent5),
		lbl5,
	)

	// group6: msg, output, function
	ent6a := widget.NewEntry()
	ent6a.SetPlaceHolder("Public message")
	ent6b := widget.NewEntry()
	ent6b.SetPlaceHolder("Output name")
	btn6a := widget.NewButtonWithIcon("Encrypt", theme.ViewRestoreIcon(), func() {
		if p.isWorking {
			return
		}

		// PubCplx
		pubc := new(PubCplx)
		pubc.AlgoType, pubc.PeerPub, pubc.MyPri = p.Account.KeyType, p.pub, p.pri

		// EncCplx
		ec := new(EncCplx)
		ec.ImgType = p.imgType
		ec.PackType = p.packType
		ec.EncType = p.encType
		ec.Msg = ent6a.Text
		ec.Smsg = ent0.Text

		dst := CleanPath(ent6b.Text)
		if dst == "" {
			dst = "output"
		}
		var dsts []string
		if p.Config.JoinInput {
			dsts = append(dsts, dst)
		} else {
			for _, tgt := range p.Targets {
				dsts = append(dsts, filepath.Base(tgt))
			}
		}
		for i := range dsts {
			dsts[i] += "." + ec.ImgType
		}
		go p.Encrypt(dsts, pubc, ec)
	})
	btn6a.Importance = widget.HighImportance
	box6 := container.NewBorder(ent6a, nil, nil, btn6a, ent6b)

	// group7: main layout
	box7a := container.NewVBox(
		box2, widget.NewSeparator(),
		box3, widget.NewSeparator(),
		box4, widget.NewSeparator(),
		box5, widget.NewSeparator(),
		box6,
	)
	box7b := container.NewHSplit(box1, container.NewScroll(box7a))
	box7b.Offset = 0.4
	p.Content.Objects = []fyne.CanvasObject{box7b}
}

func (p *Page6) Encrypt(dsts []string, pubc *PubCplx, ec *EncCplx) {
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
				dialog.ShowInformation("Success", "Encrypted successfully", p.Window)
			} else {
				dialog.ShowError(err, p.Window)
			}
		})
	}()
	tgts := make([]string, len(p.Targets))
	copy(tgts, p.Targets)
	pg := new(Progress)
	pg.Init(p.Window, p.progbar, &err)
	if len(tgts) == 0 {
		var res []byte
		res, err = EncMsg(nil, pubc, ec, pg)
		var txtRes string
		if err == nil {
			txtRes, err = Bencode.Encode64(res, "#", 0, 0)
		}
		fyne.Do(func() { p.textResult.SetText(txtRes) })
	} else if p.Config.JoinInput { // join input files
		err = EncFiles(tgts, dsts[0], nil, pubc, ec, pg)
	} else { // separate files
		for i, tgt := range tgts {
			err = EncFiles([]string{tgt}, dsts[i], nil, pubc, ec, pg)
			if err != nil {
				break
			}
		}
	}
}

// ===== mode7: decrypt pub =====
type Page7 struct {
	Window  fyne.Window
	Content *fyne.Container
	Config  *U1Config
	Account *Account

	textResult *widget.Entry
	Targets    []string
	list       *widget.List
	selected   int

	isWorking bool
	status    *widget.Label
	progbar   *widget.ProgressBar

	msgView *widget.Entry
	peerPub []byte
	myPub   []byte
	pri     []byte
}

func (p *Page7) Main(w fyne.Window, co *fyne.Container, c *U1Config, a *Account) {
	p.Window, p.Content, p.Config, p.Account = w, co, c, a
	p.Targets = make([]string, 0)
	p.isWorking = false
}

func (p *Page7) Fill() {
	// group0: text input, smsg output
	ent0 := widget.NewMultiLineEntry()
	ent0.SetPlaceHolder("Text data\n(Input)")
	p.textResult = widget.NewMultiLineEntry()
	p.textResult.SetPlaceHolder("Secure message\n(Output)")
	btn0a := widget.NewButtonWithIcon("Fetch Input", theme.UploadIcon(), func() {
		path, err := ZenityFile("Load Text File")
		if err != nil {
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		ent0.SetText(string(data))
	})
	btn0b := widget.NewButtonWithIcon("Save Output", theme.DownloadIcon(), func() { os.WriteFile("yas-msg.txt", []byte(p.textResult.Text), 0644) })
	box0 := container.NewVBox(container.NewGridWithColumns(2, ent0, p.textResult), container.NewGridWithColumns(2, btn0a, btn0b))

	// group1: file management
	p.list = widget.NewList(
		func() int { return len(p.Targets) },
		func() fyne.CanvasObject { return widget.NewLabel("template path") },
		func(id widget.ListItemID, obj fyne.CanvasObject) { obj.(*widget.Label).SetText(p.Targets[id]) },
	)
	p.selected = -1
	p.list.OnSelected = func(id widget.ListItemID) {
		p.selected = id
		p.msgView.SetText("Msg: " + p.View())
	}
	btn1a := widget.NewButtonWithIcon("Add file", theme.FileIcon(), func() { ListAddFile(p.list, &p.Targets) })
	btn1b := widget.NewButtonWithIcon("Add dir", theme.FolderIcon(), func() { ListAddFolder(p.list, &p.Targets) })
	btn1c := widget.NewButtonWithIcon("Del path", theme.DeleteIcon(), func() { ListDelTgt(p.list, &p.Targets, p.selected); p.selected = -1 })
	btn1d := widget.NewButtonWithIcon("Del all", theme.ContentClearIcon(), func() { ListDelTgt(p.list, &p.Targets, len(p.Targets)); p.selected = -1 })
	box1 := container.NewBorder(box0, container.NewHBox(btn1a, btn1b, btn1c, btn1d), nil, nil, p.list)

	// group2: status view
	p.status = widget.NewLabel("Idle")
	if p.isWorking {
		p.status.SetText("Working...")
	}
	p.progbar = widget.NewProgressBar()
	box2 := container.NewVBox(widget.NewLabelWithStyle("Decrypt with public key", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}), p.status, p.progbar)

	// group3: peer public key
	p.peerPub = nil
	lbl3 := widget.NewLabel("[0B 00000000] default")
	sel3 := widget.NewSelect(p.Config.GetPub(), func(s string) { ChooseKF(lbl3, &p.peerPub, s, p.Config.PublicKeys) })
	sel3.PlaceHolder = "Select from Contacts"
	btn3a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { SelectPub(lbl3, &p.peerPub, nil) })
	ent3 := widget.NewEntry()
	ent3.SetPlaceHolder("port/secret: 8001/...")
	btn3b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { ReceivePub(p.Window, lbl3, ent3, &p.peerPub) })
	box3 := container.NewVBox(
		container.NewHBox(widget.NewLabel("Peer Public (default=Null):"), sel3),
		container.NewBorder(nil, nil, container.NewHBox(btn3a, btn3b), nil, ent3),
		lbl3,
	)

	// group4: my public key
	p.myPub = nil
	lbl4 := widget.NewLabel("[0B 00000000] default")
	sel4 := widget.NewSelect(p.Config.GetPub(), func(s string) { ChooseKF(lbl4, &p.myPub, s, p.Config.PublicKeys) })
	sel4.PlaceHolder = "Select from Contacts"
	btn4a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { SelectPub(lbl4, &p.myPub, nil) })
	ent4 := widget.NewEntry()
	ent4.SetPlaceHolder("port/secret: 8001/...")
	btn4b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { ReceivePub(p.Window, lbl4, ent4, &p.myPub) })
	box4 := container.NewVBox(
		container.NewHBox(widget.NewLabel("My Public (default=Null):"), sel4),
		container.NewBorder(nil, nil, container.NewHBox(btn4a, btn4b), nil, ent4),
		lbl4,
	)

	// group5: my private key
	p.pri = p.Account.PriKey
	lbl5 := widget.NewLabel(fmt.Sprintf("[%dB %s] default", len(p.pri), Opsec.Crc32(p.pri)))
	btn5a := widget.NewButtonWithIcon("Clear", theme.ContentRemoveIcon(), func() { p.pri = nil; lbl5.SetText("[0B 00000000] null") })
	btn5b := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { SelectPub(lbl5, &p.pri, p.Account.PriKey) })
	ent5 := widget.NewEntry()
	ent5.SetPlaceHolder("port/secret: 8001/...")
	btn5c := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { ReceivePub(p.Window, lbl5, ent5, &p.pri) })
	box5 := container.NewVBox(
		container.NewHBox(widget.NewLabel("My Private (default=MyPriv):"), btn5a),
		container.NewBorder(nil, nil, container.NewHBox(btn5b, btn5c), nil, ent5),
		lbl5,
	)

	// group6: msgview, output, function
	p.msgView = widget.NewEntry()
	p.msgView.SetPlaceHolder("Public message")
	ent6 := widget.NewEntry()
	ent6.SetPlaceHolder("Output name")
	btn6a := widget.NewButtonWithIcon("Decrypt", theme.ViewFullScreenIcon(), func() {
		if p.isWorking {
			return
		}

		// PubCplx
		pubc := new(PubCplx)
		pubc.AlgoType = p.Account.KeyType
		pubc.PeerPub = p.peerPub
		pubc.MyPub = p.myPub
		pubc.MyPri = p.pri

		dst := CleanPath(ent6.Text)
		if dst == "" {
			dst = "./"
		}
		os.MkdirAll(dst, 0644)
		go p.Decrypt(ent0.Text, dst, pubc)
	})
	btn6a.Importance = widget.HighImportance
	box6 := container.NewBorder(p.msgView, nil, nil, btn6a, ent6)

	// group7: main layout
	box7a := container.NewVBox(
		box2, widget.NewSeparator(),
		box3, widget.NewSeparator(),
		box4, widget.NewSeparator(),
		box5, widget.NewSeparator(),
		box6,
	)
	box7b := container.NewHSplit(box1, container.NewScroll(box7a))
	box7b.Offset = 0.4
	p.Content.Objects = []fyne.CanvasObject{box7b}
}

func (p *Page7) View() string {
	f, err := os.Open(p.Targets[p.selected])
	if err != nil {
		return ""
	}
	defer f.Close()
	ops := new(Opsec.Opsec)
	ops.Reset()
	header, err := ops.Read(f, 0)
	if err != nil {
		return ""
	}
	ops.View(header)
	return ops.Msg
}

func (p *Page7) Decrypt(data string, dst string, pubc *PubCplx) {
	var err error
	msg, smsg := "", ""
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
				dialog.ShowInformation("Success", "Decrypted successfully", p.Window)
			} else {
				dialog.ShowError(err, p.Window)
			}
		})
	}()
	pg := new(Progress)
	pg.Init(p.Window, p.progbar, &err)
	if data != "" { // msg-only mode
		var text []byte
		if strings.Contains(data, "#") {
			text, err = Bencode.Decode64(data, "#")
		} else {
			text, err = Bencode.Decode64(data, "")
		}
		if err != nil {
			return
		}
		msg, smsg, err = DecMsg(text, nil, pubc, pg)
		fyne.Do(func() { p.msgView.SetText(msg); p.textResult.SetText(smsg) })
		return
	}
	if p.selected < 0 || p.selected >= len(p.Targets) {
		err = fmt.Errorf("invalid selection index")
		return
	}
	msg, smsg, err = DecFile(p.Targets[p.selected], dst, nil, pubc, pg)
	fyne.Do(func() { p.msgView.SetText(msg); p.textResult.SetText(smsg) })
	return
}

// ===== mode8: contacts =====
type Page8 struct {
	Window  fyne.Window
	Content *fyne.Container
	Config  *U1Config
	Account *Account

	ipSelected  string
	pubSelected string
	pubType     string
	kf          []byte
	kfSelected  string
}

func (p *Page8) Main(w fyne.Window, co *fyne.Container, c *U1Config, a *Account) {
	p.Window, p.Content, p.Config, p.Account = w, co, c, a
}

func (p *Page8) Fill() {
	// group0: ip add/del
	ent0 := widget.NewEntry()
	ent0.SetPlaceHolder("New IP/Port")
	sel0 := widget.NewSelect(p.Config.IPs, func(s string) { p.ipSelected = s })
	sel0.PlaceHolder = "IP/Port list"
	p.ipSelected = ""
	btn0a := widget.NewButtonWithIcon("Add", theme.ContentAddIcon(), func() {
		if ent0.Text != "" && !slices.Contains(p.Config.IPs, ent0.Text) {
			p.Config.IPs = append(p.Config.IPs, ent0.Text)
			sel0.Options = p.Config.IPs
			sel0.Refresh()
			err := p.Config.Store()
			if err == nil {
				dialog.ShowInformation("Success", "IP/Port added", p.Window)
			} else {
				dialog.ShowError(err, p.Window)
			}
			ent0.SetText("")
		}
	})
	btn0a.Importance = widget.HighImportance
	btn0b := widget.NewButtonWithIcon("Del", theme.ContentRemoveIcon(), func() {
		dialog.ShowConfirm("Confirm", "Delete this IP/Port?", func(ok bool) {
			if ok && p.ipSelected != "" {
				p.Config.IPs = slices.DeleteFunc(p.Config.IPs, func(s string) bool { return s == p.ipSelected })
				sel0.Options = p.Config.IPs
				sel0.Refresh()
				p.ipSelected = ""
				err := p.Config.Store()
				if err == nil {
					dialog.ShowInformation("Success", "IP/Port deleted", p.Window)
				} else {
					dialog.ShowError(err, p.Window)
				}
			}
		}, p.Window)
	})
	btn0b.Importance = widget.DangerImportance
	box0 := container.NewVBox(
		widget.NewLabelWithStyle("Manage IP/Port (Config)", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil,
			container.NewGridWithRows(2, btn0a, btn0b),
			container.NewGridWithRows(2, ent0, sel0),
		),
	)

	// group1: pub add/del
	ent1a := widget.NewEntry()
	ent1a.SetPlaceHolder("New public key name")
	ent1b := widget.NewMultiLineEntry()
	ent1b.SetPlaceHolder("New public key data")
	pubs := p.Config.GetPub()
	sel1a := widget.NewSelect([]string{"rsa1", "rsa2", "ecc1", "pqc1"}, func(s string) { p.pubType = s })
	sel1a.SetSelected("pqc1")
	p.pubType = "pqc1"
	sel1b := widget.NewSelect(pubs, func(s string) { p.pubSelected = s })
	sel1b.PlaceHolder = "Public key list"
	p.pubSelected = ""
	btn1a := widget.NewButtonWithIcon("Add", theme.ContentAddIcon(), func() {
		if ent1a.Text != "" && ent1b.Text != "" {
			var newpub []byte
			var err error
			if strings.Contains(ent1b.Text, "#") {
				newpub, err = Bencode.Decode64(ent1b.Text, "#")
			} else {
				newpub, err = Bencode.Decode64(ent1b.Text, "")
			}
			if err != nil {
				dialog.ShowError(err, p.Window)
				return
			}
			err = p.Config.AddPub(ent1a.Text, p.pubType, newpub)
			pubs = p.Config.GetPub()
			sel1b.Options = pubs
			sel1b.Refresh()
			if err == nil {
				dialog.ShowInformation("Success", "Public Key added", p.Window)
			} else {
				dialog.ShowError(err, p.Window)
			}
			ent1a.SetText("")
			ent1b.SetText("")
		}
	})
	btn1a.Importance = widget.HighImportance
	btn1b := widget.NewButtonWithIcon("Del", theme.ContentRemoveIcon(), func() {
		dialog.ShowConfirm("Confirm", "Delete this public key?", func(ok bool) {
			if ok && p.pubSelected != "" {
				err := p.Config.DelPub(p.pubSelected)
				pubs = p.Config.GetPub()
				sel1b.Options = pubs
				sel1b.Refresh()
				if err == nil {
					dialog.ShowInformation("Success", "Public Key deleted", p.Window)
				} else {
					dialog.ShowError(err, p.Window)
				}
			}
		}, p.Window)
	})
	btn1b.Importance = widget.DangerImportance
	box1 := container.NewVBox(
		widget.NewLabelWithStyle("Manage public keys (Config)", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		ent1a, ent1b,
		container.NewBorder(nil, nil, nil,
			container.NewGridWithRows(2, btn1a, btn1b),
			container.NewGridWithRows(2, sel1a, sel1b),
		),
	)

	// group2: add keyfile
	lbl2 := widget.NewLabel("[0B 00000000] keyfile not selected")
	btn2a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { SelectKF(lbl2, &p.kf) })
	ent2a := widget.NewEntry()
	ent2a.SetPlaceHolder("port/secret: 8001/...")
	btn2b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { ReceiveKF(p.Window, lbl2, ent2a, &p.kf) })
	ent2b := widget.NewEntry()
	ent2b.SetPlaceHolder("New keyfile name")

	// group3: del keyfile
	kfs := p.Account.GetList()
	sel3 := widget.NewSelect(kfs, func(s string) { p.kfSelected = s })
	sel3.PlaceHolder = "Keyfile list"
	p.kfSelected = ""

	btn2c := widget.NewButtonWithIcon("Add", theme.ContentAddIcon(), func() {
		if p.kf != nil && ent2b.Text != "" {
			p.Account.KeyFiles[ent2b.Text] = p.kf
			err := p.Account.Store()
			kfs = p.Account.GetList()
			sel3.Options = kfs
			sel3.Refresh()
			if err == nil {
				dialog.ShowInformation("Success", "Keyfile added", p.Window)
			} else {
				dialog.ShowError(err, p.Window)
			}
			lbl2.SetText("[0B 00000000] keyfile not selected")
			p.kf = nil
			ent2b.SetText("")
		}
	})
	btn2c.Importance = widget.HighImportance
	btn3 := widget.NewButtonWithIcon("Del", theme.ContentRemoveIcon(), func() {
		dialog.ShowConfirm("Confirm", "Delete this keyfile?", func(ok bool) {
			if ok && p.kfSelected != "" {
				delete(p.Account.KeyFiles, p.kfSelected)
				err := p.Account.Store()
				kfs = p.Account.GetList()
				sel3.Options = kfs
				sel3.Refresh()
				if err == nil {
					dialog.ShowInformation("Success", "Keyfile deleted", p.Window)
				} else {
					dialog.ShowError(err, p.Window)
				}
			}
		}, p.Window)
	})
	btn3.Importance = widget.DangerImportance

	box2 := container.NewVBox(
		lbl2,
		container.NewBorder(nil, nil, container.NewHBox(btn2a, btn2b), nil, ent2a),
		container.NewBorder(nil, nil, nil, btn2c, ent2b),
	)
	box3 := container.NewBorder(nil, nil, nil, btn3, sel3)

	// group4: main layout
	box4 := container.NewGridWithColumns(2,
		container.NewVBox(box0, widget.NewSeparator(), box1),
		container.NewVBox(
			widget.NewLabelWithStyle("Add keyfile (Account)", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}), box2,
			widget.NewSeparator(),
			widget.NewLabelWithStyle("Delete keyfile (Account)", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}), box3,
		),
	)
	p.Content.Objects = []fyne.CanvasObject{box4}
}

// ===== mode9: account =====
type Page9 struct {
	Window  fyne.Window
	Content *fyne.Container
	Config  *U1Config
	Account *Account

	publbl *widget.Label
	prilbl *widget.Label
	pubent *widget.Entry
	prient *widget.Entry
	kf     []byte
}

func (p *Page9) Main(w fyne.Window, co *fyne.Container, c *U1Config, a *Account) {
	p.Window, p.Content, p.Config, p.Account = w, co, c, a
}

func (p *Page9) Fill() {
	// group0: keypair view
	defer p.Refresh()
	p.publbl = widget.NewLabel("Public key (0B 00000000)")
	p.prilbl = widget.NewLabel("Private key (0B 00000000)")
	p.pubent = widget.NewMultiLineEntry()
	p.prient = widget.NewMultiLineEntry()
	box0 := container.NewVBox(p.publbl, p.pubent, p.prilbl, p.prient)

	// group1: keypair functions
	btn1a := widget.NewButtonWithIcon("Download", theme.DownloadIcon(), func() {
		dialog.ShowConfirm("Confirm", "Download keypair?", func(ok bool) {
			if !ok {
				return
			}
			err1 := os.WriteFile("yas-public.txt", []byte(p.pubent.Text), 0644)
			err2 := os.WriteFile("yas-private.txt", []byte(p.prient.Text), 0644)
			if err1 != nil {
				dialog.ShowError(err1, p.Window)
			} else if err2 != nil {
				dialog.ShowError(err2, p.Window)
			}
		}, p.Window)
	})
	btn1a.Importance = widget.HighImportance
	btn1b := widget.NewButtonWithIcon("Fetch", theme.ContentPasteIcon(), func() {
		dialog.ShowConfirm("Confirm", "Fetch keypair?", func(ok bool) {
			if !ok {
				return
			}
			var pub, pri []byte
			var err error
			if strings.Contains(p.pubent.Text, "#") {
				pub, err = Bencode.Decode64(p.pubent.Text, "#")
			} else {
				pub, err = Bencode.Decode64(p.pubent.Text, "")
			}
			if err != nil {
				dialog.ShowError(err, p.Window)
				return
			}
			if strings.Contains(p.prient.Text, "#") {
				pri, err = Bencode.Decode64(p.prient.Text, "#")
			} else {
				pri, err = Bencode.Decode64(p.prient.Text, "")
			}
			if err != nil {
				dialog.ShowError(err, p.Window)
				return
			}
			defer p.Refresh()
			p.Account.PubKey, p.Account.PriKey = pub, pri
			if err := p.Account.Store(); err != nil {
				dialog.ShowError(err, p.Window)
				return
			}
		}, p.Window)
	})
	btn1b.Importance = widget.HighImportance
	btn1c := widget.NewButtonWithIcon("Regen", theme.ViewRefreshIcon(), func() {
		dialog.ShowConfirm("Confirm", "Regenerate keypair?", func(ok bool) {
			if !ok {
				return
			}
			defer p.Refresh()
			if err := p.Account.NewKey(); err != nil {
				dialog.ShowError(err, p.Window)
				return
			}
		}, p.Window)
	})
	btn1c.Importance = widget.HighImportance
	box1 := container.NewVBox(
		widget.NewLabelWithStyle("Manage keypair", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		box0, layout.NewSpacer(), container.NewGridWithColumns(3, btn1a, btn1b, btn1c),
	)

	// group2: keyfile selection
	lbl2 := widget.NewLabel("[0B 00000000] keyfile not selected")
	btn2a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { SelectKF(lbl2, &p.kf) })
	ent2 := widget.NewEntry()
	ent2.SetPlaceHolder("port/secret: 8001/...")
	btn2b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { ReceiveKF(p.Window, lbl2, ent2, &p.kf) })
	box2 := container.NewBorder(nil, nil, container.NewHBox(btn2a, btn2b), nil, ent2)

	// group3: pw, msg
	ent3a := widget.NewPasswordEntry()
	ent3a.SetPlaceHolder("New password")
	ent3b := widget.NewPasswordEntry()
	ent3b.SetPlaceHolder("Confirm password")
	ent3c := widget.NewEntry()
	ent3c.SetPlaceHolder("New public message")
	btn3 := widget.NewButtonWithIcon("Change", theme.ConfirmIcon(), func() {
		dialog.ShowConfirm("Confirm", "Change password?", func(ok bool) {
			if !ok {
				return
			}
			if ent3a.Text != ent3b.Text {
				dialog.ShowError(errors.New("Passwords do not match"), p.Window)
				return
			}
			p.Account.PW, p.Account.KF, p.Account.Msg = ent3a.Text, p.kf, ent3c.Text
			if err := p.Account.Store(); err != nil {
				dialog.ShowError(err, p.Window)
				return
			}
			dialog.ShowInformation("Success", "Password changed successfully", p.Window)
		}, p.Window)
	})
	btn3.Importance = widget.DangerImportance
	box3 := container.NewVBox(
		widget.NewLabelWithStyle("Change password", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		lbl2, box2, widget.NewSeparator(), ent3a, ent3b, widget.NewSeparator(), ent3c, layout.NewSpacer(), btn3,
	)

	// group4: main layout
	box4 := container.NewGridWithColumns(2, box1, box3)
	p.Content.Objects = []fyne.CanvasObject{box4}
}

func (p *Page9) Refresh() {
	pub, _ := Bencode.Encode64(p.Account.PubKey, "#", 80, 10)
	pri, _ := Bencode.Encode64(p.Account.PriKey, "#", 80, 10)
	p.publbl.SetText(fmt.Sprintf("My public key (%dB %s)", len(p.Account.PubKey), Opsec.Crc32(p.Account.PubKey)))
	p.pubent.SetText(pub)
	p.prilbl.SetText(fmt.Sprintf("My private key (%dB %s)", len(p.Account.PriKey), Opsec.Crc32(p.Account.PriKey)))
	p.prient.SetText(pri)
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			os.WriteFile("panic-log.txt", []byte(fmt.Sprintf("panic while main.main: %v", r)), 0644)
		}
	}()
	var p LoginPage
	p.Main(new(U1Config), new(Account))
}
