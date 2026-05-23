// test796d : project USAG YAS-desktop functions
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"fyne.io/fyne/v2"
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
	"github.com/taewook427/USAG-KOX/BaseUI"
	"github.com/taewook427/USAG-KOX/MemView"
	"github.com/taewook427/USAG-KOX/TP1"
)

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
	btn1a := widget.NewButtonWithIcon("Add file", theme.FileIcon(), func() { BaseUI.ListAddFile(p.list, &p.Targets) })
	btn1b := widget.NewButtonWithIcon("Add folder", theme.FolderIcon(), func() { BaseUI.ListAddFolder(p.list, &p.Targets) })
	btn1c := widget.NewButtonWithIcon("Del path", theme.DeleteIcon(), func() { BaseUI.ListDelTgt(p.list, &p.Targets, p.selected); p.selected = -1 })
	btn1d := widget.NewButtonWithIcon("Reset all", theme.ContentClearIcon(), func() { BaseUI.ListDelTgt(p.list, &p.Targets, len(p.Targets)); p.selected = -1 })
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
	output = TP1.CleanPath(output)
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
	output = TP1.CleanPath(output)
	if output == "" {
		output = "output"
	}
	err = os.MkdirAll(output, 0644)
	if err != nil {
		return
	}
	err = Unpack(tgt, output, p.PackType)
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

	KeyData  []byte // masked or not
	IsMasked bool
}

func (p *Page1) Main(w fyne.Window, co *fyne.Container, c *U1Config, a *Account) {
	p.Window, p.Content, p.Config, p.Account = w, co, c, a
	p.Target = ""
	p.SignData = ""
	p.KeyData = nil
	p.IsMasked = false
	p.isWorking = false
}

func (p *Page1) Fill() {
	// group0: sign target
	lbl0 := widget.NewLabel("No file selected")
	if p.Target != "" {
		lbl0.SetText(p.Target)
	}
	btn0 := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() {
		path, err := BaseUI.ZenityFile("")
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
		path, err := BaseUI.ZenityFile("")
		if err == nil {
			var stat os.FileInfo
			stat, err = os.Stat(path)
			if err == nil && stat.Size() > LIMIT_BIG {
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
	sel2 := widget.NewSelect(p.Config.GetPub(), func(s string) { BaseUI.ChooseKF(lbl2, &p.KeyData, s, p.Config.PublicKeys, nil); p.IsMasked = false })
	sel2.PlaceHolder = "Select from Contacts"
	btn2a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { BaseUI.SelectPub(lbl2, &p.KeyData, p.Account.PriKey, p.Account.Mask); p.IsMasked = true })
	ent2 := widget.NewEntry()
	ent2.SetPlaceHolder("port/secret: 8001/...")
	btn2b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { BaseUI.ReceivePub(p.Window, lbl2, ent2, &p.KeyData, p.Account.Mask); p.IsMasked = true })
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
	if info.Size() > LIMIT_BIG {
		err = errors.New("Target file is too large")
		return
	}
	data, err := os.ReadFile(p.Target)
	if err != nil {
		return
	}

	// 2. sign
	var sign, key []byte
	am := new(Bencrypt.AsymMaster)
	err = am.Init(p.Account.KeyType)
	if err == nil && p.IsMasked {
		key, err = p.Account.Mask.XOR(p.KeyData)
		defer sclear(key)
	}
	if err == nil {
		err = am.Loadkey(nil, key)
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
	if info.Size() > LIMIT_BIG {
		err = errors.New("Target file is too large")
		return
	}
	data, err := os.ReadFile(p.Target)
	if err != nil {
		return
	}
	var sign, key []byte
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
	if err == nil && p.IsMasked {
		key, err = p.Account.Mask.XOR(p.KeyData)
		defer sclear(key)
	}
	if err == nil {
		err = am.Loadkey(key, nil)
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
	btn1a := widget.NewButtonWithIcon("Add file", theme.FileIcon(), func() { BaseUI.ListAddFile(p.list, &p.Targets) })
	btn1b := widget.NewButtonWithIcon("Add folder", theme.FolderIcon(), func() { BaseUI.ListAddFolder(p.list, &p.Targets) })
	btn1c := widget.NewButtonWithIcon("Del path", theme.DeleteIcon(), func() { BaseUI.ListDelTgt(p.list, &p.Targets, p.selected); p.selected = -1 })
	btn1d := widget.NewButtonWithIcon("Reset all", theme.ContentClearIcon(), func() { BaseUI.ListDelTgt(p.list, &p.Targets, len(p.Targets)); p.selected = -1 })
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

		shs := Bencode.NormPW(ent2b.Text)
		shsm, _ := p.Account.Mask.XOR(shs)
		ent2b.SetText("")
		sclear(shs)
		go p.Send(addr, shsm, ent2c.Text)
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

func (p *Page2) Send(addr string, secret []byte, smsg string) {
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
	nc := &NetCplx{
		Addr:   addr,
		Secret: secret, // masked secret
		DoPad:  p.Config.DoPad,
		Pg:     pg,
	}
	switch p.Account.KeyType {
	case "rsa1", "rsa2":
		nc.HashMode, nc.PubMode = "pbk2", p.Account.KeyType
	case "ecc1", "pqc1":
		nc.HashMode, nc.PubMode = "arg2", p.Account.KeyType
	default:
		err = errors.New("Unsupported key type")
	}
	if err == nil {
		fromPub, toPub, err = Send(tgts, smsg, nc)
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
		t, e := TP1.GetIPs(true)
		if e != nil {
			dialog.ShowError(e, p.Window)
			return
		}
		for i, r := range t {
			t[i] = r + ":" + port
		}
		ips = t
		list0.Refresh()

		shs := Bencode.NormPW(ent1b.Text)
		shsm, _ := p.Account.Mask.XOR(shs)
		ent1b.SetText("")
		sclear(shs)
		go p.Recv(port, shsm)
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

func (p *Page3) Recv(port string, secret []byte) {
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
	nc := &NetCplx{
		Addr:   port,
		Secret: secret, // masked secret
		DoPad:  p.Config.DoPad,
		Pg:     pg,
	}
	fromPub, toPub, smsg, err = Receive("./", nc)
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
	mulmode  bool
	kf       []byte // masked
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
		path, err := BaseUI.ZenityFile("Load Text File")
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
	btn1a := widget.NewButtonWithIcon("Add file", theme.FileIcon(), func() { BaseUI.ListAddFile(p.list, &p.Targets) })
	btn1b := widget.NewButtonWithIcon("Add dir", theme.FolderIcon(), func() { BaseUI.ListAddFolder(p.list, &p.Targets) })
	btn1c := widget.NewButtonWithIcon("Del path", theme.DeleteIcon(), func() { BaseUI.ListDelTgt(p.list, &p.Targets, p.selected); p.selected = -1 })
	btn1d := widget.NewButtonWithIcon("Del all", theme.ContentClearIcon(), func() { BaseUI.ListDelTgt(p.list, &p.Targets, len(p.Targets)); p.selected = -1 })
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
	sel4 := widget.NewSelect(p.Account.GetList(), func(s string) { BaseUI.ChooseKF(lbl4, &p.kf, s, p.Account.KeyFiles, p.Account.Mask) })
	sel4.PlaceHolder = "Select from Account"
	btn4a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { BaseUI.SelectKF(lbl4, &p.kf, p.Account.Mask) })
	ent4 := widget.NewEntry()
	ent4.SetPlaceHolder("port/secret: 8001/...")
	btn4b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { BaseUI.ReceiveKF(p.Window, lbl4, ent4, &p.kf, p.Account.Mask) })
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
		pw := Bencode.NormPW(ent5a.Text)
		pwc.PW, _ = p.Account.Mask.XOR(pw)
		ent5a.SetText("")
		sclear(pw)
		pwc.KF = make([]byte, len(p.kf))
		copy(pwc.KF, p.kf)

		// EncCplx
		ec := new(EncCplx)
		ec.ImgType = p.imgType
		ec.PackType = p.packType
		ec.EncType = p.encType
		ec.Msg = ent5b.Text
		ec.Smsg = ent0.Text
		ec.DoPad = p.Config.DoPad

		// dsts
		dsts := make([]string, 0)
		if p.mulmode {
			dsts = append(dsts, p.Targets...)
		} else {
			dst := TP1.CleanPath(ent6.Text)
			if dst == "" {
				dst = "output"
			}
			dsts = append(dsts, dst)
		}
		for i := range dsts {
			dsts[i] += "." + ec.ImgType
		}
		go p.Encrypt(dsts, pwc, ec)
	})
	btn6a.Importance = widget.HighImportance
	chk6 := widget.NewCheck("Mul-File Mode", func(b bool) {
		p.mulmode = b
		ent6.SetText("")
		if p.mulmode {
			ent6.SetPlaceHolder("Disabled (AutoGen)")
			ent6.Disable()
		} else {
			ent6.SetPlaceHolder("Output name")
			ent6.Enable()
		}
	})
	chk6.SetChecked(false)
	p.mulmode = false
	box6 := container.NewBorder(nil, nil, nil, btn6a, ent6)

	// group7: main layout
	box7a := container.NewVBox(
		box2, widget.NewSeparator(),
		box3, widget.NewSeparator(),
		box4, widget.NewSeparator(),
		box5, widget.NewSeparator(),
		container.NewBorder(nil, nil, chk6, nil), box6,
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
				dialog.ShowInformation("Success", fmt.Sprintf("Encrypted successfully\nPW: %d bytes, KF: %d bytes", len(pwc.PW), len(pwc.KF)), p.Window)
			} else {
				dialog.ShowError(err, p.Window)
			}
		})
	}()
	tgts := make([]string, len(p.Targets))
	copy(tgts, p.Targets)
	pg := new(Progress)
	pg.Init(p.Window, p.progbar, &err)
	if len(tgts) == 0 { // msg-mode
		var res []byte
		res, err = EncMsg(pwc, nil, ec, pg)
		var txtRes string
		if err == nil {
			txtRes, err = Bencode.Encode64(res, "#", 0, 0)
		}
		fyne.Do(func() { p.textResult.SetText(txtRes) })
	} else if p.mulmode { // multi-mode
		for i, tgt := range tgts {
			err = EncFiles([]string{tgt}, dsts[i], pwc, nil, ec, pg)
			if err != nil {
				break
			}
		}
	} else { // normal-mode
		err = EncFiles(tgts, dsts[0], pwc, nil, ec, pg)
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

	mulmode bool
	memmode bool
	msgView *widget.Entry
	kf      []byte // masked
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
		path, err := BaseUI.ZenityFile("Load Text File")
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
	btn1a := widget.NewButtonWithIcon("Add file", theme.FileIcon(), func() { BaseUI.ListAddFile(p.list, &p.Targets) })
	btn1b := widget.NewButtonWithIcon("Add dir", theme.FolderIcon(), func() { BaseUI.ListAddFolder(p.list, &p.Targets) })
	btn1c := widget.NewButtonWithIcon("Del path", theme.DeleteIcon(), func() { BaseUI.ListDelTgt(p.list, &p.Targets, p.selected); p.selected = -1 })
	btn1d := widget.NewButtonWithIcon("Del all", theme.ContentClearIcon(), func() { BaseUI.ListDelTgt(p.list, &p.Targets, len(p.Targets)); p.selected = -1 })
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
	sel4 := widget.NewSelect(p.Account.GetList(), func(s string) { BaseUI.ChooseKF(lbl4, &p.kf, s, p.Account.KeyFiles, p.Account.Mask) })
	sel4.PlaceHolder = "Select from Account"
	btn4a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { BaseUI.SelectKF(lbl4, &p.kf, p.Account.Mask) })
	ent4 := widget.NewEntry()
	ent4.SetPlaceHolder("port/secret: 8001/...")
	btn4b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { BaseUI.ReceiveKF(p.Window, lbl4, ent4, &p.kf, p.Account.Mask) })
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
		pw := Bencode.NormPW(ent5.Text)
		pwc.PW, _ = p.Account.Mask.XOR(pw)
		ent5.SetText("")
		sclear(pw)
		pwc.KF = make([]byte, len(p.kf))
		copy(pwc.KF, p.kf)

		dst := TP1.CleanPath(ent6.Text)
		if dst == "" {
			dst = "./"
		}
		if !p.mulmode && !p.memmode {
			os.MkdirAll(dst, 0644)
		}
		go p.Decrypt(ent0.Text, dst, pwc)
	})
	btn6a.Importance = widget.HighImportance
	chk6 := widget.NewRadioGroup([]string{"Default", "Mul-File Mode", "In-Mem View"}, func(value string) {
		p.mulmode, p.memmode = false, false
		ent6.SetText("")
		switch value {
		case "Mul-File Mode":
			p.mulmode = true
			ent6.SetPlaceHolder("Disabled (AutoGen)")
			ent6.Disable()
		case "In-Mem View":
			p.memmode = true
			ent6.SetPlaceHolder("Disabled (Viewer)")
			ent6.Disable()
		default:
			ent6.SetPlaceHolder("Output name")
			ent6.Enable()
		}
	})
	chk6.SetSelected("Default")
	chk6.Horizontal = true
	p.mulmode, p.memmode = false, false
	box6 := container.NewBorder(nil, nil, nil, btn6a, ent6)

	// group7: main layout
	box7a := container.NewVBox(
		box2, widget.NewSeparator(),
		box4, widget.NewSeparator(),
		box5, widget.NewSeparator(),
		chk6, box6,
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
				dialog.ShowInformation("Success", fmt.Sprintf("Decrypted successfully\nPW: %d bytes, KF: %d bytes", len(pwc.PW), len(pwc.KF)), p.Window)
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
	if p.mulmode { // multi-mode
		for _, tgt := range p.Targets {
			msg, smsg, err = DecFile(tgt, filepath.Dir(tgt), pwc, nil, pg)
			if err != nil {
				break
			}
		}
	} else if p.memmode { // mem-mode
		if p.selected < 0 || p.selected >= len(p.Targets) {
			err = fmt.Errorf("invalid selection index")
			return
		}
		var res map[string][]byte
		msg, smsg, res, err = DecFileMem(p.Targets[p.selected], pwc, nil, pg)
		if err == nil {
			viewer := new(MemView.MemView)
			viewer.Main(MainApp, "YAS Viewer", res, savemem, false, true, -1)
		}
	} else { // normal-mode
		if p.selected < 0 || p.selected >= len(p.Targets) {
			err = fmt.Errorf("invalid selection index")
			return
		}
		msg, smsg, err = DecFile(p.Targets[p.selected], dst, pwc, nil, pg)
	}
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
	mulmode  bool
	pub      []byte
	pri      []byte // masked
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
		path, err := BaseUI.ZenityFile("Load Text File")
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
	btn1a := widget.NewButtonWithIcon("Add file", theme.FileIcon(), func() { BaseUI.ListAddFile(p.list, &p.Targets) })
	btn1b := widget.NewButtonWithIcon("Add dir", theme.FolderIcon(), func() { BaseUI.ListAddFolder(p.list, &p.Targets) })
	btn1c := widget.NewButtonWithIcon("Del path", theme.DeleteIcon(), func() { BaseUI.ListDelTgt(p.list, &p.Targets, p.selected); p.selected = -1 })
	btn1d := widget.NewButtonWithIcon("Del all", theme.ContentClearIcon(), func() { BaseUI.ListDelTgt(p.list, &p.Targets, len(p.Targets)); p.selected = -1 })
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
	sel4 := widget.NewSelect(p.Config.GetPub(), func(s string) { BaseUI.ChooseKF(lbl4, &p.pub, s, p.Config.PublicKeys, nil) })
	sel4.PlaceHolder = "Select from Contacts"
	btn4a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { BaseUI.SelectPub(lbl4, &p.pub, nil, nil) })
	ent4 := widget.NewEntry()
	ent4.SetPlaceHolder("port/secret: 8001/...")
	btn4b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { BaseUI.ReceivePub(p.Window, lbl4, ent4, &p.pub, nil) })
	box4 := container.NewVBox(
		container.NewHBox(widget.NewLabel("Peer Public (default=Null):"), sel4),
		container.NewBorder(nil, nil, container.NewHBox(btn4a, btn4b), nil, ent4),
		lbl4,
	)

	// group5: private key
	p.pri = p.Account.PriKey
	priv, _ := p.Account.Mask.XOR(p.pri)
	crcv := Opsec.Crc32(priv)
	sclear(priv)
	lbl5 := widget.NewLabel(fmt.Sprintf("[%dB %s] default", len(p.pri), crcv))
	btn5a := widget.NewButtonWithIcon("Clear", theme.ContentRemoveIcon(), func() { p.pri = nil; lbl5.SetText("[0B 00000000] null") })
	btn5b := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { BaseUI.SelectPub(lbl5, &p.pri, p.Account.PriKey, p.Account.Mask) })
	ent5 := widget.NewEntry()
	ent5.SetPlaceHolder("port/secret: 8001/...")
	btn5c := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { BaseUI.ReceivePub(p.Window, lbl5, ent5, &p.pri, p.Account.Mask) })
	box5 := container.NewVBox(
		container.NewHBox(widget.NewLabel("My Private (default=MyPriv):"), btn5a),
		container.NewBorder(nil, nil, container.NewHBox(btn5b, btn5c), nil, ent5),
		lbl5,
	)

	// group6: msg, output, function
	ent6a := widget.NewEntry()
	ent6a.SetPlaceHolder("Public message")
	ent6b := widget.NewEntry()
	if p.mulmode {
		ent6b.SetPlaceHolder("Disabled (AutoGen)")
		ent6b.Disable()
	} else {
		ent6b.SetPlaceHolder("Output name")
	}
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
		ec.DoPad = p.Config.DoPad

		dst := TP1.CleanPath(ent6b.Text)
		if dst == "" {
			dst = "output"
		}
		// dsts
		dsts := make([]string, 0)
		if p.mulmode {
			dsts = append(dsts, p.Targets...)
		} else {
			dst := TP1.CleanPath(ent6b.Text)
			if dst == "" {
				dst = "output"
			}
			dsts = append(dsts, dst)
		}
		for i := range dsts {
			dsts[i] += "." + ec.ImgType
		}
		go p.Encrypt(dsts, pubc, ec)
	})
	btn6a.Importance = widget.HighImportance
	chk6 := widget.NewCheck("Mul-File Mode", func(b bool) {
		p.mulmode = b
		ent6b.SetText("")
		if p.mulmode {
			ent6b.SetPlaceHolder("Disabled (AutoGen)")
			ent6b.Disable()
		} else {
			ent6b.SetPlaceHolder("Output name")
			ent6b.Enable()
		}
	})
	chk6.SetChecked(false)
	p.mulmode = false
	box6 := container.NewBorder(ent6a, nil, nil, btn6a, ent6b)

	// group7: main layout
	box7a := container.NewVBox(
		box2, widget.NewSeparator(),
		box3, widget.NewSeparator(),
		box4, widget.NewSeparator(),
		box5, widget.NewSeparator(),
		container.NewBorder(nil, nil, chk6, nil), box6,
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
	if len(tgts) == 0 { // msg-mode
		var res []byte
		res, err = EncMsg(nil, pubc, ec, pg)
		var txtRes string
		if err == nil {
			txtRes, err = Bencode.Encode64(res, "#", 0, 0)
		}
		fyne.Do(func() { p.textResult.SetText(txtRes) })
	} else if p.mulmode { // multi-mode
		for i, tgt := range tgts {
			err = EncFiles([]string{tgt}, dsts[i], nil, pubc, ec, pg)
			if err != nil {
				break
			}
		}
	} else { // normal-mode
		err = EncFiles(tgts, dsts[0], nil, pubc, ec, pg)
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

	mulmode bool
	memmode bool
	msgView *widget.Entry
	peerPub []byte
	myPub   []byte
	pri     []byte // masked
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
		path, err := BaseUI.ZenityFile("Load Text File")
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
	btn1a := widget.NewButtonWithIcon("Add file", theme.FileIcon(), func() { BaseUI.ListAddFile(p.list, &p.Targets) })
	btn1b := widget.NewButtonWithIcon("Add dir", theme.FolderIcon(), func() { BaseUI.ListAddFolder(p.list, &p.Targets) })
	btn1c := widget.NewButtonWithIcon("Del path", theme.DeleteIcon(), func() { BaseUI.ListDelTgt(p.list, &p.Targets, p.selected); p.selected = -1 })
	btn1d := widget.NewButtonWithIcon("Del all", theme.ContentClearIcon(), func() { BaseUI.ListDelTgt(p.list, &p.Targets, len(p.Targets)); p.selected = -1 })
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
	sel3 := widget.NewSelect(p.Config.GetPub(), func(s string) { BaseUI.ChooseKF(lbl3, &p.peerPub, s, p.Config.PublicKeys, nil) })
	sel3.PlaceHolder = "Select from Contacts"
	btn3a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { BaseUI.SelectPub(lbl3, &p.peerPub, nil, nil) })
	ent3 := widget.NewEntry()
	ent3.SetPlaceHolder("port/secret: 8001/...")
	btn3b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { BaseUI.ReceivePub(p.Window, lbl3, ent3, &p.peerPub, nil) })
	box3 := container.NewVBox(
		container.NewHBox(widget.NewLabel("Peer Public (default=Null):"), sel3),
		container.NewBorder(nil, nil, container.NewHBox(btn3a, btn3b), nil, ent3),
		lbl3,
	)

	// group4: my public key
	p.myPub = nil
	lbl4 := widget.NewLabel("[0B 00000000] default")
	sel4 := widget.NewSelect(p.Config.GetPub(), func(s string) { BaseUI.ChooseKF(lbl4, &p.myPub, s, p.Config.PublicKeys, nil) })
	sel4.PlaceHolder = "Select from Contacts"
	btn4a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { BaseUI.SelectPub(lbl4, &p.myPub, nil, nil) })
	ent4 := widget.NewEntry()
	ent4.SetPlaceHolder("port/secret: 8001/...")
	btn4b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { BaseUI.ReceivePub(p.Window, lbl4, ent4, &p.myPub, nil) })
	box4 := container.NewVBox(
		container.NewHBox(widget.NewLabel("My Public (default=Null):"), sel4),
		container.NewBorder(nil, nil, container.NewHBox(btn4a, btn4b), nil, ent4),
		lbl4,
	)

	// group5: my private key
	p.pri = p.Account.PriKey
	priv, _ := p.Account.Mask.XOR(p.pri)
	crcv := Opsec.Crc32(priv)
	sclear(priv)
	lbl5 := widget.NewLabel(fmt.Sprintf("[%dB %s] default", len(p.pri), crcv))
	btn5a := widget.NewButtonWithIcon("Clear", theme.ContentRemoveIcon(), func() { p.pri = nil; lbl5.SetText("[0B 00000000] null") })
	btn5b := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { BaseUI.SelectPub(lbl5, &p.pri, p.Account.PriKey, p.Account.Mask) })
	ent5 := widget.NewEntry()
	ent5.SetPlaceHolder("port/secret: 8001/...")
	btn5c := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { BaseUI.ReceivePub(p.Window, lbl5, ent5, &p.pri, p.Account.Mask) })
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

		dst := TP1.CleanPath(ent6.Text)
		if dst == "" {
			dst = "./"
		}
		if !p.mulmode && !p.memmode {
			os.MkdirAll(dst, 0644)
		}
		go p.Decrypt(ent0.Text, dst, pubc)
	})
	btn6a.Importance = widget.HighImportance
	chk6 := widget.NewRadioGroup([]string{"Default", "Mul-File Mode", "In-Mem View"}, func(value string) {
		p.mulmode, p.memmode = false, false
		ent6.SetText("")
		switch value {
		case "Mul-File Mode":
			p.mulmode = true
			ent6.SetPlaceHolder("Disabled (AutoGen)")
			ent6.Disable()
		case "In-Mem View":
			p.memmode = true
			ent6.SetPlaceHolder("Disabled (Viewer)")
			ent6.Disable()
		default:
			ent6.SetPlaceHolder("Output name")
			ent6.Enable()
		}
	})
	chk6.SetSelected("Default")
	chk6.Horizontal = true
	p.mulmode, p.memmode = false, false
	box6 := container.NewBorder(p.msgView, nil, nil, btn6a, ent6)

	// group7: main layout
	box7a := container.NewVBox(
		box2, widget.NewSeparator(),
		box3, widget.NewSeparator(),
		box4, widget.NewSeparator(),
		box5, widget.NewSeparator(),
		chk6, box6,
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
	if p.mulmode { // multi-mode
		for _, tgt := range p.Targets {
			msg, smsg, err = DecFile(tgt, filepath.Dir(tgt), nil, pubc, pg)
			if err != nil {
				break
			}
		}
	} else if p.memmode { // mem-mode
		if p.selected < 0 || p.selected >= len(p.Targets) {
			err = fmt.Errorf("invalid selection index")
			return
		}
		var res map[string][]byte
		msg, smsg, res, err = DecFileMem(p.Targets[p.selected], nil, pubc, pg)
		if err == nil {
			viewer := new(MemView.MemView)
			viewer.Main(MainApp, "YAS Viewer", res, savemem, false, true, -1)
		}
	} else { // normal-mode
		if p.selected < 0 || p.selected >= len(p.Targets) {
			err = fmt.Errorf("invalid selection index")
			return
		}
		msg, smsg, err = DecFile(p.Targets[p.selected], dst, nil, pubc, pg)
	}
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
	kf          []byte // masked
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
	btn2a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { BaseUI.SelectKF(lbl2, &p.kf, p.Account.Mask) })
	ent2a := widget.NewEntry()
	ent2a.SetPlaceHolder("port/secret: 8001/...")
	btn2b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { BaseUI.ReceiveKF(p.Window, lbl2, ent2a, &p.kf, p.Account.Mask) })
	ent2b := widget.NewEntry()
	ent2b.SetPlaceHolder("New keyfile name")

	// group3: del keyfile
	kfs := p.Account.GetList()
	sel3 := widget.NewSelect(kfs, func(s string) { p.kfSelected = s })
	sel3.PlaceHolder = "Keyfile list"
	p.kfSelected = ""

	btn2c := widget.NewButtonWithIcon("Add", theme.ContentAddIcon(), func() {
		if p.kf != nil && ent2b.Text != "" {
			p.Account.KeyFiles[ent2b.Text] = p.kf // direct add (both masked)
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

	publbl  *widget.Label
	prilbl  *widget.Label
	pubent  *widget.Entry
	prient  *widget.Entry
	viewKey bool
	kf      []byte // masked
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
	p.viewKey = false
	chk0 := widget.NewCheck("Show keys", func(value bool) { p.viewKey = value; p.Refresh() })
	chk0.SetChecked(p.viewKey)
	box0 := container.NewVBox(p.publbl, p.pubent, p.prilbl, p.prient, chk0)

	// group1: keypair functions
	btn1a := widget.NewButtonWithIcon("Download", theme.DownloadIcon(), func() {
		dialog.ShowConfirm("Confirm", "Download keypair?", func(ok bool) {
			if !ok || !p.viewKey {
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
			pri, _ = p.Account.Mask.XOR(pri) // mask pri
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
	btn2a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() { BaseUI.SelectKF(lbl2, &p.kf, p.Account.Mask) })
	ent2 := widget.NewEntry()
	ent2.SetPlaceHolder("port/secret: 8001/...")
	btn2b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() { BaseUI.ReceiveKF(p.Window, lbl2, ent2, &p.kf, p.Account.Mask) })
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
			pw := Bencode.NormPW(ent3a.Text)
			pwm, _ := p.Account.Mask.XOR(pw) // mask pw
			ent3a.SetText("")
			sclear(pw)
			p.Account.PW, p.Account.KF, p.Account.Msg, p.Account.DoPad = pwm, p.kf, ent3c.Text, p.Config.DoPad
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
	priv, _ := p.Account.Mask.XOR(p.Account.PriKey)
	defer sclear(priv)
	p.publbl.SetText(fmt.Sprintf("My public key (%dB %s)", len(p.Account.PubKey), Opsec.Crc32(p.Account.PubKey)))
	p.prilbl.SetText(fmt.Sprintf("My private key (%dB %s)", len(priv), Opsec.Crc32(priv)))
	if p.viewKey {
		pub, _ := Bencode.Encode64(p.Account.PubKey, "#", 80, 10)
		pri, _ := Bencode.Encode64(priv, "#", 80, 10)
		p.pubent.SetText(pub)
		p.prient.SetText(pri)
	} else {
		p.pubent.SetText("")
		p.prient.SetText("")
	}
}
