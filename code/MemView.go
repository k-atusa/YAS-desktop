// test813 : project USAG Memoey Viewer R1
package main

import (
	"bytes"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"

	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"

	_ "golang.org/x/image/webp"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

type MemView struct {
	Context string // for caller
	Window  fyne.Window
	Names   []string
	Data    map[string][]byte

	CurMode int // 0: image, 1: text, 2: binary
	CurIdx  int
	OnSave  func(string, []byte) // save callback

	secure   bool
	txtlimit int

	list    *widget.List
	content *fyne.Container
	modeBtn *widget.Button
	entry   *widget.Entry
}

func (v *MemView) Main(app fyne.App, title string, data map[string][]byte, onSave func(string, []byte), secure bool, txtlimit int) {
	v.Data = data
	v.OnSave = onSave
	v.Names = make([]string, 0, len(data))
	for k := range data {
		v.Names = append(v.Names, k)
	}
	sort.Strings(v.Names)

	v.secure = secure
	if txtlimit <= 0 {
		v.txtlimit = 512 * 1024
	} else {
		v.txtlimit = txtlimit
	}

	v.Window = app.NewWindow(title)
	v.Fill()
	v.Window.Resize(fyne.NewSize(720*FyneSize, 480*FyneSize))
	v.Window.CenterOnScreen()
	v.Window.Show()
}

func (v *MemView) Fill() {
	// left listview
	v.list = widget.NewList(
		func() int { return len(v.Names) },
		func() fyne.CanvasObject {
			return widget.NewLabelWithStyle("Template", fyne.TextAlignLeading, fyne.TextStyle{})
		},
		func(i widget.ListItemID, o fyne.CanvasObject) { o.(*widget.Label).SetText(v.Names[i]) },
	)
	v.list.OnSelected = func(id widget.ListItemID) { v.refreshView(id, -1) }
	v.CurIdx = -1

	// lower buttons
	v.modeBtn = widget.NewButtonWithIcon("Mode: Auto", theme.ViewRefreshIcon(), func() {
		if v.CurIdx < 0 {
			return
		}
		v.refreshView(v.CurIdx, (v.CurMode+1)%3)
	})

	btnSave := widget.NewButtonWithIcon("Save", theme.DocumentSaveIcon(), func() {
		if v.CurIdx < 0 || v.CurMode != 1 || v.OnSave == nil {
			return
		}
		data := []byte(v.entry.Text)
		clear(v.Data[v.Names[v.CurIdx]])
		v.Data[v.Names[v.CurIdx]] = data
		v.OnSave(v.Names[v.CurIdx], data)
	})
	btnSave.Importance = widget.HighImportance

	btnExit := widget.NewButtonWithIcon("Exit", theme.CancelIcon(), func() {
		v.Window.Close()
		if v.secure {
			clear(v.Names)
			for _, d := range v.Data {
				clear(d)
			}
			clear(v.Data)
			v.list, v.content, v.entry = nil, nil, nil
		}
	})
	btnExit.Importance = widget.DangerImportance
	bottomBar := container.NewHBox(v.modeBtn, layout.NewSpacer(), btnSave, btnExit)

	// set layout
	v.content = container.NewStack(widget.NewLabelWithStyle("Select a file from the list", fyne.TextAlignCenter, fyne.TextStyle{Italic: true}))
	split := container.NewHSplit(v.list, container.NewScroll(v.content))
	split.Offset = 0.3
	mainLayout := container.NewBorder(nil, bottomBar, nil, nil, split)
	v.Window.SetContent(mainLayout)
}

func (v *MemView) refreshView(idx int, mode int) {
	// set curidx and curmode
	v.CurIdx = idx
	curName := v.Names[idx]
	if mode < 0 {
		ext := strings.ToLower(filepath.Ext(curName))
		switch ext {
		case ".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp":
			v.CurMode = 0 // image
		default:
			v.CurMode = 1 // text
		}
	} else {
		v.CurMode = mode
	}

	// set modeBtn text
	switch v.CurMode {
	case 0:
		v.modeBtn.SetText("Mode: Image")
	case 1:
		v.modeBtn.SetText("Mode: Text")
	case 2:
		v.modeBtn.SetText("Mode: Binary")
	default:
		v.modeBtn.SetText("Unknown")
	}

	// load data
	data := v.Data[curName]
	if data == nil {
		v.content.Objects = []fyne.CanvasObject{widget.NewLabelWithStyle("(No Data)", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})}
		v.content.Refresh()
		return
	}

	// set content by mode
	switch v.CurMode {
	case 0: // image
		v.entry = nil
		img := canvas.NewImageFromReader(bytes.NewReader(data), curName)
		img.FillMode = canvas.ImageFillContain
		v.content.Objects = []fyne.CanvasObject{img}

	case 1, 2: // text, binary
		if len(data) > v.txtlimit {
			v.content.Objects = []fyne.CanvasObject{widget.NewLabelWithStyle("(Text size exceeds the limit)", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})}
		} else {
			v.entry = widget.NewMultiLineEntry()
			v.entry.TextStyle = fyne.TextStyle{Monospace: true}
			if v.CurMode == 1 {
				v.entry.SetText(string(data))
			} else {
				v.entry.SetText(hex.Dump(data))
				v.entry.Disable() // hex dump is readonly
			}
			v.content.Objects = []fyne.CanvasObject{v.entry}
		}
		v.content.Refresh()

	default:
		v.content.Objects = []fyne.CanvasObject{widget.NewLabelWithStyle("(Unknown Mode)", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})}
		v.content.Refresh()
	}
	v.content.Refresh()
}
