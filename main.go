package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell"
	"github.com/rivo/tview"
)

var networkHash uint32
var appdataPath = os.Getenv("appdata")
var f *os.File
var name string
var network = make(map[string]string)
var onlineTimes = make(map[string]int64)
var port = ":9999"
var mux = sync.Mutex{}
var chat *tview.TextView
var online *tview.TextView
var uiMain *tview.Flex
var app = tview.NewApplication()
var debug = false
var myIP = ownIP()
var ipregex = regexp.MustCompile(`^([0-9]{1,3}[.]){3}[0-9]{1,3}$`)

var colors = []string{"maroon", "green", "olive", "navy", "purple", "teal", "silver", "gray", "red", "lime", "yellow", "blue", "fuchsia", "aqua", "white"}

func main() {

	defer f.Close()

	if len(os.Args) == 2 && os.Args[1] == "-d" {
		debug = true
		df, _ := os.Create(appdataPath + "/quicky.log")
		f = df
	}
	// myIP
	appdataPath = appdataPath + "/quicky.json"
	var netJSON, err = ioutil.ReadFile(appdataPath)
	debugLog(appdataPath)
	if err == nil {
		json.Unmarshal([]byte(netJSON), &network)
	}
	if val, ok := network[myIP]; ok {
		debugLog(val)
		name = val
	} else {
		network[myIP] = "Anon"
		name = "Anon"
	}
	netHash()
	onlineTimes[myIP] = time.Now().Unix()

	uiMain, chat, online = ui()

	// listener
	go func() {
		laddr, err := net.ResolveUDPAddr("udp", port)
		udp, err := net.ListenUDP("udp", laddr)
		defer udp.Close()

		if err != nil {
			panic("Wtf")
		}

		buf := make([]byte, 1024)
		for {
			len, addr, _ := udp.ReadFromUDP(buf)
			receive(string(buf[:len]), addr.IP.String())
		}
	}()

	// pinger
	go func() {
		for {
			sendAll(fmt.Sprintf("/ping %s %d", name, networkHash))
			time.Sleep(5 * time.Second)
		}
	}()

	// online updater
	go func() {
		for {
			var onlineNames bytes.Buffer
			onlineCount := 0
			mux.Lock()
			now := time.Now().Unix()
			ips := make([]string, 0, len(network))
			for ip := range network {
				ips = append(ips, ip)
			}
			sort.Strings(ips)
			for _, ip := range ips {
				if val, ok := onlineTimes[ip]; ok {
					if now-val < 15 {
						onlineNames.WriteString(fmt.Sprintf("[%s]%s %s\n", colors[colorIndex(ip)], network[ip], ip))
						onlineCount++
					}
				}
			}
			mux.Unlock()
			online.SetText(onlineNames.String())
			app.Draw()
			fmt.Fprintf(f, "online: %s", onlineNames.String())
			online.SetTitle(fmt.Sprintf("Online (%d)", onlineCount))
			time.Sleep(5 * time.Second)
		}
	}()

	if err := app.SetRoot(uiMain, true).Run(); err != nil {
		panic(err)
	}
}

func send(msg string) {

	msg = strings.TrimSpace(msg)

	if msg[0] == '/' {
		words := strings.Fields(msg)

		if len(words) == 2 {
			switch words[0] {
			case "/add":
				add(words[1])
			case "/name":
				setName(words[1], myIP)
				name = words[1]
			default:
				fmt.Fprint(chat, "[red]quicky [white]unkown command\n")
			}
		} else {
			fmt.Fprint(chat, "[red]quicky [white]unkown command\n")
		}
	} else {
		sendAll(fmt.Sprintf("quicky %s", msg))
	}
}

func add(ip string) {
	if ipregex.Match([]byte(ip)) {
		go sendSingle(fmt.Sprintf("/add %s", name), ip)
		setName("Anon", ip)
	} else {
		fmt.Fprint(chat, "[red]quicky [white]invalid ip\n")
	}
}

func receive(rec string, addr string) {
	if strings.HasPrefix(rec, "quicky") {
		recvMessage(rec[len("quicky")+1:], addr)
	}
	if strings.HasPrefix(rec, "/network") {
		recNetwork(rec[len("/network")+1:])
	} else if rec[0] == '/' {
		words := strings.Fields(rec)
		if len(words) == 2 {
			words := strings.Fields(rec)
			switch words[0] {
			case "/add":
				recvAdd(words[1], addr)
			}
		} else if len(words) == 3 {
			switch words[0] {
			case "/add-single":
				setName(words[1], words[2])
			case "/ping":
				setName(words[1], addr)
				syncNetworks(words[2], addr)
				updateOnline(addr)
			}
		}
	}
}

func syncNetworks(hstr, ip string) {
	n, _ := strconv.ParseUint(hstr, 0, 32)
	if uint32(n) != networkHash {
		sendSingle(fmt.Sprintf("/network %s", string(networkMarshall())), ip)
	}
}

func updateOnline(ip string) {
	mux.Lock()
	onlineTimes[ip] = time.Now().Unix()
	mux.Unlock()
}

func recvMessage(msg, addr string) {
	mux.Lock()
	fmt.Fprintf(f, "recv: %s: %s\n", network[addr], msg)
	fmt.Fprintf(chat, "[%s]%s: %s\n", colors[colorIndex(addr)], network[addr], msg)
	mux.Unlock()
}

// C adds B
func recvAdd(name string, ip string) {

	// B tells C about everyone
	sendSingle(fmt.Sprintf("/network %s", string(networkMarshall())), ip)

	// B tells everyone about C
	sendAll(fmt.Sprintf("/add-single %s %s", name, ip))
	setName(name, ip)
}

func recNetwork(jsonStr string) {
	debugLog(jsonStr)
	newNetwork := make(map[string]string)
	json.Unmarshal([]byte(jsonStr), &newNetwork)
	mux.Lock()
	for k, v := range newNetwork {
		network[k] = v
	}
	mux.Unlock()
	saveState()
}

func sendAll(msg string) {
	mux.Lock()
	for ip := range network {
		go sendSingle(msg, ip)
	}
	mux.Unlock()
}

func sendSingle(msg string, ip string) {
	debugLog(fmt.Sprintf("sent: %s, ip: %s", msg, ip+port))
	conn, err := net.Dial("udp", ip+port)
	if err == nil {
		fmt.Fprint(conn, msg)
		conn.Close()
	}
}

func setName(name string, ip string) {
	mux.Lock()
	debugLog(fmt.Sprintf("setName: %s %s", name, ip))
	network[ip] = name
	mux.Unlock()
	saveState()
}

func saveState() {
	netHash()
	ioutil.WriteFile(appdataPath, networkMarshall(), 0644)
}

func networkMarshall() []byte {
	mux.Lock()
	networkBytes, _ := json.Marshal(network)
	mux.Unlock()
	return networkBytes
}

func debugLog(log string) {
	if debug {
		fmt.Fprintln(f, log)
	}
}

func ui() (*tview.Flex, *tview.TextView, *tview.TextView) {

	online := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)

	input := tview.NewInputField().
		SetAcceptanceFunc(func(textToCheck string, lastChar rune) bool {
			return true
		}).SetPlaceholder("my ip " + myIP + " /name [name], /add [ip], /exit").SetPlaceholderTextColor(tcell.ColorAqua)

	input.SetDoneFunc(func(key tcell.Key) {
		txt := input.GetText()
		if len(txt) > 0 {
			if txt == "/exit" {
				app.Stop()
			} else {
				send(txt)
			}
		}
		input.SetText("")
	})

	chat := tview.NewTextView().
		SetScrollable(true).
		SetDoneFunc(func(key tcell.Key) {
			if key == tcell.KeyTAB {
				input.GetFocusable()
			}
		}).SetDynamicColors(true)

	chat.SetChangedFunc(func() {
		app.Draw()
	})

	chat.SetBorder(true).SetTitle("Chat")
	online.SetBorder(true).SetTitle("Online")

	flex := tview.NewFlex().
		AddItem(tview.NewFlex().
			SetDirection(tview.FlexColumn).
			AddItem(online, 0, 1, false).
			AddItem(chat, 0, 3, false), 0, 1, false).
		SetDirection(tview.FlexRow).
		AddItem(input, 1, 1, true)

	boxes := []tview.Primitive{input, online, chat}
	focus := 0
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyTAB {
			if focus == 3 {
				focus = 0
			}
			app.SetFocus(boxes[focus])
			focus++
			debugLog(fmt.Sprintf("focus %d\n", focus))
		}
		return event
	})

	return flex, chat, online
}

func hash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

func colorIndex(s string) uint32 {
	debugLog(fmt.Sprintf("colorindex: %d", hash(s)%uint32(len(colors))))
	return hash(s) % uint32(len(colors))
}

func netHash() {
	mux.Lock()
	keys := make([]string, 0, len(network))
	for k := range network {
		keys = append(keys, k)
	}
	mux.Unlock()
	sort.Strings(keys)
	networkHash = hash(strings.Join(keys, ""))
}

func ownIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// func isIpValid(ip string) bool {
// return ipregex.Match(ip)
// hostname, err := net.LookupHost(ip)
// if err != nil {
// 	return false
// }
// if len(hostname) > 0 {
// 	debugLog("ip checked: " + hostname[0])
// }
// return true
// }
