package Plugins

import (
	"Alive/utils"
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

func OxidScanConn(host string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", host, 135), 3*time.Second)
	if err != nil {
		return false
	}

	msg1 := "\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00\xf8\x0f\xf8\x0f\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\xc4\xfe\xfc\x99\x60\x52\x1b\x10\xbb\xcb\x00\xaa\x00\x21\x34\x7a\x00\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00"
	msg2 := "\x05\x00\x00\x03\x10\x00\x00\x00\x18\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00"
	_, err = conn.Write([]byte(msg1))
	if err != nil {
		return false
	}
	reply1 := make([]byte, 256)
	_, _ = conn.Read(reply1)

	if hex.EncodeToString(reply1[0:8]) != "05000c0310000000" {
		return false
	}

	_, err = conn.Write([]byte(msg2))
	if err != nil {
		return false
	}

	reply2 := make([]byte, 512)
	_, _ = conn.Read(reply2)
	if conn != nil {
		_ = conn.Close()
	}
	c := 0
	zero := make([]byte, 1)
	var buffer bytes.Buffer
	result := make(map[string]string)
	for i := 0; i < len(reply2[42:]); {
		b := reply2[42:][i : i+2]
		i += 2
		if 42+i == len(reply2[42:]) {
			break
		}
		if string(b) == "\x09\x00" {
			break
		}
		if string(b) == "\x07\x00" {
			c += 1
			if c == 6 {
				break
			}
			buffer.Write([]byte("\x7C\x7C"))
			result["banner.string"] = strings.Join([]string{string(buffer.Bytes())}, ",")
			continue
		}
		if bytes.Equal(b[0:1], zero[0:1]) {
			continue
		}
		buffer.Write(b[0:1])
		result["banner.string"] = strings.Join([]string{string(buffer.Bytes())}, ",")
		if c == 6 {
			break
		}
	}
	if len(strings.Split(result["banner.string"], "||")) > 0 {
		s := fmt.Sprintf("%v", strings.Split(result["banner.string"], "||"))
		q := fmt.Sprintf("[oxid][%v:%v]", host, 135)
		fmt.Println(q + s)
	}
	return true
}

func OxidCheck(hostlists []string, threadNum int, logfile string) {
	var chanHosts chan string
	wg := &sync.WaitGroup{}
	if len(hostlists) > threadNum {
		chanHosts = make(chan string, threadNum)
	} else {
		chanHosts = make(chan string, len(hostlists))
	}

	for i := 0; i < threadNum; i++ {
		go OxidScan(chanHosts, wg, logfile)
	}
	for _, host := range hostlists {
		wg.Add(1)
		chanHosts <- host
	}
	close(chanHosts)
	wg.Wait()
}

func OxidScan(chanhost chan string, wg *sync.WaitGroup, logfile string) {
	for host := range chanhost {
		if OxidScanConn(host) {
			utils.LogSuccess(host, "oxid", logfile)
			wg.Done()
		} else {
			wg.Done()
		}
	}
}
