package Plugins

import (
	"Alive/utils"
	"fmt"
	gosnmp2 "github.com/gosnmp/gosnmp"
	"sync"
	"time"
)

func snmpConnect(ip string) bool {
	gosnmp := InitgoSnmp(ip, 161, "public", "2c")
	err := gosnmp.Connect()
	if err != nil {
		return false
	}
	defer gosnmp.Conn.Close()
	_, err = gosnmp.Get([]string{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"})
	if err != nil {
		return false
	}
	return true
}

func InitgoSnmp(ip string, port int, password string, version string) *gosnmp2.GoSNMP {
	gosnmp := &gosnmp2.GoSNMP{
		Target:    ip,
		Port:      uint16(port),
		Community: password,
		Transport: "udp",
		Timeout:   3 * time.Second,
		Retries:   1,
		MaxOids:   gosnmp2.MaxOids,
	}
	switch version {
	case "1":
		gosnmp.Version = gosnmp2.Version1
	case "2c":
		gosnmp.Version = gosnmp2.Version2c
	case "3":
		gosnmp.Version = gosnmp2.Version3
	}
	return gosnmp
}

func SnmapCheck(hostlists []string, threadNum int, logfile string) {
	var chanHosts chan string
	wg := &sync.WaitGroup{}
	if len(hostlists) >= threadNum {
		chanHosts = make(chan string, threadNum)
	} else {
		chanHosts = make(chan string, len(hostlists))
	}

	for i := 0; i < threadNum; i++ {
		go SnmapScan(chanHosts, wg, logfile)
	}
	for _, host := range hostlists {
		wg.Add(1)
		chanHosts <- host
	}
	close(chanHosts)
	wg.Wait()
}

func SnmapScan(chanhost chan string, wg *sync.WaitGroup, logfile string) {
	for host := range chanhost {
		if snmpConnect(host) {
			fmt.Println("snmp:" + host)
			utils.LogSuccess(host, "snmp", logfile)
			wg.Done()
		} else {
			wg.Done()
		}
	}
}
