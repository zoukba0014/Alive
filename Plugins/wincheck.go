package Plugins

import (
	"Alive/utils"
	"sync"
)

func Wincheck(hostlists []string, threadNum int, logfile string, nbtflag bool, drpcflag bool, oxidflag bool) {
	var chanHosts chan string
	wg := &sync.WaitGroup{}
	if len(hostlists) > threadNum {
		chanHosts = make(chan string, threadNum*2)
	} else {
		chanHosts = make(chan string, len(hostlists)*2)
	}

	for i := 0; i < threadNum; i++ {
		go Winscan(chanHosts, wg, logfile, nbtflag, drpcflag, oxidflag)
	}
	for _, host := range hostlists {
		wg.Add(1)
		chanHosts <- host
	}
	close(chanHosts)
	wg.Wait()
}

func Winscan(chanhost chan string, wg *sync.WaitGroup, logfile string, nbtflag bool, drpcflag bool, oxidflag bool) {
	for host := range chanhost {
		//if OxidScanConn(host) || nbt(host) || DrpcConnect(host) {
		//	utils.LogSuccess(host, "windows:", logfile)
		//	wg.Done()
		//} else {
		//	wg.Done()
		//}
		if nbtflag && drpcflag && oxidflag {
			//if nbt(host) || DrpcConnect(host) || OxidScanConn(host) {
			//	utils.LogSuccess(host, "", logfile)
			//	wg.Done()
			//}
			flag1 := nbt(host)
			flag2 := DrpcConnect(host)
			flag3 := OxidScanConn(host)
			if flag1 || flag2 || flag3 {
				utils.LogSuccess(host, "", logfile)
				wg.Done()
			} else {
				wg.Done()
			}
		} else if nbtflag && drpcflag {
			flag1 := nbt(host)
			flag2 := DrpcConnect(host)
			//flag3 := OxidScanConn(host)
			if flag1 || flag2 {
				utils.LogSuccess(host, "", logfile)
				wg.Done()
			} else {
				wg.Done()
			}
		} else if nbtflag && oxidflag {
			flag1 := nbt(host)
			//flag2 := DrpcConnect(host)
			flag3 := OxidScanConn(host)
			if flag1 || flag3 {
				utils.LogSuccess(host, "", logfile)
				wg.Done()
			} else {
				wg.Done()
			}
		} else if drpcflag && oxidflag {
			//flag1 := nbt(host)
			flag2 := DrpcConnect(host)
			flag3 := OxidScanConn(host)
			if flag2 || flag3 {
				utils.LogSuccess(host, "", logfile)
				wg.Done()
			} else {
				wg.Done()
			}
		} else if nbtflag {
			//wg.Done()
			flag1 := nbt(host)
			//flag2 := DrpcConnect(host)
			//flag3 := OxidScanConn(host)
			if flag1 {
				utils.LogSuccess(host, "", logfile)
				wg.Done()
			} else {
				wg.Done()
			}
		} else if drpcflag {
			//flag1 := nbt(host)
			flag2 := DrpcConnect(host)
			//flag3 := OxidScanConn(host)
			if flag2 {
				utils.LogSuccess(host, "", logfile)
				wg.Done()
			} else {
				wg.Done()
			}
		} else if oxidflag {
			flag3 := OxidScanConn(host)
			if flag3 {
				utils.LogSuccess(host, "", logfile)
				wg.Done()
			} else {
				wg.Done()
			}
		} else {
			wg.Done()
		}
	}
}
