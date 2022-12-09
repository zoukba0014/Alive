package Plugins

import (
	"Alive/utils"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

type Addr struct {
	ip   string
	port int
}

func PortScan(hostslist []string, ports string, timeout int64, workers int, logfile string) []string {
	var AliveAddress []string
	probePorts := utils.ParsePort(ports)
	//noPorts := common.ParsePort(common.NoPorts)
	//if len(noPorts) > 0 {
	//	temp := map[int]struct{}{}
	//	for _, port := range probePorts {
	//		temp[port] = struct{}{}
	//	}
	//
	//	for _, port := range noPorts {
	//		delete(temp, port)
	//	}
	//
	//	var newDatas []int
	//	for port, _ := range temp {
	//		newDatas = append(newDatas, port)
	//	}
	//	probePorts = newDatas
	//	sort.Ints(probePorts)
	//}
	//workers := common.Threads
	Addrs := make(chan Addr, len(hostslist)*len(probePorts))
	results := make(chan string, len(hostslist)*len(probePorts))
	var wg sync.WaitGroup

	//接收结果
	go func() {
		for found := range results {
			AliveAddress = append(AliveAddress, found)
			wg.Done()
		}
	}()

	//多线程扫描
	for i := 0; i < workers; i++ {
		go func() {
			for addr := range Addrs {
				PortConnect(addr, results, timeout, &wg, logfile)
				wg.Done()
			}
		}()
	}

	//添加扫描目标
	for _, port := range probePorts {
		for _, host := range hostslist {
			wg.Add(1)
			Addrs <- Addr{host, port}
		}
	}
	wg.Wait()
	close(Addrs)
	close(results)
	return AliveAddress
}

func WrapperTcpWithTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return WrapperTCP(network, address, d)
}

func WrapperTCP(network, address string, forward *net.Dialer) (net.Conn, error) {
	//get conn
	var conn net.Conn

	var err error
	conn, err = forward.Dial(network, address)
	if err != nil {
		return nil, err
	}

	return conn, nil

}

func PortConnect(addr Addr, respondingHosts chan<- string, adjustedTimeout int64, wg *sync.WaitGroup, logfile string) {
	host, port := addr.ip, addr.port
	conn, err := WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%v", host, port), time.Duration(adjustedTimeout)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err == nil {
		address := host + ":" + strconv.Itoa(port)
		//result := fmt.Sprintf("%s open", address)
		utils.LogSuccessP(address, logfile)
		wg.Add(1)
		respondingHosts <- address
	}
}

//func NoPortScan(hostslist []string, ports string) (AliveAddress []string) {
//	probePorts := common.ParsePort(ports)
//	noPorts := common.ParsePort(common.NoPorts)
//	if len(noPorts) > 0 {
//		temp := map[int]struct{}{}
//		for _, port := range probePorts {
//			temp[port] = struct{}{}
//		}
//
//		for _, port := range noPorts {
//			delete(temp, port)
//		}
//
//		var newDatas []int
//		for port, _ := range temp {
//			newDatas = append(newDatas, port)
//		}
//		probePorts = newDatas
//		sort.Ints(probePorts)
//	}
//	for _, port := range probePorts {
//		for _, host := range hostslist {
//			address := host + ":" + strconv.Itoa(port)
//			AliveAddress = append(AliveAddress, address)
//		}
//	}
//	return
//}
