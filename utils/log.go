package utils

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
)

var mutex sync.Mutex

func LogSuccess(host string, strings string, LogFile string) {
	mutex.Lock()
	//fmt.Println(strings + ":" + host)
	file, err := os.OpenFile(LogFile, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	_, err = file.WriteString(host + "\n")
	mutex.Unlock()
}

func LogSuccessP(host string, LogFile string) {
	mutex.Lock()
	//address := host + ":" + strconv.Itoa(port)
	fmt.Println(host)
	file, err := os.OpenFile(LogFile, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	ip := strings.Split(host, ":")
	_, err = file.WriteString(ip[0] + "\n")
	mutex.Unlock()
}
