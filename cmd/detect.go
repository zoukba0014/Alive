/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"Alive/Plugins"
	"Alive/utils"
	"fmt"
	"github.com/spf13/cobra"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// detectCmd represents the detect command
var detectCmd = &cobra.Command{
	Use: "AliveNetDetect",
	Example: `Alive AliveNetDetect -a -r 3
Alive -i 192.168.0.0/16 -r 5`,
	Args:  cobra.ExactArgs(0),
	Short: "alive network detect",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		//fmt.Println("detect start")
		if Intranet {
			fmt.Println("detect start")
			Alivedetect(Allipdetect(Randomint))
		} else if Ip != "" {
			fmt.Println("detect start")
			Alivedetect(Detectip(Ip))
		} else {
			fmt.Println("use -h ")
			os.Exit(1)
		}
		fmt.Println("detect down")
	},
}

var (
	Intranet   bool
	Ip         string
	Randomint  int
	Outputfile string
	ThreadNum  int
)

func init() {
	rootCmd.AddCommand(detectCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// detectCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// detectCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	detectCmd.Flags().BoolVarP(&Intranet, "allip", "a", false, "192.168.0.0/16,172.16.0.0-172.31.255.255,10.0.0.0/8")
	detectCmd.Flags().StringVarP(&Ip, "ip", "i", "", "detect ip segment")
	detectCmd.Flags().IntVarP(&Randomint, "randomNumber", "r", 1, "the random number of ip segment")
	detectCmd.Flags().StringVarP(&Outputfile, "outputfile", "o", "detect.txt", "outputfile")
	detectCmd.Flags().IntVarP(&ThreadNum, "threadnums", "t", 100, "number of threads")
}
func Allipdetect(randomint int) []string {
	var host []string
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 256; i++ {
		for j := 0; j < 256; j++ {
			host = append(host, "10."+strconv.Itoa(i)+"."+strconv.Itoa(j)+".1")
			host = append(host, "10."+strconv.Itoa(i)+"."+strconv.Itoa(j)+".255")
			for x := 0; x < randomint; x++ {
				host = append(host, "10."+strconv.Itoa(i)+"."+strconv.Itoa(j)+"."+strconv.Itoa(rand.Intn(254)+1))
			}
			//host = append(host, "10."+strconv.Itoa(i)+"."+strconv.Itoa(j)+"."+strconv.Itoa(rand.Intn(254)+1))
		}
	}
	for i := 16; i < 32; i++ {
		for j := 0; j < 256; j++ {
			//rand.Seed(time.Now().Unix())
			host = append(host, "172."+strconv.Itoa(i)+"."+strconv.Itoa(j)+".1")
			host = append(host, "172."+strconv.Itoa(i)+"."+strconv.Itoa(j)+".255")
			for x := 0; x < randomint; x++ {
				host = append(host, "172."+strconv.Itoa(i)+"."+strconv.Itoa(j)+"."+strconv.Itoa(rand.Intn(254)+1))
			}
		}
	}
	for i := 0; i < 256; i++ {
		//rand.Seed(time.Now().Unix())
		host = append(host, "192.168."+strconv.Itoa(i)+".1")
		host = append(host, "192.168."+strconv.Itoa(i)+".255")
		for x := 0; x < randomint; x++ {
			host = append(host, "192.168."+strconv.Itoa(i)+"."+strconv.Itoa(rand.Intn(254)+1))
		}
	}
	return host
}

func Detectip(ip string) []string {
	var host []string
	if strings.Contains(ip, ",") {
		IPList := strings.Split(ip, ",")
		for _, ip := range IPList {
			host = append(host, parseIP(ip)...)
		}
	} else {
		host = append(host, parseIP(ip)...)
	}
	//fmt.Println(host)
	return host
}

func parseIP(ip string) []string {
	//reg := regexp.MustCompile(`[a-zA-Z]+`)
	switch {
	case strings.Contains(ip, "/"):
		return parseIP1(ip, Randomint)
	case strings.Contains(ip, "-"):
		return paresIP2(ip)
	default:
		testIP := net.ParseIP(ip)
		if testIP == nil {
			return nil
		}
		return []string{ip}
	}
}

func parseIP1(ip string, randomint int) []string {
	var host []string
	switch {
	case strings.Split(ip, "/")[1] == "8":
		preip := strings.Split(ip, "/")[0]
		rand.Seed(time.Now().UnixNano())
		for i := 0; i < 256; i++ {
			for j := 0; j < 256; j++ {
				host = append(host, strings.Split(preip, ".")[0]+"."+strconv.Itoa(i)+"."+strconv.Itoa(j)+".1")
				host = append(host, strings.Split(preip, ".")[0]+"."+strconv.Itoa(i)+"."+strconv.Itoa(j)+".255")
				for x := 0; x < randomint; x++ {
					host = append(host, strings.Split(preip, ".")[0]+"."+strconv.Itoa(i)+"."+strconv.Itoa(j)+"."+strconv.Itoa(rand.Intn(254)+1))
				}
			}
		}
		return host
	case strings.Split(ip, "/")[1] == "16":
		//fmt.Println(strings.Split(ip, "/")[1])
		preip := strings.Split(ip, "/")[0]
		rand.Seed(time.Now().UnixNano())
		for i := 0; i < 256; i++ {
			//rand.Seed(time.Now().Unix())
			//fmt.Println(strings.Split(preip, ".")[0] + "." + strings.Split(preip, ".")[1] + "." + strconv.Itoa(i) + ".1")
			host = append(host, strings.Split(preip, ".")[0]+"."+strings.Split(preip, ".")[1]+"."+strconv.Itoa(i)+".1")
			host = append(host, strings.Split(preip, ".")[0]+"."+strings.Split(preip, ".")[1]+"."+strconv.Itoa(i)+".255")
			for x := 0; x < randomint; x++ {
				host = append(host, strings.Split(preip, ".")[0]+"."+strings.Split(preip, ".")[1]+"."+strconv.Itoa(i)+"."+strconv.Itoa(rand.Intn(254)+1))
			}
		}
		return host
	case strings.Split(ip, "/")[1] == "24":
		preip := strings.Split(ip, "/")[0]
		rand.Seed(time.Now().UnixNano())
		host = append(host, strings.Split(preip, ".")[0]+"."+strings.Split(preip, ".")[1]+"."+strings.Split(preip, ".")[2]+".1")
		host = append(host, strings.Split(preip, ".")[0]+"."+strings.Split(preip, ".")[1]+"."+strings.Split(preip, ".")[2]+".255")
		for x := 0; x < randomint; x++ {
			host = append(host, strings.Split(preip, ".")[0]+"."+strings.Split(preip, ".")[1]+"."+strings.Split(preip, ".")[2]+"."+strconv.Itoa(rand.Intn(254)+1))
		}
		return host
	default:
		testIP := net.ParseIP(ip)
		if testIP == nil {
			return nil
		}
		return []string{ip}
	}
}
func paresIP2(ip string) []string {
	var host []string
	ip1 := strings.Split(ip, "-")[0]
	ip2 := strings.Split(ip, "-")[1]
	if strings.Split(ip1, ".")[1] != strings.Split(ip2, ".")[1] {
		num1, err := strconv.Atoi(strings.Split(ip1, ".")[1])
		if err != nil {
			log.Fatal(err)
		}
		num2, err := strconv.Atoi(strings.Split(ip2, ".")[1])
		if err != nil {
			log.Fatal(err)
		}
		for i := num1; i <= num2; i++ {
			iptemp := fmt.Sprintf("%s.%d.0.0/16", strings.Split(ip1, ".")[0], i)
			host = append(host, parseIP1(iptemp, Randomint)...)
		}
	} else if strings.Split(ip1, ".")[2] != strings.Split(ip2, ".")[2] {
		num1, err := strconv.Atoi(strings.Split(ip1, ".")[2])
		if err != nil {
			log.Fatal(err)
		}
		num2, err := strconv.Atoi(strings.Split(ip2, ".")[2])
		if err != nil {
			log.Fatal(err)
		}
		for i := num1; i <= num2; i++ {
			iptemp := fmt.Sprintf("%s.%s.%d.0/24", strings.Split(ip1, ".")[0], strings.Split(ip1, ".")[1], i)
			host = append(host, parseIP1(iptemp, Randomint)...)
		}
	}
	return host
}

func Alivedetect(alliplist []string) {
	var alivehost []string
	rehost := Plugins.CheckLive(alliplist, false, Outputfile, ThreadNum, true)
	for _, value := range rehost {
		line := strings.Split(value, ".")
		if len(line) == 4 {
			value = fmt.Sprintf("%s.%s.%s.1/24", line[0], line[1], line[2])
			fmt.Println(value)
			alivehost = append(alivehost, value)
		}
	}
	realivehost := utils.RemoveDuplicate(alivehost)
	file, err := os.OpenFile(Outputfile, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	for _, line := range realivehost {
		_, err = file.WriteString(line + "\n")
	}
}
