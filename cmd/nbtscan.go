/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"Alive/Plugins"
	"Alive/utils"
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

// nbtscanCmd represents the nbtscan command
var nbtscanCmd = &cobra.Command{
	Use:   "nbt",
	Short: "use netbios detect",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if Ip != "" {
			host, _ := utils.ParseIP(Ip, "")
			Plugins.NbtCheck(host, ThreadNum, Outputfile)
		} else if Ipfile != "" {
			host, _ := utils.ParseIP("", Ipfile)
			Plugins.NbtCheck(host, ThreadNum, Outputfile)
		} else {
			fmt.Println("use -h")
			os.Exit(1)
		}
	},
}

//var (
//	Ipfile string
//)

func init() {
	rootCmd.AddCommand(nbtscanCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// nbtscanCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// nbtscanCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	nbtscanCmd.Flags().StringVarP(&Ipfile, "ipfile", "f", "", "target file")
	nbtscanCmd.Flags().StringVarP(&Ip, "iplist", "i", "", "ip target 192.168.0.0/16,172.16.0.0-172.31.255.255,10.0.0.0/8")
	nbtscanCmd.Flags().StringVarP(&Outputfile, "outputfile", "o", "alive.txt", "outputfile")
	nbtscanCmd.Flags().IntVarP(&ThreadNum, "threadnums", "t", 100, "number of threads")
}
