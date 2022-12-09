/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"Alive/Plugins"
	"Alive/utils"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// smbscanCmd represents the smbscan command
var smbscanCmd = &cobra.Command{
	Use:   "smb",
	Short: "use smb detect",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if Ip != "" {
			host, _ := utils.ParseIP(Ip, "")
			Plugins.SmbCheck(host, ThreadNum, Outputfile)
		} else if Ipfile != "" {
			host, _ := utils.ParseIP("", Ipfile)
			Plugins.SmbCheck(host, ThreadNum, Outputfile)
		} else {
			fmt.Println("use -h")
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(smbscanCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// smbscanCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// smbscanCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	smbscanCmd.Flags().StringVarP(&Ipfile, "ipfile", "f", "", "target file")
	smbscanCmd.Flags().StringVarP(&Ip, "iplist", "i", "", "ip target 192.168.0.0/16,172.16.0.0-172.31.255.255,10.0.0.0/8")
	smbscanCmd.Flags().StringVarP(&Outputfile, "outputfile", "o", "alive.txt", "outputfile")
	smbscanCmd.Flags().IntVarP(&ThreadNum, "threadnums", "t", 100, "number of threads")
}
