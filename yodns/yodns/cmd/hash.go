package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/spf13/cobra"
)

var Hash = &cobra.Command{
	Use:     "hash",
	Short:   "Hashes a username and password using SHA256 and returns the checksum.",
	Example: "hash --user '<enter> --password '<enter>'",
	Run: func(cmd *cobra.Command, args []string) {
		user := Must(cmd.Flags().GetString("user"))
		password := Must(cmd.Flags().GetString("password"))

		a := sha256.Sum256([]byte(user))
		fmt.Println("User: ")
		fmt.Println(hex.EncodeToString(a[:]))

		a = sha256.Sum256([]byte(password))
		fmt.Println("Password: ")
		fmt.Println(hex.EncodeToString(a[:]))
	},
}

func init() {
	rootCmd.AddCommand(Hash)

	Hash.Flags().StringP("user", "u", "", "Username to hash.")
	Hash.MarkFlagRequired("user")

	Hash.Flags().StringP("password", "p", "", "Password to hash.")
	Hash.MarkFlagRequired("password")
}
