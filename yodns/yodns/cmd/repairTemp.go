package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"path"
	"path/filepath"
	"time"
)

var RepairTemp = &cobra.Command{
	Use:   "repairTemp",
	Short: "Repairs .tmp files created by the scanner",
	Long: "If a scan crashes and is continued later, there might be .tmp files left over. " +
		"These files just end prematurely, however all but the last lines are still valid resolutions. " +
		"This command removes the invalid ending, rezips them and names changes the file ending.",
	Run: func(cmd *cobra.Command, args []string) {
		in := Must(cmd.Flags().GetString("in"))
		size := Must(cmd.Flags().GetUint("size"))
		outDir := path.Dir(in)
		zip := serialization.ZipZSTD

		paths, err := filepath.Glob(in)
		if err != nil {
			panic(err)
		}
		for _, file := range paths {
			out := getWriter(outDir, size, "protobuf", true)

			c := make(chan resolver.Result)

			reader := getFilteredReaderZip(file, "protobuf", false, &zip, 5*time.Minute)
			go func() {
				if err := reader.ReadTo(c); err != nil {
					fmt.Println(fmt.Sprintf("caught error %v", err))
				}
			}()

			for p := range c {
				if err := out.WriteAsync(p); err != nil {
					panic(err)
				}
			}

			if err := out.Wait(); err != nil {
				panic(err)
			}

		}
	},
}

func init() {
	rootCmd.AddCommand(RepairTemp)
	RepairTemp.Flags().String("in", "", "")
	RepairTemp.Flags().Uint("size", 200, "Max number of items after repacking")
}
