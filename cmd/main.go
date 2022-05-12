package main

import (
	"os"

	"github.com/spf13/pflag"

	"github.com/jbvmio/kubectl-login/pkg/cmd"
)

func main() {
	flags := pflag.NewFlagSet("kubectl-login", pflag.ExitOnError)
	pflag.CommandLine = flags

	root := cmd.NewLogin()
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
