package main

import (
	"os"

	"github.com/spf13/pflag"

	"github.com/jbvmio/kubectl-login/pkg/cmd"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func main() {
	flags := pflag.NewFlagSet("kubectl-login", pflag.ExitOnError)
	pflag.CommandLine = flags

	root := cmd.NewLogin(genericclioptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr})
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
