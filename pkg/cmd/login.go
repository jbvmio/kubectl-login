package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"k8s.io/client-go/tools/clientcmd/api"

	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// LoginOptions provides information required to log into
// the current context on a user's KUBECONFIG
type LoginOptions struct {
	configFlags *genericclioptions.ConfigFlags

	resultingContext     *api.Context
	resultingContextName string

	userSpecifiedCluster   string
	userSpecifiedContext   string
	userSpecifiedAuthInfo  string
	userSpecifiedNamespace string

	userFlagUsed bool

	rawConfig    api.Config
	listClusters bool
	args         []string
}

// NewNamespaceOptions provides an instance of NamespaceOptions with default values
func NewLoginOptions() *LoginOptions {
	return &LoginOptions{
		configFlags: genericclioptions.NewConfigFlags(true),
	}
}

// NewLogin provides a cobra command wrapping NamespaceOptions
func NewLogin() *cobra.Command {
	o := NewLoginOptions()

	cmd := &cobra.Command{
		Use:          "login [new-namespace] [flags]",
		Short:        "Login OIDC",
		Example:      fmt.Sprintf(namespaceExample, "kubectl"),
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			if err := o.Complete(c, args); err != nil {
				return err
			}
			if err := o.Validate(); err != nil {
				return err
			}

			fmt.Printf("Context:\n %+v\n", o.rawConfig.Contexts[o.resultingContextName])
			fmt.Printf("api.Context:\n %+v\n", o.resultingContext)
			fmt.Printf("rawConfig:\n %+v\n", o.rawConfig)

			if err := o.Run(); err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&o.listClusters, "list-clusters", "l", o.listClusters, "if true, print the list of all clusters in the current KUBECONFIG")
	o.configFlags.AddFlags(cmd.Flags())

	return cmd
}

// Complete sets all information required for updating the current context
func (o *LoginOptions) Complete(cmd *cobra.Command, args []string) error {
	o.args = args

	var err error
	o.rawConfig, err = o.configFlags.ToRawKubeConfigLoader().RawConfig()
	if err != nil {
		return err
	}

	o.userSpecifiedContext, err = cmd.Flags().GetString("context")
	if err != nil {
		return err
	}

	o.userSpecifiedCluster, err = cmd.Flags().GetString("cluster")
	if err != nil {
		return err
	}

	o.userSpecifiedAuthInfo, err = cmd.Flags().GetString("user")
	if err != nil {
		return err
	}

	o.userSpecifiedNamespace, err = cmd.Flags().GetString("namespace")
	if err != nil {
		return err
	}

	currentContext, exists := o.rawConfig.Contexts[o.rawConfig.CurrentContext]
	if !exists {
		return errNoContext
	}

	o.resultingContext = api.NewContext()
	o.resultingContext.Cluster = currentContext.Cluster
	o.resultingContext.AuthInfo = currentContext.AuthInfo
	o.resultingContext.Namespace = currentContext.Namespace

	// if a target context is explicitly provided by the user,
	// use that as our reference for the final, resulting context
	switch len(o.userSpecifiedContext) {
	case 0:
		o.resultingContextName = o.rawConfig.CurrentContext
	default:
		o.resultingContextName = o.userSpecifiedContext
		if userCtx, exists := o.rawConfig.Contexts[o.userSpecifiedContext]; exists {
			o.resultingContext = userCtx.DeepCopy()
		}
	}

	if len(o.userSpecifiedCluster) > 0 {
		o.resultingContext.Cluster = o.userSpecifiedCluster
	}
	if len(o.userSpecifiedAuthInfo) > 0 {
		o.userFlagUsed = true
		o.resultingContext.AuthInfo = o.userSpecifiedAuthInfo
	}
	if len(o.userSpecifiedNamespace) > 0 {
		o.resultingContext.Namespace = o.userSpecifiedNamespace
	}

	return nil
}

// Validate ensures that all required arguments and flag values are provided
func (o *LoginOptions) Validate() error {
	if len(o.resultingContextName) == 0 {
		return errNoContext
	}
	if len(o.args) >= 1 {
		return fmt.Errorf("no arguments are allowed")
	}

	// Capture Login Credentials Here:
	user, pass := initLogin(o.resultingContext.AuthInfo, o.userFlagUsed)
	fmt.Printf(">> USER: %q\n", user)
	fmt.Printf(">> PASS: %q\n", pass)
	switch "" {
	case user:
		return fmt.Errorf("empty username")
	case pass:
		return fmt.Errorf("empty password")
	}
	return nil
}

// Run .
func (o *LoginOptions) Run() error {
	return o.login()
}

func (o *LoginOptions) login() error {

	// determine if we have already saved this context to the user's KUBECONFIG before
	// if so, simply switch the current context to the existing one.
	if existingResultingCtx, exists := o.rawConfig.Contexts[o.resultingContextName]; !exists || !o.isContextEqual(existingResultingCtx) {
		fmt.Println(">>HERE<<")
		o.rawConfig.Contexts[o.resultingContextName] = o.resultingContext
	}
	o.rawConfig.CurrentContext = o.resultingContextName

	fmt.Printf(">>>>\nCONTEXT:\n %+v\n", o.rawConfig.Contexts[o.resultingContextName])
	return nil
}

func (o *LoginOptions) isContextEqual(ctxB *api.Context) bool {
	if o.resultingContext == nil || ctxB == nil {
		fmt.Println(1)
		return false
	}
	if o.resultingContext.Cluster != ctxB.Cluster {
		fmt.Println(2)
		return false
	}
	if o.resultingContext.Namespace != ctxB.Namespace {
		fmt.Println(3)
		return false
	}
	if o.resultingContext.AuthInfo != ctxB.AuthInfo {
		fmt.Println(4)
		return false
	}
	fmt.Println(5)
	return true
}
