package cmd

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"

	"k8s.io/cli-runtime/pkg/genericclioptions"
)

const defaultUser = `kubectl-login-user`

var (
	loginExample = `
	# login interactively
	%[1]s login
	# login with username
	%[1]s login --user <username>
	# login using piped credentials
	echo '<username>:<password>' | %[1]s login
`

	errNoContext = fmt.Errorf("no context is currently set, use %q to select a new one", "kubectl config use-context <context>")
	buildTime    string
	commitHash   string
)

// LoginOptions provides information required to log into
// the current context on a user's KUBECONFIG
type LoginOptions struct {
	configFlags            *genericclioptions.ConfigFlags
	resultingContext       *api.Context
	rawConfig              api.Config
	resultingContextName   string
	userSpecifiedCluster   string
	userSpecifiedContext   string
	userSpecifiedAuthInfo  string
	userSpecifiedNamespace string
	userSpecifiedPassword  string
	userFlagUsed           bool
	issuerBaseURL          string
	printVersion           bool
	args                   []string
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
		Example:      fmt.Sprintf(loginExample, "kubectl"),
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			if o.printVersion {
				fmt.Printf("kubectl-login : %s\n", `tools@etrade.com`)
				fmt.Printf("Version       : %s\n", buildTime)
				fmt.Printf("Commit        : %s\n", commitHash)
				return nil
			}
			if err := o.Complete(c, args); err != nil {
				return err
			}
			if err := o.Validate(); err != nil {
				return err
			}
			if err := o.Run(); err != nil {
				return err
			}

			return nil
		},
	}
	cmd.Flags().BoolVarP(&o.printVersion, "version", "v", o.printVersion, "Print Version and Exit")
	o.configFlags.AddFlags(cmd.Flags())
	return cmd
}

// Complete sets all information required for updating the current context
func (o *LoginOptions) Complete(cmd *cobra.Command, args []string) error {
	o.args = args
	if len(o.args) >= 1 {
		return fmt.Errorf("no arguments are allowed")
	}

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
	usr := o.resultingContext.AuthInfo
	if strings.Contains(usr, `__`) {
		usr = strings.Split(usr, `__`)[0]
	}
	// Capture Login Credentials Here:
	user, pass := initLogin(usr, o.userFlagUsed)
	switch "" {
	case user:
		return fmt.Errorf("empty username")
	case pass:
		return fmt.Errorf("empty password")
	}
	if user == defaultUser {
		return fmt.Errorf("error: can't use %q", defaultUser)
	}
	o.resultingContext.AuthInfo = user
	o.userSpecifiedPassword = pass
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
		o.rawConfig.Contexts[o.resultingContextName] = o.resultingContext
	}
	o.rawConfig.CurrentContext = o.resultingContextName
	U, err := contextOIDCIssuer(o.rawConfig)
	switch {
	case err != nil:
		return err
	case U == "":
		return fmt.Errorf("empty oidc issuing url")
	}
	U = strings.TrimSpace(U)
	iHash := base64.StdEncoding.EncodeToString([]byte(U))

	usr := o.resultingContext.AuthInfo
	if strings.Contains(usr, `__`) {
		usr = strings.Split(usr, `__`)[0]
	}
	usrClu := usr + `__` + iHash
	o.rawConfig.Contexts[o.resultingContextName].AuthInfo = usrClu

	usrAuth := &api.AuthInfo{}
	if _, there := o.rawConfig.AuthInfos[usrClu]; there {
		usrAuth = o.rawConfig.AuthInfos[usrClu]
	}

	authConfig := newAuthConfig(U)
	err = startAuth(authConfig, U, usr, o.userSpecifiedPassword)
	if err != nil {
		return fmt.Errorf("error authenticating to oidc provider: %w", err)
	}
	usrAuth.AuthProvider = authConfig
	o.rawConfig.AuthInfos[usrClu] = usrAuth
	configAccess := clientcmd.NewDefaultPathOptions()
	configAccess.LoadingRules.ExplicitPath = *o.configFlags.KubeConfig
	removeDefaultUser(&o.rawConfig, usrClu)
	return clientcmd.ModifyConfig(configAccess, o.rawConfig, true)
}

func (o *LoginOptions) isContextEqual(ctxB *api.Context) bool {
	if o.resultingContext == nil || ctxB == nil {
		return false
	}
	if o.resultingContext.Cluster != ctxB.Cluster {
		return false
	}
	if o.resultingContext.Namespace != ctxB.Namespace {
		return false
	}
	if o.resultingContext.AuthInfo != ctxB.AuthInfo {
		return false
	}
	return true
}

func removeDefaultUser(config *api.Config, newUser string) {
	if _, there := config.AuthInfos[defaultUser]; !there {
		return
	}
	for ctx := range config.Contexts {
		if config.Contexts[ctx].AuthInfo == defaultUser {
			config.Contexts[ctx].AuthInfo = newUser
		}
	}
	delete(config.AuthInfos, defaultUser)
}
