package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

// kubeconfig:
// https://github.com/kubernetes/client-go/blob/77f63643f951f19681397a995fe0916d2d5cb992/tools/clientcmd/api/types.go

// initLogin .
func initLogin(forUser string, explicit bool) (USER, PASS string) {

	switch {
	case stdinAvailable():
		d, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("error reading data from stdin: %v\n", err)
		}
		d = bytes.TrimSpace(d)
		switch {
		case explicit:
			USER = forUser
			PASS = string(d)
		default:
			login := strings.Split(string(d), `:`)
			switch len(login) {
			case 2:
				USER = login[0]
				PASS = login[1]
			default:
				fMsg := `Could not Parse Login, too many ":" ?`
				log.Fatalf("%s\n", fMsg)
			}
		}
	default:
		switch {
		case explicit:
			USER = forUser
			PASS = readSecret(secretPrompt(forUser))
			fmt.Println()
		default:
			if USER = readResponse(userPrompt(forUser)); USER == "" {
				USER = forUser
			}
			PASS = readSecret("AD password: ")
			fmt.Println()
		}
	}
	return
}

func userPrompt(forUser string) string {
	userPrompt := "AD username"
	if forUser != "" {
		userPrompt += ` [` + forUser + `]`
	}
	userPrompt += ": "
	return userPrompt
}

func secretPrompt(forUser string) string {
	userPrompt := "AD password"
	if forUser != "" {
		userPrompt += ` [` + forUser + `]`
	}
	userPrompt += ": "
	return userPrompt
}

func readResponse(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	// fmt.Print is used for compatibility with Windows:
	fmt.Print(prompt)
	r, err := reader.ReadBytes(byte(10))
	if err != nil {
		log.Fatalf("error reading response: %v\n", err)
	}
	r = bytes.TrimSpace(r)
	return fmt.Sprintf("%s", r)
}

func readSecret(prompt string) (secret string) {
	fmt.Fprintf(os.Stderr, prompt)
	byteSecret, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Error reading secret: %v\n", err)
	}
	return string(byteSecret)
}

func stdinAvailable() bool {
	stat, _ := os.Stdin.Stat()
	return (stat.Mode() & os.ModeCharDevice) == 0
}
