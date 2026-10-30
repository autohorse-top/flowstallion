// secret.go: secret management commands (P6②) — flowstallion secret set / list / rm.
//
// Values are sent to the scheduler over the API; the scheduler stores them
// AES-encrypted. The value itself is never echoed back by the API.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type secretsOut struct {
	Secrets []struct {
		Name    string `json:"name"`
		Created string `json:"created_at"`
		Updated string `json:"updated_at"`
	} `json:"secrets"`
}

func runSecret(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: flowstallion secret set|list|rm ...")
		os.Exit(1)
	}
	switch args[0] {
	case "set":
		runSecretSet(args[1:])
	case "list", "ls":
		runSecretList()
	case "rm", "delete":
		runSecretDel(args[1:])
	default:
		fmt.Fprintln(os.Stderr, "usage: flowstallion secret set|list|rm ...")
		os.Exit(1)
	}
}

func runSecretSet(args []string) {
	fs := flag.NewFlagSet("secret-set", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: flowstallion secret set <name> [value]   (value read from stdin if omitted)")
	}
	fs.Parse(args)
	if fs.NArg() < 1 || fs.NArg() > 2 {
		fs.Usage()
		os.Exit(1)
	}
	name := fs.Arg(0)
	value := ""
	if fs.NArg() == 2 {
		value = fs.Arg(1)
	} else {
		fi, err := os.Stdin.Stat()
		if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
			// piped / redirected: read the whole stream
			b, rerr := io.ReadAll(os.Stdin)
			if rerr != nil {
				fmt.Fprintf(os.Stderr, "flowstallion: cannot read value from stdin: %v\n", rerr)
				os.Exit(1)
			}
			value = string(b)
			// trim exactly one trailing newline
			value = strings.TrimSuffix(value, "\n")
		} else {
			// interactive terminal: prompt for one line
			fmt.Fprint(os.Stderr, "Value: ")
			if _, err := fmt.Scanln(&value); err != nil {
				fmt.Fprintf(os.Stderr, "flowstallion: cannot read value: %v\n", err)
				os.Exit(1)
			}
		}
	}
	c, err := apiClient()
	if err != nil {
		fatalConfig(err)
	}
	body := map[string]string{"name": name, "value": value}
	var out map[string]any
	if err := c.doJSON(http.MethodPost, "/api/secrets", body, &out); err != nil {
		fatalAPI(err)
	}
	fmt.Printf("Secret %q saved\n", name)
}

func runSecretList() {
	c, err := apiClient()
	if err != nil {
		fatalConfig(err)
	}
	var out secretsOut
	if err := c.doJSON(http.MethodGet, "/api/secrets", nil, &out); err != nil {
		fatalAPI(err)
	}
	if len(out.Secrets) == 0 {
		fmt.Println("No secrets stored.")
		return
	}
	fmt.Printf("%-28s %-22s %s\n", "NAME", "CREATED", "UPDATED")
	for _, s := range out.Secrets {
		fmt.Printf("%-28s %-22s %s\n", s.Name, s.Created, s.Updated)
	}
}

func runSecretDel(args []string) {
	fs := flag.NewFlagSet("secret-del", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: flowstallion secret rm <name>")
	}
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}
	name := fs.Arg(0)
	c, err := apiClient()
	if err != nil {
		fatalConfig(err)
	}
	if err := c.doJSON(http.MethodDelete, "/api/secrets/"+url.PathEscape(name), nil, nil); err != nil {
		fatalAPI(err)
	}
	fmt.Printf("Secret %q deleted\n", name)
}
