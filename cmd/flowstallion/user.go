// user.go: user management commands (P6①) — flowstallion users / flowstallion user add / flowstallion user del.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
)

type usersOut struct {
	Users []struct {
		Username string `json:"username"`
		Role     string `json:"role"`
		Created  string `json:"created_at"`
	} `json:"users"`
}

func runUsers(args []string) {
	fs := flag.NewFlagSet("users", flag.ExitOnError)
	fs.Parse(args)
	c, err := apiClient()
	if err != nil {
		fatalConfig(err)
	}
	var out usersOut
	if err := c.doJSON(http.MethodGet, "/api/users", nil, &out); err != nil {
		fatalAPI(err)
	}
	fmt.Printf("%-16s %-10s %s\n", "NAME", "ROLE", "CREATED")
	for _, u := range out.Users {
		fmt.Printf("%-16s %-10s %s\n", u.Username, u.Role, u.Created)
	}
}

func runUser(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: flowstallion user add|del ...")
		os.Exit(1)
	}
	switch args[0] {
	case "add":
		runUserAdd(args[1:])
	case "del", "delete":
		runUserDel(args[1:])
	default:
		fmt.Fprintln(os.Stderr, "usage: flowstallion user add|del ...")
		os.Exit(1)
	}
}

func runUserAdd(args []string) {
	fs := flag.NewFlagSet("user-add", flag.ExitOnError)
	role := fs.String("role", "viewer", "role: viewer|operator|admin")
	password := fs.String("password", "", "initial password (prompted if empty)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: flowstallion user add <name> [--role viewer|operator|admin] [--password <pass>]")
	}
	args = extractFlags(args, []string{"--role", "--password", "-role", "-password"})
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}
	name := fs.Arg(0)
	if !roleValid(*role) {
		fmt.Fprintf(os.Stderr, "flowstallion: invalid role %q (want viewer|operator|admin)\n", *role)
		os.Exit(1)
	}
	if *password == "" {
		fmt.Fprint(os.Stderr, "Password: ")
		if _, err := fmt.Scanln(&*password); err != nil {
			fmt.Fprintf(os.Stderr, "flowstallion: cannot read password: %v\n", err)
			os.Exit(1)
		}
	}
	if len(*password) < 8 {
		fmt.Fprintln(os.Stderr, "flowstallion: password must be at least 8 characters")
		os.Exit(1)
	}
	c, err := apiClient()
	if err != nil {
		fatalConfig(err)
	}
	body := map[string]string{"username": name, "role": *role, "password": *password}
	if err := c.doJSON(http.MethodPost, "/api/users", body, nil); err != nil {
		fatalAPI(err)
	}
	fmt.Printf("User %q created (role %s)\n", name, *role)
}

func runUserDel(args []string) {
	fs := flag.NewFlagSet("user-del", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: flowstallion user del <name>")
		os.Exit(1)
	}
	name := fs.Arg(0)
	c, err := apiClient()
	if err != nil {
		fatalConfig(err)
	}
	if err := c.doJSON(http.MethodDelete, "/api/users/"+url.PathEscape(name), nil, nil); err != nil {
		fatalAPI(err)
	}
	fmt.Printf("User %q deleted\n", name)
}

func roleValid(role string) bool {
	switch role {
	case "viewer", "operator", "admin":
		return true
	}
	return false
}
