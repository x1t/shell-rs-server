// Command shell-rs-server keeps ShellRS hosts, credentials and snippets in
// step across one person's devices. It stores only what the devices
// encrypted: the password that unlocks it never reaches the server.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

const usage = `usage:
  shell-rs-server serve [-listen 127.0.0.1:18090] [-db sync.db] [-trust-proxy]
  shell-rs-server user add <name> [-db sync.db] [-password-stdin]
  shell-rs-server user passwd <name> [-db sync.db] [-password-stdin]
  shell-rs-server user list [-db sync.db]
  shell-rs-server user delete <name> [-db sync.db]

user passwd deletes everything the user synced: it was encrypted with a key
from the old password. Their devices upload it again at the next sync.
`

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	switch {
	case len(args) >= 1 && args[0] == "serve":
		return serve(args[1:])
	case len(args) >= 2 && args[0] == "user":
		return userCommand(args[1], args[2:], stdin, stdout)
	default:
		fmt.Fprint(stdout, usage)
		return errors.New("unknown command")
	}
}

func serve(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:18090", "address to listen on")
	dbPath := flags.String("db", "sync.db", "database file")
	trustProxy := flags.Bool("trust-proxy", false, "take X-Real-IP from a proxy on this machine")
	if err := flags.Parse(args); err != nil {
		return err
	}
	store, err := openStore(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	server, err := newServer(store, *trustProxy)
	if err != nil {
		return err
	}
	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           server.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdown)
	}()
	log.Printf("listening on %s", *listen)
	if err := httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func userCommand(action string, args []string, stdin io.Reader, stdout io.Writer) error {
	flags := flag.NewFlagSet("user "+action, flag.ContinueOnError)
	dbPath := flags.String("db", "sync.db", "database file")
	passwordStdin := flags.Bool("password-stdin", false, "read the password from standard input")
	name, rest := splitName(args)
	if err := flags.Parse(rest); err != nil {
		return err
	}
	if action != "list" && name == "" {
		return errors.New("a user name is needed")
	}
	store, err := openStore(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	switch action {
	case "add", "passwd":
		return setPassword(store, action, name, readPassword(stdin, *passwordStdin), stdout)
	case "list":
		return listUsers(store, stdout)
	case "delete":
		if err := store.deleteUser(name); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "deleted %s\n", name)
		return nil
	default:
		return fmt.Errorf("unknown user command %q", action)
	}
}

// splitName takes the user name off the front of the arguments, if it is
// there before the flags.
func splitName(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

type passwordReader func() (string, error)

func readPassword(stdin io.Reader, fromStdin bool) passwordReader {
	return func() (string, error) {
		if fromStdin {
			line, err := bufio.NewReader(stdin).ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return "", err
			}
			return strings.TrimRight(line, "\r\n"), nil
		}
		return promptPassword()
	}
}

func promptPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	fmt.Fprint(os.Stderr, "Password: ")
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Again: ")
	second, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(first) != string(second) {
		return "", errors.New("the passwords differ")
	}
	return string(first), nil
}

func setPassword(store *Store, action, name string, read passwordReader, stdout io.Writer) error {
	password, err := read()
	if err != nil {
		return err
	}
	if len(password) < 8 {
		return errors.New("the password needs at least 8 characters")
	}
	salt := randomBytes(saltSize)
	hash := authHash(authKey(password, salt))
	if action == "add" {
		err = store.addUser(name, salt, hash)
	} else {
		err = store.resetUser(name, salt, hash)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s: password set\n", name)
	return nil
}

func listUsers(store *Store, stdout io.Writer) error {
	users, err := store.listUsers()
	if err != nil {
		return err
	}
	for _, u := range users {
		fmt.Fprintf(stdout, "%s\t%d records\t%d sessions\n", u.Username, u.Records, u.Sessions)
	}
	return nil
}
