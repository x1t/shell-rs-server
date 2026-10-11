package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func runCommand(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := run(args, strings.NewReader(stdin), &out)
	return out.String(), err
}

func TestUserCommandsManageAccounts(t *testing.T) {
	db := filepath.Join(t.TempDir(), "sync.db")
	if _, err := runCommand(t, "a fine password\n", "user", "add", "me", "-db", db, "-password-stdin"); err != nil {
		t.Fatal(err)
	}
	if _, err := runCommand(t, "a fine password\n", "user", "add", "me", "-db", db, "-password-stdin"); err == nil {
		t.Error("adding a user twice is refused")
	}
	if _, err := runCommand(t, "short\n", "user", "add", "you", "-db", db, "-password-stdin"); err == nil {
		t.Error("a short password is refused")
	}
	out, err := runCommand(t, "", "user", "list", "-db", db)
	if err != nil || out != "me\t0 records\t0 sessions\n" {
		t.Errorf("list: %q %v", out, err)
	}
	if _, err := runCommand(t, "", "user", "delete", "me", "-db", db); err != nil {
		t.Fatal(err)
	}
	if _, err := runCommand(t, "", "user", "delete", "me", "-db", db); err == nil {
		t.Error("deleting a missing user is an error")
	}
	if _, err := runCommand(t, "a fine password\n", "user", "passwd", "nobody", "-db", db, "-password-stdin"); err == nil {
		t.Error("a missing user's password is not set")
	}
}

func TestUnknownCommandsPrintUsage(t *testing.T) {
	out, err := runCommand(t, "", "frobnicate")
	if err == nil || !strings.Contains(out, "usage:") {
		t.Errorf("%q %v", out, err)
	}
	if _, err := runCommand(t, "", "user", "add"); err == nil {
		t.Error("a user name is needed")
	}
}

func TestANewerDatabaseIsLeftAlone(t *testing.T) {
	db := filepath.Join(t.TempDir(), "sync.db")
	store, err := openStore(db)
	if err != nil {
		t.Fatal(err)
	}
	store.db.Exec("PRAGMA user_version = 99")
	store.Close()
	if _, err := openStore(db); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Errorf("open: %v", err)
	}
}
