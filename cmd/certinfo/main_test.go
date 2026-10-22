package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsPipe(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "input.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !isPipe(file) {
		t.Fatal("regular file input should be read as a stream")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if isPipe(file) {
		t.Fatal("input whose Stat() fails must not be treated as a stream")
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestOut(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"without newline", "hello", "hello\n"},
		{"with newline", "hello\n", "hello\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := captureStdout(t, func() { out(tt.in) }); got != tt.want {
				t.Fatalf("out(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestIsEnv(t *testing.T) {
	const key = "CERTINFO_TEST_ENV"
	t.Setenv(key, "1")
	if !isEnv(key) {
		t.Fatal("non-empty environment variable must be reported as set")
	}
	t.Setenv(key, "")
	if isEnv(key) {
		t.Fatal("empty environment variable must be reported as unset")
	}
}

func TestIsOsArgs(t *testing.T) {
	old := os.Args
	defer func() { os.Args = old }()
	os.Args = []string{"certinfo"}
	if isOsArgs() {
		t.Fatal("no arguments must not be reported as input")
	}
	os.Args = []string{"certinfo", "input.pem"}
	if !isOsArgs() {
		t.Fatal("an argument must be reported as input")
	}
}

func TestReadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readFile(path); !strings.Contains(got, "content") {
		t.Fatalf("readFile() = %q, want file content", got)
	}
}

func TestGetPipe(t *testing.T) {
	old := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })
	if _, err := w.Write([]byte("content")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if got := getPipe(); got != "content" {
		t.Fatalf("getPipe() = %q, want %q", got, "content")
	}
}
