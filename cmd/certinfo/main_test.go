package main

import (
	"os"
	"path/filepath"
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
