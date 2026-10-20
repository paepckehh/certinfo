package main

import (
	"io"
	"log"
	"os"
	"strings"

	"paepcke.de/certinfo"
	"paepcke.de/reportstyle"
)

const (
	_app      = "[certinfo] "
	_err      = "[error] "
	_html     = "HTML"
	_noColor  = "NO_COLOR"
	_verbose  = "VERBOSE"
	_pemonly  = "PEMONLY"
	_pinonly  = "PINONLY"
	_linefeed = "\n"
)

func main() {
	style := reportstyle.StyleAnsi()
	if isEnv(_noColor) {
		style = reportstyle.StyleText()
	}
	if isEnv(_html) {
		style = reportstyle.StyleHTML()
	}
	report := &certinfo.Report{
		Summary: true,
		Style:   style,
	}
	if isEnv(_verbose) {
		report.OpenSSL = true
	}
	if isEnv(_pemonly) {
		report.Summary = false
		report.OpenSSL = false
		report.PEM = true
	}
	if isEnv(_pinonly) {
		report.PINOnly = true
	}
	switch {
	case isPipe():
		out(certinfo.Decode(getPipe(), report))
	case isOsArgs():
		for _, arg := range os.Args[1:] {
			out(certinfo.Decode(readFile(arg), report))
		}
	default:
		log.Fatal(_app + _err + "no pipe or input parameter found, example: certinfo file.txt")
	}
}

//
// LITTLE GENERIC HELPER SECTION
//

// out ...
func out(msg string) {
	if !strings.HasSuffix(msg, _linefeed) {
		msg += _linefeed
	}
	_, _ = os.Stdout.Write([]byte(msg))
}

// isPipe ...
func isPipe() bool {
	out, _ := os.Stdin.Stat()
	return out.Mode()&os.ModeCharDevice == 0
}

// getPipe ...
func getPipe() string {
	pipe, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(_app + _err + "reading data from pipe")
	}
	return string(pipe)
}

// isOsArgs ...
func isOsArgs() bool {
	return len(os.Args) > 1
}

// isEnv
func isEnv(in string) bool { return os.Getenv(in) != "" }

// readFile ...
func readFile(filename string) string {
	file, err := os.ReadFile(filename)
	if err != nil {
		log.Fatal(_app + _err + "unable to read file: " + err.Error())
	}
	return string(file)
}
