package certinfo

import (
	"bufio"
	"bytes"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

const (
	_app          = "[certinfo]"
	_rootCA       = " [RootCA]"
	_expired      = "[expired]"
	_linefeed     = "\n"
	_critical     = "[CRITICAL]"
	_yes          = "[YES]"
	_no           = "[NO]"
	_days         = " days"
	_hours        = " hours"
	_pathlen      = " [PathLen:"
	_unknown      = " [unknown] "
	_since        = " [expired since "
	_forthenext   = " [for the next "
	_openbracket  = "["
	_closebracket = "]"
	_marker       = "-----"
	_empty        = ""
	_space        = " "
)

//
// GENERIC ASCII INPUT HANDLER
//

func decodeBlock(asciiBlock string, r *Report) string {
	var err error
	var eval string
	asciiBlock, eval, err = sanitizer(asciiBlock)
	if err != nil {
		return "[certinfo] [sanitizer] [fail]: " + err.Error()
	}
	switch {
	case strings.Contains(eval, "BEGIN") && strings.Contains(eval, "SSH"):
		return SshDecode(asciiBlock, eval, r.Style)
	case strings.Contains(eval, "ssh-"):
		key, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(asciiBlock))
		if err != nil {
			return errString(err)
		}
		return SshDecodeCert(key, comment, options, rest, r.Style)
	case strings.Contains(eval, "BEGIN"):
		return multipartDecodeParallel(asciiBlock, r)
	}
	return "[certinfo] [unable to decode] [pem:failed] [ssh:failed]"
}

func sanitizer(in string) (full, cut string, err error) {
	var s strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(in))
	isCert := false
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case isCert:
			s.WriteString(line + _linefeed)
			if strings.HasPrefix(line, _marker) {
				isCert = false
			}
		case strings.HasPrefix(line, _marker):
			s.WriteString(line + _linefeed)
			isCert = true
		}
	}
	full = s.String()
	if len(full) < 32 {
		return _empty, _empty, errors.New("too short")
	}
	cut = full[:32]
	return full, cut, nil
}

func multipartDecodeParallel(asciiBlock string, r *Report) string {
	var (
		bg    sync.WaitGroup
		dChan = make(chan string, 10)
	)
	block := []byte(asciiBlock)
	go func() {
		for len(block) > 32 {
			pem, rest := pem.Decode(block)
			if pem != nil {
				bg.Add(1)
				go func() {
					dChan <- decodePemBlock(pem, r)
					bg.Done()
				}()
			}
			if bytes.Equal(block, rest) {
				break
			}
			block = rest
		}
		bg.Wait()
		close(dChan)
	}()
	var s strings.Builder
	for ss := range dChan {
		s.WriteString(ss)
	}
	return s.String()
}

//
// GENERIC OUTPUT FORMAT HELPER
//

func errString(err error) string {
	var s strings.Builder
	s.WriteString(_app)
	s.WriteString(_space)
	s.WriteString(err.Error())
	return s.String()
}

func short(in string) string {
	if len(in) > 80 {
		return in[:80]
	}
	return in
}

func shortMsg(in string) string {
	var s strings.Builder
	s.WriteString(_openbracket)
	if len(in) > 80 {
		s.WriteString(in[:80])
	} else {
		s.WriteString(in)
	}
	s.WriteString(_closebracket)
	s.WriteString(_space)
	return s.String()
}

func shortMsgArray(in []string) string {
	if len(in) < 1 {
		return _empty
	}
	var s strings.Builder
	for _, msg := range in {
		s.WriteString(shortMsg(msg))
	}
	return short(s.String())
}

func shortMsgArrayIP(in []net.IP) string {
	if len(in) < 1 {
		return _empty
	}
	var s strings.Builder
	for _, msg := range in {
		s.WriteString(shortMsg(msg.String()))
	}
	return short(s.String())
}

func shortMsgArrayURL(in []*url.URL) string {
	if len(in) > 0 {
		return _empty
	}
	var s strings.Builder
	for _, msg := range in {
		s.WriteString(shortMsg(msg.String()))
	}
	return short(s.String())
}

func itoa(in int) string       { return strconv.Itoa(in) }
func ftoa64(in float64) string { return strconv.FormatFloat(in, 'f', 0, 64) }
func itoa64(in int64) string   { return strconv.FormatInt(in, 10) }
func out(msg string)           { os.Stdout.Write([]byte(msg + _linefeed)) }
