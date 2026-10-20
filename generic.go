package certinfo

import (
	"bufio"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

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
	_sshkey       = "ssh-"
	_empty        = ""
	_space        = " "
	_shortLen     = 80
	_maxLine      = 1 << 20
)

//
// GENERIC ASCII INPUT HANDLER
//

// decodeBlock ...
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
	case strings.Contains(eval, "BEGIN"):
		return multipartDecodeParallel(asciiBlock, r)
	}
	return decodeAuthorizedKeys(asciiBlock, r)
}

// decodeAuthorizedKeys ...
func decodeAuthorizedKeys(in string, r *Report) string {
	var s strings.Builder
	for {
		key, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(in))
		if err != nil {
			if s.Len() == 0 {
				return errString(err)
			}
			break
		}
		s.WriteString(SshDecodeCert(key, comment, options, nil, r.Style))
		if len(rest) == 0 {
			break
		}
		in = string(rest)
	}
	return s.String()
}

// multipartDecodeParallel ...
func multipartDecodeParallel(asciiBlock string, r *Report) string {
	var blocks []*pem.Block
	for rest := []byte(asciiBlock); ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		blocks = append(blocks, block)
	}
	results := make([]string, len(blocks))
	var bg sync.WaitGroup
	for i, block := range blocks {
		bg.Go(func() {
			results[i] = decodePemBlock(block, r)
		})
	}
	bg.Wait()
	var s strings.Builder
	for _, result := range results {
		s.WriteString(result)
		if !strings.HasSuffix(result, _linefeed) {
			s.WriteString(_linefeed)
		}
	}
	return s.String()
}

// sanitizer ...
func sanitizer(in string) (full, cut string, err error) {
	var s strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(in))
	scanner.Buffer(nil, _maxLine)
	isCert := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case isCert:
			s.WriteString(line + _linefeed)
			if strings.HasPrefix(line, _marker) {
				isCert = false
			}
		case strings.HasPrefix(line, _marker):
			s.WriteString(line + _linefeed)
			isCert = true
		case isAuthorizedKey(line):
			s.WriteString(line + _linefeed)
		}
	}
	if serr := scanner.Err(); serr != nil {
		return _empty, _empty, serr
	}
	full = s.String()
	if len(full) < 32 {
		return _empty, _empty, errors.New("too short")
	}
	cut = full[:32]
	return full, cut, nil
}

//
// GENERIC OUTPUT FORMAT HELPER
//

// errString ...
func errString(err error) string { return _app + _space + err.Error() }

// isAuthorizedKey ...
func isAuthorizedKey(line string) bool {
	if strings.HasPrefix(line, _sshkey) {
		return true
	}
	_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	return err == nil
}

// short ...
func short(in string) string {
	if len(in) <= _shortLen {
		return in
	}
	for i := _shortLen; i > 0; i-- {
		if utf8.RuneStart(in[i]) {
			return in[:i]
		}
	}
	return in[:_shortLen]
}

// shortMsg ...
func shortMsg(in string) string {
	return _openbracket + short(in) + _closebracket + _space
}

// shortMsgArray ...
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

// shortMsgArrayIP ...
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

// shortMsgArrayURL ...
func shortMsgArrayURL(in []*url.URL) string {
	if len(in) < 1 {
		return _empty
	}
	var s strings.Builder
	for _, msg := range in {
		s.WriteString(shortMsg(msg.String()))
	}
	return short(s.String())
}

//
// LITTLE HELPER SECTION
//

func itoa(in int) string       { return strconv.Itoa(in) }
func ftoa64(in float64) string { return strconv.FormatFloat(in, 'f', 0, 64) }
