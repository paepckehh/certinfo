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
	"paepcke.de/reportstyle"
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
	_minutes      = " minutes"
	_pathlen      = " [PathLen:"
	_unknown      = " [unknown] "
	_since        = " [expired since "
	_forthenext   = " [for the next "
	_openbracket  = "["
	_closebracket = "]"
	_marker       = "-----"
	_pemBegin     = "-----BEGIN "
	_bom          = "\ufeff"
	_spanEnd      = "</span>"
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
	asciiBlock, err = sanitizer(asciiBlock)
	if err != nil {
		return errString(errors.New("[sanitizer] [fail]: "+err.Error()), r.Style)
	}
	return multipartDecodeParallel(asciiBlock, r)
}

// decodeAuthorizedKeys ...
func decodeAuthorizedKeys(in string, r *Report) string {
	return decodeAuthorizedKeysText(in, r, false)
}

// decodeAuthorizedKeysText decodes all authorized key lines of in, quiet keeps
// segments without any decodable key from turning into an error report
func decodeAuthorizedKeysText(in string, r *Report, quiet bool) string {
	var s strings.Builder
	for {
		key, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(in))
		if err != nil {
			if s.Len() == 0 && !quiet {
				return errString(err, r.Style)
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

// textDecodeJob decodes the authorized key lines of one input segment
func textDecodeJob(in string, r *Report) func() string {
	return func() string { return decodeAuthorizedKeysText(in, r, true) }
}

// multipartDecodeParallel decodes all pem blocks and authorized key segments of
// the sanitized input in parallel and joins the results in input order
func multipartDecodeParallel(asciiBlock string, r *Report) string {
	var jobs []func() string
	hasPem := false
	for rest := asciiBlock; ; {
		i := strings.Index(rest, _pemBegin)
		if i < 0 {
			jobs = append(jobs, textDecodeJob(rest, r))
			break
		}
		jobs = append(jobs, textDecodeJob(rest[:i], r))
		block, tail := pem.Decode([]byte(rest[i:]))
		if block == nil || len(tail) >= len(rest)-i {
			jobs = append(jobs, textDecodeJob(rest[i:], r))
			break
		}
		jobs = append(jobs, func() string { return decodePemBlock(block, r) })
		hasPem = true
		rest = string(tail)
	}
	if !hasPem {
		return decodeAuthorizedKeys(asciiBlock, r)
	}
	results := make([]string, len(jobs))
	var bg sync.WaitGroup
	for i, job := range jobs {
		bg.Go(func() {
			results[i] = job()
		})
	}
	bg.Wait()
	var s strings.Builder
	for _, result := range results {
		if result == _empty {
			continue
		}
		s.WriteString(result)
		if !strings.HasSuffix(result, _linefeed) {
			s.WriteString(_linefeed)
		}
	}
	return s.String()
}

// sanitizer ...
func sanitizer(in string) (full string, err error) {
	var s strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(in))
	scanner.Buffer(nil, _maxLine)
	isCert := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.TrimSpace(strings.TrimPrefix(line, _bom))
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
		return _empty, serr
	}
	full = s.String()
	if len(full) < 32 {
		return _empty, errors.New("too short")
	}
	return full, nil
}

//
// GENERIC OUTPUT FORMAT HELPER
//

// errString renders an error as a report line, escaping it for styles that
// need it (parser errors can echo attacker controlled input)
func errString(err error, e *reportstyle.Style) string {
	return _app + _space + sani(style(e), err.Error())
}

// sani escapes free form values (eg. certificate and ssh key fields) for styles
// that need it, so that inline markup in the input cannot break the report
func sani(e *reportstyle.Style, in string) string {
	if e.SaniFunc != nil {
		return e.SaniFunc(in)
	}
	return in
}

// lineEnd ends a multiline block, L3 already closed the value span of those
// styles (eg. html), so the now dangling span close tag of LE is dropped
func lineEnd(e *reportstyle.Style) string {
	return strings.TrimPrefix(e.LE, _spanEnd)
}

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
