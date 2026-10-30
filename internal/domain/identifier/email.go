package identifier

import (
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"

	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

// The email limits of TDD-01 §2.2, in octets.
const (
	maxLocalPart = 64
	maxDomain    = 253
	maxAddress   = 254
	// maxEmailInput bounds the work done on an input before the rules can refuse it.
	maxEmailInput = 1024
)

// idnaLookup converts a domain to ASCII by IDNA 2008 with the UTS #46 lookup mapping,
// non-transitional (ß stays ß), with the STD3 rules, the Bidi rule and the DNS lengths.
var idnaLookup = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),
	idna.BidiRule(),
	idna.VerifyDNSLength(true),
)

// Email is the email type (TDD-01 §2.2).
type Email struct{}

// Name returns "email".
func (Email) Name() string { return "email" }

// CanSignIn returns true.
func (Email) CanSignIn() bool { return true }

// VerifyMethods returns email_link and email_code.
func (Email) VerifyMethods() []flow.Method {
	return []flow.Method{flow.MethodEmailLink, flow.MethodEmailCode}
}

// Normalise applies TDD-01 §2.2: trim; refuse inner white space and control characters, which here
// include format (Cf) and private-use (Co) characters, invisible look-alikes of an address; NFC;
// a bare address by net/mail; split at the last "@"; the domain to ASCII by IDNA 2008, lower-cased,
// with a dot and at most 253 octets; the local part by Unicode simple case folding, 1 to 64
// octets, not starting with a combining mark; the address at most 254 octets. There are no provider rules and no DNS look-up.
func (Email) Normalise(raw string, _ Policy) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > maxEmailInput || !utf8.ValidString(s) {
		return "", notAllowed("the email address is malformed")
	}
	if strings.IndexFunc(s, invisible) >= 0 {
		return "", notAllowed("the email address has white space, control or format characters")
	}
	s = norm.NFC.String(s)
	if a, err := mail.ParseAddress(s); err != nil || a.Name != "" || a.Address != s {
		return "", notAllowed("the email address is malformed")
	}
	at := strings.LastIndexByte(s, '@')
	local, dom := s[:at], s[at+1:]

	dom, err := idnaLookup.ToASCII(dom)
	if err != nil {
		return "", notAllowed("the email domain is not a valid domain name")
	}
	dom = strings.ToLower(dom)
	if !strings.Contains(dom, ".") || len(dom) > maxDomain {
		return "", notAllowed("the email domain is not a valid domain name")
	}

	local = norm.NFC.String(strings.Map(simpleFold, local))
	if local == "" || len(local) > maxLocalPart {
		return "", notAllowed("the email local part is empty or too long")
	}
	if r, _ := utf8.DecodeRuneInString(local); unicode.Is(unicode.M, r) {
		return "", notAllowed("the email local part starts with a combining mark")
	}
	addr := local + "@" + dom
	if len(addr) > maxAddress {
		return "", notAllowed("the email address is too long")
	}
	return addr, nil
}

// Variants returns the address and its local part.
func (Email) Variants(normalised string) []string {
	at := strings.LastIndexByte(normalised, '@')
	if at < 0 {
		return []string{normalised}
	}
	return []string{normalised, normalised[:at]}
}

// CheckPolicy refuses calling codes.
func (e Email) CheckPolicy(p Policy) []PolicyError {
	if len(p.CallingCodes) > 0 {
		return []PolicyError{{Type: e.Name(), Field: "calling_codes", Message: "applies to phone only"}}
	}
	return nil
}

// invisible reports whether r is white space or a control, format or private-use character.
func invisible(r rune) bool {
	return unicode.IsSpace(r) || unicode.In(r, unicode.Cc, unicode.Cf, unicode.Co)
}

// simpleFold maps r by Unicode simple case folding (CaseFolding.txt, statuses C and S). For a rune
// with case pairs this is the lower case of its upper case, except Cherokee, which folds to upper
// case, and three status S foldings between runes that have no case mapping. A rune with no simple
// folding, such as the Turkish İ and ı, is kept: folding them would merge them with i.
func simpleFold(r rune) rune {
	switch r {
	case 0x1FD3: // ΐ, GREEK SMALL LETTER IOTA WITH DIALYTIKA AND OXIA
		return 0x0390
	case 0x1FE3: // ΰ, GREEK SMALL LETTER UPSILON WITH DIALYTIKA AND OXIA
		return 0x03B0
	case 0xFB05: // ﬅ, LATIN SMALL LIGATURE LONG S T
		return 0xFB06
	}
	if unicode.SimpleFold(r) == r {
		return r
	}
	u := unicode.ToUpper(r)
	if unicode.Is(unicode.Cherokee, u) {
		return u
	}
	return unicode.ToLower(u)
}
