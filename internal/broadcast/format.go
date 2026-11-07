package broadcast

// format.go is the message format of a broadcast (issue #1209): plain text,
// the historical behaviour, or a strict subset of Telegram's HTML parse mode.
//
// The format is part of what an approver approves. It is stored on the
// campaign and folded into the content hash (ContentHashFor), so changing it
// after preview invalidates the approval. HTML is validated at prepare time
// against an allow-list, so a message Telegram would reject is refused before
// anyone approves it, and the approval page can render exactly the structure
// recipients will see from the same parse.

import (
	"errors"
	"fmt"
	"html"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// Format names how a broadcast's text is interpreted by Telegram.
type Format string

const (
	// FormatPlain sends the text with no parse mode.
	FormatPlain Format = "plain"
	// FormatHTML sends the text with parse_mode=HTML after ValidateHTML.
	FormatHTML Format = "html"
)

// Limits on an HTML body. The visible-text limit is Telegram's own (applied
// after entity parsing); the raw and tag limits keep a pathological body from
// reaching the parser or the approval page.
const (
	MaxHTMLRawBytes = 16 << 10
	MaxHTMLTags     = 100
	maxLinkLen      = 2048
)

// ParseFormat maps the wire value to a Format. Empty means plain, so every
// existing caller keeps its behaviour.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(s))) {
	case "", FormatPlain:
		return FormatPlain, nil
	case FormatHTML:
		return FormatHTML, nil
	}
	return "", fmt.Errorf("unknown broadcast format %q (want plain or html)", s)
}

// ContentHashFor is the hash an approval is bound to. A plain campaign keeps
// the historical Hash(text), so campaigns prepared before formats existed
// still verify; an HTML campaign hashes a format-tagged form, so the same
// bytes under another format hash differently.
func ContentHashFor(f Format, text string) string {
	if f == FormatHTML {
		return Hash("html\n" + text)
	}
	return Hash(text)
}

// NormalizeContent returns the exact text that is approved and sent, or an
// error saying why Telegram would refuse it.
func NormalizeContent(f Format, text string) (string, error) {
	if f != FormatHTML {
		return NormalizeText(text)
	}
	t := strings.ReplaceAll(text, "\r\n", "\n")
	t = strings.ReplaceAll(t, "\r", "\n")
	t = strings.TrimSpace(t)
	if t == "" {
		return "", errors.New("broadcast text is empty")
	}
	if !utf8.ValidString(t) {
		return "", errors.New("broadcast text is not valid UTF-8")
	}
	if len(t) > MaxHTMLRawBytes {
		return "", fmt.Errorf("broadcast html is %d bytes; at most %d are accepted", len(t), MaxHTMLRawBytes)
	}
	if _, err := ParseHTML(t); err != nil {
		return "", err
	}
	return t, nil
}

type nodeKind int

const (
	nodeText nodeKind = iota
	nodeOpen
	nodeClose
)

type htmlNode struct {
	kind nodeKind
	tag  string // lower-case, for open/close
	href string // set on an opening <a>
	text string // unescaped, for text
}

// HTMLDoc is a validated HTML body.
type HTMLDoc struct {
	nodes []htmlNode
	// Visible is the text recipients read, with tags removed and entities
	// decoded.
	Visible string
}

// allowedTags is the subset of Telegram's HTML that a broadcast may use.
// Spoilers, custom emoji and tg-* elements are deliberately absent.
var allowedTags = map[string]bool{
	"b": true, "strong": true, "i": true, "em": true, "u": true, "ins": true,
	"s": true, "strike": true, "del": true, "code": true, "pre": true,
	"a": true, "blockquote": true,
}

// ParseHTML validates text and returns its parsed form. It enforces: only
// allow-listed tags, no attributes except a double-quoted https href on <a>,
// only the entities &lt; &gt; &amp; &quot;, no bare < > or &, properly nested
// and closed tags, <pre> holding only text or one <code>, <code> holding only
// text, and Telegram's visible-length limit.
func ParseHTML(text string) (*HTMLDoc, error) {
	var (
		nodes   []htmlNode
		visible strings.Builder
		stack   []string
		tags    int
		i       int
	)
	flush := func(b *strings.Builder) {
		if b.Len() > 0 {
			nodes = append(nodes, htmlNode{kind: nodeText, text: b.String()})
			b.Reset()
		}
	}
	var cur strings.Builder
	for i < len(text) {
		c := text[i]
		switch c {
		case '<':
			end := strings.IndexByte(text[i:], '>')
			if end < 0 {
				return nil, errors.New("html: a '<' is never closed; write &lt; for a literal <")
			}
			raw := text[i+1 : i+end]
			i += end + 1
			flush(&cur)
			tags++
			if tags > MaxHTMLTags {
				return nil, fmt.Errorf("html: more than %d tags", MaxHTMLTags)
			}
			if strings.HasPrefix(raw, "/") {
				name := strings.ToLower(strings.TrimSpace(raw[1:]))
				if !allowedTags[name] {
					return nil, fmt.Errorf("html: tag </%s> is not allowed", name)
				}
				if len(stack) == 0 || stack[len(stack)-1] != name {
					return nil, fmt.Errorf("html: </%s> does not match the open tag", name)
				}
				stack = stack[:len(stack)-1]
				nodes = append(nodes, htmlNode{kind: nodeClose, tag: name})
				continue
			}
			name, href, err := parseOpenTag(raw)
			if err != nil {
				return nil, err
			}
			if err := checkNesting(stack, name); err != nil {
				return nil, err
			}
			stack = append(stack, name)
			nodes = append(nodes, htmlNode{kind: nodeOpen, tag: name, href: href})
		case '>':
			return nil, errors.New("html: a bare '>' must be written &gt;")
		case '&':
			semi := strings.IndexByte(text[i:], ';')
			if semi < 0 || semi > 6 {
				return nil, errors.New("html: a bare '&' must be written &amp;")
			}
			var r string
			switch text[i : i+semi+1] {
			case "&lt;":
				r = "<"
			case "&gt;":
				r = ">"
			case "&amp;":
				r = "&"
			case "&quot;":
				r = `"`
			default:
				return nil, fmt.Errorf("html: entity %s is not supported (use &lt; &gt; &amp; &quot;)", text[i:i+semi+1])
			}
			cur.WriteString(r)
			visible.WriteString(r)
			i += semi + 1
		default:
			_, size := utf8.DecodeRuneInString(text[i:])
			cur.WriteString(text[i : i+size])
			visible.WriteString(text[i : i+size])
			i += size
		}
	}
	flush(&cur)
	if len(stack) != 0 {
		return nil, fmt.Errorf("html: <%s> is never closed", stack[len(stack)-1])
	}
	v := visible.String()
	if strings.TrimSpace(v) == "" {
		return nil, errors.New("html: the message has no visible text")
	}
	if n := len(utf16.Encode([]rune(v))); n > MaxTextUnits {
		return nil, fmt.Errorf("html: visible text is %d UTF-16 units; Telegram allows at most %d", n, MaxTextUnits)
	}
	return &HTMLDoc{nodes: nodes, Visible: v}, nil
}

// checkNesting enforces the structural rules Telegram applies: <code> holds
// only text, <pre> holds only text or <code>, and <a> does not nest in <a>.
func checkNesting(stack []string, name string) error {
	if len(stack) == 0 {
		return nil
	}
	parent := stack[len(stack)-1]
	switch {
	case parent == "code":
		return fmt.Errorf("html: <%s> cannot sit inside <code>", name)
	case parent == "pre" && name != "code":
		return fmt.Errorf("html: <pre> may only contain text or <code>, not <%s>", name)
	case name == "a":
		for _, s := range stack {
			if s == "a" {
				return errors.New("html: <a> cannot nest inside <a>")
			}
		}
	}
	return nil
}

// parseOpenTag reads "name" or `a href="..."` (no leading '<', no trailing
// '>'). Self-closing tags and every other attribute are refused.
func parseOpenTag(raw string) (name, href string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("html: empty tag")
	}
	if strings.HasSuffix(raw, "/") {
		return "", "", errors.New("html: self-closing tags are not allowed")
	}
	sp := strings.IndexFunc(raw, unicode.IsSpace)
	if sp < 0 {
		name = strings.ToLower(raw)
		if !allowedTags[name] {
			return "", "", fmt.Errorf("html: tag <%s> is not allowed", name)
		}
		if name == "a" {
			return "", "", errors.New(`html: <a> needs an href="https://..." attribute`)
		}
		return name, "", nil
	}
	name = strings.ToLower(raw[:sp])
	if !allowedTags[name] {
		return "", "", fmt.Errorf("html: tag <%s> is not allowed", name)
	}
	if name != "a" {
		return "", "", fmt.Errorf("html: <%s> takes no attributes", name)
	}
	rest := strings.TrimSpace(raw[sp:])
	const prefix = `href="`
	if !strings.HasPrefix(rest, prefix) || !strings.HasSuffix(rest, `"`) || len(rest) < len(prefix)+1 {
		return "", "", errors.New(`html: <a> accepts only a double-quoted href="https://..."`)
	}
	val := rest[len(prefix) : len(rest)-1]
	if strings.ContainsAny(val, `"<>`) {
		return "", "", errors.New("html: href contains a forbidden character")
	}
	val = html.UnescapeString(val)
	if err := checkHref(val); err != nil {
		return "", "", err
	}
	return name, val, nil
}

func checkHref(v string) error {
	if len(v) > maxLinkLen {
		return errors.New("html: href is too long")
	}
	for _, r := range v {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == '"' || r == '<' || r == '>' {
			return errors.New("html: href contains whitespace or control characters")
		}
	}
	u, err := url.Parse(v)
	if err != nil {
		return fmt.Errorf("html: href is not a valid URL: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("html: href must use https")
	}
	if u.Host == "" || u.User != nil {
		return errors.New("html: href needs a host and no credentials")
	}
	return nil
}

// Links lists every href in document order, so an approver sees where the
// message sends people regardless of the anchor text.
func (d *HTMLDoc) Links() []string {
	var out []string
	for _, n := range d.nodes {
		if n.kind == nodeOpen && n.tag == "a" {
			out = append(out, n.href)
		}
	}
	return out
}

// Preview renders the parsed document as safe HTML for the approval page. It
// is rebuilt from the parsed nodes -- allow-listed tag names, escaped text,
// an escaped href with rel set -- never from the submitted string, so nothing
// the operator typed reaches the page except through this function.
func (d *HTMLDoc) Preview() string {
	var b strings.Builder
	for _, n := range d.nodes {
		switch n.kind {
		case nodeText:
			b.WriteString(html.EscapeString(n.text))
		case nodeOpen:
			if n.tag == "a" {
				b.WriteString(`<a href="`)
				b.WriteString(html.EscapeString(n.href))
				b.WriteString(`" rel="noopener noreferrer nofollow">`)
			} else {
				b.WriteString("<" + n.tag + ">")
			}
		case nodeClose:
			b.WriteString("</" + n.tag + ">")
		}
	}
	return b.String()
}
