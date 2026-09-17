package events

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// maxBulkBytes caps one bulk reply read from the server.
const maxBulkBytes = 1 << 20

// Client is a minimal RESP2 client for the two commands a producer needs:
// AUTH and XADD. A full client library would bring a large dependency for a
// write-only path whose ACL user can do nothing else anyway. Not safe for
// concurrent use; the relay serializes its calls.
type Client struct {
	addr     string
	username string
	password string
	db       int
	timeout  time.Duration

	conn net.Conn
	r    *bufio.Reader
}

// ServerError is an error reply from Valkey (e.g. NOPERM, NOAUTH).
type ServerError struct{ Msg string }

func (e *ServerError) Error() string { return "valkey: " + e.Msg }

// NewClient parses redis://[user@]host:port[/db]. The password is passed
// separately so it never lives in a URL that might be logged.
func NewClient(rawURL, password string, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse valkey url: %w", err)
	}
	if u.Scheme != "redis" && u.Scheme != "valkey" {
		return nil, errors.New("valkey url must use redis:// or valkey://")
	}
	if u.Hostname() == "" {
		return nil, errors.New("valkey url has no host")
	}
	username := ""
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			return nil, errors.New("valkey url must not embed a password")
		}
		username = u.User.Username()
	}
	if username != "" && password == "" {
		// An ACL user without its password would connect anonymously and get
		// NOAUTH on every publish; refuse the configuration up front instead.
		return nil, errors.New("valkey url names a user but no password is configured")
	}
	port := u.Port()
	if port == "" {
		port = "6379"
	}
	db := 0
	if p := strings.TrimPrefix(u.Path, "/"); p != "" {
		if db, err = strconv.Atoi(p); err != nil {
			return nil, fmt.Errorf("valkey url database: %w", err)
		}
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Client{
		addr:     net.JoinHostPort(u.Hostname(), port),
		username: username,
		password: password,
		db:       db,
		timeout:  timeout,
	}, nil
}

// Close drops the connection; the next call reconnects.
func (c *Client) Close() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn, c.r = nil, nil
	}
}

func (c *Client) connect(ctx context.Context, deadline time.Time) error {
	dialer := net.Dialer{Deadline: deadline}
	conn, err := dialer.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return err
	}
	c.conn, c.r = conn, bufio.NewReader(conn)
	if c.password != "" {
		args := []string{"AUTH", c.password}
		if c.username != "" {
			args = []string{"AUTH", c.username, c.password}
		}
		if _, err := c.roundTrip(ctx, deadline, args); err != nil {
			c.Close()
			return err
		}
	}
	if c.db != 0 {
		if _, err := c.roundTrip(ctx, deadline, []string{"SELECT", strconv.Itoa(c.db)}); err != nil {
			c.Close()
			return err
		}
	}
	return nil
}

// Do runs one command and returns a simple, integer or bulk reply as a string.
// A transport failure closes the connection so the next call starts clean. The
// call ends at the client timeout or when ctx is done, whichever comes first.
// One deadline covers the whole call, including a reconnect's dial, AUTH and
// SELECT, so the timeout is a real upper bound.
func (c *Client) Do(ctx context.Context, args ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if c.conn == nil {
		if err := c.connect(ctx, deadline); err != nil {
			return "", err
		}
	}
	reply, err := c.roundTrip(ctx, deadline, args)
	if err != nil {
		var se *ServerError
		if !errors.As(err, &se) {
			c.Close()
		}
		return "", err
	}
	return reply, nil
}

func (c *Client) roundTrip(ctx context.Context, deadline time.Time, args []string) (string, error) {
	// Bind to this call's connection: the cancel callback runs on another
	// goroutine and may fire after Close has already cleared c.conn.
	conn := c.conn
	if err := conn.SetDeadline(deadline); err != nil {
		return "", err
	}
	// Unblock an in-flight read or write as soon as ctx is cancelled, so a
	// shutdown does not wait out the full timeout. Setting a deadline on a
	// connection that is already closed only returns an error.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := conn.Write([]byte(b.String())); err != nil {
		return "", err
	}
	line, err := c.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSuffix(line, "\r\n")
	if line == "" {
		return "", errors.New("valkey: empty reply")
	}
	switch line[0] {
	case '+', ':':
		return line[1:], nil
	case '-':
		return "", &ServerError{Msg: line[1:]}
	case '$':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return "", fmt.Errorf("valkey: bad bulk length %q", line)
		}
		if n < 0 {
			return "", nil
		}
		// This client only reads short AUTH/SELECT/XADD replies; refuse a
		// length that would overflow or allocate without bound.
		if n > maxBulkBytes {
			return "", fmt.Errorf("valkey: bulk reply of %d bytes exceeds %d", n, maxBulkBytes)
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(c.r, buf); err != nil {
			return "", err
		}
		return string(buf[:n]), nil
	default:
		return "", fmt.Errorf("valkey: unsupported reply type %q", line[0])
	}
}

// XAdd appends fields to a stream, trimming it approximately to maxLen.
func (c *Client) XAdd(ctx context.Context, stream string, maxLen int, fields ...string) (string, error) {
	args := append([]string{"XADD", stream, "MAXLEN", "~", strconv.Itoa(maxLen), "*"}, fields...)
	return c.Do(ctx, args...)
}

// truncateUTF8 cuts s to at most max bytes without splitting a rune, so the
// result is always valid UTF-8 (Postgres TEXT rejects anything else).
func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return strings.ToValidUTF8(s[:max], "")
}
