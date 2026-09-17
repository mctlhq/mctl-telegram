package events

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client is a minimal RESP2 client for the two commands a producer needs:
// AUTH and XADD. A full client library would bring a large dependency for a
// write-only path whose ACL user can do nothing else anyway.
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
	if _, hasPassword := u.User.Password(); hasPassword {
		return nil, errors.New("valkey url must not embed a password")
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
		username: u.User.Username(),
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

func (c *Client) connect() error {
	conn, err := net.DialTimeout("tcp", c.addr, c.timeout)
	if err != nil {
		return err
	}
	c.conn, c.r = conn, bufio.NewReader(conn)
	if c.password != "" {
		args := []string{"AUTH", c.password}
		if c.username != "" {
			args = []string{"AUTH", c.username, c.password}
		}
		if _, err := c.roundTrip(args); err != nil {
			c.Close()
			return err
		}
	}
	if c.db != 0 {
		if _, err := c.roundTrip([]string{"SELECT", strconv.Itoa(c.db)}); err != nil {
			c.Close()
			return err
		}
	}
	return nil
}

// Do runs one command and returns a simple, integer or bulk reply as a string.
// A transport failure closes the connection so the next call starts clean.
func (c *Client) Do(args ...string) (string, error) {
	if c.conn == nil {
		if err := c.connect(); err != nil {
			return "", err
		}
	}
	reply, err := c.roundTrip(args)
	if err != nil {
		var se *ServerError
		if !errors.As(err, &se) {
			c.Close()
		}
		return "", err
	}
	return reply, nil
}

func (c *Client) roundTrip(args []string) (string, error) {
	if err := c.conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := c.conn.Write([]byte(b.String())); err != nil {
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
		buf := make([]byte, n+2)
		if _, err := readFull(c.r, buf); err != nil {
			return "", err
		}
		return string(buf[:n]), nil
	default:
		return "", fmt.Errorf("valkey: unsupported reply type %q", line[0])
	}
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// XAdd appends an envelope to a stream, trimming it approximately to maxLen.
func (c *Client) XAdd(stream string, maxLen int, fields ...string) (string, error) {
	args := append([]string{"XADD", stream, "MAXLEN", "~", strconv.Itoa(maxLen), "*"}, fields...)
	return c.Do(args...)
}
