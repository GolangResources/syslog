// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !windows,!nacl,!plan9

package syslog

import (
        "errors"
        "fmt"
        "net"
        "os"
        "strings"
        "sync"
        "time"
        "crypto/tls"
        //"glog"
)

// The Priority is a combination of the syslog facility and
// severity. For example, LOG_ALERT | LOG_FTP sends an alert severity
// message from the FTP facility. The default severity is LOG_EMERG;
// the default facility is LOG_KERN.
type Priority int

const severityMask = 0x07
const facilityMask = 0xf8

type Settings struct {
	SyslogVersion	string
	PING_PREFIX	string
	SOCKET_TIMEOUT	time.Duration
	DEBUG		bool
}

var settings Settings

const (
        // Severity.

        // From /usr/include/sys/syslog.h.
        // These are the same on Linux, BSD, and OS X.
        LOG_EMERG Priority = iota
        LOG_ALERT
        LOG_CRIT
        LOG_ERR
        LOG_WARNING
        LOG_NOTICE
        LOG_INFO
        LOG_DEBUG
)

const (
        // Facility.

        // From /usr/include/sys/syslog.h.
        // These are the same up to LOG_FTP on Linux, BSD, and OS X.
        LOG_KERN Priority = iota << 3
        LOG_USER
        LOG_MAIL
        LOG_DAEMON
        LOG_AUTH
        LOG_SYSLOG
        LOG_LPR
        LOG_NEWS
        LOG_UUCP
        LOG_CRON
        LOG_AUTHPRIV
        LOG_FTP
        _ // unused
        _ // unused
        _ // unused
        _ // unused
        LOG_LOCAL0
        LOG_LOCAL1
        LOG_LOCAL2
        LOG_LOCAL3
        LOG_LOCAL4
        LOG_LOCAL5
        LOG_LOCAL6
        LOG_LOCAL7
)

// A Writer is a connection to a syslog server.
type Writer struct {
        priority        Priority
        hostname        string
        network         string
        raddr           string

        mu              sync.Mutex      // guards conn
        conn            serverConn
}

// This interface and the separate syslog_unix.go file exist for
// Solaris support as implemented by gccgo. On Solaris you cannot
// simply open a TCP connection to the syslog daemon. The gccgo
// sources have a syslog_solaris.go file that implements unixSyslog to
// return a type that satisfies this interface and simply calls the C
// library syslog function.
type serverConn interface {
        writeString(p Priority, hostname string, tag string,
                s *string, nl string) (int, error)
        close() error
}

type netConn struct {
        local           bool
        conn            net.Conn
}

// New establishes a new connection to the system log daemon. Each
// write to the returned writer sends a log message with the given
// priority (a combination of the syslog facility and severity) and
// prefix tag. If tag is empty, the os.Args[0] is used.
func New(priority Priority, s *Settings) (*Writer, error) {
        return Dial("", "", priority, s)
}

// Dial establishes a connection to a log daemon by connecting to
// address raddr on the specified network. Each write to the returned
// writer sends a log message with the facility and severity
// (from priority) and tag. If tag is empty, the os.Args[0] is used.
// If network is empty, Dial will connect to the local syslog server.
// Otherwise, see the documentation for net.Dial for valid values
// of network and raddr.
func Dial(network, raddr string, priority Priority, s *Settings) (*Writer, error) {
	if s != nil {
		settings = *s
	} else {
		settings = Settings{
			SyslogVersion:	"1",
			PING_PREFIX:	"",
			SOCKET_TIMEOUT:	60 * time.Second,
			DEBUG:		false,
		}
	}
        if priority < 0 || priority > LOG_LOCAL7|LOG_DEBUG {
                return nil, errors.New("log/syslog: invalid priority")
        }
        hostname, _ := os.Hostname()

        w := &Writer {
                priority:       priority,
                hostname:       hostname,
                network:        network,
                raddr:          raddr,
        }

        w.mu.Lock()
        defer w.mu.Unlock()

        err := w.connect()
        if err != nil {
                return nil, err
        }
        return w, err
}

func (w *Writer) Connect() (err error) {
        w.mu.Lock()
        defer w.mu.Unlock()

        return w.connect()
}

// connect makes a connection to the syslog server.
// It must be called with w.mu held.
func (w *Writer) connect() (err error) {
        if w.conn != nil {
                // ignore err from close, it makes sense to continue anyway
                w.conn.close()
                w.conn = nil
        }
        if w.network == "ctcp" {
                w.network = "tcp"
        }
        if w.network == "" {
                w.conn, err = unixSyslog()
                if w.hostname == "" {
                        w.hostname = "localhost"
                }
        } else if w.network == "tls" {
                var c net.Conn
                c, err = tls.Dial("tcp", w.raddr,
                        &tls.Config{InsecureSkipVerify: true})
                if err == nil {
                        w.conn = &netConn{conn: c}
                        if w.hostname == "" {
                                w.hostname = c.LocalAddr().String()
                        }
                }
        } else {
                var conn net.Conn
                conn, err = net.DialTimeout(w.network, w.raddr, settings.SOCKET_TIMEOUT)
                if err == nil {
                        c, ok := conn.(*net.TCPConn)
                        if !ok {
                                panic("dial tcp error")
                        }
                        c.SetKeepAlive(true)
                        c.SetKeepAlivePeriod(30 * time.Second)
                        w.conn = &netConn{conn: c}
                        if w.hostname == "" {
                                w.hostname = c.LocalAddr().String()
                        }
                }
        }
        return
}

// Write sends a log message to the syslog daemon.
func (w *Writer) Write(b []byte, tag string) (int, error) {
        s := string(b)
        return w.writeAndRetry(w.priority, &s, "", tag)
}

// Close closes a connection to the syslog daemon.
func (w *Writer) Close() error {
        w.mu.Lock()
        defer w.mu.Unlock()

        if w.conn != nil {
                err := w.conn.close()
                w.conn = nil
                return err
        }
        return nil
}

// Emerg logs a message with severity LOG_EMERG, ignoring the severity
// passed to New.
func (w *Writer) Emerg(m *string, tag string) error {
        _, err := w.writeAndRetry(LOG_EMERG, m, "", tag)
        return err
}

// Alert logs a message with severity LOG_ALERT, ignoring the severity
// passed to New.
func (w *Writer) Alert(m *string, tag string) error {
        _, err := w.writeAndRetry(LOG_ALERT, m, "", tag)
        return err
}

// Crit logs a message with severity LOG_CRIT, ignoring the severity
// passed to New.
func (w *Writer) Crit(m *string, tag string) error {
        _, err := w.writeAndRetry(LOG_CRIT, m, "", tag)
        return err
}

// Err logs a message with severity LOG_ERR, ignoring the severity
// passed to New.
func (w *Writer) Err(m *string, tag string) error {
        _, err := w.writeAndRetry(LOG_ERR, m, "", tag)
        return err
}

// Warning logs a message with severity LOG_WARNING, ignoring the
// severity passed to New.
func (w *Writer) Warning(m *string, tag string) error {
        _, err := w.writeAndRetry(LOG_WARNING, m, "", tag)
        return err
}

// Notice logs a message with severity LOG_NOTICE, ignoring the
// severity passed to New.
func (w *Writer) Notice(m *string, tag string) error {
        _, err := w.writeAndRetry(LOG_NOTICE, m, "", tag)
        return err
}

// Info logs a message with severity LOG_INFO, ignoring the severity
// passed to New.
func (w *Writer) Info(m *string, tag string) error {
        _, err := w.writeAndRetry(LOG_INFO, m, "", tag)
        return err
}

// Debug logs a message with severity LOG_DEBUG, ignoring the severity
// passed to New.
func (w *Writer) Debug(m *string, tag string) error {
        _, err := w.writeAndRetry(LOG_DEBUG, m, "", tag)
        return err
}

// Generic interface for sending syslog messages
func (w *Writer) WriteSyslog(p Priority, m *string, tag string) error {
        _, err := w.writeAndRetry(p, m, "", tag)
        return err
}

func (w *Writer) WritePing(p Priority, m *string, tag string) error {
        _, err := w.writeAndRetry(p, m, settings.PING_PREFIX, tag)
        return err
}

func (w *Writer) writeAndRetry(p Priority, s *string, pt string, tag string) (int, error) {
        pr := (w.priority & facilityMask) | (p & severityMask)
        w.mu.Lock()
        defer w.mu.Unlock()
        if w.conn != nil {
                if n, err := w.write(pr, s, pt, tag); err == nil {
                        return n, err
                }
                //glog.Println("Error sending syslog message:", err)
        }
        if err := w.connect(); err != nil {
                //glog.Println("Reconnection in writeAndRetry result:", err)
                return 0, err
        }
        return w.write(pr, s, pt, tag)
}

// write generates and writes a syslog formatted string. The
// format is as follows: <PRI>TIMESTAMP HOSTNAME TAG[PID]: MSG
func (w *Writer) write(p Priority, msg *string, pt string, tag string) (int, error) {
        // ensure it ends in a \n
        nl := ""
        if !strings.HasSuffix(*msg, "\n") {
                nl = "\n"
        }
        _, err := w.conn.writeString(p, w.hostname, pt + tag, msg, nl)
        if err != nil {
                return 0, err
        }
        // Note: return the length of the input, not the number of
        // bytes printed by Fprintf, because this must behave like
        // an io.Writer.
        return len(*msg), nil
}

// Fully syslogv2 specifications compatible implementation
func (n *netConn) writeString(p Priority, hostname, tag string, msg *string, nl string) (int, error) {
        var err error
        var l int
        now := time.Now()
        ts := now.Format("2006-01-02T15:04:05.999999Z")
        _ = n.conn.SetDeadline(now.Add(settings.SOCKET_TIMEOUT))
        m := fmt.Sprintf("<%d>%s %s %s %s %d - - %s",
                p, settings.SyslogVersion, ts, hostname, tag, os.Getpid(), *msg)
        l, err = fmt.Fprintf(n.conn, "%d %s", len(m), m)
        _ = n.conn.SetDeadline(now.Add(15 * time.Minute))
        if settings.DEBUG {
                fmt.Printf("[LOG] %d %s\n", len(m), m)
        }
        return l, err
}

func (n *netConn) close() error {
        return n.conn.Close()
}

// NewLogger creates a log.Logger whose output is written to the
// system log service with the specified priority, a combination of
// the syslog facility and severity. The logFlag argument is the flag
// set passed through to log.New to create the Logger.
/*func NewLogger(p Priority, logFlag int, tag string) (*log.Logger, error) {
        s, err := New(p)
        if err != nil {
                return nil, err
        }
        return log.New(s, "", logFlag), nil
}*/

