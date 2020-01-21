# syslog
Resilient Syslog Connector for Golang

## Example
```
package main

import (
        "github.com/GolangResources/syslog/syslog"
)

func main() {
        conn, err := syslog.Dial("ctcp", "127.0.0.1:514", syslog.LOG_NOTICE, nil)
        if (err != nil) {
                panic(err)
        }
        msg := "hi"
        conn.Notice(&msg, "apptest")
        conn.Close()
}
```
