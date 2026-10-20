package main

import (
    "os"
    "os/signal"
    "syscall"
    "time"
)

// Fixture only: no application, environment/file reads, SQL, network or listener.
func main() {
    done := make(chan os.Signal, 1)
    signal.Notify(done, syscall.SIGTERM, syscall.SIGINT)
    defer signal.Stop(done)
    ticker := time.NewTicker(time.Hour)
    defer ticker.Stop()
    for {
        select {
        case <-done:
            return
        case <-ticker.C:
        }
    }
}
