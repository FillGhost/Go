# FillGhost for Go TLS

This package extends the standard Go `tls.Conn` to support the [FillGhost Protocol](https://github.com/FillGhost/FillGhost/blob/master/SPEC.md): an anti-censorship covert padding protocol that obfuscates proxy latency patterns by injecting cryptographically correct, meaningless TLS Application Data records during proxy latency windows.

**Key Features:**
- Minimal, safe API: no changes to client-side code, no protocol modifications.
- FillGhost is initiated and terminated by application logic, allowing precise control.
- Fully random packet sizes (default 900-1400 bytes, configurable).
- Uses actual session keys and AEAD from the live TLS context.
- Works for TLS 1.3 connections (recommended).
- Does not interfere with standard `Read` and `Write` logic.

---

## Why Application-Layer Control?

Only the application/proxy knows when it has sent a request to the target server and is waiting for a response. At the TLS layer, it is **impossible** to reliably distinguish between a client request and a target server's response. Therefore, the FillGhost injection window must be **explicitly managed** by the application.

**You must call FillGhost start/stop methods yourself at the right moments.**

---

## How to Use

### 1. Enhance Your TLS Connection

After the handshake is complete and you have a `*tls.Conn` representing the client-proxy connection, you can enable FillGhost support:

```go
import (
    "github.com/FillGhost/Go/tls"
    "time"
)

cfg := tls.FillGhostConfig{
    MinLen:       900,                    // minimum payload length (bytes)
    MaxLen:       1400,                   // maximum payload length (bytes)
    Interval:     0,                      // (optional) interval between packets, 0 = as fast as possible
    InitialDelay: 3 * time.Millisecond,   // (optional) initial jitter before sending
}

// Enable FillGhost for this connection (does not start injection yet)
tlsConn.EnableFillGhost(cfg)
```

### 2. Injection Control (Application Responsibility)

After forwarding a client request to the target server, **start injection**:

```go
tlsConn.FillGhostController.Start()
```

As soon as you receive the first byte of a response from the target server, **stop injection**:

```go
tlsConn.FillGhostController.Stop()
```

**You may call Start/Stop multiple times on the same connection for multiple latency windows.**

---

## Example: HTTP Proxy Pseudocode

```go
// Accept incoming TLS connection from client as tlsConn (*tls.Conn)
// ... handshake, authentication, etc. ...

// Before forwarding request to target server:
cfg := tls.FillGhostConfig{MinLen: 900, MaxLen: 1400, Interval: 0, InitialDelay: 3 * time.Millisecond}
tlsConn.EnableFillGhost(cfg)

// For each client request:
for {
    // 1. Forward request to target server
    forwardRequestToTarget()

    // 2. Start FillGhost injection
    tlsConn.FillGhostController.Start()

    // 3. Wait for first response byte from target
    firstByte := readFirstByteFromTarget()

    // 4. Stop FillGhost injection immediately
    tlsConn.FillGhostController.Stop()

    // 5. Forward real response to client
    forwardResponseToClient(firstByte)
    // ... process rest of response as normal ...
}
```

---

## API Reference

### `FillGhostConfig`

```go
type FillGhostConfig struct {
    MinLen       int           // minimum payload length in bytes (recommended: 900)
    MaxLen       int           // maximum payload length in bytes (recommended: 1400)
    Interval     time.Duration // interval between packets (0 for max speed, or a small delay)
    InitialDelay time.Duration // optional delay before first packet (recommended: 3ms)
}
```

### `EnableFillGhost`

```go
func (c *Conn) EnableFillGhost(cfg FillGhostConfig)
```
Enables FillGhost for this connection. Does not start injection until `Start` is called.

### `FillGhostController.Start()`, `.Stop()`

- `.Start()` begins injection (runs as a goroutine, returns immediately).
- `.Stop()` signals injection to cease and waits for background goroutine exit (safe to call multiple times).

---

## Security Notes

- FillGhost packets are valid TLS records, encrypted and authenticated. Their decrypted payload is random bytes, ignored by the application protocol layer.
- Do **not** use FillGhost for covert channels. Its only purpose is to pad latency windows.
- Injection is only active between `.Start()` and `.Stop()`. No padding is sent outside these windows.
- All randomness is cryptographically secure.

---

## FAQ

**Q: Will FillGhost interfere with my normal TLS traffic?**  
A: No. FillGhost packets are injected as extra Application Data records and are ignored by well-behaved application protocols (e.g., HTTP/2, WebSocket). They are never interpreted as real application data.

**Q: Can I enable FillGhost for all traffic automatically?**  
A: Not recommended. Only the application/proxy can determine when to inject. Automatic injection at the TLS layer will not match the actual latency windows and may increase exposure to traffic analysis.

**Q: Is FillGhost compatible with TLS 1.2?**  
A: The default implementation is for TLS 1.3 and AEAD ciphers. Support for older modes is possible but not recommended for new deployments.

---

## Troubleshooting

- If `.Start()` returns an error or injection fails, check that the handshake is complete and the connection is active.
- If the client application does not tolerate extra junk data, ensure that it uses a protocol and parser that ignores unexpected Application Data (HTTP/2, WebSocket, etc).

---

## References

- [FillGhost Protocol Specification](https://github.com/FillGhost/FillGhost/blob/master/SPEC.md)
- [RFC 8446: TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [FillGhost Demo Implementation](https://github.com/FillGhost/FillGhost)
