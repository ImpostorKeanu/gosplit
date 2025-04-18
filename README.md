GoSplit is a simple TLS-aware TCP proxy that can be used
to extract cleartext data from TLS tunnels.

# Quick Usage

1. Download a binary from the releases page.
2. Generate a PEM using the `pem` subcommand. (`gosplit pem --help` for examples)
3. Start the proxy. (`gosplit run --help` for examples)

# Warning (Intended Use)

This project was developed for security research purposes (like
[eavesarp-ng]) and is inefficient. Don't use it in production
scenarios.

# Limitations

- As SSL has been deprecated in Go's crypto library, only TLS is 
  currently supported
- A static PEM certificate is used for all connections
  - Support for dynamically generated and cached certificates
    may be implemented in the future
- The client is presumed to send data first, and that first
  transmission should contain a TLS handshake
  - This breaks protocols where the TLS tunnel is negotiated
    during later stages (STARTTLS)
  - Protocols expecting the server to send the initial data
    will result in the connection blocking until timeout

# Using in Other Go Projects

GoSplit was developed as a module so that it can be used in
any Go project. Any type that implements the [Cfg interface][cfg-interface]
can be used to run a TCP [proxy server][proxy-server], allowing
the implementor to customize everything from TLS connection
fingerprinting to handling of intercepted data.

See the [GoSplit utility][utility-cfg] for a simple example of how
the interface can be implemented.

[cfg-interface]: cfg.go
[proxy-server]: proxy.go
[utility-cfg]: cmd/cfg.go

# How it Works

GoSplit checks the bytes of each initial client TCP segment to determine
if the connection should be upgraded to TLS. Data extracted from
connections are base64 encoded and logged to disk in [JSONL format][jsonl].

The following sequence diagram roughly illustrates the connection splitting
process.

[jsonl]: https://jsonlines.org/

```mermaid
sequenceDiagram
participant C as Victim TCP Client
participant GSP as GoSplit Proxy
participant S as Downstream<br/>TLS Server

C<<->>GSP: TCP Handshake

critical Client must send data first
C->>GSP: TCP Segment w/<br/>TLS Client Hello
GSP->>GSP: Fingerprint TLS<br/>Client Hello
GSP-->>GSP: Upgrade client<br/>conn to TLS
end
GSP<<->>S: TCP Handshake
GSP<<->>S: TLS Handshake
GSP<<->>C: TLS Handshake
C->>GSP: Send client data
GSP->>GSP: Log client data
GSP->>S: Send client data
S->>GSP: Send server data
GSP->>GSP: Log server data
GSP->>C: Send server data
```

[eavesarp-ng]: https://github.com/ImpostorKeanu/eavesarp-ng