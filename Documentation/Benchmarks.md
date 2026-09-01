# Benchmarks

## Remote async socket benchmark

Run one client at a time; the client sends and the server receives. Copy the server's URL ticket to the client
host.

Server settings:

```text
BenchHost=<routable address>
BenchPort=39301
BenchSchemes=tls
BenchTicketFile=<ticket path>
BenchServeSeconds=600
```

Only BenchHost is required; use BenchSchemes=tcp for plaintext TCP. Client settings:

```text
BenchTicketFile=<copied ticket path>
# Or BenchTicket=<url>
BenchCallTimeout=600
```

TransferBytes, ChunkSize, PipelineLength and SendWindow also apply to the client. Missing required settings
skip the manual suite. Removing the server ticket file stops the server early.
