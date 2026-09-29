# Benchmarks

## Remote async socket benchmark

Run one client at a time. The client connects to the server and sends, and the server receives. With
BenchDirection=download on the client the server sends and the client receives, over the same connection, which
measures the direction from a server that the client cannot be reached from. Copy the server's URL ticket to the
client host.

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
BenchDirection=upload
```

TransferBytes, ChunkSize, PipelineLength and SendWindow also apply to the client. With BenchDirection=download the
client sends them to the server, which sends with them. A server from before BenchDirection does not answer a
download, which then ends with BenchCallTimeout. Missing required settings
skip the manual suite. Removing the server ticket file stops the server early.
