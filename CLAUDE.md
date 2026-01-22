# CLAUDE.md - Network Module

This file provides guidance to Claude Code (claude.ai/code) when working with the Network module of Malterlib.

## Module Overview

The Network module provides cross-platform networking functionality including TCP/IP sockets, SSL/TLS support, asynchronous socket operations using the actor model, and address resolution. It is built on top of the Core, Concurrency, and Cryptography modules.

## Architecture

### Core Components

#### Socket Interfaces
- **ICSocket** - Base interface for all socket implementations
- **CSocket_TCP** - TCP socket implementation
- **CSocket_SSL** - SSL/TLS socket implementation with certificate validation

#### Async Socket System
- **CAsyncSocketActor** - Actor-based asynchronous socket handling
- **CAsyncSocketClientActor** - Client-side async socket actor
- **CAsyncSocketServerActor** - Server-side async socket actor with accept loop
- **CResolveActor** - Asynchronous DNS resolution actor

#### Address Types
- **CNetAddress** - Universal network address container
- **CNetAddressIPv4** - IPv4 address representation
- **CNetAddressIPv6** - IPv6 address representation
- **CNetAddressTCPv4** - TCP over IPv4 address with port
- **CNetAddressTCPv6** - TCP over IPv6 address with port

### Key Enums

```cpp
enum ENetTCPState : uint32
{
	ENetTCPState_None = 0
	, ENetTCPState_Send = DMibBit(0)        // Ready to send
	, ENetTCPState_Receive = DMibBit(1)     // Data available to receive
	, ENetTCPState_Connect = DMibBit(2)     // Connection established
	, ENetTCPState_Disconnect = DMibBit(3)  // Connection closed
	, ENetTCPState_Shutdown = DMibBit(4)    // Socket shutdown
	, ENetTCPState_Error = DMibBit(5)       // Socket error occurred
};

enum EAsyncSocketStatus : uint16
{
	EAsyncSocketStatus_None = 0
	, EAsyncSocketStatus_NormalClosure      // Graceful disconnect
	, EAsyncSocketStatus_AbnormalClosure    // Unexpected disconnect
	, EAsyncSocketStatus_Timeout            // Operation timed out
	, EAsyncSocketStatus_Rejected           // Connection rejected
	, EAsyncSocketStatus_AlreadyClosed      // Socket already closed
};

enum ENetFlag
{
	ENetFlag_None = 0
	, ENetFlag_ReuseAddress = DMibBit(0)    // Allow address reuse
	, ENetFlag_ReusePort = DMibBit(1)       // Allow port reuse
	, ENetFlag_NonBlocking = DMibBit(2)     // Non-blocking mode
};
```

## Usage Patterns

### Basic TCP Socket Connection

```cpp
// Create a TCP socket
auto pSocket = CSocket_TCP::fs_GetFactory()("");

// Connect to server
CNetAddress ServerAddress = CSocket::fs_ResolveAddress("192.168.1.100:8080");
pSocket->f_Connect
	(
		ServerAddress
		, [](ENetTCPState _StateAdded)
		{
			if (_StateAdded & ENetTCPState_Connect)
				DMibLog(Info, "Connected!");
			if (_StateAdded & ENetTCPState_Disconnect)
				DMibLog(Info, "Disconnected!");
		}
	)
;

// Send data
char const *pMessage = "Hello Server";
mint nBytesTransferred = pSocket->f_Send(pMessage, fg_StrLen(pMessage));
if (nBytesTransferred > 0)
	DMibLog(Info, "Sent {} bytes", nBytesTransferred);

// Receive data
char Buffer[1024];
mint nBytesTransferred = pSocket->f_Receive(Buffer, sizeof(Buffer));
if (nBytesTransferred > 0)
	DMibLog(Info, "Received: {}", NStr::CStr(Buffer, nBytesTransferred));

// Close connection
pSocket->f_Close();
```

### SSL/TLS Socket Connection

```cpp
// Create SSL context with certificate
CSSLSettings SSLSettings;
SSLSettings.m_PublicCertificateData = f_LoadCertificate();
SSLSettings.m_PrivateKeyData = f_LoadPrivateKey();
SSLSettings.m_LocalCertificateStore = f_LoadTrustedCertificates();

NStorage::TCSharedPointer<CSSLContext> pContext = fg_Construct(CSSLContext::EType_Client, SSLSettings);

// Create SSL socket factory
FVirtualSocketFactory fSSLFactory = CSocket_SSL::fs_GetFactory
	(
		pContext
		, [](EAuthenticationResult _Result, CSSLConnectionResult const &_ConnectionResult) -> bool
		{
			// Handle authentication result
			if (_Result == EAuthenticationResult_Success)
			{
				DMibLog(Info, "SSL authentication successful");
				return true;
			}
			DMibLog(Error, "SSL authentication failed: {}", _ConnectionResult.f_GetErrorMessage());
			return false;
		}
	)
;

// Create and connect SSL socket
auto pSSLSocket = fSSLFactory("example.com");
CNetAddress ServerAddress = CSocket::fs_ResolveAddress("example.com:443");
pSSLSocket->f_Connect
	(
		ServerAddress
		, [](ENetTCPState _StateAdded)
		{
			if (_StateAdded & ENetTCPState_Connect)
				fg_Log("SSL connection established");
		}
	)
;
```

### Async Socket Client

```cpp
// Create async client actor
TCActor<CAsyncSocketClientActor> ClientActor = fg_Construct();

// Connect to server
auto NewConnection = co_await ClientActor(&CAsyncSocketClientActor::f_Connect, "localhost:8080", "", NNetwork::ENetAddressType_TCPv4, 8080, nullptr);

// Define callbacks
CAsyncSocketCallbacks Callbacks;
Callbacks.m_fOnReceiveData = g_ActorFunctor / [](TCSharedPointer<CIOByteVector> _pMessage) -> TCFuture<void>
	{
		NStr::CStr Message(reinterpret_cast<char const *>(_pMessage->f_GetData()), _pMessage->f_GetSize());
		DMibLog(Info, "Received: {}", Message);
		co_return {};
	}
;

Callbacks.m_fOnClose = g_ActorFunctor / [](EAsyncSocketStatus _Status, NStr::CStr _Message, EAsyncSocketCloseOrigin _Origin) -> TCFuture<void>
	{
		DMibLog(Info, "Connection closed: {} (Status: {})", _Message, _Status);
		co_return {};
	}
;

auto Connection = co_await NewConnection.f_Accept(fg_Move(Callbacks));
```
## Platform-Specific Considerations

### Windows
- Uses Winsock2 API internally
- Requires proper WSAStartup/WSACleanup (handled automatically)
- IOCP used for async operations

### macOS/Linux
- Uses BSD sockets
- epoll (Linux) or kqueue (macOS) for async operations
- Unix domain sockets fully supported

### Cross-Platform
- All high-level APIs abstract platform differences
- Use CNetAddress for portable address handling
- Async actors work identically across platforms

## Testing

### Running Network Tests

```bash
# Build and run all network tests
MalterlibBuildShowProgress=false ./mib build Tests
/opt/Deploy/Tests/RunAllTests --paths '["Malterlib/Network/*"]'

# Run specific test
/opt/Deploy/Tests/RunAllTests --paths '["Malterlib/Network/AsyncSocket"]'
```

### Test Coverage Areas
- Basic TCP connectivity
- SSL/TLS connections with certificate validation
- Async socket client/server operations
- Address resolution (IPv4, IPv6, Unix)
- Error handling and timeout scenarios
- Large message fragmentation and reassembly
- Concurrent connection handling

## Dependencies

### Required Modules
- **Core** - Base types and memory management
- **Concurrency** - Actor system and futures
- **Cryptography** - SSL/TLS support

### External Libraries
- BoringSSL (for SSL/TLS)
- Platform networking libraries (Winsock2, BSD sockets)

## Security Considerations

### SSL/TLS Best Practices
- Always validate certificates in production
- Use strong cipher suites (configured in CSSLContext)
- Implement proper hostname verification
- Handle certificate expiration gracefully

### Input Validation
- Validate all received data before processing
- Implement message size limits
- Use secure allocators for sensitive data
- Clear sensitive data from memory after use

### Network Timeouts
- Always set appropriate timeouts for operations
- Implement exponential backoff for retries
- Handle partial reads/writes correctly
- Clean up resources on timeout

## Performance Tips

### Buffer Management
- Reuse buffers when possible to reduce allocations
- Use CIOByteVector for efficient buffer management
- Consider using memory pools for high-frequency allocations

### Async vs Sync
- Use async sockets for scalable server applications
- Sync sockets are simpler for client applications
- Actor model provides natural concurrency boundaries

## Debugging

### Common Issues

1. **Connection Refused**
   - Check if server is listening on correct address/port
   - Verify firewall settings
   - Ensure address format is correct

2. **SSL Handshake Failures**
   - Verify certificate validity
   - Check certificate chain completeness
   - Ensure cipher suite compatibility

3. **Async Actor Deadlocks**
   - Avoid blocking operations in actor callbacks
   - Use futures properly for synchronization
   - Check for circular dependencies

4. **Memory Leaks**
   - Ensure proper cleanup in error paths
   - Use RAII and smart pointers
   - Clear callbacks when destroying actors

## Important Notes

- Network operations are non-blocking always
- All callbacks are executed on the actor's thread
- Socket state changes are edge-triggered, not level-triggered
- Always check return values and handle partial operations
- The module uses Malterlib's custom memory allocators
- SSL contexts can be shared between multiple sockets
- Unix domain sockets use the "UNIX:" prefix in addresses
- IPv6 addresses must be enclosed in brackets when specifying ports
