// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

/*---------------------------------------------------------------------------------------------*\
	Author:			Erik Olofsson, Michael Wynne

	Contents:		NMib::NNetwork:
						CNetAddressIPv4
						CNetAddressIPv6
						CNetAddressTCPv4
						CNetAddressTCPv6
						ENetTCPState
						CNetAddress
						CSocket

					System Specifics in NMib::NSys::NNetwork:
						using CAddress = void*;

						CAddress fg_CreateAddress(::NMib::NNetwork::ENetAddressType _Type, void const* _pData, umint _nDataBytes);

						::NMib::NNetwork::ENetAddressType fg_GetAddressType(CAddress _Address);
						bool fg_GetAddressRaw(CAddress _Address, ::NMib::NNetwork::ENetAddressType _ExpectedType, void* _opRawData, umint _nDataBytes);
						CAddress fg_SetAddressRaw(CAddress _Address, ::NMib::NNetwork::ENetAddressType _Type, void const* _pRawData, umint _nDataBytes);

						CAddress fg_ResolveAddress(const NMib::NStr::CStr &_Address, ::NMib::NNetwork::ENetAddressType _PreferType = ::NMib::NNetwork::ENetAddressType_None);

						void *fg_AsyncResolveAddress_Open(const NMib::NStr::CStr &_Address, ::NMib::NNetwork::ENetAddressType _PreferType, NMib::NThread::CSemaphoreAggregate *_pReportTo);
						bool fg_AsyncResolveAddress_GetResult(void *_pResolver, CAddress& _opAddress, NMib::NStr::CStr &_Error);
						void fg_AsyncResolveAddress_Close(void *_pResolver);

						int fg_CompareAddresses(CAddress _pFirst, CAddress _pSecond);

						void fg_FreeAddress(CAddress _Address); // It is OK to free a nullptr address.

						NMib::NStr::CStr fg_GetAddressString(CAddress _Address, ENetAddressStringFlag _Flags);

					// Connection Operations
						void *fg_AsyncConnect(CAddress _pAddr, NMib::NThread::CSemaphoreAggregate *_pReportTo); // Report to the supplied event when new data is received or when we are ready to send new data and when the connection is connected

						void *fg_Listen(CAddress _pAddr, NMib::NThread::CSemaphoreAggregate *_pReportTo, NMib::NNetwork::ENetFlag _Flags); // Report to the supplied event when a new connection has arrived
						void *fg_Accept(void *_pSocket, NMib::NThread::CSemaphoreAggregate *_pReportTo, NMib::NNetwork::ENetFlag _Flags); // Report to the supplied event when new data is received or when we are ready to send new data

						void fg_Close(void *_pSocket); // Closes the socket and connection

						umint fg_Receive(void *_pSocket, void *_pData, umint _DataLen); // Returns bytes received
						umint fg_Send(void *_pSocket, const void *_pData, umint _DataLen); // Returns bytes sent

					// Socket Properties & State

						NMib::NNetwork::ENetTCPState fg_GetState(void *_pSocket); // Get the state of data available
						NMib::NStr::CStr fg_GetCloseReason(void *_pSocket);

						void *fg_InheritHandle2(void *_pSocket, NMib::NThread::CSemaphoreAggregate *_pReportTo);
						void *fg_GiveUpForInherit(void *_pSocket);
						void *fg_GetOSSocket(void *_pSocket);

						CAddress fg_GetPeerAddress(void *_pSocket);

	Comments:			Non-Blocking Operation:

						All reportable events are edge triggered. That is, they are signalled when
						the sockets state changes.

						When a reportable event is signalled you call fg_GetState(pSocket) to
						get the current state of the socket. The returned state bitfield represents
						state changes since the last time fg_GetState was called on that socket,
						NOT the current state of the socket.

						In some circumstances a reportable event will be signalled erroneously.
						This means that you should ALWAYS check the socket state after the event
						is signalled.

						TODO:
							Typedef for sockets in NSys::NNetwork
								using CSocket = void *;

\*_____________________________________________________________________________________________*/
#ifndef DMibSafety_IncMalterlib_H
#	error "You have to include this file through <Mib/Core/Core>"
#endif

#include <Mib/Core/Platform>
#include <Mib/Core/IoStream>
#include "Malterlib_Network_Exception.h"

namespace NMib::NNetwork
{
	class CNetAddressIPv4
	{
	public:
		uint8 m_IP[4] = {};

		CNetAddressIPv4() = default;

		CNetAddressIPv4(uint8 _0, uint8 _1, uint8 _2, uint8 _3)
		{
			m_IP[0] = _0;
			m_IP[1] = _1;
			m_IP[2] = _2;
			m_IP[3] = _3;
		}

		CNetAddressIPv4(const CNetAddressIPv4 &_Src)
		{
			NMemory::fg_MemCopy(m_IP, _Src.m_IP, sizeof(m_IP));
		}

		CNetAddressIPv4 &operator = (const CNetAddressIPv4 &_Src)
		{
			NMemory::fg_MemCopy(m_IP, _Src.m_IP, sizeof(m_IP));

			return *this;
		}

		template <typename tf_CStream>
		void f_Stream(tf_CStream &_Stream)
		{
			for (auto &Ip : m_IP)
				_Stream % Ip;
		}

		template <typename tf_CStr>
		void f_Format(tf_CStr &o_String) const
		{
			o_String += typename tf_CStr::CFormat("{}.{}.{}.{}") << m_IP[0] << m_IP[1] << m_IP[2] << m_IP[3];
		}

		void f_SetLocalhost()
		{
			*this = {127, 0, 0, 1};
		}
	};

	class CNetAddressIPv6
	{
	public:
		uint8 m_IP[16] = {};

		CNetAddressIPv6() = default;

		CNetAddressIPv6(	uint8 _0, uint8 _1, uint8 _2, uint8 _3
						,	uint8 _4, uint8 _5, uint8 _6, uint8 _7
						,	uint8 _8, uint8 _9, uint8 _10, uint8 _11
						,	uint8 _12, uint8 _13, uint8 _14, uint8 _15)
		{
			m_IP[0] = _0; m_IP[1] = _1;
			m_IP[2] = _2; m_IP[3] = _3;
			m_IP[4] = _4; m_IP[5] = _5;
			m_IP[6] = _6; m_IP[7] = _7;
			m_IP[8] = _8; m_IP[9] = _9;
			m_IP[10] = _10; m_IP[11] = _11;
			m_IP[12] = _12; m_IP[13] = _13;
			m_IP[14] = _14; m_IP[15] = _15;
		}

		CNetAddressIPv6(const CNetAddressIPv6 &_Src)
		{
			NMemory::fg_MemCopy(m_IP, _Src.m_IP, sizeof(m_IP));
		}

		CNetAddressIPv6 &operator = (const CNetAddressIPv6 &_Src)
		{
			NMemory::fg_MemCopy(m_IP, _Src.m_IP, sizeof(m_IP));

			return *this;
		}

		template <typename tf_CStream>
		void f_Stream(tf_CStream &_Stream)
		{
			for (auto &Ip : m_IP)
				_Stream % Ip;
		}

		void f_SetLocalhost()
		{
			*this = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
		}
	};

	enum ENetAddressType : uint32
	{
		ENetAddressType_None = 0
		, ENetAddressType_TCPv4 = 1
		, ENetAddressType_TCPv6 = 2
		, ENetAddressType_Unix = 3
	};

	enum ENetAddressStringFlag
	{
		ENetAddressStringFlag_None = 0
		, ENetAddressStringFlag_IncludeType = DMibBit(0)
		, ENetAddressStringFlag_IncludePort = DMibBit(1)
	};

	template<typename t_CIPAddress, ENetAddressType t_Type>
	class TCNetAddressTCP : public t_CIPAddress
	{
	public:
		uint16 m_Port;

		static constexpr ENetAddressType mc_Type = t_Type;

		TCNetAddressTCP()
			: m_Port(0)
		{
		}

		TCNetAddressTCP(const TCNetAddressTCP &_Src)
		{
			NMemory::fg_MemCopy(this, &_Src, sizeof(*this));
		}

		TCNetAddressTCP(const t_CIPAddress &_Src, uint16 _Port)
			: t_CIPAddress(_Src)
			, m_Port(_Port)
		{
		}

		TCNetAddressTCP &operator = (const TCNetAddressTCP &_Src)
		{
			NMemory::fg_MemCopy(this, &_Src, sizeof(*this));

			return *this;
		}

		TCNetAddressTCP &operator = (const t_CIPAddress &_Src)
		{
			(*this) = _Src;

			return *this;
		}

		t_CIPAddress const& f_GetIP() const { return *this; }

		static ENetAddressType fs_GetType()
		{
			return t_Type;
		}
	};

	using CNetAddressTCPv4 = TCNetAddressTCP<CNetAddressIPv4, ENetAddressType_TCPv4>;
	using CNetAddressTCPv6 = TCNetAddressTCP<CNetAddressIPv6, ENetAddressType_TCPv6>;

	enum ENetTCPState
	{
		ENetTCPState_None			= 0
		, ENetTCPState_Read			= DMibBit(0) // Data is awailable for reading
		, ENetTCPState_Write		= DMibBit(1) // More data can now be sent
		, ENetTCPState_Connection	= DMibBit(2) // A new connection is available for accept
		, ENetTCPState_Connected	= DMibBit(3) // A async connection has completed
		, ENetTCPState_Closed		= DMibBit(4) // The connection has been lost
		, ENetTCPState_RemoteClosed	= DMibBit(5) // A connection closure was initiated by remote call f_Shutdown
	};

	enum ENetFlag
	{
		ENetFlag_None = 0
		, ENetFlag_ReusePort = DMibBit(0) // Reuse port, allowing several sockets to bind to the same port
	};

	class CNetAddress;

	// The released half of a send: the kernel is done with the operation's buffers. Carries the
	// transfer name the submitting socket stamped on the completion, or mc_iTransferNone when it
	// stamped none
	using FSocketSendReleased = NMib::NFunction::TCFunctionMovable<void (umint _iTransfer)>;

	bool fg_IsUnixSocketAddressString(NStr::CStr const &_Address);

	// Whether an address, or the host part of a URL, names this machine's loopback interface:
	// 127/8, ::1, or the IPv4-mapped form of 127/8; "localhost" for the string form. Transports
	// treat loopback like a unix socket where the difference is the wire, not the peer
	bool fg_IsLoopbackAddress(CNetAddress const &_Address);
	bool fg_IsLoopbackHostString(NStr::CStr const &_Host);
	NStr::CStr fg_GetSafeUnixSocketPath(NStr::CStr const &_WantedPath);
}

namespace NMib::NStream
{
	template <typename t_CStream>
	class TCBinaryStreamTypeReference<t_CStream, NNetwork::CNetAddressTCPv4 >
	{
	public:
		static constexpr void fs_Feed(t_CStream &_Stream, NNetwork::CNetAddressTCPv4 const &_Data)
		{
			_Stream.f_FeedBytes(_Data.m_IP, sizeof(_Data.m_IP));
			_Stream << _Data.m_Port;
		}

		static constexpr void fs_Consume(t_CStream &_Stream, NNetwork::CNetAddressTCPv4 &_Data)
		{
			_Stream.f_ConsumeBytes(_Data.m_IP, sizeof(_Data.m_IP));
			_Stream >> _Data.m_Port;
		}
	};

	template <typename t_CStream>
	class TCBinaryStreamTypeReference<t_CStream, NNetwork::CNetAddressIPv4 >
	{
	public:
		static constexpr void fs_Feed(t_CStream &_Stream, NNetwork::CNetAddressIPv4 const &_Data)
		{
			_Stream.f_FeedBytes(_Data.m_IP, sizeof(_Data.m_IP));
		}

		static constexpr void fs_Consume(t_CStream &_Stream, NNetwork::CNetAddressIPv4 &_Data)
		{
			_Stream.f_ConsumeBytes(_Data.m_IP, sizeof(_Data.m_IP));
		}
	};

	template <typename t_CStream>
	class TCBinaryStreamTypeReference<t_CStream, NNetwork::CNetAddressTCPv6 >
	{
	public:
		static constexpr void fs_Feed(t_CStream &_Stream, NNetwork::CNetAddressTCPv6 const &_Data)
		{
			_Stream.f_FeedBytes(_Data.m_IP, sizeof(_Data.m_IP));
			_Stream << _Data.m_Port;
		}

		static constexpr void fs_Consume(t_CStream &_Stream, NNetwork::CNetAddressTCPv6 &_Data)
		{
			_Stream.f_ConsumeBytes(_Data.m_IP, sizeof(_Data.m_IP));
			_Stream >> _Data.m_Port;
		}
	};

	template <typename t_CStream>
	class TCBinaryStreamTypeReference<t_CStream, NNetwork::CNetAddressIPv6 >
	{
	public:
		static constexpr void fs_Feed(t_CStream &_Stream, NNetwork::CNetAddressIPv6 const &_Data)
		{
			_Stream.f_FeedBytes(_Data.m_IP, sizeof(_Data.m_IP));
		}

		static constexpr void fs_Consume(t_CStream &_Stream, NNetwork::CNetAddressIPv6 &_Data)
		{
			_Stream.f_ConsumeBytes(_Data.m_IP, sizeof(_Data.m_IP));
		}
	};
}

namespace NMib::NSys
{
	struct ICIoLoop;
}

namespace NMib::NSys::NNetwork
{
// Addresses
	using CAddress = void *;

	CAddress fg_CreateAddress(::NMib::NNetwork::ENetAddressType _Type, void const* _pData, umint _nDataBytes);
	CAddress fg_DuplicateAddress(CAddress _Address);

	::NMib::NNetwork::ENetAddressType fg_GetAddressType(CAddress _Address);
	bool fg_GetAddressRaw(CAddress _Address, ::NMib::NNetwork::ENetAddressType _ExpectedType, void* _opRawData, umint _nDataBytes);
	CAddress fg_SetAddressRaw(CAddress _Address, ::NMib::NNetwork::ENetAddressType _Type, void const* _pRawData, umint _nDataBytes);

	CAddress fg_ResolveAddress(const NMib::NStr::CStr &_Address, ::NMib::NNetwork::ENetAddressType _PreferType = ::NMib::NNetwork::ENetAddressType_None);

	umint fg_GetMaxUnixSocketNameLength();

	void *fg_AsyncResolveAddress_Open(const NMib::NStr::CStr &_Address, ::NMib::NNetwork::ENetAddressType _PreferType, NMib::NFunction::TCFunctionMutable<void ()> &&_fOnFinish);
	bool fg_AsyncResolveAddress_GetResult(void *_pResolver, CAddress& _opAddress, NMib::NStr::CStr &_Error);
	void fg_AsyncResolveAddress_Close(void *_pResolver);

	int fg_CompareAddresses(CAddress _pFirst, CAddress _pSecond);

	void fg_FreeAddress(CAddress _Address); // It is OK to free a nullptr address.

	NMib::NStr::CStr fg_GetAddressString(CAddress _Address, NMib::NNetwork::ENetAddressStringFlag _Flags);

	// Connection Operations

	// Report to the supplied event when new data is received or when we are ready to send new data and when the connection is connected
	void *fg_AsyncConnect(CAddress _pAddr, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange, CAddress _pBindAddr);
	void fg_StartSocket(void *_pSocket); // Starts the event loop

	// Socket event loops
	//
	// Sockets are serviced by one shared loop on its own thread unless a thread claims them through
	// the general io loop machinery (NSys::ICIoLoop in Mib/Core/IoLoop, hosted by
	// the concurrency manager): a socket created while NSys::fg_GetThreadIoLoop() is set registers
	// with that loop instead of the shared one

	// Report to the supplied event when a new connection has arrived
	void *fg_Listen(CAddress _pAddr, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange, NMib::NNetwork::ENetFlag _Flags);
	// Report to the supplied event when new data is received or when we are ready to send new data
	void *fg_ListenDatagram(CAddress _pAddr, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange, NMib::NNetwork::ENetFlag _Flags);
	// Report to the supplied event when new data is received or when we are ready to send new data
	void *fg_Accept(void *_pSocket, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange);

	void fg_Shutdown(void *_pSocket); // Closes the socket and connection

	void fg_Close(void *_pSocket); // Closes the socket and connection

	// Returns bytes received. A zero return means "nothing right now", which is either a transport
	// that would block or a peer that closed its sending side; o_bEndOfStream separates the two for
	// the layers that must tell them apart — TLS above all, where a stream that ends without its
	// close notification is a protocol error, while a plain socket learns the same thing from the
	// close event the loop is about to report
	umint fg_Receive(void *_pSocket, void *_pData, umint _DataLen, bool &o_bEndOfStream);
	umint fg_Send(void *_pSocket, const void *_pData, umint _DataLen); // Returns bytes sent
	// Returns total bytes sent across the spans in order; may stop mid span on partial progress
	umint fg_SendVectored(void *_pSocket, NSys::CIoSpan const *_pSpans, umint _nSpans);

	// Completion transfers
	//
	// Where the socket's event loop can complete transfers in the kernel (the io_uring backend), a
	// receive or send is submitted once and reported through its completion functor instead of being
	// driven by readiness events plus syscalls. The functor runs on the loop's thread exactly once per
	// submitted operation. The caller owns the buffers and must keep them untouched and alive until
	// that functor has run; closing the socket cancels outstanding operations, and each cancelled
	// operation still reports through its functor. Sends may be submitted while earlier ones are
	// outstanding; the loop reports their completions one at a time, in submission order, which is
	// the invariant the caller's byte accounting rests on — how many it actually keeps with the
	// kernel at once is the loop's own business

	// The created loop the socket registered with, null when it is serviced by the shared poller.
	// Constant for the lifetime of a started socket. What an upgrade uses to keep the connection
	// on its loop: the new transport re-registers the raw handle through the ambient binding
	NMib::NSys::ICIoLoop *fg_GetOwningIoLoop(void *_pSocket);

	// Constant for the lifetime of a started socket, so callers can decide their transfer mode once
	bool fg_SupportsCompletionIo(void *_pSocket);
	// Whether an accepted send's buffers are released directly after its completion is reported,
	// so nothing the caller recycles at the completion is still with the kernel. False while a
	// zero copy send is possible on the socket
	bool fg_SendReleaseIsPrompt(void *_pSocket);
	// False when the submission was refused (unsupported socket, or the socket is closing), in
	// which case the completion functor never runs
	bool fg_SupportsReceiveStream(void *_pSocket);
	bool fg_StartReceiveStream(void *_pSocket, umint _nBufferBytes, NStorage::TCSharedPointer<NSys::CIoStreamBackpressure> _pBackpressure, NSys::FIoStreamSink &&_fSink);
	void fg_ResumeReceiveStream(void *_pSocket);
	// Sizes the socket's kernel buffers to the window where the platform does not autotune them,
	// and bounds the unreleased bytes of zero copy sends to it. A listen socket passes the buffers on
	// to the connections it accepts
	void fg_SetSendWindow(void *_pSocket, umint _nBytes, bool _bConfigured);
	bool fg_SubmitSendVectored(void *_pSocket, NSys::CIoSpan const *_pSpans, umint _nSpans, NSys::FIoCompletion &&_fOnComplete, NSys::FIoBufferReleased &&_fOnBufferReleased);
	umint fg_SendDatagram(void *_pSocket, NSys::NNetwork::CAddress _Address, const void *_pData, umint _DataLen); // Returns bytes sent
	umint fg_ReceiveDatagram(void *_pSocket, NSys::NNetwork::CAddress _Address, void *_pData, umint _DataLen); // Returns bytes received

// Socket Properties & State

	// Report to the supplied event when new data is received or when we are ready to send new data
	void fg_SetOnStateChange(void *_pSocket, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange);

	NMib::NNetwork::ENetTCPState fg_GetState(void *_pSocket); // Get the state of data available
	NMib::NStr::CStr fg_GetCloseReason(void *_pSocket);

	// Requests the next readiness report for the given directions, forwarded to the socket's
	// loop. Only meaningful directly after a would-block observation; the platform transfer
	// functions request for themselves, so this exists for layers whose would-block observation
	// happens outside them — TLS, whose reads and writes go through its own transport
	void fg_RequestReadiness(void *_pSocket, bool _bRead, bool _bWrite);

	void *fg_InheritHandle2(void *_pSocket, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange);
	// Synchronous handoff: legal only where blocking on the loop's acknowledgement is — the
	// shared poller. Sockets on created loops use the asynchronous form
	void *fg_GiveUpForInherit(void *_pSocket);
	// Acknowledge-first handoff: consumes the platform socket, and the continuation receives the
	// raw handle once the loop holds no reference to the file — on the loop's thread for a
	// created loop, inline on the calling thread otherwise
	void fg_GiveUpForInheritAsync(void *_pSocket, NMib::NFunction::TCFunctionMovable<void (void *_pSocketHandle)> &&_fOnHandle);
	// Closes the socket and runs the continuation once the close is complete — the descriptor
	// closed and a listener's unix socket file removed — on the loop's thread for a socket on a
	// created loop, inline otherwise. An owner that reuses a listener's name waits for it. The
	// synchronous fg_Close is legal only where blocking on the loop's acknowledgement is — the
	// shared poller — and refuses for a socket on a created loop, like the inherit handoff
	void fg_CloseAsync(void *_pSocket, NMib::NFunction::TCFunctionMovable<void ()> &&_fOnClosed);
	// Closes a raw handle produced by a handoff that no transport ever adopted
	void fg_CloseSocketHandle(void *_pSocketHandle);
	void *fg_GetOSSocket(void *_pSocket);

	CAddress fg_GetPeerAddress(void *_pSocket);
	uint32 fg_GetListenPort(void *_pSocket);

	// Kernel process identity of one endpoint of a connected unix domain socket. On Linux pidfs
	// kernels (6.9 and later) the pidfs device and inode name the exact kernel process object:
	// they are boot-unique, independent of pid namespaces and immune to pid-number recycling, so
	// they are the preferred binding and support cross-namespace peers. The process id is the
	// endpoint's pid in its own namespace; it is only comparable across a connection when both
	// endpoints share a pid namespace, and it is 0 for a peer whose pid is not visible here.
	struct CProcessIdentity
	{
		uint64 m_ProcessID = 0;
		uint64 m_PidFSDevice = 0; // Non-zero only when the kernel serves pidfds from pidfs (Linux 6.9)
		uint64 m_PidFSInode = 0;
	};

	// Kernel-authenticated process identities of a connected unix domain socket: the local process
	// and the immediate peer process as reported by the kernel (getpid and SO_PEERCRED / LOCAL_PEERPID
	// / SIO_AF_UNIX_GETPEERPID). Returns false when the platform cannot supply it (a Windows build too
	// old for the peer pid ioctl) or the socket is not a connected unix socket. Defined by the Core platform layer (Malterlib/Core
	// Malterlib_Core_PlatformImp_{MacOS,Linux,MSVC}.cpp), like the other NSys::NNetwork functions
	// in this block: a platform without a network backend (for example Emscripten) defines none of
	// this block's functions, so this adds no platform requirement the block does not already have
	bool fg_GetProcessIdentity(void *_pSocket, CProcessIdentity &o_LocalIdentity, CProcessIdentity &o_PeerIdentity);

	// Whether this machine can report the kernel peer process identity of a connected unix domain
	// socket. Always true on macOS and Linux; on Windows true from the kernels that support
	// SIO_AF_UNIX_GETPEERPID (Windows 10 1809, build 17763). The authenticated unix transport is
	// gated on this
	bool fg_HasUnixSocketPeerProcessIdentity();
}

namespace NMib::NNetwork
{
	class CNetAddress
	{
	protected:
		NMib::NSys::NNetwork::CAddress mp_Address;

	public:
		CNetAddress()
			: mp_Address(nullptr)
		{}

		explicit CNetAddress(NMib::NSys::NNetwork::CAddress _Address)
			: mp_Address(_Address)
		{
		}

		CNetAddress(CNetAddress&& _ToMove)
			: mp_Address(_ToMove.mp_Address)
		{
			_ToMove.mp_Address = nullptr;
		}

		CNetAddress(CNetAddress const& _ToCopy)
			: mp_Address(nullptr)
		{
			if (_ToCopy.mp_Address)
				mp_Address = NMib::NSys::NNetwork::fg_DuplicateAddress(_ToCopy.mp_Address);
		}

		template<typename t_CAddress>
		CNetAddress(t_CAddress const &_Address)
			: mp_Address(NMib::NSys::NNetwork::fg_CreateAddress(t_CAddress::fs_GetType(), &_Address, sizeof(t_CAddress)))
		{
		}

		template<typename t_CAddress>
		CNetAddress& operator= (t_CAddress const &_Address)
		{
			f_Clear();

			mp_Address = NMib::NSys::NNetwork::fg_CreateAddress(t_CAddress::fs_GetType(), &_Address, sizeof(t_CAddress));

			return *this;
		}

		CNetAddress& operator= (CNetAddress&& _ToMove)
		{
			f_Clear();

			mp_Address = _ToMove.mp_Address;
			_ToMove.mp_Address = nullptr;

			return *this;
		}

		CNetAddress& operator= (CNetAddress const& _ToCopy)
		{
			f_Clear();

			if (_ToCopy.mp_Address)
				mp_Address = NMib::NSys::NNetwork::fg_DuplicateAddress(_ToCopy.mp_Address);

			return *this;
		}

		~CNetAddress()
		{
			f_Clear();
		}

		void f_Clear()
		{
			if (mp_Address)
			{
				NMib::NSys::NNetwork::fg_FreeAddress(mp_Address);
				mp_Address = nullptr;
			}
		}

		void *f_Detach()
		{
			void *pRet = mp_Address;
			mp_Address = nullptr;
			return pRet;
		}

		void *f_AccessRaw() const
		{
			return mp_Address;
		}

		bool f_IsEmpty() const
		{
			return mp_Address == nullptr;
		}

		NStr::CStr f_GetString(ENetAddressStringFlag _Flags) const
		{
			if (mp_Address == nullptr)
				return "";
			return NMib::NSys::NNetwork::fg_GetAddressString(mp_Address, _Flags);
		}

		ENetAddressType f_GetType() const
		{
			return mp_Address ? NMib::NSys::NNetwork::fg_GetAddressType(mp_Address) : ENetAddressType_None;
		}

		template<typename t_CAddress>
		bool f_Get(t_CAddress& _oAddress) const
		{
			return NMib::NSys::NNetwork::fg_GetAddressRaw(mp_Address, t_CAddress::fs_GetType(), &_oAddress, sizeof(t_CAddress));
		}

		bool f_Set(CNetAddress const &_Address)
		{
			f_Clear();
			if (_Address.mp_Address)
				mp_Address = NMib::NSys::NNetwork::fg_DuplicateAddress(_Address.mp_Address);

			return mp_Address != nullptr;
		}

		template<typename t_CAddress>
		bool f_Set(t_CAddress const &_Address)
		{
			f_Clear();

			if (mp_Address)
				mp_Address = NMib::NSys::NNetwork::fg_SetAddressRaw(mp_Address, t_CAddress::fs_GetType(), &_Address, sizeof(t_CAddress));
			else
				mp_Address = NMib::NSys::NNetwork::fg_CreateAddress(t_CAddress::fs_GetType(), &_Address, sizeof(t_CAddress));

			return mp_Address != nullptr;
		}

		bool f_SetPort(uint16 _Port)
		{
			if (!mp_Address)
				return false;

			switch(NMib::NSys::NNetwork::fg_GetAddressType(mp_Address))
			{
				case ENetAddressType_TCPv4:
					{
						CNetAddressTCPv4 TCPv4;
						if (!f_Get(TCPv4))
							return false;

						TCPv4.m_Port = _Port;

						return f_Set(TCPv4);
					}

				case ENetAddressType_TCPv6:
					{
						CNetAddressTCPv6 TCPv6;
						if (!f_Get(TCPv6))
							return false;

						TCPv6.m_Port = _Port;

						return f_Set(TCPv6);
					}
				default:
					return false;
			}
		}

		uint16 f_GetPort() const
		{
			if (!mp_Address)
				return 0;

			switch(NMib::NSys::NNetwork::fg_GetAddressType(mp_Address))
			{
				case ENetAddressType_TCPv4:
					{
						CNetAddressTCPv4 TCPv4;
						if (!f_Get(TCPv4))
							return 0;

						return TCPv4.m_Port;
					}

				case ENetAddressType_TCPv6:
					{
						CNetAddressTCPv6 TCPv6;
						if (!f_Get(TCPv6))
							return 0;

						return TCPv6.m_Port;
					}
				default:
					return 0;
			}
		}

		operator NMib::NSys::NNetwork::CAddress() const
		{
			return mp_Address;
		}

		bool operator == (CNetAddress const& _Other) const
		{
			return NMib::NSys::NNetwork::fg_CompareAddresses(mp_Address, _Other.mp_Address) == 0;
		}

		COrdering_Weak operator <=> (CNetAddress const& _Other) const
		{
			return NMib::NSys::NNetwork::fg_CompareAddresses(mp_Address, _Other.mp_Address) <=> 0;
		}

		template <typename tf_CStr>
		void f_Format(tf_CStr &o_Str) const
		{
			auto Type = f_GetType();

			ENetAddressStringFlag Flags = ENetAddressStringFlag_IncludePort;
			if (Type == ENetAddressType_Unix)
				Flags |= ENetAddressStringFlag_IncludeType;

			o_Str += f_GetString(Flags);
		}
	};

	class CAsyncResolver
	{
		void *mp_pResolver;
		void fp_CheckValid() const
		{
			if (!mp_pResolver)
				DMibErrorNet("Resolver is not valid");
		}
	public:

		CAsyncResolver(CAsyncResolver const &) = delete;
		CAsyncResolver &operator = (CAsyncResolver const &) = delete;

		CAsyncResolver(CAsyncResolver &&_Other)
			: mp_pResolver(_Other.mp_pResolver)
		{
			_Other.mp_pResolver = nullptr;
		}

		CAsyncResolver &operator = (CAsyncResolver &&_Other)
		{
			f_Close();
			mp_pResolver = _Other.mp_pResolver;
			_Other.mp_pResolver = nullptr;

			return *this;
		}

		CAsyncResolver()
		{
			mp_pResolver = nullptr;
		}

		~CAsyncResolver()
		{
			f_Close();
		}

		void f_Close()
		{
			if (mp_pResolver)
				NMib::NSys::NNetwork::fg_AsyncResolveAddress_Close(mp_pResolver);
			mp_pResolver = nullptr;
		}

		void f_Open(const NMib::NStr::CStr &_Address, ::NMib::NNetwork::ENetAddressType _PreferType, NMib::NFunction::TCFunctionMutable<void ()> &&_fOnFinish)
		{
			f_Close();
			mp_pResolver = NMib::NSys::NNetwork::fg_AsyncResolveAddress_Open(_Address, _PreferType, fg_Move(_fOnFinish));
		}

		void f_Open(const NMib::NStr::CStr &_Address, ::NMib::NNetwork::ENetAddressType _PreferType, NMib::NThread::CSemaphoreAggregate *_pReportTo)
		{
			f_Close();
			mp_pResolver = NMib::NSys::NNetwork::fg_AsyncResolveAddress_Open
				(
					_Address
					, _PreferType
					, [_pReportTo]()
					{
						_pReportTo->f_Signal();
					}
				)
			;
		}

		bool f_GetResult(NMib::NNetwork::CNetAddress &_Address, NStr::CStr &_Error)
		{
			fp_CheckValid();
			NMib::NSys::NNetwork::CAddress Address;
			if (NMib::NSys::NNetwork::fg_AsyncResolveAddress_GetResult(mp_pResolver, Address, _Error))
			{
				_Address = NMib::NNetwork::CNetAddress(Address);
				return true;
			}
			else
				return false;
		}
	};

	struct CSocketOperationResult
	{
		umint m_nBytes = 0;
		bool m_bSentNetwork = false;
		bool m_bReceivedNetwork = false;

		CSocketOperationResult &operator += (CSocketOperationResult const &_Other);
	};

	class CSocket
	{
		void *mp_pSocket;

		// Applied once the platform socket exists, so it can be set before the connect or listen
		umint mp_nSendWindowBytes = 0;
		bool mp_bSendWindowConfigured = false;

		void fp_ApplySendWindow()
		{
			if (mp_pSocket && mp_nSendWindowBytes)
				NMib::NSys::NNetwork::fg_SetSendWindow(mp_pSocket, mp_nSendWindowBytes, mp_bSendWindowConfigured);
		}

		void fp_CheckSocket() const
		{
			if (!mp_pSocket)
				DMibErrorNet("Socket is not valid");
		}

		static NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> fsp_GetChangeReportTo(NMib::NThread::CSemaphoreAggregate *_pReportTo)
		{
			if (_pReportTo)
			{
				return [_pReportTo](::NMib::NNetwork::ENetTCPState _StateAdded)
					{
						_pReportTo->f_Signal();
					}
				;
			}
			return NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)>();
		}
		CSocket(CSocket const& _Other);
		CSocket & operator =(CSocket const& _Other);
	public:
		CSocket()
		{
			mp_pSocket = nullptr;
		}

		// A drop has nothing to wait for, so it takes the asynchronous form: legal for a socket
		// on any loop, complete on return everywhere the synchronous close would have been
		~CSocket()
		{
			f_CloseAsync({});
		}

		CSocket(CSocket &&_Other)
		{
			mp_pSocket = _Other.mp_pSocket;
			_Other.mp_pSocket = nullptr;
		}

		CSocket & operator =(CSocket &&_Other)
		{
			mp_pSocket = _Other.mp_pSocket;
			_Other.mp_pSocket = nullptr;
			return *this;
		}

		bool f_IsValid() const
		{
			return mp_pSocket != nullptr;
		}

		// Synchronous close, complete on return; refuses for a socket on a created loop, where
		// only the asynchronous form is legal
		void f_Close()
		{
			if (mp_pSocket)
				NMib::NSys::NNetwork::fg_Close(mp_pSocket);
			mp_pSocket = nullptr;
		}

		// Consumes the platform socket at initiation; the continuation runs once the close is
		// complete, on the loop's thread for a socket on a created loop, inline otherwise
		void f_CloseAsync(NMib::NFunction::TCFunctionMovable<void ()> &&_fOnClosed)
		{
			void *pSocket = mp_pSocket;
			mp_pSocket = nullptr;
			if (pSocket)
				NMib::NSys::NNetwork::fg_CloseAsync(pSocket, fg_Move(_fOnClosed));
			else if (_fOnClosed)
				_fOnClosed();
		}

		void f_Connect(NMib::NNetwork::CNetAddress const &_Address, NMib::NThread::CSemaphoreAggregate *_pReportTo = nullptr, fp64 _Timeout = 15.0)
		{
			f_Connect(_Address, fsp_GetChangeReportTo(_pReportTo), CNetAddress(), _Timeout);
		}

		void f_Connect
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange
				, NMib::NNetwork::CNetAddress const &_BindAddress = NMib::NNetwork::CNetAddress()
				, fp64 _Timeout = 15.0
			)
		;

		void f_AsyncConnect(NMib::NNetwork::CNetAddress const &_Address, NMib::NThread::CSemaphoreAggregate *_pReportTo = nullptr)
		{
			f_Close();

			mp_pSocket = NMib::NSys::NNetwork::fg_AsyncConnect(_Address, fsp_GetChangeReportTo(_pReportTo), CNetAddress());
			fp_ApplySendWindow();
			NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
		}

		void f_AsyncConnect
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange
				, NMib::NNetwork::CNetAddress const &_BindAddress = NMib::NNetwork::CNetAddress()
			)
		{
			f_Close();

			mp_pSocket = NMib::NSys::NNetwork::fg_AsyncConnect(_Address, fg_Move(_fOnStateChange), _BindAddress);
			fp_ApplySendWindow();
			NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
		}

		void f_Listen(NMib::NNetwork::CNetAddress const &_Address, NMib::NThread::CSemaphoreAggregate *_pReportTo, ENetFlag _Flags)
		{
			f_Close();

			mp_pSocket = NMib::NSys::NNetwork::fg_Listen(_Address, fsp_GetChangeReportTo(_pReportTo), _Flags);
			fp_ApplySendWindow();
			NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
		}

		void f_Listen(NMib::NNetwork::CNetAddress const &_Address, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange, ENetFlag _Flags)
		{
			f_Close();

			mp_pSocket = NMib::NSys::NNetwork::fg_Listen(_Address, fg_Move(_fOnStateChange), _Flags);
			fp_ApplySendWindow();
			NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
		}

		void f_ListenDatagram
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange
				, ENetFlag _Flags
			)
		{
			f_Close();

			mp_pSocket = NMib::NSys::NNetwork::fg_ListenDatagram(_Address, fg_Move(_fOnStateChange), _Flags);
			NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
		}

		void f_Accept(CSocket *_pAcceptFrom, NMib::NThread::CSemaphoreAggregate *_pReportTo)
		{
			f_Close();

			mp_pSocket = NMib::NSys::NNetwork::fg_Accept(_pAcceptFrom->mp_pSocket, fsp_GetChangeReportTo(_pReportTo));
			fp_ApplySendWindow();
			if (mp_pSocket)
				NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
		}

		void f_Accept(CSocket *_pAcceptFrom, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange)
		{
			f_Close();

			mp_pSocket = NMib::NSys::NNetwork::fg_Accept(_pAcceptFrom->mp_pSocket, fg_Move(_fOnStateChange));
			fp_ApplySendWindow();
			if (mp_pSocket)
				NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
		}

		void f_InheritHandle2(void *_pSocketHandle, NMib::NThread::CSemaphoreAggregate *_pReportTo)
		{
			f_Close();

			mp_pSocket = NMib::NSys::NNetwork::fg_InheritHandle2(_pSocketHandle, fsp_GetChangeReportTo(_pReportTo));
			NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
		}

		void f_InheritHandle2(void *_pSocketHandle, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange)
		{
			f_Close();

			mp_pSocket = NMib::NSys::NNetwork::fg_InheritHandle2(_pSocketHandle, fg_Move(_fOnStateChange));
			NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
		}

		void *f_GiveUpForInherit()
		{
			return NMib::NSys::NNetwork::fg_GiveUpForInherit(mp_pSocket);
		}

		// Acknowledge-first handoff: consumes the platform socket at initiation — this wrapper is
		// empty when the call returns — and the continuation receives the raw handle on the
		// loop's thread once nothing loop-side references the file
		void f_GiveUpForInheritAsync(NMib::NFunction::TCFunctionMovable<void (void *_pSocketHandle)> &&_fOnHandle)
		{
			fp_CheckSocket();

			void *pSocket = mp_pSocket;
			mp_pSocket = nullptr;
			NMib::NSys::NNetwork::fg_GiveUpForInheritAsync(pSocket, fg_Move(_fOnHandle));
		}

		void *f_GetOSSocket()
		{
			return NMib::NSys::NNetwork::fg_GetOSSocket(mp_pSocket);
		}

		void f_SetReportTo(NMib::NThread::CSemaphoreAggregate *_pReportTo)
		{
			NMib::NSys::NNetwork::fg_SetOnStateChange(mp_pSocket, fsp_GetChangeReportTo(_pReportTo));
		}

		void f_SetOnStateChange(NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange)
		{
			NMib::NSys::NNetwork::fg_SetOnStateChange(mp_pSocket, fg_Move(_fOnStateChange));
		}

		void f_Shutdown()
		{
			fp_CheckSocket();

			return NMib::NSys::NNetwork::fg_Shutdown(mp_pSocket);
		}

		ENetTCPState f_GetState()
		{
			fp_CheckSocket();

			return NMib::NSys::NNetwork::fg_GetState(mp_pSocket);
		}

		NStr::CStr f_GetCloseReason()
		{
			fp_CheckSocket();

			return NMib::NSys::NNetwork::fg_GetCloseReason(mp_pSocket);
		}

		umint f_Receive(void *_pData, umint _DataLen, bool &o_bEndOfStream)
		{
			fp_CheckSocket();

			return NMib::NSys::NNetwork::fg_Receive(mp_pSocket, _pData, _DataLen, o_bEndOfStream);
		}

		umint f_Send(const void *_pData, umint _DataLen)
		{
			fp_CheckSocket();

			return NMib::NSys::NNetwork::fg_Send(mp_pSocket, _pData, _DataLen);
		}

		umint f_SendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans)
		{
			fp_CheckSocket();

			return NMib::NSys::NNetwork::fg_SendVectored(mp_pSocket, _pSpans, _nSpans);
		}

		void f_RequestReadiness(bool _bRead, bool _bWrite)
		{
			fp_CheckSocket();

			NMib::NSys::NNetwork::fg_RequestReadiness(mp_pSocket, _bRead, _bWrite);
		}

		bool f_SupportsCompletionIo() const
		{
			return mp_pSocket && NMib::NSys::NNetwork::fg_SupportsCompletionIo(mp_pSocket);
		}

		bool f_SendReleaseIsPrompt() const
		{
			return !mp_pSocket || NMib::NSys::NNetwork::fg_SendReleaseIsPrompt(mp_pSocket);
		}

		NMib::NSys::ICIoLoop *f_GetOwningIoLoop() const
		{
			return mp_pSocket ? NMib::NSys::NNetwork::fg_GetOwningIoLoop(mp_pSocket) : nullptr;
		}

		bool f_SupportsReceiveStream() const
		{
			return mp_pSocket && NMib::NSys::NNetwork::fg_SupportsReceiveStream(mp_pSocket);
		}

		bool f_StartReceiveStream(umint _nBufferBytes, NStorage::TCSharedPointer<NSys::CIoStreamBackpressure> _pBackpressure, NSys::FIoStreamSink &&_fSink)
		{
			fp_CheckSocket();

			return NMib::NSys::NNetwork::fg_StartReceiveStream(mp_pSocket, _nBufferBytes, fg_Move(_pBackpressure), fg_Move(_fSink));
		}

		void f_ResumeReceiveStream()
		{
			fp_CheckSocket();

			NMib::NSys::NNetwork::fg_ResumeReceiveStream(mp_pSocket);
		}

		void f_SetSendWindow(umint _nBytes, bool _bConfigured)
		{
			mp_nSendWindowBytes = _nBytes;
			mp_bSendWindowConfigured = _bConfigured;
			fp_ApplySendWindow();
		}

		bool f_SubmitSendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans, NSys::FIoCompletion &&_fOnComplete, NMib::NSys::FIoBufferReleased &&_fOnBufferReleased)
		{
			fp_CheckSocket();

			return NMib::NSys::NNetwork::fg_SubmitSendVectored(mp_pSocket, _pSpans, _nSpans, fg_Move(_fOnComplete), fg_Move(_fOnBufferReleased));
		}

		umint f_SendDatagram(NMib::NNetwork::CNetAddress const &_Address, const void *_pData, umint _DataLen)
		{
			fp_CheckSocket();

			return NMib::NSys::NNetwork::fg_SendDatagram(mp_pSocket, _Address, _pData, _DataLen);
		}

		umint f_ReceiveDatagram(NMib::NNetwork::CNetAddress &_Address, void *_pData, umint _DataLen)
		{
			fp_CheckSocket();

			return NMib::NSys::NNetwork::fg_ReceiveDatagram(mp_pSocket, _Address, _pData, _DataLen);
		}

		NMib::NNetwork::CNetAddress f_GetPeerAddress() const
		{
			fp_CheckSocket();
			return CNetAddress(NMib::NSys::NNetwork::fg_GetPeerAddress(mp_pSocket));
		}

		bool f_GetProcessIdentity(NMib::NSys::NNetwork::CProcessIdentity &o_LocalIdentity, NMib::NSys::NNetwork::CProcessIdentity &o_PeerIdentity) const
		{
			fp_CheckSocket();
			return NMib::NSys::NNetwork::fg_GetProcessIdentity(mp_pSocket, o_LocalIdentity, o_PeerIdentity);
		}

		uint32 f_GetListenPort() const
		{
			fp_CheckSocket();
			return NMib::NSys::NNetwork::fg_GetListenPort(mp_pSocket);
		}

		static NMib::NNetwork::CNetAddress fs_ResolveAddress(const NMib::NStr::CStr &_Address, ::NMib::NNetwork::ENetAddressType _PreferType = ::NMib::NNetwork::ENetAddressType_None)
		{
			return fg_Move(CNetAddress(NMib::NSys::NNetwork::fg_ResolveAddress(_Address, _PreferType)));
		}

	};

	bool fg_IsValidHostname(NStr::CStr const &_String, ch8 const *_pSeparatorChars = "", ch8 const *_pLabelChars = "");
	bool fg_IsValidLowerCaseHostname(NStr::CStr const &_String, ch8 const *_pSeparatorChars = "", ch8 const *_pLabelChars = "");
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
