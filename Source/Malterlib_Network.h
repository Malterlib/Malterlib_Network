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

						::NMib::NNetwork::ENetAddressType fg_GetAddressType(CAddress _pAddress);
						bool fg_GetAddressRaw(CAddress _pAddress, ::NMib::NNetwork::ENetAddressType _ExpectedType, void* o_pRawData, umint _nDataBytes);
						CAddress fg_SetAddressRaw(CAddress _pAddress, ::NMib::NNetwork::ENetAddressType _Type, void const* _pRawData, umint _nDataBytes);

						CAddress fg_ResolveAddress(const NMib::NStr::CStr &_Address, ::NMib::NNetwork::ENetAddressType _PreferType = ::NMib::NNetwork::ENetAddressType_None);

						void *fg_AsyncResolveAddress_Open(const NMib::NStr::CStr &_Address, ::NMib::NNetwork::ENetAddressType _PreferType, NMib::NThread::CSemaphoreAggregate *_pReportTo);
						bool fg_AsyncResolveAddress_GetResult(void *_pResolver, CAddress& o_pAddress, NMib::NStr::CStr &_Error);
						void fg_AsyncResolveAddress_Close(void *_pResolver);

						int fg_CompareAddresses(CAddress _pFirst, CAddress _pSecond);

						void fg_FreeAddress(CAddress _pAddress); // It is OK to free a nullptr address.

						NMib::NStr::CStr fg_GetAddressString(CAddress _pAddress, ENetAddressStringFlag _Flags);

					// Connection Operations
						// Report to the supplied event when new data is received or when we are ready to send new data and when the connection is connected
						void *fg_AsyncConnect(CAddress _pAddr, NMib::NThread::CSemaphoreAggregate *_pReportTo);

						// Report to the supplied event when a new connection has arrived
						void *fg_Listen(CAddress _pAddr, NMib::NThread::CSemaphoreAggregate *_pReportTo, NMib::NNetwork::ENetFlag _Flags);
						// Report to the supplied event when new data is received or when we are ready to send new data
						void *fg_Accept(void *_pSocket, NMib::NThread::CSemaphoreAggregate *_pReportTo, NMib::NNetwork::ENetFlag _Flags);

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
	struct CNetAddressIPv4
	{
		uint8 m_IP[4] = {};

		CNetAddressIPv4() = default;
		CNetAddressIPv4(uint8 _Octet0, uint8 _Octet1, uint8 _Octet2, uint8 _Octet3);
		CNetAddressIPv4(CNetAddressIPv4 const &_Src);
		CNetAddressIPv4 &operator = (CNetAddressIPv4 const &_Src);

		template <typename tf_CStream>
		void f_Stream(tf_CStream &_Stream);
		template <typename tf_CStr>
		void f_Format(tf_CStr &o_String) const;

		void f_SetLocalhost();
	};

	struct CNetAddressIPv6
	{
		uint8 m_IP[16] = {};

		CNetAddressIPv6() = default;

		CNetAddressIPv6
			(
				uint8 _Octet0
				, uint8 _Octet1
				, uint8 _Octet2
				, uint8 _Octet3
				, uint8 _Octet4
				, uint8 _Octet5
				, uint8 _Octet6
				, uint8 _Octet7
				, uint8 _Octet8
				, uint8 _Octet9
				, uint8 _Octet10
				, uint8 _Octet11
				, uint8 _Octet12
				, uint8 _Octet13
				, uint8 _Octet14
				, uint8 _Octet15
			)
		;

		CNetAddressIPv6(CNetAddressIPv6 const &_Src);
		CNetAddressIPv6 &operator = (CNetAddressIPv6 const &_Src);

		template <typename tf_CStream>
		void f_Stream(tf_CStream &_Stream);

		void f_SetLocalhost();
	};

	enum ENetAddressType : uint32
	{
		ENetAddressType_None    = 0
		, ENetAddressType_TCPv4 = 1
		, ENetAddressType_TCPv6 = 2
		, ENetAddressType_Unix  = 3
	};

	enum ENetAddressStringFlag
	{
		ENetAddressStringFlag_None          = 0
		, ENetAddressStringFlag_IncludeType = DMibBit(0)
		, ENetAddressStringFlag_IncludePort = DMibBit(1)
	};

	template <typename t_CIPAddress, ENetAddressType t_Type>
	struct TCNetAddressTCP : public t_CIPAddress
	{
		uint16 m_Port;

		static constexpr ENetAddressType mc_Type = t_Type;

		TCNetAddressTCP();
		TCNetAddressTCP(TCNetAddressTCP const &_Src);
		TCNetAddressTCP(t_CIPAddress const &_Src, uint16 _Port);
		TCNetAddressTCP &operator = (TCNetAddressTCP const &_Src);
		TCNetAddressTCP &operator = (t_CIPAddress const &_Src);

		t_CIPAddress const &f_GetIP() const;
		static ENetAddressType fs_GetType();
	};

	using CNetAddressTCPv4 = TCNetAddressTCP<CNetAddressIPv4, ENetAddressType_TCPv4>;
	using CNetAddressTCPv6 = TCNetAddressTCP<CNetAddressIPv6, ENetAddressType_TCPv6>;

	enum ENetTCPState
	{
		ENetTCPState_None           = 0
		, ENetTCPState_Read         = DMibBit(0) // Data is awailable for reading
		, ENetTCPState_Write        = DMibBit(1) // More data can now be sent
		, ENetTCPState_Connection   = DMibBit(2) // A new connection is available for accept
		, ENetTCPState_Connected    = DMibBit(3) // A async connection has completed
		, ENetTCPState_Closed       = DMibBit(4) // The connection has been lost
		, ENetTCPState_RemoteClosed = DMibBit(5) // A connection closure was initiated by remote call f_Shutdown
	};

	enum ENetFlag
	{
		ENetFlag_None        = 0
		, ENetFlag_ReusePort = DMibBit(0) // Reuse port, allowing several sockets to bind to the same port
	};

	struct CNetAddress;

	// Runs when send buffers are reusable, carrying the submitter's transfer ID or mc_iTransferNone.
	using FSocketSendReleased = NMib::NFunction::TCFunctionMovable<void (umint _iTransfer)>;

	bool fg_IsUnixSocketAddressString(NStr::CStr const &_Address);
	bool fg_IsLoopbackAddress(CNetAddress const &_Address);
	bool fg_IsLoopbackHostString(NStr::CStr const &_Host);
	NStr::CStr fg_GetSafeUnixSocketPath(NStr::CStr const &_WantedPath);
}

namespace NMib::NStream
{
	template <typename t_CStream>
	struct TCBinaryStreamTypeReference<t_CStream, NNetwork::CNetAddressTCPv4>
	{
		static constexpr void fs_Feed(t_CStream &_Stream, NNetwork::CNetAddressTCPv4 const &_Data);
		static constexpr void fs_Consume(t_CStream &_Stream, NNetwork::CNetAddressTCPv4 &_Data);
	};

	template <typename t_CStream>
	struct TCBinaryStreamTypeReference<t_CStream, NNetwork::CNetAddressIPv4>
	{
		static constexpr void fs_Feed(t_CStream &_Stream, NNetwork::CNetAddressIPv4 const &_Data);
		static constexpr void fs_Consume(t_CStream &_Stream, NNetwork::CNetAddressIPv4 &_Data);
	};

	template <typename t_CStream>
	struct TCBinaryStreamTypeReference<t_CStream, NNetwork::CNetAddressTCPv6>
	{
		static constexpr void fs_Feed(t_CStream &_Stream, NNetwork::CNetAddressTCPv6 const &_Data);
		static constexpr void fs_Consume(t_CStream &_Stream, NNetwork::CNetAddressTCPv6 &_Data);
	};

	template <typename t_CStream>
	struct TCBinaryStreamTypeReference<t_CStream, NNetwork::CNetAddressIPv6>
	{
		static constexpr void fs_Feed(t_CStream &_Stream, NNetwork::CNetAddressIPv6 const &_Data);
		static constexpr void fs_Consume(t_CStream &_Stream, NNetwork::CNetAddressIPv6 &_Data);
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

	CAddress fg_CreateAddress(::NMib::NNetwork::ENetAddressType _Type, void const *_pData, umint _nDataBytes);
	CAddress fg_CreateAddressFromNative(void const *_pAddress, umint _Size);
	CAddress fg_DuplicateAddress(CAddress _pAddress);

	::NMib::NNetwork::ENetAddressType fg_GetAddressType(CAddress _pAddress);
	uint32 fg_GetAddressScopeID(CAddress _pAddress);
	bool fg_GetAddressRaw(CAddress _pAddress, ::NMib::NNetwork::ENetAddressType _ExpectedType, void *o_pRawData, umint _nDataBytes);
	CAddress fg_SetAddressRaw(CAddress _pAddress, ::NMib::NNetwork::ENetAddressType _Type, void const *_pRawData, umint _nDataBytes);

	struct CResolveAddressParameters
	{
		NStr::CStr m_Host;
		::NMib::NNetwork::ENetAddressType m_PreferType = ::NMib::NNetwork::ENetAddressType_None;
		uint32 m_Port = 0;
	};

	CAddress fg_PrepareResolveAddress(NStr::CStr const &_Address, CResolveAddressParameters &o_Parameters);

	CAddress fg_ResolveAddress(NMib::NStr::CStr const &_Address, ::NMib::NNetwork::ENetAddressType _PreferType = ::NMib::NNetwork::ENetAddressType_None);

	NContainer::TCVector<CAddress> fg_ResolveAddresses(NStr::CStr const &_Address, ::NMib::NNetwork::ENetAddressType _PreferType);

	NContainer::TCVector<CAddress> fg_ResolveHost(NStr::CStr const &_Host, ::NMib::NNetwork::ENetAddressType _PreferType);

	umint fg_GetMaxUnixSocketNameLength();
	NStr::CStr fg_GetStagedUnixSocketPath(NStr::CStr const &_Path);
	bool fg_IsStagedUnixSocketPath(NStr::CStr const &_Path);
	bool fg_HasNativeUnixSockets(); // False where TCP and a port file emulate unix sockets

	void *fg_AsyncResolveAddress_Open(NMib::NStr::CStr const &_Address, ::NMib::NNetwork::ENetAddressType _PreferType, NMib::NFunction::TCFunctionMutable<void ()> &&_fOnFinish);
	bool fg_AsyncResolveAddress_GetResult(void *_pResolver, CAddress &o_pAddress, NMib::NStr::CStr &_Error);
	void fg_AsyncResolveAddress_Close(void *_pResolver);
	void fg_AsyncResolveAddress_CloseAsync(void *_pResolver, NMib::NFunction::TCFunctionMovable<void ()> &&_fOnClosed);

	int fg_CompareAddresses(CAddress _pFirst, CAddress _pSecond);

	void fg_FreeAddress(CAddress _pAddress); // It is OK to free a nullptr address.

	NMib::NStr::CStr fg_GetAddressString(CAddress _pAddress, NMib::NNetwork::ENetAddressStringFlag _Flags);

	// Report to the supplied event when new data is received or when we are ready to send new data and when the connection is connected
	void *fg_AsyncConnect(CAddress _pAddr, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange, CAddress _pBindAddr);
	void fg_StartSocket(void *_pSocket); // Starts the event loop

	// Report to the supplied event when a new connection has arrived
	void *fg_Listen(CAddress _pAddr, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange, NMib::NNetwork::ENetFlag _Flags);
	// Report to the supplied event when new data is received or when we are ready to send new data
	void *fg_ListenDatagram(CAddress _pAddr, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange, NMib::NNetwork::ENetFlag _Flags);
	// Report to the supplied event when new data is received or when we are ready to send new data
	void *fg_Accept(void *_pSocket, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange);

	void fg_Shutdown(void *_pSocket); // Closes the socket and connection

	void fg_Close(void *_pSocket); // Closes the socket and connection

	umint fg_Receive(void *_pSocket, void *_pData, umint _DataLen, bool &o_bEndOfStream);
	umint fg_Send(void *_pSocket, void const *_pData, umint _DataLen); // Returns bytes sent
	umint fg_SendVectored(void *_pSocket, NSys::CIoSpan const *_pSpans, umint _nSpans);

	NMib::NSys::ICIoLoop *fg_GetOwningIoLoop(void *_pSocket);
	bool fg_SupportsCompletionIo(void *_pSocket);
	bool fg_SendReleaseIsPrompt(void *_pSocket);
	bool fg_SupportsReceiveStream(void *_pSocket);
	bool fg_StartReceiveStream(void *_pSocket, umint _nBufferBytes, NStorage::TCSharedPointer<NSys::CIoStreamBackpressure> &&_pBackpressure, NSys::FIoStreamSink &&_fSink);
	void fg_ResumeReceiveStream(void *_pSocket);
	void fg_SetInheritable(void *_pSocket);
	void fg_SetSendWindow(void *_pSocket, umint _nBytes, bool _bConfigured);
	void fg_SetAbortOnClose(void *_pSocket);
	bool fg_QueryPathDeliveryRate(void *_pSocket, umint &o_nBytes, bool &o_bAppLimited);
	bool fg_IsSendWindowFull(void *_pSocket, umint _nUnreleasedBytes, umint _nStartBytes);
	umint fg_SubmitSendVectored(void *_pSocket, NSys::CIoSpan const *_pSpans, umint _nSpans, NSys::FIoCompletion &&_fOnComplete, NSys::FIoBufferReleased &&_fOnBufferReleased);
	umint fg_SendDatagram(void *_pSocket, NSys::NNetwork::CAddress _pAddress, void const *_pData, umint _DataLen); // Returns bytes sent
	umint fg_ReceiveDatagram(void *_pSocket, NSys::NNetwork::CAddress _pAddress, void *_pData, umint _DataLen); // Returns bytes received

	// Socket Properties & State

	// Report to the supplied event when new data is received or when we are ready to send new data
	void fg_SetOnStateChange(void *_pSocket, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange);
	void fg_ReownSocket(void *_pSocket, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange);

	NMib::NNetwork::ENetTCPState fg_GetState(void *_pSocket); // Get the state of data available
	NMib::NStr::CStr fg_GetCloseReason(void *_pSocket);

	void fg_RequestReadiness(void *_pSocket, bool _bRead, bool _bWrite);

	void *fg_InheritHandle2(void *_pSocket, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange);
	void *fg_GiveUpForInherit(void *_pSocket);
	void fg_GiveUpForInheritAsync(void *_pSocket, NMib::NFunction::TCFunctionMovable<void (void *_pSocketHandle)> &&_fOnHandle);
	void fg_CloseAsync(void *_pSocket, NMib::NFunction::TCFunctionMovable<void ()> &&_fOnClosed);
	void fg_CloseSocketHandle(void *_pSocketHandle);
	void *fg_GetOSSocket(void *_pSocket);

	CAddress fg_GetPeerAddress(void *_pSocket);
	uint32 fg_GetListenPort(void *_pSocket);

	// Kernel identity of a Unix endpoint. pidfs device/inode identifies the pinned process across namespaces and PID reuse.
	// Numeric PIDs are comparable only within one namespace; zero means the peer is invisible here.
	struct CProcessIdentity
	{
		uint64 m_ProcessID = 0;
		uint64 m_PidFSDevice = 0; // Non-zero only when the kernel serves pidfds from pidfs (Linux 6.9)
		uint64 m_PidFSInode = 0;
	};

	bool fg_GetProcessIdentity(void *_pSocket, CProcessIdentity &o_LocalIdentity, CProcessIdentity &o_PeerIdentity);
	bool fg_HasUnixSocketPeerProcessIdentity();
}

namespace NMib::NNetwork
{
	struct CNetAddress
	{
	protected:
		NMib::NSys::NNetwork::CAddress mp_pAddress;

	public:
		CNetAddress();
		explicit CNetAddress(NMib::NSys::NNetwork::CAddress _pAddress);
		CNetAddress(CNetAddress &&_ToMove);
		CNetAddress(CNetAddress const &_ToCopy);
		template <typename tf_CAddress>
		CNetAddress(tf_CAddress const &_Address);

		template <typename tf_CAddress>
		CNetAddress &operator = (tf_CAddress const &_Address);
		CNetAddress &operator = (CNetAddress &&_ToMove);
		CNetAddress &operator = (CNetAddress const &_ToCopy);
		~CNetAddress();

		void f_Clear();
		void *f_Detach();
		void *f_AccessRaw() const;

		bool f_IsEmpty() const;
		NStr::CStr f_GetString(ENetAddressStringFlag _Flags) const;
		ENetAddressType f_GetType() const;
		uint32 f_GetScopeID() const;

		template <typename tf_CAddress>
		bool f_Get(tf_CAddress &o_Address) const;
		bool f_Set(CNetAddress const &_Address);
		template <typename tf_CAddress>
		bool f_Set(tf_CAddress const &_Address);

		bool f_SetPort(uint16 _Port);
		uint16 f_GetPort() const;

		operator NMib::NSys::NNetwork::CAddress () const;

		bool operator == (CNetAddress const &_Other) const;
		COrdering_Weak operator <=> (CNetAddress const &_Other) const;

		template <typename tf_CStr>
		void f_Format(tf_CStr &o_Str) const;
	};

	struct CAsyncResolver
	{
		CAsyncResolver(CAsyncResolver const &_Other) = delete;
		CAsyncResolver &operator = (CAsyncResolver const &_Other) = delete;
		CAsyncResolver(CAsyncResolver &&_Other);
		CAsyncResolver &operator = (CAsyncResolver &&_Other);
		CAsyncResolver();
		~CAsyncResolver();

		void f_Close();
		void f_CloseAsync(NMib::NFunction::TCFunctionMovable<void ()> &&_fOnClosed);

		void f_Open(NMib::NStr::CStr const &_Address, ::NMib::NNetwork::ENetAddressType _PreferType, NMib::NFunction::TCFunctionMutable<void ()> &&_fOnFinish);
		void f_Open(NMib::NStr::CStr const &_Address, ::NMib::NNetwork::ENetAddressType _PreferType, NMib::NThread::CSemaphoreAggregate *_pReportTo);

		bool f_GetResult(NMib::NNetwork::CNetAddress &_Address, NStr::CStr &_Error);

	private:
		void *mp_pResolver;
		void fp_CheckValid() const;
	};

	struct CSocketOperationResult
	{
		umint m_nBytes = 0;
		bool m_bSentNetwork = false;
		bool m_bReceivedNetwork = false;

		CSocketOperationResult &operator += (CSocketOperationResult const &_Other);
	};

	struct CSocket
	{
		CSocket();
		~CSocket();
		CSocket(CSocket &&_Other);
		CSocket &operator = (CSocket &&_Other);

		bool f_IsValid() const;

		void f_Close();
		void f_CloseAsync(NMib::NFunction::TCFunctionMovable<void ()> &&_fOnClosed);

		void f_Connect(NMib::NNetwork::CNetAddress const &_Address, NMib::NThread::CSemaphoreAggregate *_pReportTo = nullptr, fp64 _Timeout = 15.0);

		void f_Connect
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange
				, NMib::NNetwork::CNetAddress const &_BindAddress = NMib::NNetwork::CNetAddress()
				, fp64 _Timeout = 15.0
			)
		;

		void f_AsyncConnect(NMib::NNetwork::CNetAddress const &_Address, NMib::NThread::CSemaphoreAggregate *_pReportTo = nullptr);

		void f_AsyncConnect
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange
				, NMib::NNetwork::CNetAddress const &_BindAddress = NMib::NNetwork::CNetAddress()
			)
		;

		void f_Listen(NMib::NNetwork::CNetAddress const &_Address, NMib::NThread::CSemaphoreAggregate *_pReportTo, ENetFlag _Flags);
		void f_Listen(NMib::NNetwork::CNetAddress const &_Address, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange, ENetFlag _Flags);

		void f_ListenDatagram
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange
				, ENetFlag _Flags
			)
		;

		void f_Accept(CSocket *_pAcceptFrom, NMib::NThread::CSemaphoreAggregate *_pReportTo);
		void f_Accept(CSocket *_pAcceptFrom, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange);

		void f_InheritHandle2(void *_pSocketHandle, NMib::NThread::CSemaphoreAggregate *_pReportTo);
		void f_InheritHandle2(void *_pSocketHandle, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange);

		void f_Adopt(CSocket &&_Socket, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange);

		void *f_GiveUpForInherit();
		void f_GiveUpForInheritAsync(NMib::NFunction::TCFunctionMovable<void (void *_pSocketHandle)> &&_fOnHandle);

		void *f_GetOSSocket();

		void f_SetReportTo(NMib::NThread::CSemaphoreAggregate *_pReportTo);
		void f_SetOnStateChange(NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange);

		void f_Shutdown();
		void f_SetAbortOnClose();

		ENetTCPState f_GetState();
		NStr::CStr f_GetCloseReason();

		umint f_Receive(void *_pData, umint _DataLen, bool &o_bEndOfStream);
		umint f_Send(void const *_pData, umint _DataLen);
		umint f_SendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans);

		void f_RequestReadiness(bool _bRead, bool _bWrite);

		bool f_SupportsCompletionIo() const;
		bool f_SendReleaseIsPrompt() const;
		NMib::NSys::ICIoLoop *f_GetOwningIoLoop() const;

		bool f_SupportsReceiveStream() const;
		bool f_StartReceiveStream(umint _nBufferBytes, NStorage::TCSharedPointer<NSys::CIoStreamBackpressure> &&_pBackpressure, NSys::FIoStreamSink &&_fSink);
		void f_ResumeReceiveStream();

		bool f_QueryPathDeliveryRate(umint &o_nBytes, bool &o_bAppLimited);
		bool f_IsSendWindowFull(umint _nUnreleasedBytes, umint _nStartBytes);

		void f_SetInheritable();
		void f_SetSendWindow(umint _nBytes, bool _bConfigured);

		umint f_SubmitSendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans, NSys::FIoCompletion &&_fOnComplete, NMib::NSys::FIoBufferReleased &&_fOnBufferReleased);

		umint f_SendDatagram(NMib::NNetwork::CNetAddress const &_Address, void const *_pData, umint _DataLen);
		umint f_ReceiveDatagram(NMib::NNetwork::CNetAddress &_Address, void *_pData, umint _DataLen);

		NMib::NNetwork::CNetAddress f_GetPeerAddress() const;
		bool f_GetProcessIdentity(NMib::NSys::NNetwork::CProcessIdentity &o_LocalIdentity, NMib::NSys::NNetwork::CProcessIdentity &o_PeerIdentity) const;
		uint32 f_GetListenPort() const;

		static NContainer::TCVector<CNetAddress> fs_ResolveAddresses(NStr::CStr const &_Address, ENetAddressType _PreferType = ENetAddressType_None);
		static NContainer::TCVector<CNetAddress> fs_ResolveHost(NStr::CStr const &_Host, ENetAddressType _PreferType = ENetAddressType_None);
		static NMib::NNetwork::CNetAddress fs_ResolveAddress(NMib::NStr::CStr const &_Address, ::NMib::NNetwork::ENetAddressType _PreferType = ::NMib::NNetwork::ENetAddressType_None);

	private:
		void *mp_pSocket;

		umint mp_nSendWindowBytes = 0; // Retained before creation, then applied to the platform socket.
		bool mp_bSendWindowConfigured = false;
		bool mp_bInheritable = false;

		void fp_ApplyInheritable();
		void fp_ApplySendWindow();
		void fp_CheckSocket() const;

		static NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> fsp_GetChangeReportTo(NMib::NThread::CSemaphoreAggregate *_pReportTo);

		CSocket(CSocket const &_Other);
		CSocket &operator = (CSocket const &_Other);

		static NContainer::TCVector<CNetAddress> fsp_AdoptAddresses(NContainer::TCVector<NMib::NSys::NNetwork::CAddress> &&_Addresses);
	};

	bool fg_IsValidHostname(NStr::CStr const &_String, ch8 const *_pSeparatorChars = "", ch8 const *_pLabelChars = "");
	bool fg_IsValidLowerCaseHostname(NStr::CStr const &_String, ch8 const *_pSeparatorChars = "", ch8 const *_pLabelChars = "");
}

#ifndef DMibPNoShortCuts
using namespace NMib::NNetwork;
#endif

#include "Malterlib_Network.hpp"
#include "Malterlib_Network_Resolve.hpp"
