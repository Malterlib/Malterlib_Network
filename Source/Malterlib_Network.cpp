// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Network.h"
#include <Mib/Cryptography/UUID>

namespace NMib::NNetwork
{
	DMibImpErrorClassImplement(CExceptionNet);

	// Keep these throws out of precompiled headers: Clang's Windows ABI can lose
	// exception copy-constructor metadata when deserializing them (LLVM #53486).
	void CSocket::fp_CheckSocket() const
	{
		if (!mp_pSocket)
			DMibErrorNet("Socket is not valid");
	}

	void CAsyncResolver::fp_CheckValid() const
	{
		if (!mp_pResolver)
			DMibErrorNet("Resolver is not valid");
	}

	template <bool tf_bLowerCase>
	bool fg_IsValidHostnameImpl(NStr::CStr const &_String, ch8 const *_pSeparatorChars, ch8 const *_pLabelChars)
	{
		if (_String.f_GetLen() > 254)
			return false;
		ch8 const *pParse = _String.f_GetStr();
		ch8 LastChar = 0;
		bool bEmptySegment = true;
		while (*pParse)
		{
			if (*pParse == '-')
				return false; // Must not start with hyphen
			if (*pParse == '.')
				return false; // Empty label allowed?
			while
			(
				*pParse
				&&
				(
					(tf_bLowerCase ? NStr::fg_CharIsLowerCaseAnsiAlphabetical(*pParse) : NStr::fg_CharIsAnsiAlphabetical(*pParse))
					|| NStr::fg_CharIsNumber(*pParse)
					|| *pParse == '-'
					|| NStr::fg_StrFindChar(_pLabelChars, *pParse) >= 0
				)
			)
			{
				LastChar = *pParse;
				bEmptySegment = false;
				++pParse;
			}
			if (LastChar == '-')
				return false; // Must not end with hyphen
			if (*pParse == '.')
				++pParse;
			else if (*pParse)
			{
				if (NStr::fg_StrFindChar(_pSeparatorChars, *pParse) < 0)
					return false; // Any other character is not allowed
				++pParse;
				bEmptySegment = true;
				LastChar = 0;
			}
		}
		if (bEmptySegment)
			return false;
		return true;
	}

	bool fg_IsValidHostname(NStr::CStr const &_String, ch8 const *_pSeparatorChars, ch8 const *_pLabelChars)
	{
		return fg_IsValidHostnameImpl<false>(_String, _pSeparatorChars, _pLabelChars);
	}

	bool fg_IsValidLowerCaseHostname(NStr::CStr const &_String, ch8 const *_pSeparatorChars, ch8 const *_pLabelChars)
	{
		return fg_IsValidHostnameImpl<true>(_String, _pSeparatorChars, _pLabelChars);
	}

	namespace
	{
		NCryptography::CUniversallyUniqueIdentifier g_HostnameRootUUID("D2C365F0-3F5E-4056-9BBB-0724C411D2FA", NCryptography::EUniversallyUniqueIdentifierFormat_Bare);
	}

	bool fg_IsUnixSocketAddressString(NStr::CStr const &_Address)
	{
		// The prefixes the platform address parsers accept for unix socket paths
		return _Address.f_StartsWith("UNIX:") || _Address.f_StartsWith("UNIX(");
	}

	// Recognizes 127/8, ::1 and IPv4-mapped loopback; the host-string form also accepts localhost.
	bool fg_IsLoopbackAddress(CNetAddress const &_Address)
	{
		CNetAddressTCPv4 TCPv4;
		if (_Address.f_Get(TCPv4))
			return TCPv4.m_IP[0] == 127;

		CNetAddressTCPv6 TCPv6;
		if (_Address.f_Get(TCPv6))
		{
			bool bMappedPrefix = true;
			for (umint iByte = 0; iByte < 10; ++iByte)
			{
				if (TCPv6.m_IP[iByte] != 0)
					bMappedPrefix = false;
			}

			if (bMappedPrefix && TCPv6.m_IP[10] == 0xff && TCPv6.m_IP[11] == 0xff)
				return TCPv6.m_IP[12] == 127;

			if (bMappedPrefix && TCPv6.m_IP[10] == 0 && TCPv6.m_IP[11] == 0)
				return TCPv6.m_IP[12] == 0 && TCPv6.m_IP[13] == 0 && TCPv6.m_IP[14] == 0 && TCPv6.m_IP[15] == 1;
		}

		return false;
	}

	bool fg_IsLoopbackHostString(NStr::CStr const &_Host)
	{
		// Case-insensitively, as host names are
		if (_Host.f_CmpNoCase(NStr::gc_Str<"localhost">.m_Str) == 0)
			return true;

		if (_Host == "::1" || _Host == "[::1]")
			return true;

		// The whole loopback net, as a literal only: a host name that begins the same way
		// resolves wherever its records say
		if (!_Host.f_StartsWith("127."))
			return false;

		ch8 const *pParse = _Host.f_GetStr() + 4;
		while (*pParse)
		{
			if (!NStr::fg_CharIsNumber(*pParse) && *pParse != '.')
				return false;
			++pParse;
		}

		return true;
	}

	NStr::CStr fg_GetSafeUnixSocketPath(NStr::CStr const &_WantedPath)
	{
		using namespace NStr;

#ifdef DPlatformFamily_Windows
		CStr WantedPath = NFile::CFile::fs_GetExpandedPath(_WantedPath);
#else
		auto const &WantedPath = _WantedPath;
#endif
		umint MaxLength = NSys::NNetwork::fg_GetMaxUnixSocketNameLength();
		if (WantedPath.f_GetLen() <= aint(MaxLength))
			return WantedPath;

		CStr ConfigHash = fg_GetHashedUuidString(WantedPath, g_HostnameRootUUID, NCryptography::EUniversallyUniqueIdentifierFormat_AlphaNum);

		CStr TempDir = NFile::CFile::fs_GetRawTemporaryDirectory();
#ifdef DPlatformFamily_Windows
		TempDir = NFile::CFile::fs_GetExpandedPath(TempDir);
#endif
		CStr Path = TempDir / ("{}.sock"_f << ConfigHash);
		if (Path.f_GetLen() <= aint(MaxLength))
			return Path;

		Path = "/tmp/{}.sock"_f << ConfigHash;
#ifdef DPlatformFamily_Windows
		Path = NFile::CFile::fs_GetExpandedPath(Path);
#endif
		return Path;
	}

	CNetAddressIPv4 &CNetAddressIPv4::operator = (CNetAddressIPv4 const &_Src)
	{
		NMemory::fg_MemCopy(m_IP, _Src.m_IP, sizeof(m_IP));

		return *this;
	}

	void CNetAddressIPv4::f_SetLocalhost()
	{
		*this = {127, 0, 0, 1};
	}

	CNetAddressIPv6::CNetAddressIPv6
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
	{
		m_IP[0] = _Octet0;
		m_IP[1] = _Octet1;
		m_IP[2] = _Octet2;
		m_IP[3] = _Octet3;
		m_IP[4] = _Octet4;
		m_IP[5] = _Octet5;
		m_IP[6] = _Octet6;
		m_IP[7] = _Octet7;
		m_IP[8] = _Octet8;
		m_IP[9] = _Octet9;
		m_IP[10] = _Octet10;
		m_IP[11] = _Octet11;
		m_IP[12] = _Octet12;
		m_IP[13] = _Octet13;
		m_IP[14] = _Octet14;
		m_IP[15] = _Octet15;
	}

	CNetAddressIPv6::CNetAddressIPv6(CNetAddressIPv6 const &_Src)
	{
		NMemory::fg_MemCopy(m_IP, _Src.m_IP, sizeof(m_IP));
	}

	CNetAddressIPv6 &CNetAddressIPv6::operator = (CNetAddressIPv6 const &_Src)
	{
		NMemory::fg_MemCopy(m_IP, _Src.m_IP, sizeof(m_IP));

		return *this;
	}

	void CNetAddressIPv6::f_SetLocalhost()
	{
		*this = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
	}

	CNetAddress::CNetAddress()
		: mp_pAddress(nullptr)
	{
	}

	CNetAddress::CNetAddress(CNetAddress &&_ToMove)
		: mp_pAddress(_ToMove.mp_pAddress)
	{
		_ToMove.mp_pAddress = nullptr;
	}

	CNetAddress::CNetAddress(CNetAddress const &_ToCopy)
		: mp_pAddress(nullptr)
	{
		if (_ToCopy.mp_pAddress)
			mp_pAddress = NMib::NSys::NNetwork::fg_DuplicateAddress(_ToCopy.mp_pAddress);
	}

	CNetAddress &CNetAddress::operator = (CNetAddress &&_ToMove)
	{
		f_Clear();

		mp_pAddress = _ToMove.mp_pAddress;
		_ToMove.mp_pAddress = nullptr;

		return *this;
	}

	CNetAddress &CNetAddress::operator = (CNetAddress const &_ToCopy)
	{
		f_Clear();

		if (_ToCopy.mp_pAddress)
			mp_pAddress = NMib::NSys::NNetwork::fg_DuplicateAddress(_ToCopy.mp_pAddress);

		return *this;
	}

	bool CNetAddress::f_IsEmpty() const
	{
		return mp_pAddress == nullptr;
	}

	NStr::CStr CNetAddress::f_GetString(ENetAddressStringFlag _Flags) const
	{
		if (mp_pAddress == nullptr)
			return "";
		return NMib::NSys::NNetwork::fg_GetAddressString(mp_pAddress, _Flags);
	}

	ENetAddressType CNetAddress::f_GetType() const
	{
		return mp_pAddress ? NMib::NSys::NNetwork::fg_GetAddressType(mp_pAddress) : ENetAddressType_None;
	}

	bool CNetAddress::f_Set(CNetAddress const &_Address)
	{
		f_Clear();
		if (_Address.mp_pAddress)
			mp_pAddress = NMib::NSys::NNetwork::fg_DuplicateAddress(_Address.mp_pAddress);

		return mp_pAddress != nullptr;
	}

	bool CNetAddress::f_SetPort(uint16 _Port)
	{
		if (!mp_pAddress)
			return false;

		switch (NMib::NSys::NNetwork::fg_GetAddressType(mp_pAddress))
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
		default: return false;
		}
	}

	CNetAddress::operator NMib::NSys::NNetwork::CAddress () const
	{
		return mp_pAddress;
	}

	bool CNetAddress::operator == (CNetAddress const &_Other) const
	{
		return NMib::NSys::NNetwork::fg_CompareAddresses(mp_pAddress, _Other.mp_pAddress) == 0;
	}

	COrdering_Weak CNetAddress::operator <=> (CNetAddress const &_Other) const
	{
		return NMib::NSys::NNetwork::fg_CompareAddresses(mp_pAddress, _Other.mp_pAddress) <=> 0;
	}

	CSocketOperationResult &CSocketOperationResult::operator += (CSocketOperationResult const &_Other)
	{
		m_nBytes += _Other.m_nBytes;
		if (_Other.m_bSentNetwork)
			m_bSentNetwork = true;
		if (_Other.m_bReceivedNetwork)
			m_bReceivedNetwork = true;
		return *this;
	}

	CSocket::CSocket()
	{
		mp_pSocket = nullptr;
	}

	// Destruction cannot block on another pool thread's loop; use asynchronous close.
	CSocket::~CSocket()
	{
		f_CloseAsync({});
	}

	// Move settings even if the platform socket has not been created yet.
	CSocket::CSocket(CSocket &&_Other)
		: mp_pSocket(fg_Exchange(_Other.mp_pSocket, nullptr))
		, mp_nSendWindowBytes(_Other.mp_nSendWindowBytes)
		, mp_bSendWindowConfigured(_Other.mp_bSendWindowConfigured)
		, mp_bInheritable(_Other.mp_bInheritable)
	{
	}

	CSocket &CSocket::operator = (CSocket &&_Other)
	{
		mp_pSocket = fg_Exchange(_Other.mp_pSocket, nullptr);
		mp_nSendWindowBytes = _Other.mp_nSendWindowBytes;
		mp_bSendWindowConfigured = _Other.mp_bSendWindowConfigured;
		mp_bInheritable = _Other.mp_bInheritable;
		return *this;
	}

	bool CSocket::f_IsValid() const
	{
		return mp_pSocket != nullptr;
	}

	// Synchronous close, complete on return; refuses for a socket on a created loop, where
	// only the asynchronous form is legal
	void CSocket::f_Close()
	{
		if (mp_pSocket)
			NMib::NSys::NNetwork::fg_Close(mp_pSocket);
		mp_pSocket = nullptr;
	}

	// Consumes the platform socket; registered sockets finish on the loop thread, unregistered sockets inline.
	void CSocket::f_CloseAsync(NMib::NFunction::TCFunctionMovable<void ()> &&_fOnClosed)
	{
		void *pSocket = mp_pSocket;
		mp_pSocket = nullptr;
		if (pSocket)
			NMib::NSys::NNetwork::fg_CloseAsync(pSocket, fg_Move(_fOnClosed));
		else if (_fOnClosed)
			_fOnClosed();
	}

	void CSocket::f_Connect(NMib::NNetwork::CNetAddress const &_Address, NMib::NThread::CSemaphoreAggregate *_pReportTo, fp64 _Timeout)
	{
		f_Connect(_Address, fsp_GetChangeReportTo(_pReportTo), CNetAddress(), _Timeout);
	}

	void CSocket::f_Connect
		(
			NMib::NNetwork::CNetAddress const &_Address
			, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange
			, NMib::NNetwork::CNetAddress const &_BindAddress
			, fp64 _Timeout
		)
	{
		f_Close();

		struct CState
		{
			NMib::NThread::CEventAutoReset m_Event;
			NAtomic::TCAtomic<bool> m_bEventAbandonned = false;
			NAtomic::TCAtomic<bool> m_bConnected = false;
			NAtomic::TCAtomic<bool> m_bClosed = false;
		};

		NStorage::TCSharedPointer<CState> pState = fg_Construct();

		auto CleanupEvent = g_OnScopeExit / [pState]
			{
				pState->m_bEventAbandonned = true;
			}
		;

		mp_pSocket = NMib::NSys::NNetwork::fg_AsyncConnect
			(
				_Address
				, [pState, fOnStateChange = fg_Move(_fOnStateChange)](::NMib::NNetwork::ENetTCPState _StateAdded) mutable
				{
					if (!pState->m_bEventAbandonned && (_StateAdded & ENetTCPState_Connected))
					{
						pState->m_bConnected = true;
						pState->m_Event.f_Signal();
						return;
					}
					if (!pState->m_bEventAbandonned && (_StateAdded & ENetTCPState_Closed))
					{
						pState->m_bClosed = true;
						pState->m_Event.f_Signal();
						return;
					}
					if (fOnStateChange)
						fOnStateChange(_StateAdded);
				}
				, _BindAddress
			)
		;

		auto Cleanup = g_OnScopeExit / [&]
			{
				// A drop: the asynchronous form is legal on any loop and nothing waits for it
				NMib::NSys::NNetwork::fg_CloseAsync(mp_pSocket, {});
				mp_pSocket = nullptr;
			}
		;

		fp_ApplyInheritable();
		fp_ApplySendWindow();
		NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);

		NTime::CStopwatch Stopwatch(true);

		while (!pState->m_bConnected)
		{
			if (pState->m_bClosed)
				DMibErrorNet(NMib::NSys::NNetwork::fg_GetCloseReason(mp_pSocket));
			fp64 TimeLeft = _Timeout - Stopwatch.f_GetTime();
			if (TimeLeft <= 0)
				DMibErrorNet("Timed out waiting for connection");
			pState->m_Event.f_WaitTimeout(TimeLeft);
		};

		Cleanup.f_Clear();
	}

	void CSocket::f_AsyncConnect(NMib::NNetwork::CNetAddress const &_Address, NMib::NThread::CSemaphoreAggregate *_pReportTo)
	{
		f_Close();

		mp_pSocket = NMib::NSys::NNetwork::fg_AsyncConnect(_Address, fsp_GetChangeReportTo(_pReportTo), CNetAddress());
		fp_ApplyInheritable();
		fp_ApplySendWindow();
		NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
	}

	void CSocket::f_AsyncConnect
		(
			NMib::NNetwork::CNetAddress const &_Address
			, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange
			, NMib::NNetwork::CNetAddress const &_BindAddress
		)
	{
		f_Close();

		mp_pSocket = NMib::NSys::NNetwork::fg_AsyncConnect(_Address, fg_Move(_fOnStateChange), _BindAddress);
		fp_ApplyInheritable();
		fp_ApplySendWindow();
		NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
	}

	void CSocket::f_Listen(NMib::NNetwork::CNetAddress const &_Address, NMib::NThread::CSemaphoreAggregate *_pReportTo, ENetFlag _Flags)
	{
		f_Close();

		mp_pSocket = NMib::NSys::NNetwork::fg_Listen(_Address, fsp_GetChangeReportTo(_pReportTo), _Flags);
		fp_ApplyInheritable();
		fp_ApplySendWindow();
		NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
	}

	void CSocket::f_Listen
		(
			NMib::NNetwork::CNetAddress const &_Address
			, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange
			, ENetFlag _Flags
		)
	{
		f_Close();

		mp_pSocket = NMib::NSys::NNetwork::fg_Listen(_Address, fg_Move(_fOnStateChange), _Flags);
		fp_ApplyInheritable();
		fp_ApplySendWindow();
		NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
	}

	void CSocket::f_ListenDatagram
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

	void CSocket::f_Accept(CSocket *_pAcceptFrom, NMib::NThread::CSemaphoreAggregate *_pReportTo)
	{
		f_Close();

		mp_pSocket = NMib::NSys::NNetwork::fg_Accept(_pAcceptFrom->mp_pSocket, fsp_GetChangeReportTo(_pReportTo));
		fp_ApplyInheritable();
		fp_ApplySendWindow();
		if (mp_pSocket)
			NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
	}

	void CSocket::f_Accept(CSocket *_pAcceptFrom, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		f_Close();

		mp_pSocket = NMib::NSys::NNetwork::fg_Accept(_pAcceptFrom->mp_pSocket, fg_Move(_fOnStateChange));
		fp_ApplyInheritable();
		fp_ApplySendWindow();
		if (mp_pSocket)
			NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
	}

	void CSocket::f_InheritHandle2(void *_pSocketHandle, NMib::NThread::CSemaphoreAggregate *_pReportTo)
	{
		f_Close();

		mp_pSocket = NMib::NSys::NNetwork::fg_InheritHandle2(_pSocketHandle, fsp_GetChangeReportTo(_pReportTo));
		NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
	}

	void CSocket::f_InheritHandle2(void *_pSocketHandle, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		f_Close();

		mp_pSocket = NMib::NSys::NNetwork::fg_InheritHandle2(_pSocketHandle, fg_Move(_fOnStateChange));
		NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
	}

	// Retains registration and kernel connection state; only the state callback changes owner.
	void CSocket::f_Adopt(CSocket &&_Socket, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		f_Close();

		mp_pSocket = _Socket.mp_pSocket;
		_Socket.mp_pSocket = nullptr;
		if (mp_pSocket)
			NMib::NSys::NNetwork::fg_ReownSocket(mp_pSocket, fg_Move(_fOnStateChange));
	}

	void *CSocket::f_GiveUpForInherit()
	{
		return NMib::NSys::NNetwork::fg_GiveUpForInherit(mp_pSocket);
	}

	// Empties the wrapper immediately; delivers the handle after removal acknowledgement makes reuse safe.
	void CSocket::f_GiveUpForInheritAsync(NMib::NFunction::TCFunctionMovable<void (void *_pSocketHandle)> &&_fOnHandle)
	{
		fp_CheckSocket();

		void *pSocket = mp_pSocket;
		mp_pSocket = nullptr;
		NMib::NSys::NNetwork::fg_GiveUpForInheritAsync(pSocket, fg_Move(_fOnHandle));
	}

	void *CSocket::f_GetOSSocket()
	{
		return NMib::NSys::NNetwork::fg_GetOSSocket(mp_pSocket);
	}

	void CSocket::f_SetReportTo(NMib::NThread::CSemaphoreAggregate *_pReportTo)
	{
		NMib::NSys::NNetwork::fg_SetOnStateChange(mp_pSocket, fsp_GetChangeReportTo(_pReportTo));
	}

	void CSocket::f_SetOnStateChange(NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		NMib::NSys::NNetwork::fg_SetOnStateChange(mp_pSocket, fg_Move(_fOnStateChange));
	}

	void CSocket::f_Shutdown()
	{
		fp_CheckSocket();

		return NMib::NSys::NNetwork::fg_Shutdown(mp_pSocket);
	}

	void CSocket::f_SetAbortOnClose()
	{
		if (mp_pSocket)
			NMib::NSys::NNetwork::fg_SetAbortOnClose(mp_pSocket);
	}

	ENetTCPState CSocket::f_GetState()
	{
		fp_CheckSocket();

		return NMib::NSys::NNetwork::fg_GetState(mp_pSocket);
	}

	NStr::CStr CSocket::f_GetCloseReason()
	{
		fp_CheckSocket();

		return NMib::NSys::NNetwork::fg_GetCloseReason(mp_pSocket);
	}

	umint CSocket::f_Receive(void *_pData, umint _DataLen, bool &o_bEndOfStream)
	{
		fp_CheckSocket();

		return NMib::NSys::NNetwork::fg_Receive(mp_pSocket, _pData, _DataLen, o_bEndOfStream);
	}

	umint CSocket::f_Send(void const *_pData, umint _DataLen)
	{
		fp_CheckSocket();

		return NMib::NSys::NNetwork::fg_Send(mp_pSocket, _pData, _DataLen);
	}

	umint CSocket::f_SendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans)
	{
		fp_CheckSocket();

		return NMib::NSys::NNetwork::fg_SendVectored(mp_pSocket, _pSpans, _nSpans);
	}

	void CSocket::f_RequestReadiness(bool _bRead, bool _bWrite)
	{
		fp_CheckSocket();

		NMib::NSys::NNetwork::fg_RequestReadiness(mp_pSocket, _bRead, _bWrite);
	}

	bool CSocket::f_SupportsCompletionIo() const
	{
		return mp_pSocket && NMib::NSys::NNetwork::fg_SupportsCompletionIo(mp_pSocket);
	}

	bool CSocket::f_SendReleaseIsPrompt() const
	{
		return !mp_pSocket || NMib::NSys::NNetwork::fg_SendReleaseIsPrompt(mp_pSocket);
	}

	NMib::NSys::ICIoLoop *CSocket::f_GetOwningIoLoop() const
	{
		return mp_pSocket ? NMib::NSys::NNetwork::fg_GetOwningIoLoop(mp_pSocket) : nullptr;
	}

	bool CSocket::f_SupportsReceiveStream() const
	{
		return mp_pSocket && NMib::NSys::NNetwork::fg_SupportsReceiveStream(mp_pSocket);
	}

	bool CSocket::f_StartReceiveStream(umint _nBufferBytes, NStorage::TCSharedPointer<NSys::CIoStreamBackpressure> &&_pBackpressure, NSys::FIoStreamSink &&_fSink)
	{
		fp_CheckSocket();

		return NMib::NSys::NNetwork::fg_StartReceiveStream(mp_pSocket, _nBufferBytes, fg_Move(_pBackpressure), fg_Move(_fSink));
	}

	void CSocket::f_ResumeReceiveStream()
	{
		fp_CheckSocket();

		NMib::NSys::NNetwork::fg_ResumeReceiveStream(mp_pSocket);
	}

	bool CSocket::f_QueryPathDeliveryRate(umint &o_nBytes, bool &o_bAppLimited)
	{
		return mp_pSocket && NMib::NSys::NNetwork::fg_QueryPathDeliveryRate(mp_pSocket, o_nBytes, o_bAppLimited);
	}

	bool CSocket::f_IsSendWindowFull(umint _nUnreleasedBytes, umint _nStartBytes)
	{
		return mp_pSocket && NMib::NSys::NNetwork::fg_IsSendWindowFull(mp_pSocket, _nUnreleasedBytes, _nStartBytes);
	}

	// Set before connect/listen/accept for a receiver unable to replace completion bindings.
	void CSocket::f_SetInheritable()
	{
		mp_bInheritable = true;
		fp_ApplyInheritable();
	}

	// Before or after the socket exists: a socket in place takes the window now, and one made
	// later takes it as it is created
	void CSocket::f_SetSendWindow(umint _nBytes, bool _bConfigured)
	{
		mp_nSendWindowBytes = _nBytes;
		mp_bSendWindowConfigured = _bConfigured;
		fp_ApplySendWindow();
	}

	umint CSocket::f_SubmitSendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans, NSys::FIoCompletion &&_fOnComplete, NMib::NSys::FIoBufferReleased &&_fOnBufferReleased)
	{
		fp_CheckSocket();

		return NMib::NSys::NNetwork::fg_SubmitSendVectored(mp_pSocket, _pSpans, _nSpans, fg_Move(_fOnComplete), fg_Move(_fOnBufferReleased));
	}

	umint CSocket::f_SendDatagram(NMib::NNetwork::CNetAddress const &_Address, void const *_pData, umint _DataLen)
	{
		fp_CheckSocket();

		return NMib::NSys::NNetwork::fg_SendDatagram(mp_pSocket, _Address, _pData, _DataLen);
	}

	umint CSocket::f_ReceiveDatagram(NMib::NNetwork::CNetAddress &_Address, void *_pData, umint _DataLen)
	{
		fp_CheckSocket();

		return NMib::NSys::NNetwork::fg_ReceiveDatagram(mp_pSocket, _Address, _pData, _DataLen);
	}

	NMib::NNetwork::CNetAddress CSocket::f_GetPeerAddress() const
	{
		fp_CheckSocket();
		return CNetAddress(NMib::NSys::NNetwork::fg_GetPeerAddress(mp_pSocket));
	}

	bool CSocket::f_GetProcessIdentity(NMib::NSys::NNetwork::CProcessIdentity &o_LocalIdentity, NMib::NSys::NNetwork::CProcessIdentity &o_PeerIdentity) const
	{
		fp_CheckSocket();
		return NMib::NSys::NNetwork::fg_GetProcessIdentity(mp_pSocket, o_LocalIdentity, o_PeerIdentity);
	}

	uint32 CSocket::f_GetListenPort() const
	{
		fp_CheckSocket();
		return NMib::NSys::NNetwork::fg_GetListenPort(mp_pSocket);
	}

	NMib::NNetwork::CNetAddress CSocket::fs_ResolveAddress(NMib::NStr::CStr const &_Address, ::NMib::NNetwork::ENetAddressType _PreferType)
	{
		return fg_Move(CNetAddress(NMib::NSys::NNetwork::fg_ResolveAddress(_Address, _PreferType)));
	}

	void CSocket::fp_ApplyInheritable()
	{
		if (mp_pSocket && mp_bInheritable)
			NMib::NSys::NNetwork::fg_SetInheritable(mp_pSocket);
	}

	void CSocket::fp_ApplySendWindow()
	{
		if (mp_pSocket && mp_nSendWindowBytes)
			NMib::NSys::NNetwork::fg_SetSendWindow(mp_pSocket, mp_nSendWindowBytes, mp_bSendWindowConfigured);
	}

	NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> CSocket::fsp_GetChangeReportTo(NMib::NThread::CSemaphoreAggregate *_pReportTo)
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
}
