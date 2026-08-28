// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Network.h"
#include <Mib/Cryptography/UUID>

namespace NMib::NNetwork
{
	DMibImpErrorClassImplement(CExceptionNet);

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

	bool fg_IsLoopbackAddress(CNetAddress const &_Address)
	{
		CNetAddressTCPv4 TCPv4;
		if (_Address.f_Get(TCPv4))
			return TCPv4.m_IP[0] == 127;

		CNetAddressTCPv6 TCPv6;
		if (_Address.f_Get(TCPv6))
		{
			bool bMappedPrefix = true;
			for (umint i = 0; i < 10; ++i)
			{
				if (TCPv6.m_IP[i] != 0)
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

		umint MaxLength = NSys::NNetwork::fg_GetMaxUnixSocketNameLength();
		if (_WantedPath.f_GetLen() <= aint(MaxLength))
			return _WantedPath;

		CStr ConfigHash = fg_GetHashedUuidString(_WantedPath, g_HostnameRootUUID, NCryptography::EUniversallyUniqueIdentifierFormat_AlphaNum);

		CStr TempDir = NFile::CFile::fs_GetRawTemporaryDirectory();
		CStr Path = TempDir / ("{}.sock"_f << ConfigHash);
		if (Path.f_GetLen() <= aint(MaxLength))
			return Path;

		return "/tmp/{}.sock"_f << ConfigHash;
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
}
