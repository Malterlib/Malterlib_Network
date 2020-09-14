// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include "Malterlib_Network.h"
#include <Mib/Cryptography/UUID>

namespace NMib::NNetwork
{
	DMibImpErrorClassImplement(CExceptionNet);

	bool fg_IsValidHostname(NStr::CStr const &_String, ch8 const *_pSeparatorChars, ch8 const *_pLabelChars)
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
			while (*pParse && (NStr::fg_CharIsAnsiAlphabetical(*pParse) || NStr::fg_CharIsNumber(*pParse) || *pParse == '-' || NStr::fg_StrFindChar(_pLabelChars, *pParse) >= 0))
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

	namespace
	{
		NCryptography::CUniversallyUniqueIdentifier g_HostnameRootUUID("D2C365F0-3F5E-4056-9BBB-0724C411D2FA", NCryptography::EUniversallyUniqueIdentifierFormat_Bare);
	}

	NStr::CStr fg_GetSafeUnixSocketPath(NStr::CStr const &_WantedPath)
	{
		using namespace NStr;

		mint MaxLength = NSys::NNetwork::fg_GetMaxUnixSocketNameLength();
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
			NMib::NThread::CEventAutoResetReportable m_Event;
			NAtomic::TCAtomic<bool> m_bEventAbandonned = false;
			NAtomic::TCAtomic<bool> m_bConnected = false;
		};

		NStorage::TCSharedPointer<CState> pState = fg_Construct();

		auto CleanupEvent = g_OnScopeExit > [pState]
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
					if (fOnStateChange)
						fOnStateChange(_StateAdded);
				}
				, _BindAddress
			)
		;

		auto Cleanup = g_OnScopeExit > [&]
			{
				NMib::NSys::NNetwork::fg_Close(mp_pSocket);
				mp_pSocket = nullptr;
			}
		;

		NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);

		NTime::CClock Clock(true);

		while (!pState->m_bConnected && Clock.f_GetTime() < _Timeout)
		{
			fp64 TimeLeft = _Timeout - Clock.f_GetTime();
			if (TimeLeft <= 0)
				DMibErrorNet("Timed out waiting for connection");
			pState->m_Event.f_WaitTimeout(TimeLeft);
		};

		Cleanup.f_Clear();
	}
}
