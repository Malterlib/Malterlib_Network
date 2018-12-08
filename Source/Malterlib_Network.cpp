// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include "Malterlib_Network.h"
#include <Mib/Cryptography/UUID>

namespace NMib::NNetwork
{
	bool fg_IsValidHostname(NStr::CStr const &_String, ch8 const *_pSeparatorChars)
	{
		if (_String.f_IsEmpty())
			return false;
		if (_String.f_GetLen() > 254)
			return false;
		ch8 const *pParse = _String.f_GetStr();
		ch8 LastChar = 0;
		while (*pParse)
		{
			if (*pParse == '-')
				return false; // Must not start with hyphen
			if (*pParse == '.')
				return false; // Empty label allowed?
			while (*pParse && (NStr::fg_CharIsAnsiAlphabetical(*pParse) || NStr::fg_CharIsNumber(*pParse) || *pParse == '-'))
			{
				LastChar = *pParse;
				++pParse;
			}
			if (LastChar == '-')
				return false; // Must not end with hyphen
			if (*pParse)
			{
				if (NStr::fg_StrFindChar(_pSeparatorChars, *pParse) < 0 && *pParse != '.')
					return false; // Any other character is not allowed
				++pParse;
			}
		}
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
}
