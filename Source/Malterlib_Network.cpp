// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include "Malterlib_Network.h"

namespace NMib::NNet
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
}
