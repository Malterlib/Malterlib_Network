#pragma once

namespace NMib
{
	namespace NNet
	{
		enum ESSLKeyType
		{
			ESSLKeyType_RSA
			, ESSLKeyType_EC_secp256r1
			, ESSLKeyType_EC_secp384r1
			, ESSLKeyType_EC_secp521r1
		};
		
		struct CSSLKeySettings_RSA
		{
			CSSLKeySettings_RSA() = default;
			CSSLKeySettings_RSA(uint32 _KeyLength)
				: m_KeyLength(_KeyLength)
			{
			}
			
			uint32 m_KeyLength = 4096; 
		};
		
		struct CSSLKeySettings_EC_secp256r1
		{
		};
		
		struct CSSLKeySettings_EC_secp384r1
		{
		};
		
		struct CSSLKeySettings_EC_secp521r1
		{
		};
		
		using CSSLKeySetting = NContainer::TCStreamableVariant
			<
				ESSLKeyType
				, CSSLKeySettings_RSA, ESSLKeyType_RSA
				, CSSLKeySettings_EC_secp256r1, ESSLKeyType_EC_secp256r1
				, CSSLKeySettings_EC_secp384r1, ESSLKeyType_EC_secp384r1
				, CSSLKeySettings_EC_secp521r1, ESSLKeyType_EC_secp521r1
			>
		;
		
		enum ESSLDigest
		{
			ESSLDigest_Automatic
			, ESSLDigest_SHA256
			, ESSLDigest_SHA384
			, ESSLDigest_SHA512
		};
		
		struct CSignOptions
		{
			ESSLDigest m_Digest = ESSLDigest_Automatic;
			int32 m_Serial = 1;
			int32 m_Days = 365;
		};
	}
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNet;
#endif
