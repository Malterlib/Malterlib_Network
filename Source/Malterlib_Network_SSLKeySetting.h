#pragma once

#include <Mib/Storage/Variant>

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
			, ESSLKeyType_EC_X25519
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
		
		struct CSSLKeySettings_EC_X25519
		{
		};
		
		using CSSLKeySetting = NContainer::TCStreamableVariant
			<
				ESSLKeyType
				, CSSLKeySettings_RSA, ESSLKeyType_RSA
				, CSSLKeySettings_EC_secp256r1, ESSLKeyType_EC_secp256r1
				, CSSLKeySettings_EC_secp384r1, ESSLKeyType_EC_secp384r1
				, CSSLKeySettings_EC_secp521r1, ESSLKeyType_EC_secp521r1
				, CSSLKeySettings_EC_X25519, ESSLKeyType_EC_X25519
			>
		;
		
		enum ESSLDigest
		{
			ESSLDigest_Automatic
			, ESSLDigest_SHA256
			, ESSLDigest_SHA384
			, ESSLDigest_SHA512
		};

		struct CCertificateExtension
		{
			bool operator == (CCertificateExtension const &_Right) const;
			bool operator < (CCertificateExtension const &_Right) const;

			template <typename tf_CFormatInto>
			void f_Format(tf_CFormatInto &o_FormatInto) const
			{
				o_FormatInto += typename tf_CFormatInto::CFormat("{}{}") << m_Value << (m_bCritical ? " - critical" : "");
			}

			NStr::CStr m_Value;
			bool m_bCritical = false;
		};

		struct CSignOptions
		{
			void f_AddExtension_SubjectKeyIdentifier(bool _bCritical = false);
			void f_AddExtension_AuthorityKeyIdentifier(bool _bCritical = false);
 
			ESSLDigest m_Digest = ESSLDigest_Automatic;
			int32 m_Serial = 1;
			int32 m_Days = 365;
			NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> m_Extensions;
		};
	}
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNet;
#endif
