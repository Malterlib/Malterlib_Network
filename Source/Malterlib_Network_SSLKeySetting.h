#pragma once

#include <Mib/Storage/Variant>

namespace NMib::NNetwork
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

	using CSSLKeySetting = NStorage::TCStreamableVariant
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
		ESSLDigest_None
		, ESSLDigest_Automatic
		, ESSLDigest_SHA512
		, ESSLDigest_SHA384
		, ESSLDigest_SHA256
		, ESSLDigest_SHA224
		, ESSLDigest_SHA1		// Be careful, only to be used for compatibility with legacy systems (borken hash)
		, ESSLDigest_MD5		// Be careful, only to be used for compatibility with legacy systems (borken hash)
		, ESSLDigest_MD4		// Be careful, only to be used for compatibility with legacy systems (borken hash)
	};

	enum ESSLCrypto
	{
		ESSLCrypto_AES_256_CBC
		, ESSLCrypto_AES_128_CBC
		, ESSLCrypto_AES_256_OFB	// Be careful (stream cipher)
		, ESSLCrypto_AES_128_OFB	// Be careful (stream cipher)
		, ESSLCrypto_DES_EDE3_CBC	// Be careful, only to be used for compatibility with legacy systems (weak croypto)
		, ESSLCrypto_AES_256_ECB	// Be careful, only to be used for compatibility with legacy systems (ECB mode)
		, ESSLCrypto_AES_128_ECB	// Be careful, only to be used for compatibility with legacy systems (ECB mode)
//			, ESSLCrypto_AES_128_CTR // Needs to have interface for specifying counter
//			, ESSLCrypto_AES_256_CTR // Needs to have interface for specifying counter
//			, ESSLCrypto_AES_256_XTS // Needs to have interface for specifying counter
	};

	enum ESSLCryptoFlags
	{
		ESSLCryptoFlags_None = DMibBit(0)
		, ESSLCryptoFlags_Decrypt = DMibBit(1)
		, ESSLCryptoFlags_Encrypt = DMibBit(2)
		, ESSLCryptoFlags_UsePadding = DMibBit(3)
	};

	enum EKeyDerivationType
	{
		EKeyDerivationType_Scrypt
		, EKeyDerivationType_PKCS5_PBKDF2_HMAC
		, EKeyDerivationType_PKCS5_Deprecated
	};

	struct CKeyDerivationSettings_Scrypt
	{
		ESSLDigest m_Digest = ESSLDigest_SHA512;
		uint64 m_Workload = 1 << 15; // (N)
		uint64 m_Ratio = 8; // (r)
		uint64 m_Parallel = 1; // (p)
		mint m_MaxMemory = 1024 * 1024 * 64;
	};

	struct CKeyDerivationSettings_PKCS5_PBKDF2_HMAC
	{
		ESSLDigest m_Digest = ESSLDigest_SHA512;
		uint32 m_Rounds = 10000;
	};

	struct CKeyDerivationSettings_PKCS5_Deprecated
	{
		ESSLDigest m_Digest = ESSLDigest_SHA256;
		uint32 m_Rounds = 1 << 17;
	};

	using CKeyDerivationSettings = NStorage::TCStreamableVariant
		<
			EKeyDerivationType
			, CKeyDerivationSettings_Scrypt, EKeyDerivationType_Scrypt
			, CKeyDerivationSettings_PKCS5_PBKDF2_HMAC, EKeyDerivationType_PKCS5_PBKDF2_HMAC
		>
	;

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

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
