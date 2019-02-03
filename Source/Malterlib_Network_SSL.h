
#pragma once

#include <Mib/Cryptography/Hashes/SHA>
#include "Malterlib_Network.h"
#include "Malterlib_Network_Exception.h"
#include "Malterlib_Network_SSLKeySetting.h"
#include <Mib/Memory/Allocators/Secure>

extern "C"
{
	typedef struct x509_store_st X509_STORE;
}

namespace NMib::NNetwork
{
	DMibImpErrorClassDefine(CExceptionNetSSL, CExceptionNet);
#	define DMibErrorNetSSL(_Description) DMibImpError(NMib::NNetwork::CExceptionNetSSL, _Description)

#	ifndef DMibPNoShortCuts
#		define DErrorNetSSL(_Description) DMibErrorNetSSL(_Description)
#	endif
		
	struct CSSLSettings
	{
		enum EVerificationFlag
		{
			EVerificationFlag_None = 0
			, EVerificationFlag_UserCanAcceptUntrusted				= DMibBit(0)
			, EVerificationFlag_RememberTrustedCertificates			= DMibBit(1)
			, EVerificationFlag_UseSpecificPeerCertificate			= DMibBit(2)
			, EVerificationFlag_UseOSStoreIfNoCASpecified			= DMibBit(3)
			, EVerificationFlag_VerifyHostnameMatches				= DMibBit(4)
			, EVerificationFlag_UserCanIgnoreVerificationFailures	= DMibBit(5)
			, EVerificationFlag_AllowInsecureSSL					= DMibBit(6)
			, EVerificationFlag_AllowMissingPeerCertificate			= DMibBit(7)
			, EVerificationFlag_IgnoreVerificationFailures			= DMibBit(8)
			, EVerificationFlag_IgnoreTrustFailures					= DMibBit(9)
			, EVerificationFlag_DisallowEllipticCurveDHKeyExchange	= DMibBit(10)
			, EVerificationFlag_AllowInsecureCipherSuites			= DMibBit(11)
			, EVerificationFlag_AllowInsecureSSLVersions			= DMibBit(12)
		};

		enum EProtocol
		{
			EProtocol_SSL,
			EProtocol_TLS,
		};

		bool operator==(CSSLSettings const &_Other) const
		{
			return
				m_PublicCertificateData == _Other.m_PublicCertificateData
				&& m_PrivateKeyData == _Other.m_PrivateKeyData
				&& m_CRLData == _Other.m_CRLData
				&& m_CACertificateData == _Other.m_CACertificateData
				&& m_CAStoreLocation == _Other.m_CAStoreLocation
				&& m_PathToCRLs == _Other.m_PathToCRLs
				&& m_VerificationFlags == _Other.m_VerificationFlags
				&& m_VerificationDepth == _Other.m_VerificationDepth
				&& m_LocalCertificateStore == _Other.m_LocalCertificateStore
				&& m_Protocol == _Other.m_Protocol
			;
		}

		void f_MarkAsDirty() { m_bDirty = true; }
		void f_MarkAsClean() { m_bDirty = false; }
		bool f_IsDirty() const { return m_bDirty; }

		bool f_IsPeerCertificateVerified() const
		{
			return !m_CACertificateData.f_IsEmpty() || !m_CAStoreLocation.f_IsEmpty();
		}

		bool f_UserCanManageCertificates() const
		{
			return (m_VerificationFlags & EVerificationFlag_RememberTrustedCertificates) && (m_VerificationFlags & EVerificationFlag_UserCanAcceptUntrusted);
		}

		bool f_UserCanIgnoreTrustFailures() const
		{
			return m_VerificationFlags & EVerificationFlag_UserCanAcceptUntrusted;
		}

		bool f_UserCanIgnoreVerificationFailures() const
		{
			return m_VerificationFlags & EVerificationFlag_UserCanIgnoreVerificationFailures;
		}

		bool f_CanConnectToInsecureSSL() const
		{
			return m_VerificationFlags & EVerificationFlag_AllowInsecureSSL;
		}

		bool m_bDirty = false;

		NContainer::CByteVector m_PublicCertificateData;
		NContainer::CSecureByteVector m_PrivateKeyData;
		NContainer::CByteVector m_CRLData;
		NContainer::CByteVector m_CACertificateData;

		NStr::CStr m_CAStoreLocation;
		NStr::CStr m_PathToCRLs;

		EVerificationFlag m_VerificationFlags = EVerificationFlag_None;
		int m_VerificationDepth = 9;

		NContainer::TCVector<NContainer::CByteVector> m_LocalCertificateStore;

		EProtocol m_Protocol = EProtocol_TLS;

	};

	class CSSLConnectionResult
	{
	public:
		enum EMiscError
		{
			EMiscError_HostnameMisMatch = 5000,
			EMiscError_InvalidCertificateAuthorityLocation,
			EMiscError_InvalidPublicCertificate,
			EMiscError_InvalidPrivateKey,
			EMiscError_CertificatePrivateKeyMisMatch,
			EMiscError_InvalidCRLData,
			EMiscError_InvalidCRLPath,
			EMiscError_InvalidCertificateAuthorityData,
			EMiscError_InternalError,
			EMiscError_MismatchingSpecificCertificate,
		};

		struct CCertificate
		{
			NContainer::CByteVector m_Data;
			NContainer::TCMap<int,int> m_Errors;

			bool operator==(CCertificate const &_Other) const
			{
				return m_Data == _Other.m_Data && m_Errors == _Other.m_Errors;
			}
		};

		bool operator==(CSSLConnectionResult const &_Other) const
		{
			return (mp_Certificates == _Other.mp_Certificates &&
				mp_bTrustErrorsOccured == _Other.mp_bTrustErrorsOccured &&
				mp_bVerificationErrorsOccured == _Other.mp_bVerificationErrorsOccured &&
				mp_MiscErrors == _Other.mp_MiscErrors &&
				mp_SSLErrors == _Other.mp_SSLErrors);
		}

		NContainer::CByteVector f_GetPeerCertificate() const;
		NContainer::TCVector<NContainer::CByteVector> f_GetCertificateChain() const;

		CSSLConnectionResult() : mp_bTrustErrorsOccured(false), mp_bVerificationErrorsOccured(false), mp_bConnectionRefused(false) {}
		~CSSLConnectionResult() {}

		void f_LogError(mint _Depth, int _Error);
		void f_LogMiscError(EMiscError _Error);
		bool f_HasLoggedCertificateChain() const { return !mp_Certificates.f_IsEmpty(); }
		void f_LogCertificate(mint _Depth, NContainer::CByteVector const &_Certificate);

		NStr::CStr f_GetPeerCertificateName() const;
		NStr::CStr f_GetPeerCertificateDistinguishedName_RFC2253() const;
		NStr::CStr f_GetPeerCertificateDescription() const;
		NStr::CStr f_GetPeerCertificateInformation() const;
		NStr::CStr f_GetPeerCertificateFingerprint() const;

		bool f_ContainsTrustErrors() const;
		bool f_ContainsVerificationErrors() const;
		bool f_ConnectionRefused() const;
		bool f_ContainsInvalidContextErrors() const;
		void f_SetConnectionRefused();
		bool f_PeerCertificatesMatchesSpecificCertificate(NContainer::CByteVector const &_SpecificCertificate) const;
		bool f_PeerCertificateMatchesRememberedCertificates(NContainer::TCVector<NContainer::CByteVector> const &_LocalStore) const;
		void f_AddSSLError(NStr::CStr const &_SSLError);

		enum EFormat
		{
			EHtml,
			ECommaSeperated,
		};

		NStr::CStr f_GetErrorMessage(EFormat _Format = ECommaSeperated) const;

	protected:

		static bool fsp_IsTrustError(int _Error);
		NStr::CStr fp_StringForError(int _Error) const;
		NStr::CStr fp_GetLibraryStringForError(int _Error) const;

		NContainer::TCMap<mint, CCertificate> mp_Certificates;
		NContainer::TCMap<EMiscError, int> mp_MiscErrors;
		NStr::CStr mp_SSLErrors;
		bool mp_bTrustErrorsOccured;
		bool mp_bVerificationErrorsOccured;
		bool mp_bConnectionRefused;

	};

	class CSSLContext;

	class CSSLConnection
	{
	public:
		class CInternal;

		enum EAuthenticationResult
		{
			EAuthenticationResult_Success,
			EAuthenticationResult_Failure,
			EAuthenticationResult_SocketNotReady,
		};

		enum EState
		{
			EState_None,
			EState_InvalidContext,
			EState_RequiresUserDecisionOnTrust,
			EState_ConnectionFailed,
			EState_ConnectionShutdown,
			EState_WriteFailed,
			EState_ReadFailed,
			EState_ShutdownFailed,
		};

		typedef NFunction::TCFunction<void (EAuthenticationResult _Result, CSSLConnectionResult const &_ConnectionResult)> FAuthenticationResultCallback;
		typedef NFunction::TCFunction<void (CSSLConnectionResult const &_ConnectionResult)> FUserTrustDecisionCallback;

		CSSLConnection
			(
				NStorage::TCSharedPointer<CSSLContext> const &_pContext
				, FAuthenticationResultCallback &&_AuthenticationResultCallback
				, FUserTrustDecisionCallback &&_UserTrustDecisionCallback
				, NStr::CStr const &_Hostname
			)
		;
		~CSSLConnection();

		bool f_GiveSocket(void *_pSocket);
		void* f_GetSocket() const;
		bool f_HasSocket() const;

		void f_SetHostname(NStr::CStr const &_Hostname);
		NStr::CStr f_GetHostname() const;
		void f_SetExpectedConnectionResult(CSSLConnectionResult const &_ExpectedResult);

		NStr::CStr f_GetLastError() const;
		bool f_BrokenState() const;
		bool f_Connected() const;

		bool f_Connect();
		bool f_Accept();
		bool f_HandshakeInProgress() const;
		bool f_Shutdown();

		CSocketOperationResult f_Send(const void *_pData, mint _nLen);
		CSocketOperationResult f_Receive(void *_pData, mint _nLen);

#ifndef DMibSSLLibrary_BoringSSL								
		bool f_Decrypt(const void *_pDataIn, void *_pDataOut, int _Len);
#endif

		CSSLSettings::EVerificationFlag f_GetVerificationFlags() const;
		CSSLConnectionResult& f_GetConnectionResult() { return mp_Result; }
		CSSLConnectionResult const& f_GetConnectionResult() const { return mp_Result; }
		NCryptography::CHashDigest_SHA256 f_GetSessionKeyDigest() const;

	protected:
		NStorage::TCUniquePointer<CInternal> mp_pInternal;
		CSSLConnectionResult mp_Result;
	};

	class CSSLContext
	{
	public:

		enum EType
		{
			EType_Client,
			EType_Server,
		};

		enum EState
		{
			EState_None = 0,
			EState_InvalidCertificateAuthorityLocation = DMibBit(1),
			EState_InvalidPublicCertificate = DMibBit(2),
			EState_InvalidPrivateKey = DMibBit(3),
			EState_CertificatePrivateKeyMisMatch = DMibBit(4),
			EState_InvalidCRLData = DMibBit(5),
			EState_InvalidCRLPath = DMibBit(6),
			EState_InvalidCertificateAuthorityData = DMibBit(7),
		};

		enum EKeyUsage
		{
			EKeyUsage_None = 0
			, EKeyUsage_DigitalSignature = DMibBit(0)
			, EKeyUsage_NonRepudiation = DMibBit(1)
			, EKeyUsage_KeyEncipherment = DMibBit(2)
			, EKeyUsage_DataEncipherment = DMibBit(3)
			, EKeyUsage_KeyAgreement = DMibBit(4)
			, EKeyUsage_CertificateSign = DMibBit(5)
			, EKeyUsage_CRLSign = DMibBit(6)
			, EKeyUsage_EncipherOnly = DMibBit(7)
			, EKeyUsage_DecipherOnly = DMibBit(8)
		};


		struct CCertificateOptions
		{
			void f_AddExtension_BasicConstraints(bool _bCA, bool _bCritical = true);
			void f_AddExtension_KeyUsage(EKeyUsage _KeyUsage, bool _bCritical = true);
			void f_MakeCA();

			NStr::CStr m_CommonName; // CN
			NContainer::TCMap<NStr::CStr, NStr::CStr> m_RelativeDistinguishedNames;
			NContainer::TCVector<NStr::CStr> m_Hostnames;
			NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> m_Extensions;
			CSSLKeySetting m_KeySetting;
		};

		CSSLContext(EType _Type, CSSLSettings const &_Settings);
		~CSSLContext();

		bool f_IsValid() const;
		void f_ReportInvalidContext(CSSLConnectionResult &_ConnectionResult) const;

		bool f_IsClientContext() const;
		bool f_IsServerContext() const;

		CSSLSettings const& f_GetSettings() const;

		CSSLSettings::EVerificationFlag f_GetVerificationFlags() const;
		bool f_CanAskUserToTrustServers() const;

		static NStr::CStr fs_GetCertificateName(NContainer::CByteVector const &_CertificateData);
		static NStr::CStr fs_GetCertificateDistinguishedName_RFC2253(NContainer::CByteVector const &_CertificateData);
		static NStr::CStr fs_GetIssuerName(NContainer::CByteVector const &_CertificateData);
		static NStr::CStr fs_GetCertificateFingerprint(NContainer::CByteVector const &_CertificateData);
		static NContainer::TCVector<NStr::CStr> fs_GetCertificateHostnames(NContainer::CByteVector const &_CertificateData, bool _bCheckCommonName = true);
		static NContainer::TCVector<NStr::CStr> fs_GetSortedHostnames(NContainer::TCVector<NStr::CStr> const &_Unsorted);
		static NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> fs_GetCertificateExtensions(NContainer::CByteVector const &_CertificateData);
		static NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> fs_GetCertificateRequestExtensions(NContainer::CByteVector const &_CertificateData);

		static NStr::CStr fs_GetCertificateHostnamesStr(NContainer::CByteVector const &_CertificateData);
		static NTime::CTime fs_GetCertificateExpirationTime(NContainer::CByteVector const &_CertificateData);
		static NStr::CStr fs_GetCertificateDescription(NContainer::CByteVector const &_CertificateData);
		static NStr::CStr fs_GetCertificateInformation(NContainer::CByteVector const &_CertificateData);

		static void fs_RegisterExtension(NStr::CStr const &_OID, NStr::CStr const &_ShortName, NStr::CStr const &_LongName);

		static void fs_GenerateSelfSignedCertAndKey
			(
				CCertificateOptions const &_Options
				, NContainer::CByteVector &o_CertData
				, NContainer::CSecureByteVector &o_KeyData
				, CSignOptions const &_SignOptions = {}
			)
		;
		static void fs_GenerateClientCertificateRequest
			(
				CCertificateOptions const &_Options
				, NContainer::CByteVector &o_CertRequestData
				, NContainer::CSecureByteVector &o_KeyData
				, ESSLDigest _Digest = ESSLDigest_Automatic
			)
		;
		static void fs_SignClientCertificate
			(
				NContainer::CByteVector const &_CACertificate
				, NContainer::CSecureByteVector const &_CAKey
				, NContainer::CByteVector const &_CertRequestData
				, NContainer::CByteVector &o_SignedCertificateData
				, CSignOptions const &_SignOptions = {}
			)
		;
		static void fs_VerifyCertificateRequestSameKeyAsCertificate(NContainer::CByteVector const &_CertRequestData, NContainer::CByteVector const &_CertData);

		static NContainer::CSecureByteVector fs_SignMessage
			(
				NContainer::CSecureByteVector const &_Message
				, NContainer::CSecureByteVector const &_KeyData
				, ESSLDigest _Digest = ESSLDigest_Automatic
			);
		static bool fs_VerifySignature
			(
				NContainer::CSecureByteVector const &_Message
				, NContainer::CSecureByteVector const &_KeyData
				, NContainer::CSecureByteVector const &_Signature
				, ESSLDigest _Digest = ESSLDigest_Automatic
			);
		static void fs_GenerateKeys
			(
				NContainer::CSecureByteVector &o_PrivateKeyData
				, NContainer::CSecureByteVector &o_PublicKeyData
				, NNetwork::CSSLKeySetting _KeySetting = CSSLKeySettings_EC_secp521r1{}
			)
		;

		static void fs_GetSystemCertificates(X509_STORE *_pCertificateStoreStore);

		class CInternal;
	protected:
		class CSession;
		NStorage::TCUniquePointer<CSession> fp_CreateSession();

		friend class CSSLConnectionResult;
		friend class CSSLConnection::CInternal;

		NStorage::TCUniquePointer<CInternal> mp_pInternal;

	};

	struct CEncryptKeyIV
	{
		CEncryptKeyIV
			(
				NContainer::CSecureByteVector const &_Key
				, NContainer::CSecureByteVector const &_IV
				, NNetwork::ESSLCrypto _Crypto = ESSLCrypto_AES_256_CBC
			)
		;

		static CEncryptKeyIV fs_GenerateKeyIV
			(
				NStr::CStrSecure const &_Password
				, NContainer::CSecureByteVector const &_Salt
				, CKeyDerivationSettings_PKCS5_Deprecated const &_Settings
				, NNetwork::ESSLCrypto _Crypto = ESSLCrypto_AES_256_CBC
			)
		;

		static uint32 fs_GetKeyLen(NNetwork::ESSLCrypto _Crypto);
		static uint32 fs_GetIVLen(NNetwork::ESSLCrypto _Crypto);
		static uint32 fs_GetHMACKeyLen(NNetwork::ESSLDigest _Digest);
		static uint32 fs_GetBlockSize(NNetwork::ESSLCrypto _Crypto);
		static NContainer::CSecureByteVector fs_GetRandomKey(NNetwork::ESSLCrypto _Crypto);
		static NContainer::CSecureByteVector fs_GetRandomIV(NNetwork::ESSLCrypto _Crypto);
		static NContainer::CSecureByteVector fs_GetRandomHMACKey(NNetwork::ESSLDigest _Digest);

		NContainer::CSecureByteVector const m_Key;
		NContainer::CSecureByteVector const m_IV;
		NNetwork::ESSLCrypto m_Crypto;
	};

	NContainer::CSecureByteVector fg_DeriveKey
		(
			NStr::CStrSecure const &_Password
			, NContainer::CSecureByteVector const &_PasswordSalt
			, CKeyDerivationSettings const &_Settings
			, mint _KeyLen
		)
	;

	struct CKeyExpansion
	{
		CKeyExpansion
			(
				NStr::CStrSecure const &_Password
				, NContainer::CSecureByteVector const &_PasswordSalt
				, CKeyDerivationSettings const &_Settings
				, NContainer::CSecureByteVector const &_ExpansionSalt
				, NNetwork::ESSLDigest _Digest = ESSLDigest_SHA512
			)
		;
		CKeyExpansion
			(
				NContainer::CSecureByteVector const &_Key
				, NContainer::CSecureByteVector const &_ExpansionSalt
				, NNetwork::ESSLDigest _Digest = ESSLDigest_SHA512
			)
		;
		~CKeyExpansion();

		CEncryptKeyIV f_GetKeyIV(NNetwork::ESSLCrypto _Crypto = ESSLCrypto_AES_256_CBC) const;
		NContainer::CSecureByteVector f_GetHMACKey(ESSLDigest _Digest = ESSLDigest_SHA512) const;

		NContainer::CSecureByteVector f_GetKey(NStr::CStr const &_Label, mint _Length) const;

	private:
		NNetwork::ESSLDigest mp_Digest = NNetwork::ESSLDigest_None;
		NContainer::CSecureByteVector mp_PseudoRandomKey;
	};

	class CEncryptAES
	{
	public:

		CEncryptAES(CEncryptKeyIV const &_KeyIV);
		~CEncryptAES();

		uint32 f_Encrypt(uint8 *_pSource, uint32 _SourceLen, uint8 *_pDest) const;
		uint32 f_Decrypt(uint8 *_pSource, uint32 _SourceLen, uint8 *_pDest) const;

	private:
		struct CInternal;
		NStorage::TCUniquePointer<CInternal> mp_pInternal;
	};

	// If all the data is available at once, use CEncryptAES. CIncrementalEncrypt does the same job but can operate on piecemeal data.
	//
	// When padding is used, feed the Encrypter all the data (while (!EndOfData) Encrypter.f_{De,En}crypt(Data);) and then call Encrypter.f_FinalizePadded{De,En}crypt
	// to get the final block from the Encrypter.
	class CIncrementalEncrypt
	{
	public:
		CIncrementalEncrypt(NNetwork::ESSLCryptoFlags _Flags, CEncryptKeyIV const &_KeyIV);
		~CIncrementalEncrypt();

		uint32 f_Encrypt(uint8 const *_pSource, uint32 _SourceLen, uint8 *_pDest);
		uint32 f_Decrypt(uint8 const *_pSource, uint32 _SourceLen, uint8 *_pDest);
		uint32 f_FinalizePaddedEncrypt(uint8 *_pDest, uint32 _DestLen);
		uint32 f_FinalizePaddedDecrypt(uint8 *_pDest, uint32 _DestLen);

	private:
		struct CInternal;
		NStorage::TCUniquePointer<CInternal> mp_pInternal;
	};

	class CIncrementalHMAC
	{
	public:
		CIncrementalHMAC(ESSLDigest _Digest, NContainer::CSecureByteVector const &_Key);
		~CIncrementalHMAC();

		void f_Update(uint8 const *_pSource, uint32 _SourceLen);
		uint32 f_Finalize(uint8 *_pDest, uint32 _DestLen);
		uint32 f_GetHMACSize() const;

	private:
		struct CInternal;
		NStorage::TCUniquePointer<CInternal> mp_pInternal;
	};

	NCryptography::CHashDigest_SHA256 fg_MessageAuthenication_HMAC_SHA256(uint8 const *_pData, mint _DataLen, uint8 const *_pKey, mint _KeyLen);
	NCryptography::CHashDigest_SHA1 fg_MessageAuthenication_HMAC_SHA1(uint8 const *_pData, mint _DataLen, uint8 const *_pKey, mint _KeyLen);
	NCryptography::CHashDigest_SHA256 fg_MessageAuthenication_HMAC_SHA256(NContainer::CSecureByteVector const &_Data, NContainer::CSecureByteVector const &_Key);
	NCryptography::CHashDigest_SHA1 fg_MessageAuthenication_HMAC_SHA1(NContainer::CSecureByteVector const &_Data, NContainer::CSecureByteVector const &_Key);
	NCryptography::CHashDigest_SHA256 fg_MessageAuthenication_HMAC_SHA256(NContainer::CByteVector const &_Data, NContainer::CSecureByteVector const &_Key);
	NCryptography::CHashDigest_SHA1 fg_MessageAuthenication_HMAC_SHA1(NContainer::CByteVector const &_Data, NContainer::CSecureByteVector const &_Key);
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
