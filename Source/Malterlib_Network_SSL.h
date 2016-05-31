
#pragma once

#include <Mib/Cryptography/Hashes/SHA>
#include "Malterlib_Network_Exception.h"
#include <Mib/Memory/Allocators/Secure>

namespace NMib
{
	namespace NNet
	{
		DMibImpErrorClass(CExceptionNetSSL, CExceptionNet);
#		define DMibErrorNetSSL(_Description) DMibImpError(NMib::NNet::CExceptionNetSSL, _Description)

#		ifndef DMibPNoShortCuts
#			define DErrorNetSSL(_Description) DMibErrorNetSSL(_Description)
#		endif
		
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

			NContainer::TCVector<uint8> m_PublicCertificateData;
			NContainer::TCVector<uint8, NMem::CAllocator_HeapSecure> m_PrivateKeyData;
			NContainer::TCVector<uint8> m_CRLData;
			NContainer::TCVector<uint8> m_CACertificateData;

			NStr::CStr m_CAStoreLocation;
			NStr::CStr m_PathToCRLs;

			EVerificationFlag m_VerificationFlags = EVerificationFlag_None;
			int m_VerificationDepth = 9;

			NContainer::TCVector<NContainer::TCVector<uint8>> m_LocalCertificateStore;
			
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
				NContainer::TCVector<uint8> m_Data;
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

			NContainer::TCVector<uint8> f_GetPeerCertificate() const;
			NContainer::TCVector<NContainer::TCVector<uint8>> f_GetCertificateChain() const;

			CSSLConnectionResult() : mp_bTrustErrorsOccured(false), mp_bVerificationErrorsOccured(false), mp_bConnectionRefused(false) {}
			~CSSLConnectionResult() {}

			void f_LogError(int _Depth, int _Error);
			void f_LogMiscError(EMiscError _Error);
			bool f_HasLoggedCertificateChain() const { return !mp_Certificates.f_IsEmpty(); }
			void f_LogCertificate(int _Depth, NContainer::TCVector<uint8> const &_Certificate);

			NStr::CStr f_GetPeerCertificateName() const;
			NStr::CStr f_GetPeerCertificateDescription() const;
			NStr::CStr f_GetPeerCertificateInformation() const;
			NStr::CStr f_GetPeerCertificateFingerprint() const;

			bool f_ContainsTrustErrors() const;
			bool f_ContainsVerificationErrors() const;
			bool f_ConnectionRefused() const;
			bool f_ContainsInvalidContextErrors() const;
			void f_SetConnectionRefused();
			bool f_PeerCertificatesMatchesSpecificCertificate(NContainer::TCVector<uint8> const &_SpecificCertificate) const;
			bool f_PeerCertificateMatchesRememberedCertificates(NContainer::TCVector<NContainer::TCVector<uint8>> const &_LocalStore) const;
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

			NContainer::TCMap<int,CCertificate> mp_Certificates;
			NContainer::TCMap<EMiscError,int> mp_MiscErrors;
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

			CSSLConnection(NPtr::TCSharedPointer<CSSLContext> const &_pContext, FAuthenticationResultCallback &&_AuthenticationResultCallback, FUserTrustDecisionCallback &&_UserTrustDecisionCallback);
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

			mint f_Send(const void *_pData, mint _nLen);
			mint f_Receive(void *_pData, mint _nLen);

			bool f_Decrypt(const void *_pDataIn, void *_pDataOut, int _Len);

			CSSLSettings::EVerificationFlag f_GetVerificationFlags() const;
			CSSLConnectionResult& f_GetConnectionResult() { return mp_Result; }
			CSSLConnectionResult const& f_GetConnectionResult() const { return mp_Result; }
			NDataProcessing::CHashDigest_SHA256 f_GetSessionKey() const;

		protected:
			NPtr::TCUniquePointer<CInternal> mp_pInternal;
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

			struct CCertificateExtension
			{
				NStr::CStr m_Value;
				bool m_bCritical = false;
				
				bool operator == (CCertificateExtension const &_Right) const; 
				bool operator < (CCertificateExtension const &_Right) const;
				
				template <typename tf_CFormatInto>
				void f_Format(tf_CFormatInto &o_FormatInto) const
				{
					o_FormatInto += typename tf_CFormatInto::CFormat("{}{}") << m_Value << (m_bCritical ? " - critical" : "");
				}
			};
			
			struct CCertificateOptions
			{
				NStr::CStr m_Subject;
				NContainer::TCVector<NStr::CStr> m_Hostnames;
				NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> m_Extensions;
				uint32 m_KeyLength = 2048;
			};
			
			CSSLContext(EType _Type, CSSLSettings const &_Settings);
			~CSSLContext();

			bool f_IsValid() const;
			void f_ReportInvalidContext(CSSLConnectionResult &_ConnectionResult) const;

			int f_GetExDataIndex() const;
			bool f_IsClientContext() const;
			bool f_IsServerContext() const;

			CSSLSettings const& f_GetSettings() const;

			CSSLSettings::EVerificationFlag f_GetVerificationFlags() const;
			bool f_CanAskUserToTrustServers() const;

			static NStr::CStr fs_GetCertificateName(NContainer::TCVector<uint8> const &_CertificateData);
			static NStr::CStr fs_GetIssuerName(NContainer::TCVector<uint8> const &_CertificateData);
			static NStr::CStr fs_GetCertificateFingerprint(NContainer::TCVector<uint8> const &_CertificateData);
			static NContainer::TCVector<NStr::CStr> fs_GetCertificateHostnames(NContainer::TCVector<uint8> const &_CertificateData, bool _bCheckCommonName = true);
			static NContainer::TCVector<NStr::CStr> fs_GetSortedHostnames(NContainer::TCVector<NStr::CStr> const &_Unsorted);
			static NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> fs_GetCertificateExtensions(NContainer::TCVector<uint8> const &_CertificateData);
			static NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> fs_GetCertificateRequestExtensions(NContainer::TCVector<uint8> const &_CertificateData);
			
			static NStr::CStr fs_GetCertificateHostnamesStr(NContainer::TCVector<uint8> const &_CertificateData);
			static NTime::CTime fs_GetCertificateExpirationTime(NContainer::TCVector<uint8> const &_CertificateData);
			static NStr::CStr fs_GetCertificateDescription(NContainer::TCVector<uint8> const &_CertificateData);
			static NStr::CStr fs_GetCertificateInformation(NContainer::TCVector<uint8> const &_CertificateData);

			static void fs_RegisterExtension(NStr::CStr const &_OID, NStr::CStr const &_ShortName, NStr::CStr const &_LongName);

			static void fs_GenerateSelfSignedCertAndKey
				(
					CCertificateOptions const &_Options
					, NContainer::TCVector<uint8> &o_CertData
					, NContainer::TCVector<uint8, NMem::CAllocator_HeapSecure> &o_KeyData
					, int _Serial = 0
					, int _Days = 365
				)
			;
			static void fs_GenerateClientCertificateRequest
				(
					CCertificateOptions const &_Options
					, NContainer::TCVector<uint8> &o_CertRequestData
					, NContainer::TCVector<uint8, NMem::CAllocator_HeapSecure> &o_KeyData
				)
			;
			static void fs_SignClientCertificate
				(
					NContainer::TCVector<uint8> const &_CACertificate
					, NContainer::TCVector<uint8, NMem::CAllocator_HeapSecure> const &_CAKey
					, NContainer::TCVector<uint8> const &_CertRequestData
					, NContainer::TCVector<uint8> &o_SignedCertificateData
					, int _Serial = 0
					, int _Days = 365
				)
			;
			static void fs_VerifyCertificateRequestSameKeyAsCertificate(NContainer::TCVector<uint8> const &_CertRequestData, NContainer::TCVector<uint8> const &_CertData);

		protected:
			class CSession;
			NPtr::TCUniquePointer<CSession> fp_CreateSession();

			friend class CSSLConnectionResult;
			friend class CSSLConnection::CInternal;
			class CInternal;

			NPtr::TCUniquePointer<CInternal> mp_pInternal;

		};
		
		class CEncryptAES
		{
		public:
			
			struct CSalt
			{
				uint8 m_Salt[8];
			};
			
			CEncryptAES(NStr::CStrSecure const &_Password, CSalt const *_pSalt);
			~CEncryptAES();
			
			uint32 f_Encrypt(uint8 *_pSource, uint32 _SourceLen, uint8 *_pDest) const;
			uint32 f_Decrypt(uint8 *_pSource, uint32 _SourceLen, uint8 *_pDest) const;
		
		private:
			struct CInternal;
			NPtr::TCUniquePointer<CInternal> mp_pInternal;
		};
	}
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNet;
#endif
