// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include <Mib/Cryptography/Hashes/SHA>
#include "Malterlib_Network.h"
#include "Malterlib_Network_Exception.h"
#include <Mib/Memory/Allocators/Secure>

namespace NMib::NNetwork
{
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

		bool operator == (CSSLSettings const &_Other) const noexcept
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

		struct CResultCertificate
		{
			NContainer::CByteVector m_Data;
			NContainer::TCMap<int,int> m_Errors;

			bool operator == (CResultCertificate const &_Other) const noexcept
			{
				return m_Data == _Other.m_Data && m_Errors == _Other.m_Errors;
			}
		};

		bool operator == (CSSLConnectionResult const &_Other) const noexcept
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

		void f_LogError(umint _Depth, int _Error);
		void f_LogMiscError(EMiscError _Error);
		bool f_HasLoggedCertificateChain() const { return !mp_Certificates.f_IsEmpty(); }
		void f_LogCertificate(umint _Depth, NContainer::CByteVector const &_Certificate);

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

		NContainer::TCMap<umint, CResultCertificate> mp_Certificates;
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

		using FAuthenticationResultCallback = NFunction::TCFunction<void (EAuthenticationResult _Result, CSSLConnectionResult const &_ConnectionResult)>;
		using FUserTrustDecisionCallback = NFunction::TCFunction<void (CSSLConnectionResult const &_ConnectionResult)>;

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
		void *f_GetSocket() const;
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

		CSocketOperationResult f_Send(const void *_pData, umint _nLen);
		CSocketOperationResult f_Receive(void *_pData, umint _nLen);

		CSSLSettings::EVerificationFlag f_GetVerificationFlags() const;
		CSSLConnectionResult &f_GetConnectionResult() { return mp_Result; }
		CSSLConnectionResult const &f_GetConnectionResult() const { return mp_Result; }
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

		CSSLContext(EType _Type, CSSLSettings const &_Settings);
		~CSSLContext();

		bool f_IsValid() const;
		void f_ReportInvalidContext(CSSLConnectionResult &_ConnectionResult) const;

		bool f_IsClientContext() const;
		bool f_IsServerContext() const;

		CSSLSettings const &f_GetSettings() const;

		CSSLSettings::EVerificationFlag f_GetVerificationFlags() const;
		bool f_CanAskUserToTrustServers() const;

		class CInternal;

	protected:
		class CSession;
		NStorage::TCUniquePointer<CSession> fp_CreateSession();

		friend class CSSLConnectionResult;
		friend class CSSLConnection::CInternal;

		NStorage::TCUniquePointer<CInternal> mp_pInternal;
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
