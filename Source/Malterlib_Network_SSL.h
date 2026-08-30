// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include <Mib/Cryptography/Hashes/SHA>
#include "Malterlib_Network.h"
#include "Malterlib_Network_Exception.h"
#include <Mib/Memory/Allocators/Secure>

// TLS configuration defaults. In builds carrying the io debugging overrides each knob is
// overridable at runtime: MalterlibSSLCompletionIoSend / MalterlibSSLCompletionIoReceive
// (MalterlibSSLCompletionIo sets both), MalterlibSSLZeroCopy and MalterlibSSLSendBatching.

// Submitted transfers for TLS, per direction: the ciphertext is this connection's own, so it
// can be handed to the kernel and left alone until the completion says it has been read
#ifndef DMibConfig_SSLCompletionIoSend
	#define DMibConfig_SSLCompletionIoSend 1
#endif

#ifndef DMibConfig_SSLCompletionIoReceive
	#define DMibConfig_SSLCompletionIoReceive 1
#endif

// Seals application records straight into the transport's buffer instead of letting the library
// copy them out through the BIO, and gathers the caller's spans into each record rather than
// staging them together first
#ifndef DMibConfig_SSLZeroCopy
	#define DMibConfig_SSLZeroCopy 1
#endif

// Whether a run of sends holds the records it produces in the transport and hands the whole
// gather to the socket as one write, instead of each record leaving as it is made. Pays off
// whenever a gather spans several records; costs a staging copy where it holds only one
#ifndef DMibConfig_SSLSendBatching
	#define DMibConfig_SSLSendBatching 1
#endif

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

		// Scope that holds the records a run of sends produces in the transport, so a queue
		// of messages leaves as one write instead of one per record
		struct CSendBatch
		{
			CSendBatch(CSSLConnection &_Connection);
			~CSendBatch();

			CSendBatch(CSendBatch const &) = delete;
			CSendBatch &operator = (CSendBatch const &) = delete;

		protected:
			CSSLConnection &mp_Connection;
		};

		// One whole TLS record with its framing. A destination smaller than this can never hold
		// the record body the plaintext is paired against, so it is served the other way
		static constexpr umint mc_nMaxRecordSize = 17 * 1024;

		CSSLConnection
			(
				NStorage::TCSharedPointer<CSSLContext> const &_pContext
				, FAuthenticationResultCallback &&_AuthenticationResultCallback
				, FUserTrustDecisionCallback &&_UserTrustDecisionCallback
				, NStr::CStr const &_Hostname
			)
		;
		~CSSLConnection();

		// The transport the connection reads and writes through. It stays the caller's to own and
		// must outlive the connection; a socket that is closed under it stops the connection rather
		// than being reached through
		void f_GiveSocket(CSocket *_pSocket);
		bool f_HasSocket() const;

		// Hands the transport what a stalled send left behind, for the write readiness the socket
		// layer reports afterwards. Records the library has produced are the transport's to deliver,
		// and outside a transfer call nothing else would offer them again
		CSocketOperationResult f_FlushPending();

		// Holds the records a run of sends produces in the transport, so a queue of messages leaves
		// as one write instead of one per record. Open it around sends only, and close it with
		// f_FlushPending: the library considers a record delivered once it has handed it over and
		// will never offer it again, so held records are owed by whoever held them
		void f_SetSendBatching(bool _bBatching);

		// What one transfer is worth to the consumer, which sizes the ciphertext buffering
		void f_SetTransferSizeHint(umint _nBytes);

		// Seals the spans into the transport buffer without copying the plaintext. Returns false
		// when the library will not take that path, leaving the caller to fall back
		bool f_TrySealVectored(NSys::CIoSpan const *_pSpans, umint _nSpans, CSocketOperationResult &o_Result);

		// Opens records into the caller's buffer without copying the plaintext. Returns false when
		// the library will not take that path, leaving the caller to fall back
		bool f_TryOpenInto(void *_pData, umint _nLen, CSocketOperationResult &o_Result);

		// Completion transfers: the ciphertext is this connection's, so it can be handed to the
		// kernel and left alone until the completion says it has been read
		bool f_SupportsZeroCopy() const;
		umint f_GetSendDepth() const;
		void f_SetSendDepth(umint _nDepth);
		// The bytes a socket that releases its sends late lets the connection keep pinned; grows the ring of generations to hold them
		void f_SetSendWindow(umint _nBytes);
		umint f_GetSendGenerations() const;
		bool f_SupportsCompletionIoSend() const;
		bool f_SupportsCompletionIoReceive() const;
		bool f_BeginSend(void const *&o_pData, umint &o_nBytes, umint &o_iBuffer);
		// Whether a submitted send holds part of the outbound buffer
		bool f_IsSendPinned() const;
		// Whether a send operation could be begun right now; false while everything is blocked
		// behind buffer-released notifications
		bool f_CanBeginSend() const;
		smint f_NextBeginSend() const;
		umint f_GetPendingSend() const;
		umint f_GetPendingSendUnpinned() const;
		// Once submitted operations drive the send direction they are its only writer: the
		// transport never flushes synchronously on its own from then on
		void f_SetCompletionSend(bool _bCompletionSend);
		// In completion mode inbound ciphertext arrives as a stream of segments; the standing
		// kernel receive is then the connection's only reader and the synchronous fill refuses
		void f_SetCompletionReceive(bool _bCompletionReceive);
		umint f_GetInboundBufferSize() const;
		// End the connection over something the caller cannot retry, in whichever direction it
		// happened, so the state the close path reports says what actually went wrong
		void f_FailSend(NStr::CStr _Error);
		void f_FailReceive(NStr::CStr _Error);
		// The memory an outstanding transfer refers to, which has to outlive this connection
		// because the socket can be torn down before the completion runs
		NStorage::TCSharedPointer<NContainer::CByteVector> f_GetPinnedKeepAlive(umint _iBuffer) const;
		// True when the buffer's staged ciphertext has fully left with this completion — the
		// moment the transfers whose seals it carries are done
		bool f_SendCompleted(umint _iBuffer, umint _nBytes);
		// The generation new seals land in, which names the operation a transfer resolves with
		umint f_GetFillBuffer() const;
		// The operation's buffer-released notification: the kernel no longer references the
		// buffer and it may be filled again
		void f_ReleaseSendBuffer(umint _iBuffer);
		// One piece of the receive stream, appended in arrival order with the reference that
		// keeps it alive; dropping the piece when it is consumed is all the retiring there is
		void f_AppendCipherSegment(void const *_pData, umint _nBytes, NStorage::TCSharedPointer<CVirtualDestroyBase const> &&_pOwner);
		// Drops every piece still queued, for a connection being torn down
		void f_ClearCipherQueue();
		// Copies stream-buffer pieces into owned storage when an incomplete record traps them:
		// their window charges release, so a parked stream can deliver the completing bytes
		void f_CompactCipherIfStalled();

		// Give a buffer back untouched, for an operation the transport below would not accept;
		// what f_BeginSend hands out belongs to an operation until released
		void f_AbortSend(umint _iBuffer);
		bool f_OpenHeld(void *_pData, umint _nLen, CSocketOperationResult &o_Result);

		bool f_IsSendBufferFull() const;

		void f_SetHostname(NStr::CStr const &_Hostname);
		NStr::CStr f_GetHostname() const;
		void f_SetExpectedConnectionResult(CSSLConnectionResult const &_ExpectedResult);

		NStr::CStr f_GetLastError() const;
		bool f_BrokenState() const;
		bool f_ReceivedShutdown() const;
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
