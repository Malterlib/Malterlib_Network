// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Network_Socket_AuthenticatedUnix.h"

#include <Mib/Cryptography/BoringSSL>
#include <Mib/Cryptography/Certificate>
#include <Mib/Cryptography/PublicCrypto>
#include <Mib/Cryptography/RandomData>
#include <Mib/Cryptography/Hashes/SHA>
#include <Mib/Stream/Streams/Vector>

namespace NMib::NNetwork
{
	using namespace NCryptography;

	namespace
	{
		// All integers use the framework default (little endian) binary stream. Every message is
		// a 4 byte length followed by the payload. Hello: magic(8) role(1) process-id(8)
		// nonce(32) certificate count(2), each certificate as length(4) + data. Signature: the
		// raw signature bytes over the transcript of both hellos, empty for an anonymous
		// client. Acceptance: a single marker byte, sent after verifying the peer and required
		// from the peer before completion — unsigned, since the pid binding at the hello stage
		// already excludes an intermediary
		using CStream = NStream::CBinaryStreamMemory<>;
		using CStreamReader = NStream::CBinaryStreamMemoryPtr<>;
		using CStreamAppender = NStream::CBinaryStreamMemoryRef<>;

		constexpr ch8 gc_pHandshakeMagic[8] = {'M', 'i', 'b', 'P', 'A', 'u', 't', '1'};
		constexpr ch8 gc_pTranscriptLabel[] = "MalterlibPlainAuthV1";
		constexpr umint gc_NonceSize = 32;
		constexpr umint gc_MaxHandshakeFrameSize = 256 * 1024;
		constexpr umint gc_MaxCertificateChainLength = 8; // Bounds pre-authentication allocations from untrusted hellos
		constexpr uint8 gc_RoleClient = 0;
		constexpr uint8 gc_RoleServer = 1;
		constexpr uint8 gc_AcceptMarker = 0x4B; // Payload of the acceptance message each side sends once it verified the peer

		NContainer::CSecureByteVector fg_NormalizePrivateKeyToDER(NContainer::CSecureByteVector const &_KeyData)
		{
			// Trust manager keys are stored as PEM while CPublicCrypto signing expects DER
			if (!_KeyData.f_IsEmpty() && _KeyData[0] == 0x30)
				return _KeyData;

			EVP_PKEY *pKey = NBoringSSL::fg_LoadPrivateKey(_KeyData);
			auto Cleanup = g_OnScopeExit / [&]
				{
					EVP_PKEY_free(pKey);
				}
			;

			return NBoringSSL::fg_ConvertPrivateKeyToDER(pKey);
		}
	}

	// Compile-time constant on POSIX (macOS and Linux via LOCAL_PEERPID / SO_PEERCRED); a
	// runtime version check on Windows (SIO_AF_UNIX_GETPEERPID)
	bool fg_IsAuthenticatedUnixSupported()
	{
#if defined(DPlatformFamily_macOS) || defined(DPlatformFamily_Linux)
		return true;
#elif defined(DPlatformFamily_Windows)
		return NMib::NSys::NNetwork::fg_HasUnixSocketPeerProcessIdentity();
#else
		return false;
#endif
	}

	bool CAuthenticatedUnixContext::f_IsClientContext() const
	{
		return m_Type == EType::mc_Client;
	}

	bool CAuthenticatedUnixContext::f_IsServerContext() const
	{
		return m_Type == EType::mc_Server;
	}

	CAuthenticatedUnixContext::CAuthenticatedUnixContext(EType _Type, CSSLSettings const &_Settings, NCryptography::CCertificateVerifyOptions const &_VerifyOptions)
		: m_Settings(_Settings)
		, m_VerifyOptions(_VerifyOptions)
		, m_Type(_Type)
	{
		if (!fg_IsAuthenticatedUnixSupported())
			DMibErrorNet("wsa requires kernel peer-process authentication (macOS/Linux/Windows); use the wss/TLS transport");

		bool bHasCertificate = !m_Settings.m_PublicCertificateData.f_IsEmpty();
		bool bHasKey = !m_Settings.m_PrivateKeyData.f_IsEmpty();

		if (bHasCertificate != bHasKey)
			DMibErrorNet("Certificate and private key must both be set or both be empty");

		// The OS trust store cannot identify a unix socket peer: this transport verifies no
		// hostname, so OS store trust alone would accept any process holding any publicly trusted
		// certificate of the matching role as the peer. Peer identity must come from a pinned CA
		// certificate (or an explicit insecure/anonymous opt-in), so the OS store fallback is
		// rejected here instead of silently running an identity-free verification
		if
		(
			(m_Settings.m_VerificationFlags & CSSLSettings::EVerificationFlag_UseOSStoreIfNoCASpecified) != 0
			&& m_Settings.m_CACertificateData.f_IsEmpty()
		)
		{
			DMibErrorNet("wsa peer verification cannot use the OS trust store (no hostname is verified); pin a CA certificate instead");
		}

		if (_Type == EType::mc_Server && !bHasKey)
			DMibErrorNet("Server context requires a certificate and private key");

		if (bHasKey)
			m_PrivateKeyDER = fg_NormalizePrivateKeyToDER(m_Settings.m_PrivateKeyData);

		if (bHasCertificate && bHasKey)
		{
			// A private key that does not pair with the certificate's public key can never complete
			// a handshake (every peer rejects the transcript signature), so the mismatch is a
			// configuration error rejected here instead of surfacing as repeated runtime connection
			// failures; the TLS context performs the same pairing check
			X509 *pCertificate = NBoringSSL::fg_LoadCertificate(m_Settings.m_PublicCertificateData);
			auto CleanupCertificate = g_OnScopeExit / [&]
				{
					X509_free(pCertificate);
				}
			;

			EVP_PKEY *pPrivateKey = NBoringSSL::fg_LoadPrivateKeyFromDER(m_PrivateKeyDER);
			auto CleanupPrivateKey = g_OnScopeExit / [&]
				{
					EVP_PKEY_free(pPrivateKey);
				}
			;

			ERR_clear_error();
			if (!X509_check_private_key(pCertificate, pPrivateKey))
				DMibErrorNet("Certificate public key does not match the private key");

			// The signing key must work through CPublicCrypto's streaming digest APIs, which
			// exclude Ed25519 (one-shot signing only) and key agreement algorithms
			int KeyType = EVP_PKEY_id(pPrivateKey);
			if (KeyType != EVP_PKEY_RSA && KeyType != EVP_PKEY_EC)
				DMibErrorNet("Certificate private key algorithm cannot sign the handshake (RSA or EC required)");

			// A local key outside the configured whitelist could never complete a handshake (every
			// peer running the same configuration rejects the leaf), so the mismatch is rejected up
			// front as a configuration error
			if (!m_VerifyOptions.m_AllowedLeafKeyTypes.f_IsEmpty() && !NBoringSSL::fg_KeyMatchesAllowedSetting(pPrivateKey, m_VerifyOptions.m_AllowedLeafKeyTypes))
				DMibErrorNet("Certificate private key type is not in the allowed key types");
		}

		if (bHasCertificate)
		{
			m_LocalCertificateChain.f_Insert(m_Settings.m_PublicCertificateData);

			if (!m_Settings.m_CACertificateData.f_IsEmpty() && m_Settings.m_CACertificateData != m_Settings.m_PublicCertificateData)
				m_LocalCertificateChain.f_Insert(m_Settings.m_CACertificateData);
		}
	}

	CSocket_AuthenticatedUnix::CSocket_AuthenticatedUnix(NStorage::TCSharedPointer<CAuthenticatedUnixContext> const &_pContext)
		: mp_pContext(_pContext)
	{
	}

	CSocket_AuthenticatedUnix::~CSocket_AuthenticatedUnix()
	{
	}

	bool CSocket_AuthenticatedUnix::f_IsValid() const
	{
		return mp_Socket.f_IsValid();
	}

	bool CSocket_AuthenticatedUnix::f_HandshakeDone() const
	{
		return mp_State == EState::mc_Done;
	}

	void CSocket_AuthenticatedUnix::f_Close()
	{
		return mp_Socket.f_Close();
	}

	void CSocket_AuthenticatedUnix::f_CloseAsync(NMib::NFunction::TCFunctionMovable<void ()> &&_fOnClosed)
	{
		mp_Socket.f_CloseAsync(fg_Move(_fOnClosed));
	}

	void CSocket_AuthenticatedUnix::f_Shutdown()
	{
		// On an established connection this is a half close: the underlying shutdown only closes
		// the write side, so sends stop while reads keep draining data the peer already sent until
		// it closes. A handshake still in progress cannot be half closed and moves to the terminal
		// shutdown state instead
		if (mp_State == EState::mc_Done)
			mp_bSendShutdown = true;
		else
			mp_State = EState::mc_ShutdownSocket;

		mp_Socket.f_Shutdown();
	}

	void CSocket_AuthenticatedUnix::fp_ResetConnectionState()
	{
		// A socket object can be reused for a new connection attempt; nothing from a previous attempt
		// may leak into the next handshake (the hello handler appends to the peer chain) or into the
		// status this object reports for the new connection. The state itself resets too: connect can
		// throw before assigning a new state, and a stale EState::mc_Done would then keep reporting a
		// completed handshake on a dead socket
		mp_State = EState::mc_None;
		mp_pHandshake.f_Clear();
		mp_PeerCertificateChain.f_Clear();
		mp_CloseReason.f_Clear();
		mp_ExtraState.f_Store(0);
		mp_bTransportConnected.f_Store(false);
		mp_bBrokenStateReported = false;
		mp_bSendShutdown = false;
		mp_bHandshakeSentNetwork = false;
		mp_bHandshakeReceivedNetwork = false;
	}

	// _Generation is the value the caller read when it bumped the generation for this attempt
	NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> CSocket_AuthenticatedUnix::fp_SharedOnStateChange(uint32 _Generation)
	{
		return [this, _Generation](ENetTCPState _StateAdded)
			{
				// The callback is optional and can also be cleared through f_SetOnStateChange at
				// any time, so it must be checked under the lock before invoking. The generation
				// check drops callbacks from a previous connection attempt of a reused object:
				// the generation is bumped under this same lock when a new attempt installs its
				// callback, so a stale callback cannot interleave with the new attempt
				DMibLock(mp_fOnStateChangeLock);
				if (mp_ConnectionGeneration != _Generation)
					return;

				// A writable edge while the handshake is pending must re-enter the handshake
				// pump even though the owner has no application data to send: events are edge
				// triggered, so a partially written handshake frame would otherwise never
				// finish flushing. Surfacing a read makes the owner call f_Receive, which
				// drives the pump on its calling thread
				if ((_StateAdded & ENetTCPState_Write) && mp_bHandshakePumpOnWrite)
				{
					mp_ExtraState.f_FetchOr(ENetTCPState_Read);
					_StateAdded |= ENetTCPState_Read;
				}

				if (mp_fOnStateChange)
					mp_fOnStateChange(_StateAdded);
			}
		;
	}

	void CSocket_AuthenticatedUnix::f_Connect
		(
			NMib::NNetwork::CNetAddress const &_Address
			, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
			, NMib::NNetwork::CNetAddress const &_BindAddress
		)
	{
		if (!mp_pContext->f_IsClientContext())
			DMibErrorNet("Authenticated unix context is not a client context when trying to connect");

		// A previous socket still registered with the poller reads mp_fOnStateChange from the poller
		// thread and could deliver its stale events to the new attempt, so it is closed before the
		// new callback is installed; the generation bump and the assignment happen under the lock
		// because an in-flight callback from the old socket can still be executing after the close
		// returns, and the bump makes it drop out before touching the new attempt
		mp_Socket.f_Close();
		uint32 Generation;
		{
			DMibLock(mp_fOnStateChangeLock);
			Generation = ++mp_ConnectionGeneration;
			mp_fOnStateChange = fg_Move(_fOnStateChange);
			mp_bHandshakePumpOnWrite = true;
		}
		fp_ResetConnectionState();
		mp_Socket.f_Connect(_Address, fp_SharedOnStateChange(Generation), _BindAddress);
		mp_bTransportConnected.f_Store(true);
		mp_State = EState::mc_Connect;
		fp_HandleHandshake();
	}

	void CSocket_AuthenticatedUnix::f_AsyncConnect
		(
			NMib::NNetwork::CNetAddress const &_Address
			, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
			, NMib::NNetwork::CNetAddress const &_BindAddress
		)
	{
		if (!mp_pContext->f_IsClientContext())
			DMibErrorNet("Authenticated unix context is not a client context when trying to connect");

		// See f_Connect: the previous socket is closed before the generation bump and the new
		// callback are installed under the lock, which makes an in-flight callback from the old
		// socket drop out before touching the new attempt
		mp_Socket.f_Close();
		uint32 Generation;
		{
			DMibLock(mp_fOnStateChangeLock);
			Generation = ++mp_ConnectionGeneration;
			mp_fOnStateChange = fg_Move(_fOnStateChange);
			mp_bHandshakePumpOnWrite = true;
		}
		fp_ResetConnectionState();
		mp_State = EState::mc_Connect;
		return mp_Socket.f_AsyncConnect
			(
				_Address
				, [this, Generation](ENetTCPState _StateAdded)
				{
					// The callback is optional and can also be cleared through f_SetOnStateChange
					// at any time, so it must be checked under the lock before invoking. The
					// generation check drops callbacks from a previous attempt of a reused
					// object: a stale connected event would otherwise mark the new attempt's
					// transport connected before it is, and its handshake would query the peer
					// identity of an unconnected socket and fail permanently
					DMibLock(mp_fOnStateChangeLock);
					if (mp_ConnectionGeneration != Generation)
						return;

					if (_StateAdded & ENetTCPState_Connected)
					{
						// The handshake must not start before the connect completed: the owner
						// can pump earlier and the peer identity of an unconnected socket cannot
						// be queried, which would permanently fail an otherwise valid attempt.
						// The surfaced read kickstarts the owner into f_Receive, which drives
						// the handshake on its calling thread
						mp_bTransportConnected.f_Store(true);
						mp_ExtraState.f_FetchOr(ENetTCPState_Read);
						_StateAdded |= ENetTCPState_Read;
					}

					// See fp_SharedOnStateChange: a writable edge during the handshake must
					// re-enter the pump or a partially written frame would never finish flushing
					if ((_StateAdded & ENetTCPState_Write) && mp_bHandshakePumpOnWrite)
					{
						mp_ExtraState.f_FetchOr(ENetTCPState_Read);
						_StateAdded |= ENetTCPState_Read;
					}

					if (mp_fOnStateChange)
						mp_fOnStateChange(_StateAdded);
				}
				, _BindAddress
			)
		;
	}

	void CSocket_AuthenticatedUnix::f_Listen
		(
			NMib::NNetwork::CNetAddress const &_Address
			, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
			, NMib::NNetwork::ENetFlag _Flags
		)
	{
		if (!mp_pContext->f_IsServerContext())
			DMibErrorNet("Authenticated unix context is not a server context when trying to listen");

		// See f_Connect: the previous socket is closed before the generation bump and the new
		// callback are installed under the lock, which makes an in-flight callback from the old
		// socket drop out before touching the new attempt. The reset also matches the other entry
		// points, so a reused object does not report a previous connection's close reason, pending
		// states or peer certificate chain for the new listener
		mp_Socket.f_Close();
		uint32 Generation;
		{
			DMibLock(mp_fOnStateChangeLock);
			Generation = ++mp_ConnectionGeneration;
			mp_fOnStateChange = fg_Move(_fOnStateChange);
			mp_bHandshakePumpOnWrite = false;
		}
		fp_ResetConnectionState();
		mp_State = EState::mc_Listen;
		return mp_Socket.f_Listen(_Address, fp_SharedOnStateChange(Generation), _Flags);
	}

	void CSocket_AuthenticatedUnix::f_ListenDatagram
		(
			NMib::NNetwork::CNetAddress const &_Address
			, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
			, NMib::NNetwork::ENetFlag _Flags
		)
	{
		DMibErrorNet("Datagrams not supported");
	}

	NStorage::TCUniquePointer<ICSocket> CSocket_AuthenticatedUnix::f_Accept(NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		NStorage::TCUniquePointer<CSocket_AuthenticatedUnix> pSocket = fg_Construct(mp_pContext);
		// Pre-registration: the fresh socket has no poller callbacks yet, so no lock is needed
		pSocket->mp_fOnStateChange = fg_Move(_fOnStateChange);
		pSocket->mp_bHandshakePumpOnWrite = true;
		pSocket->mp_Socket.f_Accept(&mp_Socket, pSocket->fp_SharedOnStateChange(pSocket->mp_ConnectionGeneration));
		if (!pSocket->mp_Socket.f_IsValid())
			return nullptr;
		pSocket->mp_bTransportConnected.f_Store(true);
		pSocket->mp_State = EState::mc_Handshake;
		pSocket->fp_StartHandshake();
		pSocket->fp_HandleHandshake();
		return fg_Move(pSocket);
	}

	void CSocket_AuthenticatedUnix::f_InheritHandle(void *_pSocketHandle, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		// See f_Connect: the previous socket is closed before the generation bump and the new
		// callback are installed under the lock, which makes an in-flight callback from the old
		// socket drop out before touching the new attempt
		mp_Socket.f_Close();
		uint32 Generation;
		{
			DMibLock(mp_fOnStateChangeLock);
			Generation = ++mp_ConnectionGeneration;
			mp_fOnStateChange = fg_Move(_fOnStateChange);
			mp_bHandshakePumpOnWrite = true;
		}
		fp_ResetConnectionState();
		mp_Socket.f_InheritHandle2(_pSocketHandle, fp_SharedOnStateChange(Generation));
		if (!mp_Socket.f_IsValid())
			return;

		mp_bTransportConnected.f_Store(true);
		mp_State = EState::mc_Handshake;
		fp_StartHandshake();
		fp_HandleHandshake();
	}

	void *CSocket_AuthenticatedUnix::f_GiveUpForInherit()
	{
		DMibErrorNet("Not implemented");
		return nullptr;
	}

	void *CSocket_AuthenticatedUnix::f_GetOSSocket()
	{
		return mp_Socket.f_GetOSSocket();
	}

	void CSocket_AuthenticatedUnix::f_SetOnStateChange(NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		{
			DMibLock(mp_fOnStateChangeLock);
			mp_fOnStateChange = fg_Move(_fOnStateChange);
		}
	}

	ENetTCPState CSocket_AuthenticatedUnix::f_GetState()
	{
		return mp_Socket.f_GetState() | (ENetTCPState)mp_ExtraState.f_Exchange(0);
	}

	NStr::CStr CSocket_AuthenticatedUnix::f_GetCloseReason()
	{
		if (!mp_CloseReason.f_IsEmpty())
			return mp_CloseReason;

		return mp_Socket.f_GetCloseReason();
	}

	CSocketOperationResult CSocket_AuthenticatedUnix::f_Receive(void *_pData, umint _DataLen)
	{
		bool bHandshakeDone = fp_HandleHandshake();

		// Report handshake bytes as network activity even though no payload was produced, so the
		// caller's inactivity accounting sees a progressing handshake
		CSocketOperationResult Result;
		Result.m_bSentNetwork = mp_bHandshakeSentNetwork;
		Result.m_bReceivedNetwork = mp_bHandshakeReceivedNetwork;
		mp_bHandshakeSentNetwork = false;
		mp_bHandshakeReceivedNetwork = false;

		if (!bHandshakeDone)
			return Result;

		// End of stream is reported through the close event instead
		bool bEndOfStream = false;

		Result.m_nBytes = mp_Socket.f_Receive(_pData, _DataLen, bEndOfStream);
		if (Result.m_nBytes != 0)
			Result.m_bReceivedNetwork = true;

		return Result;
	}

	CSocketOperationResult CSocket_AuthenticatedUnix::f_Send(const void *_pData, umint _DataLen)
	{
		if (mp_State == EState::mc_ShutdownSocket || mp_bSendShutdown)
			return {};

		bool bHandshakeDone = fp_HandleHandshake();

		// Report handshake bytes as network activity even though no payload was consumed, so the
		// caller's inactivity accounting sees a progressing handshake
		CSocketOperationResult Result;
		Result.m_bSentNetwork = mp_bHandshakeSentNetwork;
		Result.m_bReceivedNetwork = mp_bHandshakeReceivedNetwork;
		mp_bHandshakeSentNetwork = false;
		mp_bHandshakeReceivedNetwork = false;

		if (!bHandshakeDone || !_DataLen)
			return Result;

		umint nBytes = mp_Socket.f_Send(_pData, _DataLen);
		Result.m_nBytes = nBytes;
		if (nBytes != 0)
			Result.m_bSentNetwork = true;

		return Result;
	}

	CSocketOperationResult CSocket_AuthenticatedUnix::f_SendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans)
	{
		if (mp_State == EState::mc_ShutdownSocket || mp_bSendShutdown)
			return {};

		bool bHandshakeDone = fp_HandleHandshake();

		// Report handshake bytes as network activity even though no payload was consumed, so the
		// caller's inactivity accounting sees a progressing handshake
		CSocketOperationResult Result;
		Result.m_bSentNetwork = mp_bHandshakeSentNetwork;
		Result.m_bReceivedNetwork = mp_bHandshakeReceivedNetwork;
		mp_bHandshakeSentNetwork = false;
		mp_bHandshakeReceivedNetwork = false;

		if (!bHandshakeDone || !_nSpans)
			return Result;

		umint nBytes = mp_Socket.f_SendVectored(_pSpans, _nSpans);
		Result.m_nBytes = nBytes;
		if (nBytes != 0)
			Result.m_bSentNetwork = true;

		return Result;
	}

	ICSocketCompletionIo *CSocket_AuthenticatedUnix::f_GetCompletionIo()
	{
		if (mp_State != EState::mc_Done)
			return nullptr;

		return mp_Socket.f_SupportsCompletionIo() ? this : nullptr;
	}

	NMib::NSys::ICIoLoop *CSocket_AuthenticatedUnix::f_GetOwningIoLoop()
	{
		return mp_Socket.f_GetOwningIoLoop();
	}

	void CSocket_AuthenticatedUnix::f_SetTransferSizeHint(umint _nBytes)
	{
		mp_nTransferSizeHint = _nBytes;
	}

	void CSocket_AuthenticatedUnix::f_SetSendWindow(umint _nBytes, bool _bConfigured)
	{
		mp_Socket.f_SetSendWindow(_nBytes, _bConfigured);
	}

	bool CSocket_AuthenticatedUnix::f_SupportsCompletionReceive() const
	{
		return mp_Socket.f_SupportsReceiveStream();
	}

	umint CSocket_AuthenticatedUnix::f_GetReceiveBufferBytes() const
	{
		return fg_Max(mp_nTransferSizeHint, umint(4096));
	}

	bool CSocket_AuthenticatedUnix::f_StartReceiveStream(NStorage::TCSharedPointer<NSys::CIoStreamBackpressure> _pBackpressure, NSys::FIoStreamSink &&_fSink)
	{
		if (mp_State != EState::mc_Done || !mp_Socket.f_SupportsReceiveStream())
			return false;

		return mp_Socket.f_StartReceiveStream(fg_Max(mp_nTransferSizeHint, umint(4096)), fg_Move(_pBackpressure), fg_Move(_fSink));
	}

	void CSocket_AuthenticatedUnix::f_ResumeReceiveStream()
	{
		mp_Socket.f_ResumeReceiveStream();
	}

	// The segments are the payload as delivered: the caller gets a shared view of the buffer the
	// kernel filled, riding its owner, and nothing is copied on the way
	bool CSocket_AuthenticatedUnix::f_ResolveReceiveSegmentShared(NSys::CIoStreamSegment &_Segment, NContainer::CSharedByteVector &o_Data, NSys::CIoCompletion &o_Result)
	{
		if (_Segment.m_Status != NSys::EIoCompletionStatus::mc_Done || !_Segment.m_nBytes)
			return false;

		o_Result.m_Status = NSys::EIoCompletionStatus::mc_Done;
		o_Result.m_nBytes = _Segment.m_nBytes;
		o_Data = NContainer::CSharedByteVector(_Segment.m_pData, _Segment.m_nBytes, fg_Move(_Segment.m_pOwner));

		return true;
	}

	// Only terminals reach this — data goes through the shared resolve — and a terminal has
	// nothing to deliver beyond its status
	bool CSocket_AuthenticatedUnix::f_ResolveReceiveSegment(NSys::CIoStreamSegment &_Segment, void *_pDestination, umint _nDestination, NSys::CIoCompletion &o_Result)
	{
		(void)_pDestination;
		(void)_nDestination;

		o_Result.m_Status = _Segment.m_Status;
		o_Result.m_Error = _Segment.m_Error;
		o_Result.m_nBytes = 0;

		return true;
	}

	bool CSocket_AuthenticatedUnix::f_SubmitSendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans, NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased)
	{
		if (mp_State != EState::mc_Done || mp_bSendShutdown)
			return false;

		return mp_Socket.f_SubmitSendVectored
			(
				_pSpans
				, _nSpans
				, fg_Move(_fOnComplete)
				,
				[fOnReleased = fg_Move(_fOnReleased)]() mutable
				{
					fOnReleased(NMib::NSys::CIoCompletion::mc_iTransferNone);
				}
			)
		;
	}

	umint CSocket_AuthenticatedUnix::f_SendDatagram(NMib::NNetwork::CNetAddress const &_Address, const void *_pData, umint _DataLen)
	{
		DMibErrorNet("Datagrams not supported");
		return 0;
	}

	umint CSocket_AuthenticatedUnix::f_ReceiveDatagram(NMib::NNetwork::CNetAddress &_Address, void *_pData, umint _DataLen)
	{
		DMibErrorNet("Datagrams not supported");
		return 0;
	}

	NMib::NNetwork::CNetAddress CSocket_AuthenticatedUnix::f_GetPeerAddress() const
	{
		return mp_Socket.f_GetPeerAddress();
	}

	uint32 CSocket_AuthenticatedUnix::f_GetListenPort() const
	{
		return mp_Socket.f_GetListenPort();
	}

	NStorage::TCUniquePointer<ICSocketConnectionInfo> CSocket_AuthenticatedUnix::f_GetConnectionInfo() const
	{
		NStorage::TCUniquePointer<CSocketConnectionInfo_SSL> pReturn = fg_Construct();

		if (!mp_PeerCertificateChain.f_IsEmpty())
			pReturn->m_PeerCertificate = mp_PeerCertificateChain[0];
		pReturn->m_CertificateChain = mp_PeerCertificateChain;

		return fg_Move(pReturn);
	}

	FVirtualSocketFactory CSocket_AuthenticatedUnix::fs_GetFactory(NStorage::TCSharedPointer<CAuthenticatedUnixContext> const &_pContext)
	{
		return [=](NStr::CStr const &_Hostname) -> NStorage::TCUniquePointer<ICSocket>
			{
				return fg_Construct<CSocket_AuthenticatedUnix>(_pContext);
			}
		;
	}

	bool CSocket_AuthenticatedUnix::fp_QueryProcessIdentity()
	{
		auto &Handshake = *mp_pHandshake;

		// Bind the handshake to the kernel-authenticated process identities of this connection. A
		// failure here is fatal: the certificate-only handshake must never run without the binding
		if (!mp_Socket.f_GetProcessIdentity(Handshake.m_LocalIdentity, Handshake.m_ExpectedPeerIdentity))
			return false;

		// The local process always knows its own pid; the peer needs either a pid usable in this
		// namespace or an exact pidfs identity (a cross-namespace peer on a pidfs kernel)
		Handshake.m_bProcessIdentityValid =
			Handshake.m_LocalIdentity.m_ProcessID != 0
			&& (Handshake.m_ExpectedPeerIdentity.m_ProcessID != 0 || Handshake.m_ExpectedPeerIdentity.m_PidFSInode != 0)
		;

		return Handshake.m_bProcessIdentityValid;
	}

	void CSocket_AuthenticatedUnix::fp_StartHandshake()
	{
		mp_pHandshake = fg_Construct();

		if (!fp_QueryProcessIdentity())
			return fp_FailHandshake("Could not obtain kernel peer process identity");

		auto &Handshake = *mp_pHandshake;
		auto &CertificateChain = mp_pContext->m_LocalCertificateChain;

		// The certificate count is written as a uint16 and the peer caps it, so a longer local chain
		// could not be sent without overflowing the field. This never happens with the leaf + CA the
		// context builds, but reject it rather than silently truncate the count.
		if (CertificateChain.f_GetLen() > gc_MaxCertificateChainLength)
			return fp_FailHandshake("Local certificate chain too long");

		uint8 Nonce[gc_NonceSize];
		fg_GenerateRandomData(Nonce, gc_NonceSize);

		CStream Hello;
		Hello.f_FeedBytes(gc_pHandshakeMagic, sizeof(gc_pHandshakeMagic));
		Hello << uint8(mp_pContext->f_IsClientContext() ? gc_RoleClient : gc_RoleServer);
		Hello << Handshake.m_LocalIdentity.m_ProcessID;
		Hello << Handshake.m_LocalIdentity.m_PidFSDevice;
		Hello << Handshake.m_LocalIdentity.m_PidFSInode;
		Hello.f_FeedBytes(Nonce, gc_NonceSize);
		Hello << uint16(CertificateChain.f_GetLen());

		for (auto &Certificate : CertificateChain)
		{
			// The length is written as a uint32 and the peer rejects any frame past this bound, so a
			// larger certificate could neither be represented nor accepted
			if (Certificate.f_GetLen() > gc_MaxHandshakeFrameSize)
				return fp_FailHandshake("Local certificate too large");

			Hello << uint32(Certificate.f_GetLen());
			Hello.f_FeedBytes(Certificate.f_GetArray(), Certificate.f_GetLen());
		}

		Handshake.m_LocalHello = Hello.f_MoveVector();

		fp_QueueFrame(Handshake.m_LocalHello);
	}

	void CSocket_AuthenticatedUnix::fp_QueueFrame(NContainer::CByteVector const &_Payload)
	{
		// The frame length is written as a uint32 and the peer rejects anything past this bound, so
		// there is no point building a frame we could not represent or that would be refused
		if (_Payload.f_GetLen() > gc_MaxHandshakeFrameSize)
			return fp_FailHandshake("Handshake message too large");

		// Write the length prefix and payload straight onto the end of the outgoing buffer
		CStreamAppender Outgoing(mp_pHandshake->m_OutgoingHandshake);
		Outgoing.f_SetPositionFromEnd(0);
		Outgoing << uint32(_Payload.f_GetLen());
		if (!_Payload.f_IsEmpty())
			Outgoing.f_FeedBytes(_Payload.f_GetArray(), _Payload.f_GetLen());
	}

	void CSocket_AuthenticatedUnix::fp_FlushOutgoing()
	{
		if (mp_State != EState::mc_Handshake)
			return;

		auto &Handshake = *mp_pHandshake;

		while (Handshake.m_nOutgoingHandshakeSent < Handshake.m_OutgoingHandshake.f_GetLen())
		{
			umint nSent = mp_Socket.f_Send
				(
					Handshake.m_OutgoingHandshake.f_GetArray() + Handshake.m_nOutgoingHandshakeSent
					, Handshake.m_OutgoingHandshake.f_GetLen() - Handshake.m_nOutgoingHandshakeSent
				)
			;
			if (!nSent)
				break;

			mp_bHandshakeSentNetwork = true;
			Handshake.m_nOutgoingHandshakeSent += nSent;
		}
	}

	bool CSocket_AuthenticatedUnix::fp_ReadFrame(NContainer::CByteVector &o_Payload)
	{
		auto &Handshake = *mp_pHandshake;

		// A peer closing mid handshake surfaces through the close event, so end of stream is
		// treated the same as no data here
		bool bEndOfStream = false;

		while (Handshake.m_nFrameLengthReceived < sizeof(Handshake.m_FrameLength))
		{
			umint nRead = mp_Socket.f_Receive(Handshake.m_FrameLength + Handshake.m_nFrameLengthReceived, sizeof(Handshake.m_FrameLength) - Handshake.m_nFrameLengthReceived, bEndOfStream);
			if (!nRead)
				return false;

			mp_bHandshakeReceivedNetwork = true;
			Handshake.m_nFrameLengthReceived += nRead;
		}

		CStreamReader LengthReader;
		LengthReader.f_OpenRead(Handshake.m_FrameLength, sizeof(Handshake.m_FrameLength));
		uint32 Length = 0;
		LengthReader >> Length;

		if (Length > gc_MaxHandshakeFrameSize)
		{
			fp_FailHandshake("Handshake message too large");
			return false;
		}

		Handshake.m_IncomingFrame.f_SetLen(Length);

		while (Handshake.m_nIncomingFrameReceived < Length)
		{
			umint nRead = mp_Socket.f_Receive(Handshake.m_IncomingFrame.f_GetArray() + Handshake.m_nIncomingFrameReceived, Length - Handshake.m_nIncomingFrameReceived, bEndOfStream);
			if (!nRead)
				return false;

			mp_bHandshakeReceivedNetwork = true;
			Handshake.m_nIncomingFrameReceived += nRead;
		}

		o_Payload = fg_Move(Handshake.m_IncomingFrame);
		Handshake.m_IncomingFrame.f_Clear();
		Handshake.m_nFrameLengthReceived = 0;
		Handshake.m_nIncomingFrameReceived = 0;

		return true;
	}

	NContainer::CSecureByteVector CSocket_AuthenticatedUnix::fp_BuildTranscript(bool _bServerRole) const
	{
		auto &Handshake = *mp_pHandshake;
		NContainer::CByteVector const &ClientHello = mp_pContext->f_IsClientContext() ? Handshake.m_LocalHello : Handshake.m_PeerHello;
		NContainer::CByteVector const &ServerHello = mp_pContext->f_IsClientContext() ? Handshake.m_PeerHello : Handshake.m_LocalHello;

		// SHA-512 so the transcript hash keeps 256 bit collision resistance and does not become the
		// weak link below the certificate keys (the trust manager defaults to EC secp521r1)
		auto ClientDigest = CHash_SHA512::fs_DigestFromData(ClientHello);
		auto ServerDigest = CHash_SHA512::fs_DigestFromData(ServerHello);

		NContainer::CSecureByteVector Message;
		Message.f_InsertLast((uint8 const *)gc_pTranscriptLabel, sizeof(gc_pTranscriptLabel) - 1);
		Message.f_InsertLast(_bServerRole ? gc_RoleServer : gc_RoleClient);
		Message.f_InsertLast(ClientDigest.f_GetData(), CHashDigest_SHA512::mc_Size);
		Message.f_InsertLast(ServerDigest.f_GetData(), CHashDigest_SHA512::mc_Size);

		return Message;
	}

	void CSocket_AuthenticatedUnix::fp_HandleHelloFrame(NContainer::CByteVector const &_Payload)
	{
		auto &Handshake = *mp_pHandshake;

		// The identities were captured at handshake start; without them the binding cannot hold
		if (!Handshake.m_bProcessIdentityValid)
			return fp_FailHandshake("Missing kernel peer process identity");

		CStreamReader Reader;
		Reader.f_OpenRead(_Payload.f_GetArray(), _Payload.f_GetLen());

		auto fRemaining = [&]() -> umint
			{
				return umint(Reader.f_GetLength() - Reader.f_GetPosition());
			}
		;

		// Reject a truncated hello explicitly so malformed input never has to rely on the stream
		// throwing; the fixed header fields below are then guaranteed present
		umint HeaderSize = sizeof(gc_pHandshakeMagic) + sizeof(uint8) + 3 * sizeof(uint64) + gc_NonceSize + sizeof(uint16);
		if (_Payload.f_GetLen() < HeaderSize)
			return fp_FailHandshake("Invalid handshake hello");

		uint8 Magic[sizeof(gc_pHandshakeMagic)];
		Reader.f_ConsumeBytes(Magic, sizeof(Magic));
		if (NMemory::fg_MemCmp(Magic, (uint8 const *)gc_pHandshakeMagic, sizeof(Magic)) != 0)
			return fp_FailHandshake("Invalid handshake magic");

		uint8 PeerRole = 0;
		Reader >> PeerRole;
		uint8 ExpectedPeerRole = mp_pContext->f_IsClientContext() ? gc_RoleServer : gc_RoleClient;
		if (PeerRole != ExpectedPeerRole)
			return fp_FailHandshake("Invalid handshake role");

		// The peer must claim exactly the process identity the kernel reports for this connection.
		// This check is mandatory and no certificate verification flag can disable it: a relay (a
		// different process on the socket) reports its own identity and cannot hold the claimed
		// value. On pidfs kernels (Linux 6.9) the identity is the peer pidfd's boot-unique inode,
		// which names the exact kernel process object, so cross-namespace peers are supported and
		// pid-number recycling cannot line up a stale match. Without pidfs the binding is the
		// numeric pid, which f_GetProcessIdentity only reports after confirming the peer shares
		// this pid namespace on kernels that can introspect it; on kernels too old for that the
		// numeric binding stands alone and a deliberately constructed cross-namespace relay is an
		// accepted residual risk
		uint64 ClaimedPeerProcessID = 0;
		Reader >> ClaimedPeerProcessID;

		uint64 ClaimedPeerPidFSDevice = 0;
		Reader >> ClaimedPeerPidFSDevice;

		uint64 ClaimedPeerPidFSInode = 0;
		Reader >> ClaimedPeerPidFSInode;

		if (ClaimedPeerProcessID == 0)
			return fp_FailHandshake("Invalid handshake process id");

		if (Handshake.m_ExpectedPeerIdentity.m_PidFSInode != 0)
		{
			// Pid numbers from different namespaces are not comparable, so the exact pidfs identity
			// replaces the numeric pid comparison here rather than augmenting it
			if
			(
				ClaimedPeerPidFSDevice != Handshake.m_ExpectedPeerIdentity.m_PidFSDevice
				|| ClaimedPeerPidFSInode != Handshake.m_ExpectedPeerIdentity.m_PidFSInode
			)
			{
				return fp_FailHandshake("Handshake process identity does not match kernel peer process identity");
			}
		}
		else if (ClaimedPeerProcessID != Handshake.m_ExpectedPeerIdentity.m_ProcessID)
			return fp_FailHandshake("Handshake process id does not match kernel peer process id");

		uint8 Nonce[gc_NonceSize];
		Reader.f_ConsumeBytes(Nonce, sizeof(Nonce));

		uint16 nCertificates = 0;
		Reader >> nCertificates;

		if (nCertificates > gc_MaxCertificateChainLength)
			return fp_FailHandshake("Too many certificates in handshake");

		for (umint i = 0; i < nCertificates; ++i)
		{
			if (fRemaining() < sizeof(uint32))
				return fp_FailHandshake("Invalid handshake certificate chain");

			uint32 CertificateLength = 0;
			Reader >> CertificateLength;

			if (!CertificateLength || CertificateLength > fRemaining())
				return fp_FailHandshake("Invalid handshake certificate chain");

			NContainer::CByteVector Certificate;
			Certificate.f_SetLen(CertificateLength);
			Reader.f_ConsumeBytes(Certificate.f_GetArray(), CertificateLength);

			mp_PeerCertificateChain.f_Insert(fg_Move(Certificate));
		}

		if (!Reader.f_IsAtEndOfStream())
			return fp_FailHandshake("Trailing data in handshake hello");

		Handshake.m_PeerHello = _Payload;

		NContainer::CByteVector SignaturePayload;
		if (!mp_pContext->m_PrivateKeyDER.f_IsEmpty())
		{
			auto Transcript = fp_BuildTranscript(mp_pContext->f_IsServerContext());
			auto Signature = CPublicCrypto::fs_SignMessage(Transcript, mp_pContext->m_PrivateKeyDER);
			SignaturePayload.f_InsertLast(Signature.f_GetArray(), Signature.f_GetLen());
		}

		fp_QueueFrame(SignaturePayload);
		Handshake.m_Stage = EHandshakeStage::mc_WaitSignature;
	}

	void CSocket_AuthenticatedUnix::fp_HandleSignatureFrame(NContainer::CByteVector const &_Payload)
	{
		auto &Settings = mp_pContext->m_Settings;
		bool bIgnoreVerification = (Settings.m_VerificationFlags & CSSLSettings::EVerificationFlag_IgnoreVerificationFailures) != 0;

		// An anonymous hello is unsigned, so its claimed pid carries no relay binding — only the
		// server side loses relay proof of the client identity; server authentication stays
		// mandatory. Require a client certificate where the server must know it is talking
		// directly to a specific client process
		if (mp_PeerCertificateChain.f_IsEmpty())
		{
			if (!mp_pContext->f_IsServerContext() || !(Settings.m_VerificationFlags & CSSLSettings::EVerificationFlag_AllowMissingPeerCertificate))
				return fp_FailHandshake("Missing peer certificate");

			if (!_Payload.f_IsEmpty())
				return fp_FailHandshake("Unexpected signature from anonymous peer");

			fp_AcceptPeer();
			return;
		}

		if (_Payload.f_IsEmpty())
			return fp_FailHandshake("Missing handshake signature");

		NStr::CStr ChainError;

		// Enforce the peer's role the same way a TLS stack would: a client authenticates a server
		// certificate, a server authenticates a client certificate, so a role-scoped certificate cannot
		// be presented in the opposite direction. The system store is never consulted: the context
		// constructor rejects the OS store fallback because there is no hostname to bind OS trust to
		auto RequiredPurpose = mp_pContext->f_IsClientContext() ? EVerificationPurpose_ServerAuth : EVerificationPurpose_ClientAuth;
		NContainer::TCVector<NContainer::CByteVector> VerifiedChain;
		if (!CCertificate::fs_VerifyCertificateChain(mp_PeerCertificateChain, Settings.m_CACertificateData, false, RequiredPurpose, mp_pContext->m_VerifyOptions, &VerifiedChain, ChainError))
		{
			if (!bIgnoreVerification)
				return fp_FailHandshake(NStr::fg_Format("Peer certificate verification failed: {}", ChainError));
		}
		else
		{
			// Report the path verification actually built, matching the TLS socket which logs the
			// constructed chain; the wire list could carry extra unrelated certificates or omit a
			// store-supplied path, and connection info must not present those as authenticated
			mp_PeerCertificateChain = fg_Move(VerifiedChain);
		}

		// The signature is always required so the peer proves possession of the certificate key,
		// even when chain verification failures are ignored
		auto PublicKey = CCertificate::fs_GetCertificatePublicKey(mp_PeerCertificateChain[0]);
		auto Transcript = fp_BuildTranscript(mp_pContext->f_IsClientContext());
		NContainer::CSecureByteVector Signature;
		Signature.f_InsertLast(_Payload.f_GetArray(), _Payload.f_GetLen());

		if (!CPublicCrypto::fs_VerifySignature(Transcript, PublicKey, Signature))
			return fp_FailHandshake("Invalid handshake signature");

		fp_AcceptPeer();
	}

	void CSocket_AuthenticatedUnix::fp_AcceptPeer()
	{
		// Confirm the verified peer and wait for its confirmation before reporting completion:
		// without the mutual acceptance an endpoint whose certificate the peer rejects would
		// report a successful handshake on a connection the peer is about to close
		NContainer::CByteVector Accept;
		Accept.f_InsertLast(gc_AcceptMarker);
		fp_QueueFrame(Accept);

		mp_pHandshake->m_Stage = EHandshakeStage::mc_WaitAccept;
	}

	void CSocket_AuthenticatedUnix::fp_HandleAcceptFrame(NContainer::CByteVector const &_Payload)
	{
		if (_Payload.f_GetLen() != 1 || _Payload[0] != gc_AcceptMarker)
			return fp_FailHandshake("Invalid handshake acceptance");

		mp_pHandshake->m_Stage = EHandshakeStage::mc_Done;
	}

	void CSocket_AuthenticatedUnix::fp_PumpHandshake()
	{
		try
		{
			NException::CDisableExceptionTraceScope DisableTrace;

			fp_FlushOutgoing();

			NContainer::CByteVector Payload;
			while (mp_State == EState::mc_Handshake && mp_pHandshake->m_Stage != EHandshakeStage::mc_Done && fp_ReadFrame(Payload))
			{
				if (mp_pHandshake->m_Stage == EHandshakeStage::mc_WaitHello)
					fp_HandleHelloFrame(Payload);
				else if (mp_pHandshake->m_Stage == EHandshakeStage::mc_WaitSignature)
					fp_HandleSignatureFrame(Payload);
				else
					fp_HandleAcceptFrame(Payload);
			}

			fp_FlushOutgoing();
		}
		catch (NException::CException const &_Exception)
		{
			fp_FailHandshake(NStr::fg_Format("Handshake failed: {}", _Exception.f_GetErrorStr()));
		}
	}

	void CSocket_AuthenticatedUnix::fp_FailHandshake(NStr::CStr const &_Reason)
	{
		if (mp_State == EState::mc_Disconnected)
			return;

		mp_CloseReason = _Reason;
		mp_State = EState::mc_Disconnected;
		mp_Socket.f_Shutdown();

		bool bReport = !mp_bBrokenStateReported;
		mp_bBrokenStateReported = true;
		if (bReport)
			mp_ExtraState.f_FetchOr(ENetTCPState_Closed);

		{
			DMibLock(mp_fOnStateChangeLock);
			mp_bHandshakePumpOnWrite = false;
			if (bReport && mp_fOnStateChange)
				mp_fOnStateChange(ENetTCPState_Closed);
		}
	}

	void CSocket_AuthenticatedUnix::fp_HandleHandshakeDone()
	{
		mp_State = EState::mc_Done;

		// Drop all handshake-only state; the peer certificate chain stays on the socket for
		// f_GetConnectionInfo
		mp_pHandshake.f_Clear();

		// Allow the user the chance to send or receive any deferred data
		mp_ExtraState.f_FetchOr(ENetTCPState_Read | ENetTCPState_Write);

		{
			DMibLock(mp_fOnStateChangeLock);
			mp_bHandshakePumpOnWrite = false;
			if (mp_fOnStateChange)
				mp_fOnStateChange(ENetTCPState_Read | ENetTCPState_Write);
		}
	}

	bool CSocket_AuthenticatedUnix::fp_HandleHandshake()
	{
		switch (mp_State)
		{
		case EState::mc_ShutdownSocket:
		case EState::mc_Disconnected:
			mp_pHandshake.f_Clear();
			return false;
		case EState::mc_Done:
			return true;
		case EState::mc_None:
		case EState::mc_Listen:
			return false;
		case EState::mc_Connect:
			// An async connect may not have completed yet: the owner can pump before the connected
			// notification arrives, and starting the handshake then would query the peer identity
			// of an unconnected socket and permanently fail an otherwise valid attempt
			if (!mp_bTransportConnected.f_Load())
				return false;

			mp_State = EState::mc_Handshake;
			fp_StartHandshake();

			break;
		case EState::mc_Handshake:
			break;
		}

		fp_PumpHandshake();

		// A failed handshake left a terminal state; release the transient buffers with it
		if (mp_State != EState::mc_Handshake)
		{
			mp_pHandshake.f_Clear();
			return false;
		}

		auto &Handshake = *mp_pHandshake;
		if (Handshake.m_Stage == EHandshakeStage::mc_Done && Handshake.m_nOutgoingHandshakeSent == Handshake.m_OutgoingHandshake.f_GetLen())
		{
			fp_HandleHandshakeDone();
			return true;
		}

		return false;
	}

}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
