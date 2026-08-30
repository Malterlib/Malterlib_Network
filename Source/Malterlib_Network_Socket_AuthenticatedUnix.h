// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include <Mib/Core/Core>
#include <Mib/Cryptography/Certificate>
#include "Malterlib_Network_Socket.h"
#include "Malterlib_Network.h"
#include "Malterlib_Network_SSL.h"
#include "Malterlib_Network_Socket_SSL.h"

namespace NMib::NNetwork
{
	// True when this machine can bind the authenticated unix handshake to the kernel-reported
	// peer process id. The transport must never run without that binding: unsupported machines
	// fail context construction and callers use the TLS wss transport instead
	bool fg_IsAuthenticatedUnixSupported();

	// Certificate configuration for CSocket_AuthenticatedUnix; reuses CSSLSettings so callers
	// can feed the same certificates, keys and flags they would give a TLS context. Only the
	// certificate and key data, m_CACertificateData and the AllowMissingPeerCertificate and
	// IgnoreVerificationFailures flags are honored; hostname verification, CRLs, pinning and
	// the remaining TLS policy flags are not implemented
	struct CAuthenticatedUnixContext
	{
		enum class EType
		{
			mc_Client
			, mc_Server
		};

		CAuthenticatedUnixContext(EType _Type, CSSLSettings const &_Settings, NCryptography::CCertificateVerifyOptions const &_VerifyOptions = {});

		bool f_IsClientContext() const;
		bool f_IsServerContext() const;

		CSSLSettings m_Settings;
		// Restricts the peer leaf to the key types and signature digests the caller's protocol
		// issues; the local certificate is checked against the same key types at construction so a
		// mismatch fails as a configuration error instead of failing every handshake. Empty leaves
		// the axis unrestricted
		NCryptography::CCertificateVerifyOptions m_VerifyOptions;
		NContainer::CSecureByteVector m_PrivateKeyDER; // Normalized for CPublicCrypto signing; empty for anonymous clients
		NContainer::TCVector<NContainer::CByteVector> m_LocalCertificateChain; // Leaf first followed by the CA certificate, matching what a TLS context sends
		EType m_Type;
	};

	// Mutually authenticates Unix-domain socket peers with certificate signatures over a nonce
	// exchange. The signed data includes the kernel-reported peer pids, binding each certificate
	// to the process the kernel identifies, and completion is mutual: a rejected endpoint never
	// reports a completed handshake. Application data is plaintext — confidentiality comes from
	// the kernel boundary. Listen, accept and handshake must happen in one process; handoff
	// topologies (pre-fork accept, socket inheritance) must use the TLS wss transport.
	// Connection info is reported as CSocketConnectionInfo_SSL so existing certificate-based
	// identity checks work unchanged
	struct CSocket_AuthenticatedUnix final : public ICSocket, public ICSocketCompletionIo
	{
		CSocket_AuthenticatedUnix(CSocket_AuthenticatedUnix const &) = delete;
		CSocket_AuthenticatedUnix &operator = (CSocket_AuthenticatedUnix const &) = delete;

		CSocket_AuthenticatedUnix(NStorage::TCSharedPointer<CAuthenticatedUnixContext> const &_pContext);
		virtual ~CSocket_AuthenticatedUnix() override;

		virtual bool f_IsValid() const override;
		virtual bool f_HandshakeDone() const override;
		virtual void f_Close() override;
		virtual void f_CloseAsync(NMib::NFunction::TCFunctionMovable<void ()> &&_fOnClosed) override;
		virtual void f_Shutdown() override;
		virtual void f_Connect
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
				, NMib::NNetwork::CNetAddress const &_BindAddress = NMib::NNetwork::CNetAddress()
			) override
		;
		virtual void f_AsyncConnect
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
				, NMib::NNetwork::CNetAddress const &_BindAddress = NMib::NNetwork::CNetAddress()
			) override
		;
		virtual void f_Listen
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
				, NMib::NNetwork::ENetFlag _Flags
			) override
		;
		virtual void f_ListenDatagram
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
				, NMib::NNetwork::ENetFlag _Flags
			) override
		;
		virtual NStorage::TCUniquePointer<ICSocket> f_Accept(NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange) override;
		virtual void f_InheritHandle(void *_pSocketHandle, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange) override;
		virtual void *f_GiveUpForInherit() override;
		virtual void *f_GetOSSocket() override;
		virtual void f_SetOnStateChange(NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange) override;
		virtual ENetTCPState f_GetState() override;
		virtual NStr::CStr f_GetCloseReason() override;
		virtual CSocketOperationResult f_Receive(void *_pData, umint _DataLen) override;
		virtual CSocketOperationResult f_Send(const void *_pData, umint _DataLen) override;
		virtual CSocketOperationResult f_SendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans) override;
		virtual umint f_SendDatagram(NMib::NNetwork::CNetAddress const &_Address, const void *_pData, umint _DataLen) override;
		virtual umint f_ReceiveDatagram(NMib::NNetwork::CNetAddress &_Address, void *_pData, umint _DataLen) override;
		virtual NMib::NNetwork::CNetAddress f_GetPeerAddress() const override;
		virtual uint32 f_GetListenPort() const override;
		virtual NStorage::TCUniquePointer<ICSocketConnectionInfo> f_GetConnectionInfo() const override;

		// Completion transfers are a pure pass-through once the handshake has completed: frame
		// reads during the handshake consume exactly their framed bytes, so no stream data is
		// buffered in this layer when it finishes
		virtual void f_SetTransferSizeHint(umint _nBytes) override;
		virtual void f_SetSendWindow(umint _nBytes, bool _bConfigured) override;
		virtual bool f_QueryPathBandwidthDelay(umint &o_nBytes, bool &o_bAppLimited) override;
		virtual ICSocketCompletionIo *f_GetCompletionIo() override;
		virtual NMib::NSys::ICIoLoop *f_GetOwningIoLoop() override;
		virtual bool f_SupportsCompletionReceive() const override;
		virtual umint f_GetReceiveBufferBytes() const override;
		virtual bool f_StartReceiveStream(NStorage::TCSharedPointer<NSys::CIoStreamBackpressure> _pBackpressure, NSys::FIoStreamSink &&_fSink) override;
		virtual void f_ResumeReceiveStream() override;
		virtual bool f_ResolveReceiveSegmentShared(NSys::CIoStreamSegment &_Segment, NContainer::CSharedByteVector &o_Data, NSys::CIoCompletion &o_Result) override;
		virtual bool f_ResolveReceiveSegment(NSys::CIoStreamSegment &_Segment, void *_pDestination, umint _nDestination, NSys::CIoCompletion &o_Result) override;
		virtual bool f_SubmitSendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans, NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased) override;

		static FVirtualSocketFactory fs_GetFactory(NStorage::TCSharedPointer<CAuthenticatedUnixContext> const &_pContext);

	private:
		enum class EState
		{
			mc_None
			, mc_Connect
			, mc_Handshake
			, mc_Listen
			, mc_Done
			, mc_ShutdownSocket
			, mc_Disconnected
		};

		enum class EHandshakeStage
		{
			mc_WaitHello
			, mc_WaitSignature
			, mc_WaitAccept // Peer signature verified and acceptance sent; the peer's acceptance completes the handshake
			, mc_Done
		};

		// State only needed while the handshake runs, behind a unique pointer so an established
		// connection carries none of it
		struct CHandshakeState
		{
			NContainer::CByteVector m_OutgoingHandshake;
			umint m_nOutgoingHandshakeSent = 0;
			umint m_nFrameLengthReceived = 0;
			NContainer::CByteVector m_IncomingFrame;
			umint m_nIncomingFrameReceived = 0;

			NContainer::CByteVector m_LocalHello;
			NContainer::CByteVector m_PeerHello;

			NSys::NNetwork::CProcessIdentity m_LocalIdentity; // getpid of this endpoint, signed into the local hello
			NSys::NNetwork::CProcessIdentity m_ExpectedPeerIdentity; // Kernel reported peer pid of this connection; the peer must claim exactly this

			EHandshakeStage m_Stage = EHandshakeStage::mc_WaitHello;
			uint8 m_FrameLength[4] = {};
			bool m_bProcessIdentityValid = false;
		};

		void fp_ResetConnectionState(); // Clears everything a previous connection attempt left behind before this object starts a new one
		bool fp_QueryProcessIdentity();
		void fp_StartHandshake();
		bool fp_HandleHandshake();
		void fp_HandleHandshakeDone();
		void fp_PumpHandshake();
		void fp_FlushOutgoing();
		bool fp_ReadFrame(NContainer::CByteVector &o_Payload);
		void fp_QueueFrame(NContainer::CByteVector const &_Payload);
		void fp_HandleHelloFrame(NContainer::CByteVector const &_Payload);
		void fp_HandleSignatureFrame(NContainer::CByteVector const &_Payload);
		void fp_HandleAcceptFrame(NContainer::CByteVector const &_Payload);
		void fp_AcceptPeer(); // Queues the acceptance and waits for the peer's; called once the peer's signature (or allowed anonymity) is verified
		NContainer::CSecureByteVector fp_BuildTranscript(bool _bServerRole) const;
		void fp_FailHandshake(NStr::CStr const &_Reason);
		NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> fp_SharedOnStateChange(uint32 _Generation);

		NAtomic::TCAtomic<uint32> mp_ExtraState;
		uint32 mp_ConnectionGeneration = 0; // Bumped under mp_fOnStateChangeLock (owner thread only) when the object is reused; poller callbacks read it under the lock and drop out when stale
		NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> mp_fOnStateChange;
		NThread::CMutual mp_fOnStateChangeLock;
		CSocket mp_Socket;
		umint mp_nTransferSizeHint = 0;
		NStorage::TCSharedPointer<CAuthenticatedUnixContext> mp_pContext;

		NStorage::TCUniquePointer<CHandshakeState> mp_pHandshake; // Present only while the handshake runs

		NContainer::TCVector<NContainer::CByteVector> mp_PeerCertificateChain;
		NStr::CStr mp_CloseReason;

		EState mp_State = EState::mc_None;
		bool mp_bHandshakePumpOnWrite = false; // Guarded by mp_fOnStateChangeLock: the poller-readable mirror of "handshake pending"; mp_State itself is only touched on the owner's thread
		NAtomic::TCAtomic<bool> mp_bTransportConnected; // Set once the underlying socket is connected (poller thread for async connect); the handshake must not start before that
		bool mp_bBrokenStateReported = false;
		bool mp_bSendShutdown = false; // f_Shutdown on an established connection half-closes: sends stop while reads keep draining until remote closure

		// Handshake bytes moved since the last f_Receive/f_Send result: handshake progress is
		// real network activity and must reach the caller's operation result, or inactivity
		// timeouts would disconnect a handshake that is advancing but not yet complete
		bool mp_bHandshakeSentNetwork = false;
		bool mp_bHandshakeReceivedNetwork = false;
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
