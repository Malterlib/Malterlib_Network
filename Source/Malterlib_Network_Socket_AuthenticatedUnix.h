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
	bool fg_IsAuthenticatedUnixSupported();

	// Uses certificate/key data, explicit CA, AllowMissingPeerCertificate and IgnoreVerificationFailures from CSSLSettings.
	// Other TLS policy, including hostname checks, CRLs and pinning settings, is unsupported.
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
		NCryptography::CCertificateVerifyOptions m_VerifyOptions; // Empty axes are unrestricted; local keys must also satisfy the key whitelist.
		NContainer::CSecureByteVector m_PrivateKeyDER; // Normalized for CPublicCrypto signing; empty for anonymous clients
		NContainer::TCVector<NContainer::CByteVector> m_LocalCertificateChain; // Leaf first followed by the CA certificate, matching what a TLS context sends
		EType m_Type;
	};

	// Certificate-signed nonces bind to kernel process identity; payload remains plaintext within the kernel confidentiality boundary.
	// Listen, accept and handshake must share a process; inherited or pre-fork listeners require TLS.
	// Completion requires mutual acceptance; connection info uses CSocketConnectionInfo_SSL.
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
		virtual void f_SetAbortOnClose() override;
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

		virtual void f_SetTransferSizeHint(umint _nBytes) override;
		virtual void f_SetSendWindow(umint _nBytes, bool _bConfigured) override;
		virtual void f_SetInheritable() override;
		virtual void f_AdoptSocket(CSocket &&_Socket, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange) override;
		virtual bool f_QueryPathDeliveryRate(umint &o_nBytes, bool &o_bAppLimited) override;
		virtual ICSocketCompletionIo *f_GetCompletionIo() override;
		virtual NMib::NSys::ICIoLoop *f_GetOwningIoLoop() override;
		virtual bool f_SupportsCompletionReceive() const override;
		virtual umint f_GetReceiveBufferBytes() const override;
		virtual bool f_StartReceiveStream(NStorage::TCSharedPointer<NSys::CIoStreamBackpressure> _pBackpressure, NSys::FIoStreamSink &&_fSink) override;
		virtual void f_ResumeReceiveStream() override;
		virtual bool f_ResolveReceiveSegmentShared(NSys::CIoStreamSegment &_Segment, NContainer::CSharedByteVector &o_Data, NSys::CIoCompletion &o_Result) override;
		virtual bool f_ResolveReceiveSegment(NSys::CIoStreamSegment &_Segment, void *_pDestination, umint _nDestination, NSys::CIoCompletion &o_Result) override;
		virtual umint f_SubmitSendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans, NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased) override;

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

		struct CHandshakeState
		{
			NContainer::CByteVector m_OutgoingHandshake;
			umint m_nOutgoingHandshakeSent = 0;
			umint m_nFrameLengthReceived = 0;
			NContainer::CByteVector m_IncomingFrame;
			umint m_nIncomingFrameReceived = 0;

			NContainer::CByteVector m_LocalHello;
			NContainer::CByteVector m_PeerHello;

			NSys::NNetwork::CProcessIdentity m_LocalIdentity; // Local kernel identity signed into the hello.
			NSys::NNetwork::CProcessIdentity m_ExpectedPeerIdentity; // The peer must claim this kernel-reported identity.

			EHandshakeStage m_Stage = EHandshakeStage::mc_WaitHello;
			uint8 m_FrameLength[4] = {};
			bool m_bProcessIdentityValid = false;
		};

		void fp_ResetConnectionState();
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
		void fp_AcceptPeer();
		NContainer::CSecureByteVector fp_BuildTranscript(bool _bServerRole) const;
		void fp_FailHandshake(NStr::CStr const &_Reason);
		NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> fp_SharedOnStateChange(uint32 _Generation);

		NAtomic::TCAtomic<uint32> mp_ExtraState;

		uint32 mp_ConnectionGeneration = 0; // Owner increments under callback lock on reuse; poller callbacks reject stale generations under that lock.
		NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> mp_fOnStateChange;
		NThread::CMutual mp_fOnStateChangeLock;
		CSocket mp_Socket;
		umint mp_nTransferSizeHint = 0;
		NStorage::TCSharedPointer<CAuthenticatedUnixContext> mp_pContext;

		NStorage::TCUniquePointer<CHandshakeState> mp_pHandshake; // Present only while the handshake runs

		NContainer::TCVector<NContainer::CByteVector> mp_PeerCertificateChain;
		NStr::CStr mp_CloseReason;

		EState mp_State = EState::mc_None;
		bool mp_bHandshakePumpOnWrite = false; // Callback-lock-protected handshake mirror; mp_State belongs to the owner thread.
		NAtomic::TCAtomic<bool> mp_bTransportConnected; // Handshake may start only after transport connection is reported.
		bool mp_bBrokenStateReported = false;
		bool mp_bSendShutdown = false; // f_Shutdown on an established connection half-closes: sends stop while reads keep draining until remote closure

		bool mp_bHandshakeSentNetwork = false; // Handshake traffic must reset inactivity accounting before application payload is available.
		bool mp_bHandshakeReceivedNetwork = false;
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
