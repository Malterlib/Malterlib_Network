// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include <Mib/Core/Core>
#include "Malterlib_Network_Socket.h"
#include "Malterlib_Network.h"
#include "Malterlib_Network_SSL.h"

namespace NMib::NNetwork
{
	struct CSocketConnectionInfo_SSL final : public ICSocketConnectionInfo
	{
		NContainer::CByteVector m_PeerCertificate;
		NContainer::TCVector<NContainer::CByteVector> m_CertificateChain;
	};

	class CSocket_SSL final : public ICSocket, public ICSocketCompletionIo
	{
		CSocket_SSL(CSocket_SSL const &) = delete;
		CSocket_SSL &operator = (CSocket_SSL const &) = delete;

	public:
		CSocket_SSL
			(
				NStorage::TCSharedPointer<CSSLContext> const &_pContext
				, CSSLConnection::FAuthenticationResultCallback const &_AuthenticationResultCallback
				, CSSLConnection::FUserTrustDecisionCallback const &_UserTrustDecisionCallback
				, NStr::CStr const &_Hostname
			)
		;
		virtual ~CSocket_SSL() override;

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
		virtual void f_SetTransferSizeHint(umint _nBytes) override;
		virtual void f_SetSendWindow(umint _nBytes, bool _bConfigured) override;
		virtual void f_SetInheritable() override;
		virtual void f_AdoptSocket(CSocket &&_Socket, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange) override;
		virtual bool f_QueryPathDeliveryRate(umint &o_nBytes, bool &o_bAppLimited) override;
		virtual NMib::NSys::ICIoLoop *f_GetOwningIoLoop() override;
		virtual ICSocketCompletionIo *f_GetCompletionIo() override;

		virtual umint f_SubmitSendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans, NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased) override;
		virtual bool f_ContinueSend(NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased) override;
		virtual bool f_StartReceiveStream(NStorage::TCSharedPointer<NSys::CIoStreamBackpressure> _pBackpressure, NSys::FIoStreamSink &&_fSink) override;
		virtual void f_ResumeReceiveStream() override;
		virtual bool f_ResolveReceiveSegment(NSys::CIoStreamSegment &_Segment, void *_pDestination, umint _nDestination, NSys::CIoCompletion &o_Result) override;
		virtual bool f_ResolveHeld(void *_pDestination, umint _nDestination, NSys::CIoCompletion &o_Result) override;
		virtual bool f_ResolveSend(NMib::NSys::CIoCompletion &_Result) override;
		virtual void f_ResolveSendRelease(umint _iTransfer) override;
		virtual void f_OnCompletionActivated() override;
		virtual umint f_GetSendDepth() const override;
		virtual bool f_SupportsCompletionSend() const override;
		virtual bool f_CanSubmitSend() const override;
		virtual bool f_IsSendWindowFull(umint _nUnreleasedBytes, umint _nStartBytes) override;
		virtual bool f_SupportsSendStaging() const override;
		virtual bool f_HasSendOperationInFlight() const override;
		virtual bool f_ReceiveStreamEndedByProtocol() const override;
		virtual bool f_SupportsCompletionReceive() const override;
		virtual umint f_GetReceiveBufferBytes() const override;
		virtual bool f_HasPendingOutput() const override;

	public:
		virtual umint f_SendDatagram(NMib::NNetwork::CNetAddress const &_Address, const void *_pData, umint _DataLen) override;
		virtual umint f_ReceiveDatagram(NMib::NNetwork::CNetAddress &_Address, void *_pData, umint _DataLen) override;
		virtual NMib::NNetwork::CNetAddress f_GetPeerAddress() const override;
		virtual uint32 f_GetListenPort() const override;
		virtual NStorage::TCUniquePointer<ICSocketConnectionInfo> f_GetConnectionInfo() const override;

		static FVirtualSocketFactory fs_GetFactory
			(
				NStorage::TCSharedPointer<CSSLContext> const &_pContext
				, CSSLConnection::FAuthenticationResultCallback const &_AuthenticationResultCallback = fg_Default()
				, CSSLConnection::FUserTrustDecisionCallback const &_UserTrustDecisionCallback = fg_Default()
			)
		;

	private:
		enum EState
		{
			EState_None
			, EState_Connect
			, EState_Connected
			, EState_Accept
			, EState_Listen
			, EState_Done
			, EState_Shutdown
			, EState_ShutdownSocket
			, EState_Disconnected
		};

		// Caller transfer bound to its ciphertext generation. Staged transfers retain callbacks;
		// the carrier transfer uses the kernel operation's callback pair.
		struct CSendOperation
		{
			NSys::FIoCompletion m_fOnComplete;
			FSocketSendReleased m_fOnReleased;
			umint m_nPlaintext = 0;
			uint32 m_iBuffer = 0; // Generation whose ciphertext carries this transfer.
			int32 m_iNextForBuffer = -1;
			int32 m_iNextFree = -1;
			bool m_bHasFunctors : 1 = false;
			bool m_bInUse : 1 = false;
			bool m_bResolved : 1 = false;
			bool m_bReleased : 1 = false;
			bool m_bLinked : 1 = false;
		};

		bool fp_HandleHandshake();
		void fp_HandleHandshakeDone();
		void fp_CheckBrokenState();
		void fp_AddTCPState(ENetTCPState _ToAdd);
		NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> fp_SharedOnStateChange();

		auto fp_AllocateSendOperation() -> smint;
		void fp_TryFreeSendOperation(umint _iOperation);
		void fp_LinkSendOperation(umint _iOperation);
		void fp_ContinueShutdown();
		void fp_FreeSendOperation(umint _iOperation);
		bool fp_SubmitPinnedSend(void const *_pData, umint _nBytes, umint _iBuffer, NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased);
		void fp_ParkSendOperation(umint _iOperation, NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased);
		bool fp_CarrySend(smint _iOperation, NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased);
		void fp_ResolveOpsForBuffer(umint _iBuffer, NMib::NSys::CIoCompletion const &_Result, umint &o_nCarrierPlaintext);
		void fp_ReleaseOpsForBuffer(umint _iBuffer, umint _iTransfer);
		void fp_FailAllSendOperations();

		static constexpr umint mcp_nMaxRecordBytes = 16 * 1024; // Maximum plaintext per TLS record.
		NContainer::TCVector<CSendOperation> mp_SendOperations; // Indexed pool with per-generation and newest-first free lists; grows to observed window demand.
		NContainer::TCVector<int32> mp_iBufferOperationHead;
		umint mp_nSendWindowBytes = 0;
		NContainer::CByteVector mp_SendStaging;
		NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> mp_fOnStateChange;
		NThread::CMutual mp_fOnStateChangeLock;
		CSocket mp_Socket;
		NMib::NSys::CIoSubSystem *mp_pIo = &NMib::NSys::fg_IoSubSystem();

		NStorage::TCSharedPointer<CSSLContext> mp_pSSLContext;
		CSSLConnection::FAuthenticationResultCallback mp_AuthenticationResultCallback;
		CSSLConnection::FUserTrustDecisionCallback mp_UserTrustDecisionCallback;

		CSSLConnection mp_SSLConnection;

		umint mp_nSendPlaintextHeld = 0; // Carrier plaintext accumulated until the continuation chain reports once.
		umint mp_nSendOpsInFlight = 0; // Kernel sends retained in submission order.

		NAtomic::TCAtomic<uint32> mp_ExtraState;
		EState mp_State = EState_None;
		int32 mp_iFreeOperationHead = -1;

		bool mp_bSendFailed = false; // First failure ends the connection; later completions only settle records.
		bool mp_bCompletionActive = false; // Disable synchronous I/O only in directions using submitted operations.
		bool mp_bBrokenStateReported = false;
		bool mp_bSendWindowWasFull = false; // Resolve records fullness that release-driven submission asks cannot observe.
		bool mp_bSendWindowPending = false; // Apply after the final generation unpins.
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
