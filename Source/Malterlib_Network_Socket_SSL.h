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
		virtual NMib::NSys::ICIoLoop *f_GetOwningIoLoop() override;
		virtual ICSocketCompletionIo *f_GetCompletionIo() override;

		virtual bool f_SubmitSendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans, NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased) override;
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
		virtual bool f_SupportsSendStaging() const override;
		virtual bool f_HasSendOperationInFlight() const override;
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

		// One caller transfer: the plaintext one f_SubmitSendVectored call handed over, the
		// generation its seal landed in, and — for a transfer staged while an operation was in
		// flight — the caller's functors, fired on the caller's thread when that generation's
		// ciphertext has fully left. The transfer whose call submitted the operation carries no
		// functors here: its own ride the operation and report through the ordinary completion
		// One transfer in progress, laid out without padding
		struct CSendOperation
		{
			NSys::FIoCompletion m_fOnComplete;
			FSocketSendReleased m_fOnReleased;
			umint m_nPlaintext = 0;

			// The generation the seal landed in, the operations carrying the same generation as a
			// list per generation, and the free operations as a list; -1 ends either list
			uint32 m_iBuffer = 0;
			int32 m_iNextForBuffer = -1;
			int32 m_iNextFree = -1;
			bool m_bHasFunctors = false;
			bool m_bInUse = false;
			bool m_bResolved = false;
			bool m_bReleased = false;
			bool m_bLinked = false;
		};

		bool fp_HandleHandshake();
		void fp_HandleHandshakeDone();
		void fp_CheckBrokenState();
		void fp_AddTCPState(ENetTCPState _ToAdd);
		NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> fp_SharedOnStateChange();

		auto fp_AllocateSendOperation() -> smint;
		void fp_TryFreeSendOperation(umint _iOperation);
		void fp_LinkSendOperation(umint _iOperation);
		void fp_FreeSendOperation(umint _iOperation);
		bool fp_SubmitPinnedSend(void const *_pData, umint _nBytes, umint _iBuffer, NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased);
		// Fires the stored functors of every staged transfer whose seals the generation
		// carried; the operation's own transfer reports through the completion instead
		void fp_ResolveOpsForBuffer(umint _iBuffer, NMib::NSys::CIoCompletion const &_Result, umint &o_nCarrierPlaintext);
		// Fires the releases likewise, freeing each transfer that has heard both halves
		void fp_ReleaseOpsForBuffer(umint _iBuffer, umint _iTransfer);
		void fp_FailAllSendOperations();

		// What one TLS record carries at most; gathered sends stage up to this per seal
		static constexpr umint mcp_nMaxRecordBytes = 16 * 1024;
		// The transfers in progress, as many as the window has needed at once; the free ones a
		// list through them, newest first, and the ones carrying a generation a list per generation
		NContainer::TCVector<CSendOperation> mp_SendOperations;
		int32 mp_iFreeOperationHead = -1;
		NContainer::TCVector<int32> mp_iBufferOperationHead;
		umint mp_nSendWindowBytes = 0;
		NContainer::CByteVector mp_SendStaging;
		NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> mp_fOnStateChange;
		NThread::CMutual mp_fOnStateChangeLock;
		CSocket mp_Socket;
		NStorage::TCSharedPointer<CSSLContext> mp_pSSLContext;
		CSSLConnection::FAuthenticationResultCallback mp_AuthenticationResultCallback;
		CSSLConnection::FUserTrustDecisionCallback mp_UserTrustDecisionCallback;

		CSSLConnection mp_SSLConnection;

		// Plaintext of the operation chain's own transfers that has not been reported yet:
		// continuations carry nothing of their own, so the chain reports once
		umint mp_nSendPlaintextHeld = 0;

		// Sends with the kernel right now; the loop completes them in submission order, and
		// the transport's pinned-generation depth bounds the count
		umint mp_nSendOpsInFlight = 0;

		NAtomic::TCAtomic<uint32> mp_ExtraState;
		EState mp_State = EState_None;

		// Set by the first send that failed; the connection is over and later completions only
		// clear their records
		bool mp_bSendFailed = false;

		// Set when the caller says it is driving this socket's sends with submitted operations;
		// the synchronous send entry point refuses from then on. Which directions are submitted
		// comes from f_SupportsCompletionSend / Receive, so a connection can submit one way and
		// stay synchronous the other
		bool mp_bCompletionActive = false;

		bool mp_bBrokenStateReported = false;
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
