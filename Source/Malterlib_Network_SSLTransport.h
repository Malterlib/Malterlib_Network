// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include "Malterlib_Network_Socket.h"

typedef struct crypto_ivec_st CRYPTO_IVEC;

namespace NMib::NNetwork
{
	// What a TLS connection reads and writes through: a buffered transport over the socket
	// layer in place of the descriptor BoringSSL would otherwise drive itself. Buffering
	// batches record reads and writes, and the socket layer's readiness protocol requests
	// the next report whenever the transport would block
	struct CSSLTransport
	{
		enum class ETransferResult
		{
			mc_Data
			, mc_WouldBlock
			, mc_EndOfStream
			, mc_Failed
		};

		// One entry of the outbound ring
		struct COut
		{
			NStorage::TCSharedPointer<NContainer::CByteVector> m_pData = fg_Construct();
			umint m_nFill = 0;
			umint m_iSent = 0;

			// Whether an operation is reading this entry, and the bytes it holds while it is
			bool m_bPinned = false;
			umint m_nPinnedBytes = 0;
		};

		// One piece of the inbound ciphertext stream. m_pOwner / m_pOwned is what keeps the
		// bytes alive; dropping the piece drops the reference, which is all the retiring
		// there is
		struct CCipherSegment
		{
			uint8 const *m_pData = nullptr;
			umint m_nBytes = 0;
			NStorage::TCSharedPointer<CVirtualDestroyBase const> m_pOwner;
			NStorage::TCSharedPointer<NContainer::CByteVector> m_pOwned;
		};

		CSSLTransport();
		~CSSLTransport();

		void f_SetCompletionSend(bool _bCompletionSend);
		void f_SetCompletionReceive(bool _bCompletionReceive);
		void f_SetSendDepth(umint _nDepth);
		umint f_GetSendDepth() const;
		void f_SetSendWindow(umint _nBytes);
		umint f_GetSendGenerations() const;
		void f_SetSocket(CSocket *_pSocket);
		void f_SetDeferFlush(bool _bDefer);

		bool f_HasSocket() const;
		umint f_GetBytesReceived() const;
		umint f_GetBytesSent() const;
		umint f_GetPendingWrite() const;
		umint f_GetPendingWriteUnpinned() const;
		bool f_IsFull() const;
		umint f_GetPendingRead() const;
		bool f_IsEndOfStream() const;
		NStr::CStr const &f_GetTransportError() const;

		ETransferResult f_Read(void *_pData, umint _nBytes, umint &o_nRead);
		ETransferResult f_Write(void const *_pData, umint _nBytes, umint &o_nWritten);
		ETransferResult f_Flush();

		bool f_BeginSend(void const *&o_pData, umint &o_nBytes, umint &o_iBuffer);
		void f_AbortSend(umint _iBuffer);
		bool f_SendCompleted(umint _iBuffer, umint _nBytes);
		umint f_GetFillBuffer() const;
		void f_ReleaseSendBuffer(umint _iBuffer);
		bool f_IsSendPinned() const;
		smint f_NextBeginSend() const;
		bool f_CanBeginSend() const;
		NStorage::TCSharedPointer<NContainer::CByteVector> f_GetPinnedKeepAlive(umint _iBuffer) const;

		uint8 *f_BeginSeal(umint _nWanted, umint &o_nRoom);
		void f_CommitSeal(umint _nBytes);

		static umint fsp_RecordFramingAllowance(umint _nBytes);

		void f_SetOutboundCap(umint _nBytes);
		void f_SetInboundSize(umint _nBytes);

		ETransferResult f_FillCipher();
		void fp_AppendOwnedCipher(umint _nRead);

		uint8 *f_BeginHold(umint &o_nRoom);
		void f_CommitHold(umint _nBytes);
		umint f_TakeHeld(void *_pData, umint _nBytes);
		umint f_GetHeld() const;

		void f_AppendCipherSegment(void const *_pData, umint _nBytes, NStorage::TCSharedPointer<CVirtualDestroyBase const> &&_pOwner);
		void f_CompactCipherIfStalled();
		umint fp_GetCipherQueueLen() const;
		umint f_GetCipherFragments(CRYPTO_IVEC *o_pFragments) const;
		umint f_GetCipherPending() const;
		void f_ConsumeCipher(umint _nBytes);
		void f_ClearCipherQueue();

		// Holds one maximum sized record with its framing, so a refill covers a whole record and
		// the header reads around it are served from memory
		static constexpr umint mc_nInboundBufferSize = 17 * 1024;

		// What one flush hands the transport at most. Reaching it flushes early even inside a
		// batch, which bounds what a connection whose peer stopped reading holds on to
		static constexpr umint mc_nOutboundBufferCap = 32 * 1024;

		// One record's plaintext, plus what TLS 1.3 writes past it before trimming
		static constexpr umint mc_nPlainHoldSize = 17 * 1024;

		// How many sends' buffers may await their zero copy release at once. Each un-released
		// generation holds a ring entry, so this is what the ring is sized from
		static constexpr umint mc_nMaxSendDepth = 8;

		static constexpr umint mc_nOutBuffers = mc_nMaxSendDepth + 1;

		// The most ciphertext pieces one decrypt call is offered; a queue longer than this is
		// compacted first, so a record can never sit undecryptable past the cap
		static constexpr umint mc_nMaxCipherFragments = 64;

	protected:

		ETransferResult fp_Receive(void *_pData, umint _nBytes, umint &o_nRead);
		void fp_ReleasePin(umint _iBuffer);
		bool fp_IsPinned(umint _iBuffer) const;
		bool fp_SendWindowFull() const;
		void fp_AdvanceFill();
		void fp_EnsureFillWritable();
		void fp_Compact();
		void fp_Reserve(umint _nBytes);
		void fp_Append(void const *_pData, umint _nBytes);

		CSocket *mp_pSocket = nullptr;

		// One more entry than the most sends that can be pinned at once, so there is always a
		// buffer left to seal into while the rest are with the kernel. mc_nOutBuffers entries, or
		// what the send window needs once one is set
		NContainer::TCVector<COut> mp_Out;

		// The buffer a still-outstanding zero copy send displaced from the ring, kept so it
		// can go back in once that send's notification releases it
		NStorage::TCSharedPointer<NContainer::CByteVector> mp_pOutRetired;

		NStr::CStr mp_TransportError;
		NContainer::CByteVector mp_Plain;

		// Inbound ciphertext, in arrival order, as the pieces it arrived in. A piece is either
		// a loop-owned stream buffer — kept alive through its owner until fully consumed — or a span
		// of this transport's own fill buffer on the readiness path. The record layer opens
		// records across pieces, so nothing is ever moved to make one contiguous; consuming
		// advances the head piece in place, which is all the carry there is
		NContainer::TCVector<CCipherSegment> mp_CipherQueue;

		// The readiness path's fill storage: consecutive reads append here and extend the
		// queue's tail piece, so a trickle of bytes stays one piece instead of many
		NStorage::TCSharedPointer<NContainer::CByteVector> mp_pCipherFill;

		umint mp_iOutFill = 0;

		// One entry per operation whose buffer-released notification is still owed, oldest
		// first; a short send's continuation adds a second entry for the same buffer. Sized
		// one past the generation cap for exactly that continuation
		NContainer::TCVector<umint> mp_PinnedOrder;

		umint mp_nPinned = 0;
		umint mp_nPinnedBytes = 0;
		umint mp_nSendWindowBytes = 0;
		umint mp_nSendDepth = 1;
		umint mp_nBytesReceived = 0;
		umint mp_nBytesSent = 0;
		umint mp_nOutboundCap = mc_nOutboundBufferCap;
		umint mp_nPlainFill = 0;
		umint mp_iPlainRead = 0;
		umint mp_iCipherHead = 0;
		umint mp_nCipherFillUsed = 0;
		umint mp_nCipherSize = mc_nInboundBufferSize;

		bool mp_bCompletionSend = false;
		bool mp_bCompletionReceive = false;
		bool mp_bEndOfStream = false;
		bool mp_bDeferFlush = false;
	};
}
