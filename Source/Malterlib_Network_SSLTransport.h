// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include "Malterlib_Network_Socket.h"
#include <Mib/Time/Stopwatch>

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

		// One generation of outbound ciphertext, laid out without padding. The buffer is
		// allocated on first use. Pinned while an operation reads it, which is while its
		// pinned bytes are nonzero: only unsent bytes are ever pinned
		struct COut
		{
			NStorage::TCSharedPointer<NContainer::CByteVector> m_pData;
			umint m_nFill = 0;
			umint m_iSent = 0;
			umint m_nPinnedBytes = 0;

			// When the generation was pinned, for the release latency sample its release takes
			uint64 m_PinStamp = 0;

			// The next generation with unsent bytes, in the order they were sealed, or the next
			// free one; -1 ends either list
			int32 m_iNextUnsent = -1;
			int32 m_iNextFree = -1;
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

		// The submitter's ask when the window refuses its next send: full while more wants out
		// is the moment to grow, and the refusal happens at the gates — const, and reached
		// before f_BeginSend ever runs — so the consideration has to be reachable from outside
		void f_ConsiderSendWindowGrowth();

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

		// How many sends' buffers may await their zero copy release at once on a socket that
		// releases them promptly; a socket that holds them to the acknowledgement is bounded by
		// the send window in bytes instead
		static constexpr umint mc_nMaxSendDepth = 8;

		// The most ciphertext pieces one decrypt call is offered; a queue longer than this is
		// compacted first, so a record can never sit undecryptable past the cap
		static constexpr umint mc_nMaxCipherFragments = 64;

	protected:

		ETransferResult fp_Receive(void *_pData, umint _nBytes, umint &o_nRead);
		void fp_ReleasePin(umint _iBuffer);
		bool fp_IsPinned(umint _iBuffer) const;
		bool fp_SendWindowFull() const;
		umint fp_GetEffectiveSendWindow() const;
		void fp_RollLagEpochs(uint64 _Now);
		void fp_EnsureWindowTicks();
		void fp_ConsiderSendWindowGrowth();
		static uint64 fsp_NowTicks();
		void fp_EnqueueUnsent(umint _iBuffer);
		void fp_PushUnsentFront(umint _iBuffer);
		umint fp_DequeueUnsentHead();
		umint fp_TakeFreeEntry();
		void fp_NoteFillGained(umint _nBytes);
		void fp_AdvanceFill();
		void fp_EnsureFillWritable();
		void fp_Compact();
		void fp_Reserve(umint _nBytes);
		void fp_Append(void const *_pData, umint _nBytes);

		CSocket *mp_pSocket = nullptr;

		// The generations: a pool that grows by one only when a seal finds every entry pinned,
		// so a connection holds what its window has actually needed. Freed entries are a list
		// through the entries, newest first, so the memory the kernel just let go of is what the
		// next records land in while it is still in cache
		NContainer::TCVector<COut> mp_Out;

		// The buffer a still-outstanding zero copy send displaced from the fill, kept so it
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

		// The generations with unsent bytes that no operation carries, oldest first: what the
		// flush drains and a begin pins, in the order the records were sealed. The fill is its
		// tail whenever it holds anything
		int32 mp_iUnsentHead = -1;
		int32 mp_iUnsentTail = -1;

		umint mp_nPinned = 0;
		umint mp_nPinnedBytes = 0;
		umint mp_nSendWindowBytes = 0;

		// Unsent bytes over every generation, and over the unpinned ones alone; kept with every
		// change so asking costs nothing whatever the pool holds
		umint mp_nPendingWrite = 0;
		umint mp_nPendingWriteUnpinned = 0;

		// The cap on pinned bytes within the configured window: eight frames to begin with, which
		// a local path never outgrows, and grown toward the bandwidth-delay product the kernel
		// reports for the connection — asked only when every buffer is pinned and more wants to go
		// out, at most every ten milliseconds. A cap the path does not need stays small, so the
		// pipeline runs dry now and then and the release notifications keep coming promptly. It
		// shrinks slowly: only once the product has stayed under it for a second, and then by no
		// longer letting pins above the new cap be replaced as their releases come
		umint mp_nWindowEffective = 0;
		umint mp_nWindowShrinkTarget = 0;
		// The pacing intervals in raw timer ticks, computed from the timer frequency at the first
		// query; the transport runs on its connection alone, so plain members need no guard
		uint64 mp_WindowQueryIntervalTicks = 0;
		uint64 mp_WindowShrinkAfterTicks = 0;
		uint64 mp_WindowTicksPerSecond = 0;
		uint64 mp_WindowQueryStamp = 0;
		uint64 mp_WindowShrinkSince = 0;

		// The release latency's sliding minimum: two epochs of the lowest pin-to-release lag
		// seen, so the growth target multiplies the delivery rate by the lag a release meets
		// with no self-queueing ahead of it, and a changed path re-teaches it within two epochs
		uint64 mp_MinReleaseLagTicks[2] = {};
		uint64 mp_LagEpochStamp = 0;
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
		int32 mp_iFreeHead = -1;
	};
}
