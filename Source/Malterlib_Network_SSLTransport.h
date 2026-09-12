// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include "Malterlib_Network_Socket.h"
#include <Mib/Core/IoStream>
#include <Mib/Time/Stopwatch>

typedef struct crypto_ivec_st CRYPTO_IVEC;

namespace NMib::NNetwork
{
	// Owns TLS transport buffering; all record and BIO paths share its ordered ciphertext queues.
	struct CSSLTransport
	{
		enum class ETransferResult
		{
			mc_Data
			, mc_WouldBlock
			, mc_EndOfStream
			, mc_Failed
		};

		// Outbound generation allocated on first use; pinned bytes cannot be overwritten until kernel release.
		struct COut
		{
			NStorage::TCSharedPointer<NContainer::CByteVector> m_pData;
			umint m_nFill = 0;
			umint m_iSent = 0;
			umint m_nPinnedBytes = 0;
			uint64 m_PinStamp = 0; // Submit-to-release latency sample; zero when unsampled.
			int32 m_iNextUnsent = -1; // Links either the unsent or free list; -1 ends the list.
			int32 m_iNextFree = -1;
		};

		// The segment's owner retains inbound ciphertext until consumed.
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
		bool f_IsCompletionSend() const;
		void f_SetCompletionReceive(bool _bCompletionReceive);
		void f_SetSendDepth(umint _nDepth);
		umint f_GetSendDepth() const;
		void f_SetSendWindow(umint _nBytes);
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
		void f_SendCompleted(umint _iBuffer, umint _nBytes);
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
		umint f_GetCipherQueueEntries() const;
		umint f_GetCipherFragments(CRYPTO_IVEC *o_pFragments) const;
		umint f_GetCipherPending() const;
		void f_ConsumeCipher(umint _nBytes);
		void f_ClearCipherQueue();

		static constexpr umint mc_nInboundBufferSize = 17 * 1024; // Fits one complete framed TLS record.
		static constexpr umint mc_nOutboundBufferCap = 32 * 1024; // Synchronous deferrals attempt an early flush at this cap.
		static constexpr umint mc_nPlainHoldSize = 17 * 1024; // Includes TLS 1.3 bytes written beyond plaintext before trimming.

		static constexpr umint mc_nMaxSendDepth = 8; // Prompt-release generation cap; late-release transports use the byte window.

		static constexpr umint mc_nCipherQueueCapacity = 8; // Compact live pieces on overflow and reclaim consumed-majority slots to bound metadata.
		static constexpr umint mc_nMaxCipherFragments = mc_nCipherQueueCapacity;

	protected:
		void fp_PushCipherSegment(CCipherSegment &&_Segment);
		void fp_ReclaimCipherConsumed();
		void fp_CompactCipher();

		ETransferResult fp_Receive(void *_pData, umint _nBytes, umint &o_nRead);
		void fp_ReleasePin(umint _iBuffer);
		bool fp_IsPinned(umint _iBuffer) const;
		bool fp_SendWindowFull() const;
		umint fp_GetEffectiveSendWindow() const;
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
		NMib::NSys::CIoSubSystem *mp_pIo = &NMib::NSys::fg_IoSubSystem();

		NContainer::TCVector<COut> mp_Out; // Grows on demand; free generations are reused newest-first for cache locality.
		NStorage::TCSharedPointer<NContainer::CByteVector> mp_pOutRetired; // Reusable only after the displaced zero-copy send releases it.

		NStr::CStr mp_TransportError;
		NContainer::CByteVector mp_Plain;

		CCipherSegment mp_CipherQueue[mc_nCipherQueueCapacity]; // Live range is [mp_iCipherHead, mp_nCipherQueue); each segment retains its bytes until consumed.
		umint mp_nCipherQueue = 0;
		NStorage::TCSharedPointer<NContainer::CByteVector> mp_pCipherFill; // Consecutive readiness reads extend one queue piece.

		umint mp_iOutFill = 0;
		int32 mp_iUnsentHead = -1; // Oldest unpinned unsent generation; fill is the tail when nonempty.
		int32 mp_iUnsentTail = -1;

		umint mp_nPinned = 0;
		umint mp_nPinnedBytes = 0;
		umint mp_nPendingWrite = 0; // Cached totals avoid scanning a pool sized by earlier bursts.
		umint mp_nPendingWriteUnpinned = 0;

		NSys::CIoSendWindow mp_Window; // Connection-thread-owned; floor and granularity track the outbound generation size.
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
