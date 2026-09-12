// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Network_SSLTransport.h"

#include <Mib/Cryptography/BoringSSL>

namespace NMib::NNetwork
{
	CSSLTransport::CSSLTransport()
	{
		mp_Out.f_SetLen(1);
	}

	CSSLTransport::~CSSLTransport()
	{
		f_ClearCipherQueue();
	}

	void CSSLTransport::f_SetCompletionSend(bool _bCompletionSend)
	{
		mp_bCompletionSend = _bCompletionSend;
	}

	bool CSSLTransport::f_IsCompletionSend() const
	{
		return mp_bCompletionSend;
	}

	void CSSLTransport::f_SetCompletionReceive(bool _bCompletionReceive)
	{
		mp_bCompletionReceive = _bCompletionReceive;
	}

	// Limit unreleased generations for prompt-release transports.
	void CSSLTransport::f_SetSendDepth(umint _nDepth)
	{
		mp_nSendDepth = fg_Clamp(_nDepth, umint(1), mc_nMaxSendDepth);
	}

	umint CSSLTransport::f_GetSendDepth() const
	{
		return mp_nSendDepth;
	}

	// Set before the first pin; grow generation storage only as the byte window fills.
	void CSSLTransport::f_SetSendWindow(umint _nBytes)
	{
		DMibFastCheck(!mp_nPinned);

		mp_Window.m_nMaxBytes = _nBytes;
	}

	// Call after the const staging gate refuses with more output pending; growth must be considered before beginning a send.
	void CSSLTransport::f_ConsiderSendWindowGrowth()
	{
		fp_ConsiderSendWindowGrowth();
	}

	// Exclude pinned generations from pending output or the drain could spin submitting empty continuations.
	umint CSSLTransport::f_GetPendingWriteUnpinned() const
	{
		return mp_nPendingWriteUnpinned;
	}

	void CSSLTransport::f_SetSocket(CSocket *_pSocket)
	{
		mp_pSocket = _pSocket;
	}

	// The owner must end deferral on every path; the library flushes only handshake flights and fatal alerts.
	void CSSLTransport::f_SetDeferFlush(bool _bDefer)
	{
		mp_bDeferFlush = _bDefer;
	}

	bool CSSLTransport::f_HasSocket() const
	{
		return mp_pSocket && mp_pSocket->f_IsValid();
	}

	umint CSSLTransport::f_GetBytesReceived() const
	{
		return mp_nBytesReceived;
	}

	umint CSSLTransport::f_GetBytesSent() const
	{
		return mp_nBytesSent;
	}

	umint CSSLTransport::f_GetPendingWrite() const
	{
		return mp_nPendingWrite;
	}

	bool CSSLTransport::f_IsFull() const
	{
		return f_GetPendingWrite() >= mp_nOutboundCap;
	}

	umint CSSLTransport::f_GetPendingRead() const
	{
		return f_GetCipherPending();
	}

	bool CSSLTransport::f_IsEndOfStream() const
	{
		return mp_bEndOfStream;
	}

	// Transport errors cannot unwind through library frames; expose them after the SSL call returns.
	NStr::CStr const &CSSLTransport::f_GetTransportError() const
	{
		return mp_TransportError;
	}

	// Serve fallback library reads from the same ciphertext queue or they could skip bytes already buffered.
	CSSLTransport::ETransferResult CSSLTransport::f_Read(void *_pData, umint _nBytes, umint &o_nRead)
	{
		o_nRead = 0;

		if (mp_TransportError)
			return ETransferResult::mc_Failed;

		if (!f_GetCipherPending())
		{
			if (mp_bEndOfStream || !f_HasSocket())
				return ETransferResult::mc_EndOfStream;

			ETransferResult Result = f_FillCipher();
			if (Result != ETransferResult::mc_Data)
				return Result;
		}

		CRYPTO_IVEC Fragments[mc_nMaxCipherFragments];
		umint nFragments = f_GetCipherFragments(Fragments);

		for (umint iFragment = 0; iFragment < nFragments && o_nRead < _nBytes; ++iFragment)
		{
			umint nCopy = fg_Min(Fragments[iFragment].len, _nBytes - o_nRead);
			NMemory::fg_MemCopy((uint8 *)_pData + o_nRead, Fragments[iFragment].in, nCopy);
			o_nRead += nCopy;
		}

		f_ConsumeCipher(o_nRead);

		return ETransferResult::mc_Data;
	}

	CSSLTransport::ETransferResult CSSLTransport::f_Write(void const *_pData, umint _nBytes, umint &o_nWritten)
	{
		o_nWritten = 0;

		if (mp_TransportError)
			return ETransferResult::mc_Failed;

		if (!f_HasSocket())
			return ETransferResult::mc_Failed;

		// Accept whole library writes: rejecting them fixes the retry length, which a changing gather cannot reproduce.
		// Apply backpressure before handing plaintext to the library to avoid BAD_WRITE_RETRY.
		fp_Append(_pData, _nBytes);
		o_nWritten = _nBytes;

		// Synchronous deferrals flush at the cap. Completion mode must leave all writing to submitted operations.
		if (!mp_bCompletionSend && (!mp_bDeferFlush || f_GetPendingWrite() >= mp_nOutboundCap))
			f_Flush();

		return ETransferResult::mc_Data;
	}

	CSSLTransport::ETransferResult CSSLTransport::f_Flush()
	{
		if (mp_TransportError)
			return ETransferResult::mc_Failed;

		// Never synchronously send around pinned older records; it would reorder TLS sequence numbers.
		if (mp_nPinned)
			return ETransferResult::mc_WouldBlock;

		while (mp_iUnsentHead >= 0)
		{
			umint iBuffer = umint(mp_iUnsentHead);
			COut &Buffer = mp_Out[iBuffer];

			while (Buffer.m_iSent < Buffer.m_nFill)
			{
				if (!f_HasSocket())
					return ETransferResult::mc_Failed;

				umint nSent = 0;
				try
				{
					nSent = mp_pSocket->f_Send(Buffer.m_pData->f_GetArray() + Buffer.m_iSent, Buffer.m_nFill - Buffer.m_iSent);
				}
				catch (NException::CException const &_Exception)
				{
					mp_TransportError = _Exception.f_GetErrorStr();
					return ETransferResult::mc_Failed;
				}

				if (!nSent)
					return ETransferResult::mc_WouldBlock;

				Buffer.m_iSent += nSent;
				mp_nBytesSent += nSent;
				mp_nPendingWrite -= nSent;
				mp_nPendingWriteUnpinned -= nSent;
			}

			// Retain the drained allocation for subsequent batches.
			fp_DequeueUnsentHead();
			Buffer.m_iSent = 0;
			Buffer.m_nFill = 0;
			if (iBuffer != mp_iOutFill)
			{
				mp_Out[iBuffer].m_iNextFree = mp_iFreeHead;
				mp_iFreeHead = int32(iBuffer);
			}
		}

		return ETransferResult::mc_Data;
	}

	// Pin the oldest unsent generation. Move the fill elsewhere before later seals can write kernel-owned bytes.
	bool CSSLTransport::f_BeginSend(void const *&o_pData, umint &o_nBytes, umint &o_iBuffer)
	{
		if (mp_TransportError || mp_iUnsentHead < 0)
			return false;

		if (fp_SendWindowFull())
		{
			fp_ConsiderSendWindowGrowth();
			if (fp_SendWindowFull())
				return false;
		}

		umint iBuffer = fp_DequeueUnsentHead();
		COut &Buffer = mp_Out[iBuffer];

		o_pData = Buffer.m_pData->f_GetArray() + Buffer.m_iSent;
		o_nBytes = Buffer.m_nFill - Buffer.m_iSent;
		o_iBuffer = iBuffer;

		Buffer.m_nPinnedBytes = o_nBytes;

		// Sample only low-occupancy pins so window growth does not amplify its own queue.
		if (mp_nPinned <= 1)
			Buffer.m_PinStamp = fsp_NowTicks();

		++mp_nPinned;
		mp_nPinnedBytes += o_nBytes;
		mp_nPendingWriteUnpinned -= o_nBytes;

#if DMibConfig_IoDebug_Enable
		if (auto *pStats = fg_NetIoStats())
		{
			if (mp_nPinned > pStats->m_nSslMaxPinned.f_Load(NAtomic::gc_MemoryOrder_Relaxed))
				pStats->m_nSslMaxPinned.f_Store(mp_nPinned, NAtomic::gc_MemoryOrder_Relaxed);
			if (mp_nPinnedBytes > pStats->m_nSslMaxPinnedBytes.f_Load(NAtomic::gc_MemoryOrder_Relaxed))
				pStats->m_nSslMaxPinnedBytes.f_Store(mp_nPinnedBytes, NAtomic::gc_MemoryOrder_Relaxed);
		}
#endif

		// Move the fill before sealing again; pool growth may invalidate existing references.
		if (iBuffer == mp_iOutFill)
			fp_AdvanceFill();

		return true;
	}

	// Unaccepted bytes return to the unsent head so they remain first on the wire.
	void CSSLTransport::f_AbortSend(umint _iBuffer)
	{
		fp_ReleasePin(_iBuffer);
	}

	// Completion drains the generation but retains its pin until buffer release; the kernel may still read it.
	void CSSLTransport::f_SendCompleted(umint _iBuffer, umint _nBytes)
	{
		DMibFastCheck(fp_IsPinned(_iBuffer));

		COut &Buffer = mp_Out[_iBuffer];
		DMibFastCheck(_nBytes == Buffer.m_nFill - Buffer.m_iSent);

		mp_nBytesSent += _nBytes;
		mp_nPendingWrite -= _nBytes;
		Buffer.m_iSent = 0;
		Buffer.m_nFill = 0;
	}

	umint CSSLTransport::f_GetFillBuffer() const
	{
		return mp_iOutFill;
	}

	// Tolerate a pin already returned by refusal; its release callback still runs.
	void CSSLTransport::f_ReleaseSendBuffer(umint _iBuffer)
	{
		fp_ReleasePin(_iBuffer);
	}

	bool CSSLTransport::f_IsSendPinned() const
	{
		return mp_nPinned != 0;
	}

	// Return the oldest unpinned generation with unsent bytes, or -1. Pinned bytes already belong to an operation.
	smint CSSLTransport::f_NextBeginSend() const
	{
		if (mp_TransportError || fp_SendWindowFull())
			return -1;

		return mp_iUnsentHead;
	}

	bool CSSLTransport::f_CanBeginSend() const
	{
		// Only an unpinned generation can be begun — a pinned one's bytes are already
		// with their operation — so the window is the whole answer
		return !mp_TransportError && !fp_SendWindowFull();
	}

	// Retain memory independently of socket lifetime until the kernel releases it.
	NStorage::TCSharedPointer<NContainer::CByteVector> CSSLTransport::f_GetPinnedKeepAlive(umint _iBuffer) const
	{
		DMibFastCheck(fp_IsPinned(_iBuffer));

		return mp_Out[_iBuffer].m_pData;
	}

	// Direct seals and BIO output share one ordered buffer.
	uint8 *CSSLTransport::f_BeginSeal(umint _nWanted, umint &o_nRoom)
	{
		fp_EnsureFillWritable();
		fp_Compact();
		fp_Reserve(_nWanted);

		COut &Buffer = mp_Out[mp_iOutFill];
		o_nRoom = Buffer.m_pData->f_GetLen() - Buffer.m_nFill;

		return Buffer.m_pData->f_GetArray() + Buffer.m_nFill;
	}

	void CSSLTransport::f_CommitSeal(umint _nBytes)
	{
		DMibFastCheck(!fp_IsPinned(mp_iOutFill));

		fp_NoteFillGained(_nBytes);
	}

	// Include TLS framing beyond the payload cap or a full transport frame splits into a maximum send plus a tiny tail.
	umint CSSLTransport::fsp_RecordFramingAllowance(umint _nBytes)
	{
		return _nBytes / 256 + 512;
	}

	void CSSLTransport::f_SetOutboundCap(umint _nBytes)
	{
		mp_nOutboundCap = fg_Max(_nBytes + fsp_RecordFramingAllowance(_nBytes), mc_nOutboundBufferCap);
	}

	// Each readiness buffer must hold a whole record so a carried tail plus one refill can complete it.
	void CSSLTransport::f_SetInboundSize(umint _nBytes)
	{
		mp_nCipherSize = fg_Max(_nBytes + fsp_RecordFramingAllowance(_nBytes), mc_nInboundBufferSize);
	}

	// Read into owned storage and append to the same queue used by direct record opening.
	CSSLTransport::ETransferResult CSSLTransport::f_FillCipher()
	{
		if (mp_TransportError)
			return ETransferResult::mc_Failed;

		// The standing receive is the sole kernel reader in completion mode; still serve ciphertext already queued.
		if (mp_bCompletionReceive)
			return ETransferResult::mc_WouldBlock;

		if (mp_bEndOfStream || !f_HasSocket())
			return ETransferResult::mc_EndOfStream;

		// The fill buffer can only be recycled or resized while nothing in the queue
		// points into it
		if (!fp_GetCipherQueueLen())
		{
			f_ClearCipherQueue();

			if (!mp_pCipherFill)
				mp_pCipherFill = fg_Construct();
			if (mp_pCipherFill->f_GetLen() < mp_nCipherSize)
				mp_pCipherFill->f_SetLen(mp_nCipherSize, false);
		}
		else if (!mp_pCipherFill || mp_nCipherFillUsed >= mp_pCipherFill->f_GetLen())
		{
			// Retain the old fill through queued pieces; only fresh storage may receive more bytes.
			auto pFresh = NStorage::TCSharedPointer<NContainer::CByteVector>(fg_Construct());
			pFresh->f_SetLen(mp_nCipherSize, false);
			mp_pCipherFill = fg_Move(pFresh);
			mp_nCipherFillUsed = 0;
		}

		umint nRead = 0;
		ETransferResult Result = fp_Receive(mp_pCipherFill->f_GetArray() + mp_nCipherFillUsed, mp_pCipherFill->f_GetLen() - mp_nCipherFillUsed, nRead);
		if (Result != ETransferResult::mc_Data)
			return Result;

		fp_AppendOwnedCipher(nRead);

		return ETransferResult::mc_Data;
	}

	// Merge consecutive reads into one queue piece to avoid metadata growth on trickle input.
	void CSSLTransport::fp_AppendOwnedCipher(umint _nRead)
	{
		uint8 const *pStart = mp_pCipherFill->f_GetArray() + mp_nCipherFillUsed;
		mp_nCipherFillUsed += _nRead;

		if (fp_GetCipherQueueLen())
		{
			CCipherSegment &Tail = mp_CipherQueue[mp_nCipherQueue - 1];
			if (Tail.m_pOwned == mp_pCipherFill && Tail.m_pData + Tail.m_nBytes == pStart)
			{
				Tail.m_nBytes += _nRead;
				return;
			}
		}

		// The push can compact, which lets go of the fill; the piece keeps the buffer alive
		CCipherSegment Segment;
		Segment.m_pData = pStart;
		Segment.m_nBytes = _nRead;
		Segment.m_pOwned = mp_pCipherFill;
		fp_PushCipherSegment(fg_Move(Segment));
	}

	// Use one-record holdover storage when plaintext cannot fit in the caller's remaining capacity.
	uint8 *CSSLTransport::f_BeginHold(umint &o_nRoom)
	{
		// Drain existing held plaintext before opening another record here or it would be lost.
		DMibFastCheck(!f_GetHeld());

		if (mp_Plain.f_GetLen() < mc_nPlainHoldSize)
			mp_Plain.f_SetLen(mc_nPlainHoldSize);

		mp_iPlainRead = 0;
		mp_nPlainFill = 0;
		o_nRoom = mp_Plain.f_GetLen();

		return mp_Plain.f_GetArray();
	}

	void CSSLTransport::f_CommitHold(umint _nBytes)
	{
		mp_nPlainFill = _nBytes;
	}

	umint CSSLTransport::f_TakeHeld(void *_pData, umint _nBytes)
	{
		umint nCopy = fg_Min(_nBytes, mp_nPlainFill - mp_iPlainRead);

		if (nCopy)
		{
			NMemory::fg_MemCopy((uint8 *)_pData, mp_Plain.f_GetArray() + mp_iPlainRead, nCopy);
			mp_iPlainRead += nCopy;
		}

		return nCopy;
	}

	umint CSSLTransport::f_GetHeld() const
	{
		return mp_nPlainFill - mp_iPlainRead;
	}

	// Retain the segment owner until its bytes are consumed.
	void CSSLTransport::f_AppendCipherSegment(void const *_pData, umint _nBytes, NStorage::TCSharedPointer<CVirtualDestroyBase const> &&_pOwner)
	{
		mp_nBytesReceived += _nBytes;

		CCipherSegment Segment;
		Segment.m_pData = (uint8 const *)_pData;
		Segment.m_nBytes = _nBytes;
		Segment.m_pOwner = fg_Move(_pOwner);
		fp_PushCipherSegment(fg_Move(Segment));
	}

	// Reclaim consumed slots before compacting live pieces when capacity is exhausted.
	void CSSLTransport::fp_PushCipherSegment(CCipherSegment &&_Segment)
	{
		if (mp_nCipherQueue == mc_nCipherQueueCapacity)
		{
			if (mp_iCipherHead)
				fp_ReclaimCipherConsumed();
			else
				fp_CompactCipher();
		}

		mp_CipherQueue[mp_nCipherQueue++] = fg_Move(_Segment);
	}

	void CSSLTransport::fp_ReclaimCipherConsumed()
	{
		umint nLive = fp_GetCipherQueueLen();

		for (umint iSegment = 0; iSegment < nLive; ++iSegment)
			mp_CipherQueue[iSegment] = fg_Move(mp_CipherQueue[mp_iCipherHead + iSegment]);

		mp_nCipherQueue = nLive;
		mp_iCipherHead = 0;
	}

	// If a partial record pins charged buffers, backpressure can block the bytes needed to finish it.
	// Copy only on no progress to release those charges without penalizing ordinary record straddles.
	void CSSLTransport::f_CompactCipherIfStalled()
	{
		bool bOwners = false;
		for (umint iSegment = mp_iCipherHead; iSegment < mp_nCipherQueue; ++iSegment)
		{
			if (mp_CipherQueue[iSegment].m_pOwner)
			{
				bOwners = true;
				break;
			}
		}

		if (!bOwners)
			return;

#if DMibConfig_IoDebug_Enable
		if (auto *pStats = NNetwork::fg_NetIoStats())
			pStats->m_nSslCompacts.f_FetchAdd(1, NAtomic::gc_MemoryOrder_Relaxed);
#endif

		fp_CompactCipher();
	}

	void CSSLTransport::fp_CompactCipher()
	{
		umint nTotal = f_GetCipherPending();

		auto pCompact = NStorage::TCSharedPointer<NContainer::CByteVector>(fg_Construct());
		pCompact->f_SetLen(fg_Max(nTotal, mp_nCipherSize), false);

		umint nUsed = 0;
		for (umint iSegment = mp_iCipherHead; iSegment < mp_nCipherQueue; ++iSegment)
		{
			CCipherSegment const &Segment = mp_CipherQueue[iSegment];
			NMemory::fg_MemCopy(pCompact->f_GetArray() + nUsed, Segment.m_pData, Segment.m_nBytes);
			nUsed += Segment.m_nBytes;
		}

		f_ClearCipherQueue();

		if (nUsed)
		{
			CCipherSegment &Segment = mp_CipherQueue[mp_nCipherQueue++];
			Segment.m_pData = pCompact->f_GetArray();
			Segment.m_nBytes = nUsed;
			Segment.m_pOwned = fg_Move(pCompact);
		}

		mp_pCipherFill.f_Clear();
	}

	umint CSSLTransport::fp_GetCipherQueueLen() const
	{
		return mp_nCipherQueue - mp_iCipherHead;
	}

	// Includes consumed slots until reclamation; compaction keeps the total within capacity.
	umint CSSLTransport::f_GetCipherQueueEntries() const
	{
		return mp_nCipherQueue;
	}

	// Offer queued pieces oldest first; the advanced head offset carries incomplete-record state.
	umint CSSLTransport::f_GetCipherFragments(CRYPTO_IVEC *o_pFragments) const
	{
		umint nFragments = 0;

		for (umint iSegment = mp_iCipherHead; iSegment < mp_nCipherQueue; ++iSegment)
		{
			CCipherSegment const &Segment = mp_CipherQueue[iSegment];

			if (Segment.m_nBytes)
				o_pFragments[nFragments++] = CRYPTO_IVEC{Segment.m_pData, Segment.m_nBytes};
		}

		return nFragments;
	}

	umint CSSLTransport::f_GetCipherPending() const
	{
		umint nPending = 0;

		for (umint iSegment = mp_iCipherHead; iSegment < mp_nCipherQueue; ++iSegment)
			nPending += mp_CipherQueue[iSegment].m_nBytes;

		return nPending;
	}

	// Release fully consumed segment owners so stream backpressure can resume.
	void CSSLTransport::f_ConsumeCipher(umint _nBytes)
	{
		umint nLeft = _nBytes;

		while (nLeft)
		{
			DMibFastCheck(fp_GetCipherQueueLen());

			CCipherSegment &Head = mp_CipherQueue[mp_iCipherHead];

			umint nTaken = fg_Min(nLeft, Head.m_nBytes);
			Head.m_pData += nTaken;
			Head.m_nBytes -= nTaken;
			nLeft -= nTaken;

			if (Head.m_nBytes)
				break;

			Head.m_pOwner.f_Clear();
			Head.m_pOwned.f_Clear();
			++mp_iCipherHead;
		}

		if (!fp_GetCipherQueueLen())
			f_ClearCipherQueue();
		else if (mp_iCipherHead >= fp_GetCipherQueueLen())
		{
			// Straddling records may never empty the queue; reclaim consumed-majority slots for amortized constant append cost.
			fp_ReclaimCipherConsumed();
		}
	}

	void CSSLTransport::f_ClearCipherQueue()
	{
		for (umint iSegment = 0; iSegment < mp_nCipherQueue; ++iSegment)
			mp_CipherQueue[iSegment] = CCipherSegment();

		mp_nCipherQueue = 0;
		mp_iCipherHead = 0;
		mp_nCipherFillUsed = 0;
	}

	CSSLTransport::ETransferResult CSSLTransport::fp_Receive(void *_pData, umint _nBytes, umint &o_nRead)
	{
		bool bEndOfStream = false;
		try
		{
			o_nRead = mp_pSocket->f_Receive(_pData, _nBytes, bEndOfStream);
		}
		catch (NException::CException const &_Exception)
		{
			mp_TransportError = _Exception.f_GetErrorStr();
			return ETransferResult::mc_Failed;
		}

		mp_nBytesReceived += o_nRead;

		if (o_nRead)
			return ETransferResult::mc_Data;

		if (bEndOfStream)
		{
			mp_bEndOfStream = true;
			return ETransferResult::mc_EndOfStream;
		}

		return ETransferResult::mc_WouldBlock;
	}

	// Refusal may have already released the pin. Unsent bytes return to the head; drained generations return newest-first to the free list.
	void CSSLTransport::fp_ReleasePin(umint _iBuffer)
	{
		COut &Buffer = mp_Out[_iBuffer];
		if (!Buffer.m_nPinnedBytes)
			return;

		// The release latency feeds the window's sliding minimum: the lag of a release that
		// met no self-queueing is what the growth target multiplies the delivery rate by
		if (Buffer.m_PinStamp)
		{
			uint64 Now = fsp_NowTicks();
			NSys::fg_SampleIoSendReleaseLag(mp_Window, Now - Buffer.m_PinStamp, Now, mp_pIo->m_nWindowShrinkAfterTicks);

			Buffer.m_PinStamp = 0;
		}

		--mp_nPinned;
		mp_nPinnedBytes -= Buffer.m_nPinnedBytes;
		Buffer.m_nPinnedBytes = 0;

		// Only a send that was never accepted leaves bytes behind here; a completed one drained
		// the generation before its release came
		if (Buffer.m_iSent < Buffer.m_nFill)
		{
			mp_nPendingWriteUnpinned += Buffer.m_nFill - Buffer.m_iSent;
			fp_PushUnsentFront(_iBuffer);

			return;
		}

		Buffer.m_iSent = 0;
		Buffer.m_nFill = 0;
		mp_Out[_iBuffer].m_iNextFree = mp_iFreeHead;
		mp_iFreeHead = int32(_iBuffer);
	}

	// Whether another generation may be pinned: within the depth for a socket that releases
	// its sends promptly, otherwise within the cap
	bool CSSLTransport::fp_SendWindowFull() const
	{
		if (!mp_Window.m_nMaxBytes)
			return mp_nPinned >= f_GetSendDepth();

		return mp_nPinnedBytes >= fp_GetEffectiveSendWindow();
	}

	umint CSSLTransport::fp_GetEffectiveSendWindow() const
	{
		// The window a connection begins at: one generation, which the path grows past only
		// when its bandwidth-delay product asks
		umint nFloor = fg_Min(mp_Window.m_nMaxBytes, mp_nOutboundCap);
		if (!mp_Window.m_nEffectiveBytes)
			return nFloor;

		return fg_Clamp(mp_Window.m_nEffectiveBytes, nFloor, mp_Window.m_nMaxBytes);
	}

	uint64 CSSLTransport::fsp_NowTicks()
	{
		return uint64(NTime::NPlatform::fg_TimerRaw_PreciseGet());
	}

	// Pace delivery-rate queries and refresh window floor/granularity from one outbound generation.
	// Shared growth logic uses minimum release lag to avoid chasing self-queueing.
	void CSSLTransport::fp_ConsiderSendWindowGrowth()
	{
		if (!mp_pSocket)
			return;

		auto &Io = *mp_pIo;

		uint64 Now = fsp_NowTicks();
		if (mp_Window.m_QueryStamp && Now - mp_Window.m_QueryStamp < Io.m_nWindowQueryIntervalTicks)
			return;
		mp_Window.m_QueryStamp = Now;

		umint nDeliveryRate = 0;
		bool bAppLimited = false;
		if (!mp_pSocket->f_QueryPathDeliveryRate(nDeliveryRate, bAppLimited))
			return;

		// The transport's send unit is a full generation and the window starts at one of them;
		// the outbound cap follows the fragmentation size, so both are refreshed at each ask
		mp_Window.m_nStartBytes = fg_Min(mp_Window.m_nMaxBytes, mp_nOutboundCap);
		mp_Window.m_nLargestSendBytes = mp_nOutboundCap;
		mp_Window.m_nEffectiveBytes = fp_GetEffectiveSendWindow();

		NSys::fg_ConsiderIoSendWindowGrowth(mp_Window, nDeliveryRate, bAppLimited, Now, Io.m_nTicksPerSecond, Io.m_nWindowShrinkAfterTicks);

	#if DMibConfig_IoDebug_Enable
		if (auto *pStats = fg_NetIoStats())
		{
			uint64 nLagTicks = NSys::fg_GetIoSendMinReleaseLag(mp_Window, Now, Io.m_nWindowShrinkAfterTicks);

			umint nBandwidthDelay = umint(uint64(nDeliveryRate) * nLagTicks / Io.m_nTicksPerSecond);
			umint nNow = fp_GetEffectiveSendWindow();
			if (nNow > pStats->m_nSslWindowMax.f_Load(NAtomic::gc_MemoryOrder_Relaxed))
				pStats->m_nSslWindowMax.f_Store(nNow, NAtomic::gc_MemoryOrder_Relaxed);
			pStats->m_nSslWindowBandwidthDelay.f_Store(nBandwidthDelay, NAtomic::gc_MemoryOrder_Relaxed);
			pStats->m_nSslWindowQueries.f_FetchAdd(1, NAtomic::gc_MemoryOrder_Relaxed);
		}
	#endif
	}

	void CSSLTransport::fp_EnqueueUnsent(umint _iBuffer)
	{
		mp_Out[_iBuffer].m_iNextUnsent = -1;
		if (mp_iUnsentTail >= 0)
			mp_Out[umint(mp_iUnsentTail)].m_iNextUnsent = int32(_iBuffer);
		else
			mp_iUnsentHead = int32(_iBuffer);
		mp_iUnsentTail = int32(_iBuffer);
	}

	void CSSLTransport::fp_PushUnsentFront(umint _iBuffer)
	{
		mp_Out[_iBuffer].m_iNextUnsent = mp_iUnsentHead;
		mp_iUnsentHead = int32(_iBuffer);
		if (mp_iUnsentTail < 0)
			mp_iUnsentTail = int32(_iBuffer);
	}

	umint CSSLTransport::fp_DequeueUnsentHead()
	{
		DMibFastCheck(mp_iUnsentHead >= 0);

		umint iBuffer = umint(mp_iUnsentHead);
		mp_iUnsentHead = mp_Out[iBuffer].m_iNextUnsent;
		if (mp_iUnsentHead < 0)
			mp_iUnsentTail = -1;
		mp_Out[iBuffer].m_iNextUnsent = -1;

		return iBuffer;
	}

	// Reuse the newest free generation for cache locality; grow only when the window needs another.
	umint CSSLTransport::fp_TakeFreeEntry()
	{
		if (mp_iFreeHead >= 0)
		{
			umint iBuffer = umint(mp_iFreeHead);
			mp_iFreeHead = mp_Out[iBuffer].m_iNextFree;
			mp_Out[iBuffer].m_iNextFree = -1;

			return iBuffer;
		}

		umint iBuffer = mp_Out.f_GetLen();
		mp_Out.f_SetLen(iBuffer + 1);

		return iBuffer;
	}

	void CSSLTransport::fp_NoteFillGained(umint _nBytes)
	{
		COut &Buffer = mp_Out[mp_iOutFill];
		bool bHadUnsent = Buffer.m_iSent < Buffer.m_nFill;

		Buffer.m_nFill += _nBytes;
		mp_nPendingWrite += _nBytes;
		mp_nPendingWriteUnpinned += _nBytes;

		if (!bHadUnsent && _nBytes)
			fp_EnqueueUnsent(mp_iOutFill);
	}

	bool CSSLTransport::fp_IsPinned(umint _iBuffer) const
	{
		return mp_Out[_iBuffer].m_nPinnedBytes != 0;
	}

	void CSSLTransport::fp_AdvanceFill()
	{
		mp_iOutFill = fp_TakeFreeEntry();
	}

	void CSSLTransport::fp_EnsureFillWritable()
	{
		COut &Buffer = mp_Out[mp_iOutFill];

		if (!Buffer.m_pData || !Buffer.m_pData.f_GetRefCount())
			return;

		DMibFastCheck(Buffer.m_nFill == Buffer.m_iSent);

		// Reuse displaced storage only after its kernel pin has been released.
		if (mp_pOutRetired && !mp_pOutRetired.f_GetRefCount())
			fg_Swap(Buffer.m_pData, mp_pOutRetired);
		else
		{
			mp_pOutRetired = Buffer.m_pData;
			Buffer.m_pData = fg_Construct();
		}

		Buffer.m_nFill = 0;
		Buffer.m_iSent = 0;
	}

	// On stalls, move only the unsent suffix down to reuse the sent prefix.
	void CSSLTransport::fp_Compact()
	{
		COut &Buffer = mp_Out[mp_iOutFill];

		if (!Buffer.m_iSent)
			return;

		umint nPending = Buffer.m_nFill - Buffer.m_iSent;

		if (nPending)
			NMemory::fg_MemMove(Buffer.m_pData->f_GetArray(), Buffer.m_pData->f_GetArray() + Buffer.m_iSent, nPending);

		Buffer.m_nFill = nPending;
		Buffer.m_iSent = 0;
	}

	// Retain peak per-generation capacity so steady sends avoid reallocating.
	void CSSLTransport::fp_Reserve(umint _nBytes)
	{
		COut &Buffer = mp_Out[mp_iOutFill];

		if (!Buffer.m_pData)
			Buffer.m_pData = fg_Construct();

		if (Buffer.m_pData->f_GetLen() < Buffer.m_nFill + _nBytes)
			Buffer.m_pData->f_SetLen(Buffer.m_nFill + _nBytes, false);
	}

	void CSSLTransport::fp_Append(void const *_pData, umint _nBytes)
	{
		fp_EnsureFillWritable();
		fp_Compact();
		fp_Reserve(_nBytes);

		COut &Buffer = mp_Out[mp_iOutFill];
		NMemory::fg_MemCopy(Buffer.m_pData->f_GetArray() + Buffer.m_nFill, (uint8 const *)_pData, _nBytes);
		fp_NoteFillGained(_nBytes);
	}
}
