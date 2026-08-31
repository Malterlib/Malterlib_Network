// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Network_SSLTransport.h"

#include <Mib/Cryptography/BoringSSL>

namespace NMib::NNetwork
{
	// Loop buffers still queued go home when the connection dies mid-stream: their pool
	// waits for every hold, and nothing would consume them anymore
	CSSLTransport::CSSLTransport()
	{
		// The fill; its buffer comes with the first seal
		mp_Out.f_SetLen(1);
	}

	CSSLTransport::~CSSLTransport()
	{
		f_ClearCipherQueue();
	}

	// Inbound ciphertext arrives as a stream of segments — loop-owned buffers in
	// completion mode, this transport's own in readiness mode — and completion mode may
	// not read the socket itself: the standing kernel receive is the only reader
	void CSSLTransport::f_SetCompletionSend(bool _bCompletionSend)
	{
		mp_bCompletionSend = _bCompletionSend;
	}

	void CSSLTransport::f_SetCompletionReceive(bool _bCompletionReceive)
	{
		mp_bCompletionReceive = _bCompletionReceive;
	}

	// How many un-released send generations this connection actually allows. One
	// reproduces the unpipelined path
	void CSSLTransport::f_SetSendDepth(umint _nDepth)
	{
		mp_nSendDepth = fg_Clamp(_nDepth, umint(1), mc_nMaxSendDepth);
	}

	umint CSSLTransport::f_GetSendDepth() const
	{
		return mp_nSendDepth;
	}

	// The bytes a socket that releases its sends only at the peer's acknowledgement lets this
	// connection keep pinned. Nothing is allocated for it: generations come into being as the
	// window actually fills. Set once, before the first operation pins anything
	void CSSLTransport::f_SetSendWindow(umint _nBytes)
	{
		DMibFastCheck(!mp_nPinned);

		mp_nSendWindowBytes = _nBytes;
	}

	void CSSLTransport::f_ConsiderSendWindowGrowth()
	{
		fp_ConsiderSendWindowGrowth();
	}

	// What still needs an operation of its own: unsent bytes in generations no operation
	// carries. Pinned generations' bytes are with their operations already — several fly at
	// once — and counting them here would have the drain spin submitting continuations that
	// find nothing to pin
	umint CSSLTransport::f_GetPendingWriteUnpinned() const
	{
		return mp_nPendingWriteUnpinned;
	}

	void CSSLTransport::f_SetSocket(CSocket *_pSocket)
	{
		mp_pSocket = _pSocket;
	}

	// While this is set the records the library produces stay here instead of leaving one
	// transport write each, which is what turns a gather of queued messages into one write.
	// The library never pushes them out on its own: it flushes the write side for handshake
	// flights and for fatal alerts and nowhere else, so what opened the deferral is the only
	// thing that can close it, and it has to close it on every path
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
		umint nPending = 0;
		for (COut const &Buffer : mp_Out)
			nPending += Buffer.m_nFill - Buffer.m_iSent;

		return nPending;
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

	// Set once a transport call has failed. The failure is carried out through the return
	// values rather than thrown, because nothing may unwind through the library's frames,
	// and it is reported once the SSL call the transport was serving has returned
	NStr::CStr const &CSSLTransport::f_GetTransportError() const
	{
		return mp_TransportError;
	}

	// Serves the library out of the same ciphertext the record layer opens in place, so
	// there is one inbound buffer however the connection is being driven. Without that a
	// call that fell back to the library would read past bytes already held here
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

		// The record is always taken. Refusing one makes the library pin exactly how many
		// bytes the retry has to offer (s3_pkt.cc:133, and tls_write_app_data through
		// unreported_bytes_written), and a sender that coalesces queued messages into one
		// write cannot promise to rebuild that same chunk: the queue it gathers from has
		// moved on, and offering fewer bytes is BAD_WRITE_RETRY. So back pressure lives
		// above the library instead, where f_IsSendBufferFull stops the next chunk from
		// being handed over at all
		fp_Append(_pData, _nBytes);
		o_nWritten = _nBytes;

		// Outside a deferral the record leaves as it is produced; inside one the cap still
		// forces an attempt, bounding what a peer that stopped reading makes this hold.
		// Never under completion sends: submitted operations are then the only writer,
		// and a synchronous flush would put ciphertext on the wire no operation carries
		if (!mp_bCompletionSend && (!mp_bDeferFlush || f_GetPendingWrite() >= mp_nOutboundCap))
			f_Flush();

		return ETransferResult::mc_Data;
	}

	CSSLTransport::ETransferResult CSSLTransport::f_Flush()
	{
		if (mp_TransportError)
			return ETransferResult::mc_Failed;

		// Nothing may go out around a submitted send. Its bytes are the older ones and are
		// already with the kernel, so writing anything here would put a later record on the
		// wire first and the peer would reject the stream. What is waiting is picked up by
		// the completion instead, which resumes from the oldest buffer that still holds
		if (mp_nPinned)
			return ETransferResult::mc_WouldBlock;

		// Oldest first, so records leave in the order they were sealed
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

			// Drained, so the fill goes back to the start. The allocation stays: it is what
			// the records are staged in, and a connection that has sent once will send
			// again, where giving it up here would mean allocating one per flush
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

	// Names the pending bytes for a submitted send and pins them: the oldest generation no
	// operation carries, so records leave in the order they were sealed. When it is the fill,
	// the fill moves to a free entry so later seals land and leave after them. The window caps
	// what may await release at once
	bool CSSLTransport::f_BeginSend(void const *&o_pData, umint &o_nBytes, umint &o_iBuffer)
	{
		if (mp_TransportError || mp_iUnsentHead < 0)
			return false;

		// Every buffer pinned while more wants to go out is the moment to ask the path
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

		// Sealing may not land in what the kernel is reading. The pool may grow here, so
		// nothing above is touched past this point
		if (iBuffer == mp_iOutFill)
			fp_AdvanceFill();

		return true;
	}

	// Gives one buffer back without any of it having been sent, for a send that was never
	// accepted. The fill is left where f_BeginSend moved it; the generation goes back to the
	// head of the unsent list, so what was not sent is still what goes out next
	void CSSLTransport::f_AbortSend(umint _iBuffer)
	{
		fp_ReleasePin(_iBuffer);
	}

	// What the kernel took, into the accounting. The pin stays: it is released by the
	// operation's buffer-released notification, which for a zero copy send comes only
	// when the peer has acknowledged the pages — until then the buffer may be read (a
	// short send's remainder goes out from it) but not written
	bool CSSLTransport::f_SendCompleted(umint _iBuffer, umint _nBytes)
	{
		DMibFastCheck(fp_IsPinned(_iBuffer));

		COut &Buffer = mp_Out[_iBuffer];
		Buffer.m_iSent += _nBytes;
		mp_nBytesSent += _nBytes;
		mp_nPendingWrite -= _nBytes;

		if (Buffer.m_iSent >= Buffer.m_nFill)
		{
			Buffer.m_iSent = 0;
			Buffer.m_nFill = 0;

			return true;
		}

		return false;
	}

	// The generation new seals land in, which is what names the operation their caller's
	// transfer resolves with
	umint CSSLTransport::f_GetFillBuffer() const
	{
		return mp_iOutFill;
	}

	// The operation's buffer-released notification: the kernel no longer references the
	// buffer and it may be filled again. Tolerates a pin already gone — a send that was
	// never accepted gave its pin back through f_AbortSend, and its release still runs
	void CSSLTransport::f_ReleaseSendBuffer(umint _iBuffer)
	{
		fp_ReleasePin(_iBuffer);
	}

	bool CSSLTransport::f_IsSendPinned() const
	{
		return mp_nPinned != 0;
	}

	// Which generation the next begin would pin: the oldest with unsent bytes that no
	// operation carries, or -1. What lets a submitter tell whether its own seal is next in
	// line — an older generation ahead of it must leave first, under its own operation.
	// Several fly at once and none of them ever reports short, so a pinned generation's
	// unsent bytes belong to the operation already carrying it and are never next
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

	// What the kernel is reading, as something that keeps it alive on its own. The socket
	// can be torn down while an operation is still outstanding, and the completion runs
	// after that, so the memory cannot belong to the socket
	NStorage::TCSharedPointer<NContainer::CByteVector> CSSLTransport::f_GetPinnedKeepAlive(umint _iBuffer) const
	{
		DMibFastCheck(fp_IsPinned(_iBuffer));

		return mp_Out[_iBuffer].m_pData;
	}

	// Hands the caller room to seal records into. The bytes land in the same buffer the
	// flush drains, so a sealed batch and whatever the library wrote through the BIO leave
	// in one write, in the order they were produced
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

	// Sized from what the consumer says one transfer is worth, so raising the WebSocket's
	// fragmentation size deepens batching without touching the record logic.
	// The record layer's own framing rides on top of what the caller asks to carry, so
	// the cap and the buffers allow for it — without the allowance a full fragment's
	// ciphertext crosses the cap and splits into a maximum send plus a tail
	umint CSSLTransport::fsp_RecordFramingAllowance(umint _nBytes)
	{
		return _nBytes / 256 + 512;
	}

	void CSSLTransport::f_SetOutboundCap(umint _nBytes)
	{
		mp_nOutboundCap = fg_Max(_nBytes + fsp_RecordFramingAllowance(_nBytes), mc_nOutboundBufferCap);
	}

	// Ciphertext for the record layer to open in place, in two buffers that take turns. A
	// record left incomplete by one read stays where it lies and is named as the first of
	// two fragments next time, so nothing is moved to make it contiguous. Each buffer holds
	// a whole record, so an incomplete tail plus a full buffer always covers one
	void CSSLTransport::f_SetInboundSize(umint _nBytes)
	{
		mp_nCipherSize = fg_Max(_nBytes + fsp_RecordFramingAllowance(_nBytes), mc_nInboundBufferSize);
	}

	// Reads into this transport's own fill buffer and appends the bytes to the ciphertext
	// queue. The caller then opens records from everything queued together
	CSSLTransport::ETransferResult CSSLTransport::f_FillCipher()
	{
		if (mp_TransportError)
			return ETransferResult::mc_Failed;

		// The standing kernel receive is the only reader in completion mode; reading here
		// would put two readers on one descriptor. The bytes already queued are still
		// served — this only says no more can be fetched, which is what the handshake and
		// shutdown paths do with a transport that has nothing for them yet
		if (mp_bCompletionReceive)
			return ETransferResult::mc_WouldBlock;

		if (mp_bEndOfStream || !f_HasSocket())
			return ETransferResult::mc_EndOfStream;

		// The fill buffer can only be recycled or resized while nothing in the queue
		// points into it
		if (!fp_GetCipherQueueLen())
		{
			mp_CipherQueue.f_Clear();
			mp_iCipherHead = 0;
			mp_nCipherFillUsed = 0;

			if (!mp_pCipherFill)
				mp_pCipherFill = fg_Construct();
			if (mp_pCipherFill->f_GetLen() < mp_nCipherSize)
				mp_pCipherFill->f_SetLen(mp_nCipherSize, false);
		}
		else if (!mp_pCipherFill || mp_nCipherFillUsed >= mp_pCipherFill->f_GetLen())
		{
			// Exhausted while older bytes are still being read: a fresh buffer continues
			// the stream, and the queued pieces keep the old one alive
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

	// Extends the queue's tail piece when the new bytes continue it, so consecutive reads
	// stay one piece; a fresh buffer starts a new one
	void CSSLTransport::fp_AppendOwnedCipher(umint _nRead)
	{
		uint8 const *pStart = mp_pCipherFill->f_GetArray() + mp_nCipherFillUsed;
		mp_nCipherFillUsed += _nRead;

		if (fp_GetCipherQueueLen())
		{
			CCipherSegment &Tail = mp_CipherQueue[mp_CipherQueue.f_GetLen() - 1];
			if (Tail.m_pOwned == mp_pCipherFill && Tail.m_pData + Tail.m_nBytes == pStart)
			{
				Tail.m_nBytes += _nRead;
				return;
			}
		}

		CCipherSegment Segment;
		Segment.m_pData = pStart;
		Segment.m_nBytes = _nRead;
		Segment.m_pOwned = mp_pCipherFill;
		mp_CipherQueue.f_Insert(fg_Move(Segment));
	}

	// Plaintext that had nowhere to go. A record decrypts as one piece, and what it
	// produces can be a little more than the caller asked for, so when the destination
	// cannot take a whole record it is opened here instead and handed over across calls.
	// Bounded by one record, and only used when the destination is nearly full
	uint8 *CSSLTransport::f_BeginHold(umint &o_nRoom)
	{
		// Opening into the hold discards what it had, so a caller that has not drained it
		// would lose plaintext it already reported. f_TryOpenInto serves the hold first,
		// which is what makes this hold
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

	// One piece of the receive stream, appended in arrival order with the reference that
	// keeps it alive. Nothing is scarce here: the buffer frees itself when the queue and
	// every other holder are done with it, so there is no pool to preserve and no copy
	// to make
	void CSSLTransport::f_AppendCipherSegment(void const *_pData, umint _nBytes, NStorage::TCSharedPointer<CVirtualDestroyBase const> &&_pOwner)
	{
		mp_nBytesReceived += _nBytes;

		CCipherSegment Segment;
		Segment.m_pData = (uint8 const *)_pData;
		Segment.m_nBytes = _nBytes;
		Segment.m_pOwner = fg_Move(_pOwner);
		mp_CipherQueue.f_Insert(fg_Move(Segment));
	}

	// Called when opening produced nothing — an incomplete record — while stream buffers
	// sit in the queue. Their capacity is charged against the connection's receive
	// window, and a window parked over those charges would never see the bytes that
	// complete the record: copying the pieces into owned storage and dropping the owners
	// releases the charges and lets the stream continue. Keyed on the no-progress call,
	// so an ordinary straddle — completed by the very next delivery — never pays the copy
	void CSSLTransport::f_CompactCipherIfStalled()
	{
		bool bOwners = false;
		for (umint iSegment = mp_iCipherHead; iSegment < mp_CipherQueue.f_GetLen(); ++iSegment)
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

		umint nTotal = f_GetCipherPending();

		auto pCompact = NStorage::TCSharedPointer<NContainer::CByteVector>(fg_Construct());
		pCompact->f_SetLen(fg_Max(nTotal, mp_nCipherSize), false);

		umint nUsed = 0;
		for (umint iSegment = mp_iCipherHead; iSegment < mp_CipherQueue.f_GetLen(); ++iSegment)
		{
			CCipherSegment const &Segment = mp_CipherQueue[iSegment];
			NMemory::fg_MemCopy(pCompact->f_GetArray() + nUsed, Segment.m_pData, Segment.m_nBytes);
			nUsed += Segment.m_nBytes;
		}

		mp_CipherQueue.f_Clear();
		mp_iCipherHead = 0;

		if (nUsed)
		{
			CCipherSegment Segment;
			Segment.m_pData = pCompact->f_GetArray();
			Segment.m_nBytes = nUsed;
			Segment.m_pOwned = fg_Move(pCompact);
			mp_CipherQueue.f_Insert(fg_Move(Segment));
		}

		// The owned fill continues after the compacted bytes, in fresh storage
		mp_pCipherFill.f_Clear();
		mp_nCipherFillUsed = 0;
	}

	umint CSSLTransport::fp_GetCipherQueueLen() const
	{
		return mp_CipherQueue.f_GetLen() - mp_iCipherHead;
	}

	// The ciphertext held, as the pieces it lies in, oldest first. A record can run from
	// one piece into the next, so all of them are offered together; the head piece's
	// advanced start is the carry, with nothing separate to track
	umint CSSLTransport::f_GetCipherFragments(CRYPTO_IVEC *o_pFragments) const
	{
		umint nFragments = 0;

		for (umint iSegment = mp_iCipherHead; iSegment < mp_CipherQueue.f_GetLen() && nFragments < mc_nMaxCipherFragments; ++iSegment)
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

		for (umint iSegment = mp_iCipherHead; iSegment < mp_CipherQueue.f_GetLen(); ++iSegment)
			nPending += mp_CipherQueue[iSegment].m_nBytes;

		return nPending;
	}

	// Retires what the record layer took, oldest piece first. A fully consumed loop
	// buffer goes back to its pool here, which is what lets the kernel keep receiving
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
		{
			mp_CipherQueue.f_Clear();
			mp_iCipherHead = 0;
			mp_nCipherFillUsed = 0;
		}
	}

	// Drops every piece still queued, for a connection being torn down; the references
	// falling is all the releasing there is
	void CSSLTransport::f_ClearCipherQueue()
	{
		mp_CipherQueue.f_Clear();
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

	// Releases the named generation from its operation. Tolerates a pin already gone — a send
	// that was never accepted gave its pin back through f_AbortSend, and its release still
	// runs. A generation with bytes still unsent goes back to the head of the unsent list, being
	// the oldest; a drained one goes to the free entries, newest first
	void CSSLTransport::fp_ReleasePin(umint _iBuffer)
	{
		COut &Buffer = mp_Out[_iBuffer];
		if (!Buffer.m_nPinnedBytes)
			return;

		// The release latency feeds the window's sliding minimum: the lag of a release that
		// met no self-queueing is what the growth target multiplies the delivery rate by
		if (Buffer.m_PinStamp)
		{
			fp_EnsureWindowTicks();

			uint64 Now = fsp_NowTicks();
			if (!mp_LagEpochStamp || Now - mp_LagEpochStamp >= mp_WindowShrinkAfterTicks)
			{
				mp_MinReleaseLagTicks[1] = mp_MinReleaseLagTicks[0];
				mp_MinReleaseLagTicks[0] = 0;
				mp_LagEpochStamp = Now;
			}

			uint64 LagTicks = Now - Buffer.m_PinStamp;
			if (!mp_MinReleaseLagTicks[0] || LagTicks < mp_MinReleaseLagTicks[0])
				mp_MinReleaseLagTicks[0] = LagTicks;

			Buffer.m_PinStamp = 0;
		}

		--mp_nPinned;
		mp_nPinnedBytes -= Buffer.m_nPinnedBytes;
		Buffer.m_nPinnedBytes = 0;

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
		if (!mp_nSendWindowBytes)
			return mp_nPinned >= f_GetSendDepth();

		return mp_nPinnedBytes >= fp_GetEffectiveSendWindow();
	}

	umint CSSLTransport::fp_GetEffectiveSendWindow() const
	{
		// The window a connection begins at: one generation, which the path grows past only
		// when its bandwidth-delay product asks
		umint nFloor = fg_Min(mp_nSendWindowBytes, mp_nOutboundCap);
		if (!mp_nWindowEffective)
			return nFloor;

		return fg_Clamp(mp_nWindowEffective, nFloor, mp_nSendWindowBytes);
	}

	uint64 CSSLTransport::fsp_NowTicks()
	{
		return uint64(NTime::NPlatform::fg_TimerRaw_PreciseGet());
	}

	// The cap is binding and more wants out. The kernel's delivery rate times the least release
	// latency this connection has observed, plus a quarter and two frames of margin, is what the
	// cap grows toward — by no more than a doubling per query, so one odd reading cannot open it
	// wide. A product at or under the cap leaves it where it is: the pipeline then keeps running
	// dry, which is what lets the release notifications through. A product under three quarters
	// of the cap for a whole second brings the cap down to it, and nothing is moved for that:
	// pins above it are simply not replaced as their releases arrive. A rate the kernel says the
	// sender held back never shrinks anything — a small cap would then read as a small path
	void CSSLTransport::fp_EnsureWindowTicks()
	{
		if (mp_WindowQueryIntervalTicks)
			return;

		uint64 Frequency = uint64(NTime::NPlatform::fg_TimerRaw_PreciseFrequency());
		mp_WindowQueryIntervalTicks = Frequency / 100;
		mp_WindowShrinkAfterTicks = Frequency;
		mp_WindowTicksPerSecond = Frequency;
	}

	void CSSLTransport::fp_ConsiderSendWindowGrowth()
	{
		if (!mp_pSocket)
			return;

		// The path is asked at most every 10 ms, and the cap shrinks only once the target has
		// stayed low for a second
		fp_EnsureWindowTicks();

		uint64 Now = fsp_NowTicks();
		if (mp_WindowQueryStamp && Now - mp_WindowQueryStamp < mp_WindowQueryIntervalTicks)
			return;
		mp_WindowQueryStamp = Now;

		umint nDeliveryRate = 0;
		bool bAppLimited = false;
		if (!mp_pSocket->f_QueryPathDeliveryRate(nDeliveryRate, bAppLimited))
			return;

		// The delivery rate times the least release latency observed is what must stay pinned
		// for the pipeline to never run dry of it; the least lag rather than the average keeps
		// the product from chasing its own queue
		uint64 nLagTicks = mp_MinReleaseLagTicks[0];
		if (mp_MinReleaseLagTicks[1] && (!nLagTicks || mp_MinReleaseLagTicks[1] < nLagTicks))
			nLagTicks = mp_MinReleaseLagTicks[1];

		umint nBandwidthDelay = umint(uint64(nDeliveryRate) * nLagTicks / mp_WindowTicksPerSecond);

		umint nCap = fp_GetEffectiveSendWindow();
		umint nTarget = fg_Min(nBandwidthDelay + nBandwidthDelay / 4 + 2 * mp_nOutboundCap, mp_nSendWindowBytes);
		if (nTarget > nCap)
		{
			mp_nWindowEffective = fg_Min(nTarget, nCap * 2);
			mp_WindowShrinkSince = 0;
		}
		else if (bAppLimited || nTarget >= nCap - nCap / 4)
			mp_WindowShrinkSince = 0;
		else
		{
			if (!mp_WindowShrinkSince)
				mp_WindowShrinkSince = Now;
			mp_nWindowShrinkTarget = nTarget;
			if (Now - mp_WindowShrinkSince >= mp_WindowShrinkAfterTicks)
			{
				mp_nWindowEffective = mp_nWindowShrinkTarget;
				mp_WindowShrinkSince = 0;
			}
		}

	#if DMibConfig_IoDebug_Enable
		if (auto *pStats = fg_NetIoStats())
		{
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

	// A free generation, the most recently released one first, or a new one when every entry
	// is with the kernel: the pool only ever grows to what the window has needed
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

	// Bytes sealed into the fill. The first of them puts the fill at the tail of the unsent list
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

	// Whether an operation is still reading this buffer
	bool CSSLTransport::fp_IsPinned(umint _iBuffer) const
	{
		return mp_Out[_iBuffer].m_nPinnedBytes != 0;
	}

	// Moves the fill to a generation no operation is reading
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

		// The buffer swapped out last time comes back once its operation has let go, so a
		// connection sending steadily stops allocating here after the first time
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

	// Only the unsent tail is worth keeping, and it moves down to the start rather than
	// being removed from the front, so the sent prefix is reused instead of the buffer
	// being reshaped around it. This is the stalled path only: a flush that drained has
	// already put the fill back at the start
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

	// Grows to what the connection has needed and stays there, so steady state stops
	// allocating entirely. What it holds is one gather's worth: on the readiness path the
	// outbound cap bounds that, and on the submitted path it is whatever the caller
	// offered in one call, because those records share a single write
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
