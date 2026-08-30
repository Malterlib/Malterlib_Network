// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Concurrency/ConcurrencyManager>
#include <Mib/Concurrency/Actor/Timer>
#include <Mib/Concurrency/ActorSubscription>
#include <Mib/Container/PagedByteVector>
#include <Mib/Cryptography/Exception>
#include <Mib/Concurrency/IoCompletionOpTracker>

#include <deque>

#include "Malterlib_Network_AsyncSocket.h"

#if defined(DCompiler_clang) && !defined(DPlatformFamily_Emscripten)
#	define DEnableVector
#endif

#ifdef DEnableVector
using vec4uint32 = uint32 __attribute__((ext_vector_type(4)));
#endif

namespace NMib::NNetwork
{
	namespace
	{
		enum EState
		{
			EState_None
			, EState_Connected
			, EState_Disconnected
		};

		enum EIncomingDataResult
		{
			EIncomingDataResult_Continue
			, EIncomingDataResult_ProcessIncoming
			, EIncomingDataResult_StopReceiving
		};

		struct COutgoingMessage
		{
			~COutgoingMessage()
			{
				if (m_Promise)
					m_Promise->f_SetException(DMibErrorInstance("Outgoing message abandoned"));
			}

			NContainer::CSharedByteVector m_Data;
			NStorage::TCOptionalClearOnMove<NConcurrency::TCPromise<void>> m_Promise;
		};

		// A queued send referencing the shared message buffer in place: the socket is a raw
		// byte stream with no framing, so messages are sent straight from their buffers and
		// the keep alive releases when the last byte is on the wire
		struct COutgoingSegment
		{
			NContainer::CSharedByteVector m_Data;
			umint m_iSent = 0;
		};

		struct COutgoingDataPromise
		{
			COutgoingDataPromise() = default;
			COutgoingDataPromise(COutgoingDataPromise &&) = default;

			~COutgoingDataPromise()
			{
				if (m_Promise)
					m_Promise->f_SetException(DMibErrorInstance("Outgoing message abandoned"));
			}

			uint64 m_Position = 0;
			NStorage::TCOptionalClearOnMove<NConcurrency::TCPromise<void>> m_Promise;
		};

		struct CNotifyClose
		{
			EAsyncSocketStatus m_Status;
			NStr::CStr m_Message;
			EAsyncSocketCloseOrigin m_Origin;
		};

		constexpr static umint gc_IncomingPageSize = 2048;
		constexpr static umint gc_CopySmallDeliveryThreshold = 1024;
	}

	struct CAsyncSocketActor::CInternal
	{
		// The io subsystem, cached since each access through the getter is an atomic operation
		NMib::NSys::CIoSubSystem *mp_pIo = &NMib::NSys::fg_IoSubSystem();

		// What each operation in flight took. Addressed rather than ordered, because
		// operations do not always report in submission order
		struct CSendReservation
		{
			umint m_nBytes:sizeof(umint) * 8 - 1 = 0;
			umint m_bInUse:1 = false;
		};

		CInternal
			(
				CAsyncSocketActor *_pThis
				, bool _bClient
				, umint _MaxMessageSize
				, umint _FragmentationSize
				, fp64 _Timeout
				, FAsyncSocketUpgradeCheck &&_fCheckUpgrade
			)
			: m_pThis(_pThis)
			, m_IncomingData(gc_IncomingPageSize)
			, m_UpgradeCheckData(gc_IncomingPageSize)
			, m_fCheckUpgrade(fg_Move(_fCheckUpgrade))
			, m_bClient(_bClient)
			, m_MaxMessageSize(_MaxMessageSize)
			// Bounded so every gather size derived from it fits the reservation bit field,
			// on 32 bit platforms included
			, m_FramentationSize(fg_Min(_FragmentationSize, umint(1) << 30))
			, m_Timeout(_Timeout)
		{
		}

		~CInternal()
		{
			DMibFastCheck(!m_bDestroyed || m_OutgoingDataPromises.empty());
			DMibFastCheck(!m_bDestroyed || m_PendingMessages.f_IsEmpty());

			if (m_ClosePromise)
				m_ClosePromise->f_SetException(DMibErrorInstance("Abandoned close"));
			if (m_UpgradeSocketPromise)
				m_UpgradeSocketPromise->f_SetException(DMibErrorInstance("Abandoned socket upgrade"));
		}

		void f_OnReceivedData();
		void f_OnSentData();

		void f_UpdateTimeout();
		void f_SetupTimeout();
		void f_StopTimeout();

		void f_ShutdownDone(NStr::CStr const &_Error);

		void f_HandleDataMessage(NContainer::CSharedByteVector &&_Data);
		void f_DeliverReceiveBuffer();
		bool f_HasBufferedReceive() const;
		EIncomingDataResult f_CheckIncomingData();
		EIncomingDataResult f_HandleIncomingData(uint8 const *_pData, umint _nBytes);
		void f_MoveUpgradeCheckDataToIncoming(umint _nBytes);
		void f_MoveAllUpgradeCheckDataToIncoming();
		void f_FinishConnection();

		COutgoingMessage &f_QueueMessage(NContainer::CSharedByteVector const &_Data, uint32 _Priority);
		void f_WriteQueuedMessages();

		NNetwork::ICSocketCompletionIo *f_GetCompletionIo();
		NNetwork::ICSocketCompletionIo *f_GetCompletionIoSend();
		NNetwork::ICSocketCompletionIo *f_GetCompletionIoReceive();

		umint f_GatherSendSpans(NSys::CIoSpan *o_pSpans, umint &o_nSpans, NContainer::TCVector<NContainer::CSharedByteVector> &o_KeepAlives);
		void f_ConsumeSentBytes(umint _nSentBytes);
		void f_ReleaseTransferState();
		void f_TryReleaseDeferredTransferState();

		void f_NotifyClose(EAsyncSocketStatus _Status, NStr::CStr const &_Message, EAsyncSocketCloseOrigin _Origin);

		CAsyncSocketActor *m_pThis = nullptr;
		NStorage::TCUniquePointer<NNetwork::ICSocket> m_pSocket;
		NMib::NNetwork::CNetAddress m_PeerAddress;

		EState m_State = EState_None;

		NContainer::CPagedByteVector m_IncomingData;
		NContainer::CPagedByteVector m_UpgradeCheckData;

		// Connected state delivery target: the stream's bytes are turned into plaintext (or
		// copied) here and the buffer is handed to the receive callback whole, which moves the
		// allocation rather than the bytes. One suffices — segments arrive and are resolved in
		// stream order on this thread, and the kernel's buffers are the loop's, not this one
		NContainer::CIOByteVector m_ReceiveData;
		umint m_nReceiveFill = 0;
		FAsyncSocketUpgradeCheck m_fCheckUpgrade;
		NContainer::TCLinkedList<COutgoingSegment> m_OutgoingSegments;
		// Unsent bytes across all outgoing segments. This counts the logical bytes a view segment
		// refers to rather than bytes this connection allocated, so a shared payload queued many
		// times can push it past what a 32 bit umint would hold
		uint64 m_nOutgoingQueuedBytes = 0;
		std::deque<COutgoingDataPromise> m_OutgoingDataPromises;

		CAsyncSocketActor::CCloseInfo m_CloseInfo;

		NContainer::TCMap<uint32, NContainer::TCLinkedList<COutgoingMessage>> m_PendingMessages;

		NStorage::TCOptionalClearOnMove<NConcurrency::TCPromise<CAsyncSocketActor::CCloseInfo>> m_ClosePromise;
		NContainer::TCLinkedList<NFunction::TCFunction<void (NStr::CStr const &_Error)>> m_OnShutdown;

		CAsyncSocketCallbacks m_Callbacks;
		NContainer::TCVector<NContainer::CSharedByteVector> m_DeferredOnReciveData;
		CNotifyClose m_DeferredNotifyClose;

		NConcurrency::TCPromise<CFinishConnectionResult> m_FinishConnectionPromise;
		NStorage::TCOptionalClearOnMove<NConcurrency::TCPromise<NStorage::TCUniquePointer<NNetwork::ICSocketConnectionInfo>>> m_UpgradeSocketPromise;

		NConcurrency::CActorSubscription m_TimeoutTimerSubscription;
		NTime::CStopwatch m_TimeoutReceivedData;
		NTime::CStopwatch m_TimeoutSentData;
		NStorage::TCSharedPointer<NConcurrency::CIoCompletionOpTracker> m_pOpTracker;

		// Taken once, when completion transfers are activated. The socket cannot be replaced
		// past that point (an upgrade is ruled out before activation), and a completion still
		// has to be resolved through the same implementation after it has stopped offering
		// the mode
		NNetwork::ICSocketCompletionIo *m_pCompletionIo = nullptr;

		// The stream's flow-control accounting, shared with every buffer it has delivered
		NStorage::TCSharedPointer<NSys::CIoStreamBackpressure> m_pReceiveBackpressure;

		fp64 m_Timeout = 0.0;
		umint m_TimeoutTimerSubscriptionSequence = 0;
		uint64 m_nSentBytes = 0;

		umint m_MaxMessageSize = 0;
		umint m_FramentationSize = 0;

		// Sends with the socket right now; one at most, which is what keeps the stream in
		// order with no ordering protocol between operations
		umint m_nSendOpsInFlight = 0;

		// Plaintext handed to operations that have not reported yet, so a second operation
		// cannot gather bytes the first is already carrying
		umint m_nOutgoingSubmitted = 0;

		static constexpr umint mc_nMaxSendReservations = 8;
		CSendReservation m_SendReservations[mc_nMaxSendReservations];

		NNetwork::ENetTCPState m_DeferredTCPState = NNetwork::ENetTCPState_None;
		NNetwork::ENetTCPState m_PendingProcessState = NNetwork::ENetTCPState_None;
		// Close-class states reported while a receive operation was in flight; they wait for
		// its data, which can hold the peer's close frame
		NNetwork::ENetTCPState m_DeferredCloseStates = NNetwork::ENetTCPState_None;

		bool m_bClient = false;
		bool m_bInProcessState = false;
		bool m_bOnCloseCalled = false;
		bool m_bDeferringCallbacks = true;
		bool m_bUpgradeRequired = false;
		bool m_bShutdownCalled = false;
		bool m_bCompletionIo = false;

		// The acknowledge-first handoff suspends f_UpgradeSocket between consuming the old
		// transport and adopting the handle; close and further upgrades reject while it is set

		// The standing receive: started once, ended by exactly one terminal segment. While
		// active and unended, close-class poll states wait for it — it still holds the bytes
		// that precede the close, and it always terminates once the peer is gone
		bool m_bReceiveStreamActive = false;
		bool m_bReceiveStreamEnded = false;

		bool m_bDeferredShutdownCleanup = false;
#if DMibConfig_Tests_Enable
		bool m_bDebugNoProcessing = false;
		// Segments parked unprocessed while the test hook holds delivery; their buffer capacity
		// stays charged against the stream's window, which pauses the stream exactly like
		// unprocessed bytes paused the readiness path
		NContainer::TCVector<NSys::CIoStreamSegment> m_DebugHeldSegments;
#endif
#if DMibEnableSafeCheck > 0
		bool m_bDestroyed = false;
#endif
	};

	CAsyncSocketActor::CAsyncSocketActor(bool _bClient, umint _MaxMessageSize, umint _FragmentationSize, fp64 _Timeout, FAsyncSocketUpgradeCheck &&_fCheckUpgrade)
		: mp_pInternal(fg_Construct(this, _bClient, _MaxMessageSize, _FragmentationSize, _Timeout, fg_Move(_fCheckUpgrade)))
	{
		auto &Internal = *mp_pInternal;
		Internal.f_SetupTimeout();
	}

	CAsyncSocketActor::~CAsyncSocketActor()
	{
	}

	// The socket's completion transfer interface; null when the connection runs on readiness.
	// Cached at activation — the socket cannot be replaced after that
	NNetwork::ICSocketCompletionIo *CAsyncSocketActor::CInternal::f_GetCompletionIo()
	{
		if (!m_bCompletionIo || !m_pSocket)
			return nullptr;

		return m_pCompletionIo;
	}

	// Per direction; null when that direction does not accept submits. For new submits only —
	// resolve in-flight completions through f_GetCompletionIo
	NNetwork::ICSocketCompletionIo *CAsyncSocketActor::CInternal::f_GetCompletionIoSend()
	{
		auto *pCompletionIo = f_GetCompletionIo();

		return pCompletionIo && pCompletionIo->f_SupportsCompletionSend() ? pCompletionIo : nullptr;
	}

	NNetwork::ICSocketCompletionIo *CAsyncSocketActor::CInternal::f_GetCompletionIoReceive()
	{
		auto *pCompletionIo = f_GetCompletionIo();

		return pCompletionIo && pCompletionIo->f_SupportsCompletionReceive() ? pCompletionIo : nullptr;
	}

	COutgoingMessage &CAsyncSocketActor::CInternal::f_QueueMessage
		(
			NContainer::CSharedByteVector const &_Data
			, uint32 _Priority
		)
	{
		DMibFastCheck(!m_pThis->f_IsDestroyed());

		auto &NewMessage = m_PendingMessages[_Priority].f_Insert();
		NewMessage.m_Data = _Data;

		return NewMessage;
	}

	void CAsyncSocketActor::CInternal::f_WriteQueuedMessages()
	{
		while (auto pList = m_PendingMessages.f_FindLargest())
		{
			DMibCheck(!pList->f_IsEmpty());

			auto &Pending = pList->f_GetFirst();

			umint nBytes = Pending.m_Data.f_GetLen();
			if (nBytes)
			{
				auto &Segment = m_OutgoingSegments.f_Insert();
				Segment.m_Data = Pending.m_Data;
				m_nOutgoingQueuedBytes += nBytes;
			}

			if (Pending.m_Promise)
			{
				COutgoingDataPromise Promise;
				Promise.m_Position = m_nSentBytes + m_nOutgoingQueuedBytes;
				Promise.m_Promise = fg_Move(Pending.m_Promise);
				m_OutgoingDataPromises.push_back(fg_Move(Promise));
			}

			pList->f_Remove(Pending);
			if (pList->f_IsEmpty())
				m_PendingMessages.f_Remove(pList);
		}
	}

	umint CAsyncSocketActor::CInternal::f_GatherSendSpans(NSys::CIoSpan *o_pSpans, umint &o_nSpans, NContainer::TCVector<NContainer::CSharedByteVector> &o_KeepAlives)
	{
		umint nSpans = 0;
		umint nGatheredBytes = 0;

		// One gather is one transport write, so a connection that frames at more than this would
		// otherwise have its frames split across writes for no reason. The floor keeps small
		// framing from making the gather too small to be worth the call
		umint nMaxGatherBytes = fg_Max(umint(256 * 1024), m_FramentationSize + gc_SocketFramingMargin);

		// What operations already in flight took. They report before this gather's bytes go out, so
		// the stream stays in order; what must not happen is offering their bytes a second time
		umint nSkip = m_nOutgoingSubmitted;

		for (auto &Segment : m_OutgoingSegments)
		{
			umint nAvailable = Segment.m_Data.f_GetLen() - Segment.m_iSent;
			if (nSkip >= nAvailable)
			{
				nSkip -= nAvailable;
				continue;
			}

			umint iStart = Segment.m_iSent + nSkip;
			nSkip = 0;

			// A segment holds a whole message, so it is clamped to what is left of the
			// gather budget: sockets without a vectored implementation fall back to one
			// f_Send per span, and the SSL one takes an int length
			umint nSegmentBytes = fg_Min(Segment.m_Data.f_GetLen() - iStart, nMaxGatherBytes - nGatheredBytes);

			o_pSpans[nSpans].m_pData = Segment.m_Data.f_GetArray() + iStart;
			o_pSpans[nSpans].m_nBytes = nSegmentBytes;
			nGatheredBytes += nSegmentBytes;
			++nSpans;

			// The payload has to outlive the kernel's use of these pages, which for a zero copy
			// send ends at the buffer-released notification — after the transfer was reported
			// and the segment possibly retired from the queue. The released functor carries
			// these, so consuming the queue never frees pages the kernel still references
			o_KeepAlives.f_Insert(Segment.m_Data);
			if (nSpans >= NNetwork::ICSocket::mc_MaxSendSpans || nGatheredBytes >= nMaxGatherBytes)
				break;
		}

		o_nSpans = nSpans;

		return nGatheredBytes;
	}

	void CAsyncSocketActor::CInternal::f_ConsumeSentBytes(umint _nSentBytes)
	{
		uint64 PrevSent = m_nSentBytes;
		m_nSentBytes += _nSentBytes;

		while (!m_OutgoingDataPromises.empty())
		{
			auto &Promise = m_OutgoingDataPromises.front();
			uint64 Diff = Promise.m_Position - PrevSent;
			if (Diff <= _nSentBytes)
			{
				Promise.m_Promise->f_SetResult();
				Promise.m_Promise.f_Clear();
				m_OutgoingDataPromises.pop_front();
				continue;
			}
			break;
		}

		// Consume the sent bytes across head segments; a fully sent segment releases its
		// keep alive on the shared message buffer
		m_nOutgoingQueuedBytes -= _nSentBytes;
		umint nConsumed = _nSentBytes;
		while (nConsumed)
		{
			auto &Head = m_OutgoingSegments.f_GetFirst();
			umint nHeadRemaining = Head.m_Data.f_GetLen() - Head.m_iSent;
			umint nThis = fg_Min(nConsumed, nHeadRemaining);
			Head.m_iSent += nThis;
			nConsumed -= nThis;

			if (Head.m_iSent == Head.m_Data.f_GetLen())
				m_OutgoingSegments.f_Remove(Head);
		}
	}

	void CAsyncSocketActor::CInternal::f_ReleaseTransferState()
	{
		m_OutgoingSegments.f_Clear();
		m_nOutgoingQueuedBytes = 0;
		m_nOutgoingSubmitted = 0;
		for (auto &Reservation : m_SendReservations)
			Reservation.m_bInUse = false;
		m_ReceiveData.f_Clear();
		m_nReceiveFill = 0;
#if DMibConfig_Tests_Enable
		m_DebugHeldSegments.f_Clear();
#endif
	}

	void CAsyncSocketActor::CInternal::f_TryReleaseDeferredTransferState()
	{
		if (m_nSendOpsInFlight)
			return;

		// Close states parked behind an operation are that operation's to hand back. Nothing else
		// reports them a second time, so a path that reaches here without resolving them would
		// lose the close entirely. Taken before they are acted on, so a disconnect coming back
		// through here finds nothing left to do
		NNetwork::ENetTCPState DeferredStates = m_DeferredCloseStates;
		m_DeferredCloseStates = NNetwork::ENetTCPState_None;

		if (m_bDeferredShutdownCleanup)
		{
			m_bDeferredShutdownCleanup = false;
			f_ReleaseTransferState();
		}

		// Last, because it can disconnect and leave nothing here worth touching
		if (DeferredStates)
			m_pThis->fp_ProcessState(DeferredStates);
	}

#if DMibConfig_Tests_Enable
	NConcurrency::TCFuture<void> CAsyncSocketActor::f_DebugStopProcessing(fp64 _Timeout)
	{
		if (f_IsDestroyed())
			co_return DMibErrorInstance("Destroying socket");

		auto &Internal = *mp_pInternal;
		Internal.m_bDebugNoProcessing = true;
		Internal.m_Timeout = _Timeout;
		Internal.f_SetupTimeout();

		co_return {};
	}
#endif

	NConcurrency::TCFuture<void> CAsyncSocketActor::fp_Destroy()
	{
		auto &Internal = *mp_pInternal;

#if DMibEnableSafeCheck > 0
		Internal.m_bDestroyed = true;
#endif

		if (Internal.m_pOpTracker)
		{
			// In-flight completion transfers still hold kernel references into the buffers this
			// destroy releases below. Closing the socket cancels them, and the fence resolves once
			// the last completion functor has released its hold; only then may the segments
			// and the receive buffer be dropped. The actor outlives fp_Destroy, so everything the
			// operations point into stays alive across the await
			Internal.m_pSocket.f_Clear();

			auto &Tracker = *Internal.m_pOpTracker;
			auto DrainFuture = Tracker.m_DrainPromise.f_CreateNew().f_Future();
			uint32 Previous = Tracker.m_State.f_FetchOr(NConcurrency::CIoCompletionOpTracker::mc_DrainFlag, NAtomic::gc_MemoryOrder_SequentiallyConsistent);
			if (!Previous)
				(*Tracker.m_DrainPromise).f_SetResult();

			co_await fg_Move(DrainFuture);
		}

		Internal.m_PendingMessages.f_Clear();
		Internal.m_OutgoingDataPromises.clear();
		Internal.m_OutgoingSegments.f_Clear();
		Internal.m_nOutgoingQueuedBytes = 0;
		if (Internal.m_ClosePromise)
		{
			Internal.m_ClosePromise->f_SetException(DMibErrorInstance("Abandoned close"));
			Internal.m_ClosePromise.f_Clear();
		}

		co_return {};
	}

	NConcurrency::TCFuture<NStorage::TCUniquePointer<NNetwork::ICSocketConnectionInfo>> CAsyncSocketActor::f_UpgradeSocket(NNetwork::FVirtualSocketFactory _SocketFactory, NStr::CStr _Hostname)
	{
		if (f_IsDestroyed())
			co_return DMibErrorInstance("Destroying socket");
		if (!_SocketFactory)
			co_return DMibErrorInstance("Socket upgrade requires a socket factory");

		auto &Internal = *mp_pInternal;
		if (!Internal.m_pSocket || Internal.m_State != EState_Connected)
			co_return DMibErrorInstance("Socket upgrade requires a connected socket");
		if (!Internal.m_bUpgradeRequired)
			co_return DMibErrorInstance("Socket upgrade requires CAsyncSocketClientActor::f_SetDefaultUpgradeCheckFactory or CAsyncSocketServerActor::f_SetDefaultUpgradeCheckFactory callback to return EAsyncSocketUpgradeCheckResult_Upgrade");
		if (!Internal.m_IncomingData.f_IsEmpty() || !Internal.m_UpgradeCheckData.f_IsEmpty() || Internal.f_HasBufferedReceive() || Internal.m_nOutgoingQueuedBytes || !Internal.m_PendingMessages.f_IsEmpty() || !Internal.m_OutgoingDataPromises.empty())
			co_return DMibErrorInstance("Socket upgrade requires empty incoming and outgoing buffers");
		if (Internal.m_UpgradeSocketPromise)
			co_return DMibErrorInstance("Socket upgrade already in progress");

		NStorage::TCUniquePointer<NNetwork::ICSocket> pNewSocket = _SocketFactory(_Hostname);
		Internal.m_bUpgradeRequired = false;
		auto DeferredTCPState = Internal.m_DeferredTCPState;
		Internal.m_DeferredTCPState = NNetwork::ENetTCPState_None;

		// Completion transfers never activate while an upgrade is still possible, so the socket
		// changes hands with nothing in flight
		DMibFastCheck(!Internal.m_bCompletionIo && !Internal.m_bReceiveStreamActive && !Internal.m_nSendOpsInFlight);

		// The platform socket itself moves to the new transport: its registration, its loop and what
		// the kernel knows of the connection all stay as they are, only the state callback changes
		// hands. Nothing is given up or inherited, so the socket needs no inheritable handle. The old
		// transport is consumed by the move
		NConcurrency::TCActor<CAsyncSocketActor> ThisActor = fg_ThisActor(this);
		NNetwork::CSocket Socket = Internal.m_pSocket->f_GiveUpSocket();
		Internal.m_pSocket.f_Clear();
		pNewSocket->f_AdoptSocket
			(
				fg_Move(Socket)
				, [WeakThis = ThisActor.f_Weak()](NNetwork::ENetTCPState _StateAdded)
				{
					auto This = WeakThis.f_Lock();
					if (!This)
						return;
					This.f_Bind<&CAsyncSocketActor::fp_StateAdded>(_StateAdded).f_DiscardResult();
				}
			)
		;

		Internal.m_pSocket = fg_Move(pNewSocket);

		// A transport that buffers on the way through sizes that buffering from what one transfer
		// is worth here, which is the same size the receive buffer is cut to
		if (Internal.m_pSocket)
			Internal.m_pSocket->f_SetTransferSizeHint(fg_Max(Internal.m_FramentationSize, umint(4096)) + gc_SocketFramingMargin);
		Internal.m_State = EState_None;

		auto Future = Internal.m_UpgradeSocketPromise.f_CreateNew().f_Future();
		fp_CheckHandshake(Internal);
		if (DeferredTCPState)
			fp_ProcessState(DeferredTCPState);

		co_await NConcurrency::ECoroutineFlag_BreakSelfReference;

		co_return co_await fg_Move(Future);
	}

	NConcurrency::TCFuture<CAsyncSocketActor::CCloseInfo> CAsyncSocketActor::f_Close(EAsyncSocketStatus _Status, NStr::CStr _Reason)
	{
		if (f_IsDestroyed())
			co_return DMibErrorInstance("Destroying socket");

		auto &Internal = *mp_pInternal;
		if (Internal.m_ClosePromise)
			co_return DMibErrorInstance("Socket close already initiated");

		if (!Internal.m_pSocket || Internal.m_State == EState_Disconnected)
		{
			CAsyncSocketActor::CCloseInfo CloseInfo;
			CloseInfo.m_Status = EAsyncSocketStatus_AlreadyClosed;
			CloseInfo.m_Reason = "Already fully closed";
			co_return fg_Move(CloseInfo);
		}

		auto CloseFuture = Internal.m_ClosePromise.f_CreateNew().f_Future();

		fp_Disconnect(_Status, _Reason, false, EAsyncSocketCloseOrigin_Local);

		co_await NConcurrency::ECoroutineFlag_BreakSelfReference;

		co_return co_await fg_Move(CloseFuture);
	}

	void CAsyncSocketActor::CInternal::f_ShutdownDone(NStr::CStr const &_Error)
	{
		// The socket is gone, so queued messages and unsent data can never complete. Fail their promises instead of leaving them unresolved forever.
		m_PendingMessages.f_Clear();
		m_OutgoingDataPromises.clear();

		// A disconnected actor can stay referenced, so the zero copy buffers are released here
		// rather than held until destruction: the receive buffer is a fragmentation sized
		// allocation and each outgoing segment keeps its whole shared payload alive. A completion
		// transfer still in flight pins these buffers on the kernel side, so its cancellation
		// completion runs the release instead
		if (m_nSendOpsInFlight)
			m_bDeferredShutdownCleanup = true;
		else
			f_ReleaseTransferState();

		for (auto &fOnShutdown : m_OnShutdown)
			fOnShutdown(_Error);
		m_OnShutdown.f_Clear();
	}

	NConcurrency::TCFuture<CAsyncSocketActor::CCloseInfo> CAsyncSocketActor::f_CloseWithLinger(EAsyncSocketStatus _Status, NStr::CStr _Reason, fp64 _MaxLingerTime)
	{
		if (f_IsDestroyed())
			co_return DMibErrorInstance("Destroying socket");

		{
			auto &Internal = *mp_pInternal;

			if (!Internal.m_pSocket || Internal.m_State == EState_Disconnected)
			{
				CAsyncSocketActor::CCloseInfo CloseInfo;
				CloseInfo.m_Status = EAsyncSocketStatus_AlreadyClosed;
				CloseInfo.m_Reason = "Already fully closed";

				fg_ThisActor(this).f_Destroy().f_DiscardResult();

				co_return fg_Move(CloseInfo);
			}
		}

		auto ProcessingActor = NConcurrency::fg_ThisConcurrentActor();

		NConcurrency::TCPromiseFuturePair<CAsyncSocketActor::CCloseInfo> Promise;
		{
			auto &Internal = *mp_pInternal;
			struct CState
			{
				~CState()
				{
					if (!m_bHandled)
						f_Finish();
				}

				void f_Finish()
				{
					fg_Move(m_AsyncSocketActor).f_Destroy().f_DiscardResult();
				}

				NConcurrency::TCActor<CAsyncSocketActor> m_AsyncSocketActor;
				NAtomic::TCAtomic<bool> m_bHandled;
			};

			NStorage::TCSharedPointer<CState> pState = fg_Construct();
			pState->m_AsyncSocketActor = fg_ThisActor(this);

			auto Cleanup = NConcurrency::g_OnScopeExitActor(ProcessingActor) / [pState, Promise = Promise.m_Promise]
				{
					if (pState->m_bHandled.f_Exchange(true))
						return;

					Promise.f_SetException(DMibErrorInstance("Socket destroyed"));
					pState->f_Finish();
				}
			;

			Internal.m_OnShutdown.f_Insert
				(
					[Cleanup, pState, Promise = Promise.m_Promise, this](NStr::CStr const &_Error)
					{
						if (pState->m_bHandled.f_Exchange(true))
							return;

						auto &Internal = *mp_pInternal;
						if (!_Error.f_IsEmpty())
							Promise.f_SetException(DMibErrorInstance(fg_Format("Unclean socket shutdown: {}", _Error)));
						else
							Promise.f_SetResult(fg_Move(Internal.m_CloseInfo));
						pState->f_Finish();
					}
				)
			;

			f_Close(_Status, _Reason) > ProcessingActor / [pState, Promise = Promise.m_Promise](NConcurrency::TCAsyncResult<NNetwork::CAsyncSocketActor::CCloseInfo> &&_Result)
				{
					if (!_Result)
					{
						if (pState->m_bHandled.f_Exchange(true))
							return;

						Promise.f_SetException(fg_Move(_Result));
						pState->f_Finish();
					}
				}
			;

			NConcurrency::fg_Timeout(_MaxLingerTime, false)(ProcessingActor) > [Promise = fg_Move(Promise.m_Promise), pState]() -> NConcurrency::TCFuture<void>
				{
					if (pState->m_bHandled.f_Exchange(true))
						co_return {};

					Promise.f_SetException(DMibErrorInstance("Timed out waiting for socket to close gracefully"));
					pState->f_Finish();

					co_return {};
				}
			;
		}

		co_await fg_ContinueRunningOnActor(ProcessingActor);

		co_return co_await fg_Move(Promise.m_Future);
	}

	NConcurrency::TCFuture<void> CAsyncSocketActor::f_SendData(NContainer::CSharedByteVector const _Message, uint32 _Priority)
	{
		if (f_IsDestroyed())
			co_return DMibErrorInstance("Destroying socket");

		auto &Internal = *mp_pInternal;
		DMibLog(DebugVerbose3, " ++++ {} f_SendBinary", !Internal.m_bClient);

		umint nBytes = _Message.f_GetLen();

		if (nBytes > Internal.m_MaxMessageSize)
			co_return DMibErrorInstance("Message is bigger than max message size");

		if (_Priority == TCLimitsInt<uint32>::mc_Max)
			co_return DMibErrorInstance("0xffffffff priority is reserved for internal messages");

		if (Internal.m_State == EState_Disconnected)
			co_return DMibErrorInstance("Cannot send data on a disconnected socket");

		co_await NConcurrency::ECoroutineFlag_BreakSelfReference;

		auto &NewMessage = Internal.f_QueueMessage(_Message, _Priority);
		auto Future = NewMessage.m_Promise.f_CreateNew().f_Future();
		DMibLog(DebugVerbose3, " ++++ {} Queue message", !Internal.m_bClient);
		fp_UpdateSend();

		co_return co_await fg_Move(Future);
	}

	void CAsyncSocketActor::fp_StateAdded(NNetwork::ENetTCPState _StateAdded)
	{
		fp_ProcessState(_StateAdded);
	}

	void CAsyncSocketActor::CInternal::f_NotifyClose(EAsyncSocketStatus _Status, NStr::CStr const &_Message, EAsyncSocketCloseOrigin _Origin)
	{
		if (m_bOnCloseCalled)
			return;
		m_bOnCloseCalled = true;

		if (m_Callbacks.m_fOnClose)
		{
			m_Callbacks.m_fOnClose.f_CallDiscard(_Status, _Message, _Origin);
			return;
		}

		m_DeferredNotifyClose = {_Status, _Message, _Origin};
	}

	void CAsyncSocketActor::fp_Disconnect(EAsyncSocketStatus _Status, NStr::CStr const &_Reason, bool _bFatal, EAsyncSocketCloseOrigin _Origin)
	{
		auto &Internal = *mp_pInternal;

		if (Internal.m_State == EState_Disconnected)
		{
			if (_bFatal)
			{
				Internal.m_pSocket.f_Clear();
				Internal.f_ShutdownDone(_Reason);
			}
			return; // Already disconnected
		}

		if (Internal.m_State == EState_Connected)
		{
			if (!_bFatal)
				fp_Shutdown();
			if (_Origin == EAsyncSocketCloseOrigin_Remote)
			{
				Internal.m_CloseInfo.m_Status = _Status;
				Internal.m_CloseInfo.m_Reason = _Reason;
				if (Internal.m_ClosePromise)
				{
					Internal.m_ClosePromise->f_SetResult(Internal.m_CloseInfo);
					Internal.m_ClosePromise.f_Clear();
				}
			}
			Internal.f_NotifyClose(_Status, _Reason, _Origin);
		}
		else
		{
			if (!Internal.m_FinishConnectionPromise.f_IsSet())
			{
				CFinishConnectionResult Result;
				Result.m_Result = EFinishConnectionResult_Error;
				if (Internal.m_pSocket)
					Result.m_ConnectionInfo.m_pSocketInfo = Internal.m_pSocket->f_GetConnectionInfo();
				Result.m_ConnectionInfo.m_PeerAddress = Internal.m_PeerAddress;
				Result.m_ConnectionInfo.m_ErrorStatus = _Status;
				Result.m_ConnectionInfo.m_Error = _Reason;

				Internal.m_FinishConnectionPromise.f_SetResult(fg_Move(Result));
			}
			if (Internal.m_UpgradeSocketPromise)
			{
				Internal.m_UpgradeSocketPromise->f_SetException(DMibErrorInstance(_Reason));
				Internal.m_UpgradeSocketPromise.f_Clear();
			}
		}

		if (_bFatal)
		{
			Internal.m_CloseInfo.m_Status = _Status;
			Internal.m_CloseInfo.m_Reason = fg_Format("Abnormal closure: {}", _Reason);
			if (Internal.m_ClosePromise)
			{
				Internal.m_ClosePromise->f_SetResult(Internal.m_CloseInfo);
				Internal.m_ClosePromise.f_Clear();
			}
			Internal.f_NotifyClose(_Status, _Reason, _Origin);

			Internal.m_pSocket.f_Clear();
			Internal.f_ShutdownDone(_Reason);
		}

		// Messages that were queued but not yet written can never be sent after a disconnect. Fail their promises instead of leaving them unresolved forever.
		Internal.m_PendingMessages.f_Clear();
		if (_bFatal)
			Internal.m_OutgoingDataPromises.clear();

		Internal.m_State = EState_Disconnected;
		Internal.f_StopTimeout();
	}

	void CAsyncSocketActor::fp_Shutdown()
	{
		try
		{
			auto &Internal = *mp_pInternal;
			if (Internal.m_pSocket && !Internal.m_bShutdownCalled)
			{
				Internal.m_pSocket->f_Shutdown();
				Internal.m_bShutdownCalled = true;
			}
		}
		catch (NCryptography::CExceptionCryptography const &_Error)
		{
			fp_Disconnect(EAsyncSocketStatus_AbnormalClosure, NStr::fg_Format("Socket exception: {}", _Error.f_GetErrorStr()), true, EAsyncSocketCloseOrigin_Remote);
		}
		catch (NNetwork::CExceptionNet const &_Error)
		{
			fp_Disconnect(EAsyncSocketStatus_AbnormalClosure, NStr::fg_Format("Socket exception: {}", _Error.f_GetErrorStr()), true, EAsyncSocketCloseOrigin_Remote);
		}
	}

	void CAsyncSocketActor::fp_UpdateSend()
	{
		auto &Internal = *mp_pInternal;
		if (!Internal.m_pSocket || !Internal.m_pSocket->f_IsValid())
			return;

		if (Internal.m_State == EState_Connected)
			Internal.f_WriteQueuedMessages();
		else
			fp_CheckHandshake(Internal);

#if DMibConfig_Tests_Enable
		if (Internal.m_bDebugNoProcessing)
			return;
#endif

		// Asked per direction: a connection whose receives are submitted but whose sends are not
		// takes the readiness path below, which is the one that leaves write readiness armed to
		// come back for the rest of a short write. The completion branch has no such edge, and
		// with no send operation to submit a stalled write would never be finished
		if (auto *pCompletionIoSend = Internal.f_GetCompletionIoSend())
		{
			// A staging socket takes sends whenever its gate allows — while its operation is
			// in flight included, which is what runs the seal ahead of the wire
			// Every send is a submitted operation, several in flight at once: the loop
			// publishes them in submission order, which is the whole ordering story, and the
			// socket's own gate bounds how many are outstanding
			while (Internal.m_pSocket->f_IsValid() && pCompletionIoSend->f_CanSubmitSend() && Internal.m_nOutgoingQueuedBytes > Internal.m_nOutgoingSubmitted)
			{
				umint nBefore = Internal.m_nOutgoingSubmitted;
				fp_SubmitSendOp();
				if (Internal.m_nOutgoingSubmitted == nBefore)
					break;

				if (Internal.m_State == EState_Connected)
					Internal.f_WriteQueuedMessages();
			}

			if (Internal.m_State == EState_Disconnected && !Internal.m_nOutgoingQueuedBytes)
				fp_Shutdown();

			fp_DrainSocketOutput();

			return;
		}

		bool bDidSend = false;
		while (Internal.m_nOutgoingQueuedBytes && Internal.m_pSocket->f_IsValid())
		{
			// Gather the head segments as spans (no copy) and hand them to the socket as one
			// vectored operation: each segment references its shared message buffer in place
			NSys::CIoSpan Spans[NNetwork::ICSocket::mc_MaxSendSpans];
			umint nSpans = 0;
			NContainer::TCVector<NContainer::CSharedByteVector> KeepAlives;
			umint nGatheredBytes = Internal.f_GatherSendSpans(Spans, nSpans, KeepAlives);
			if (!nGatheredBytes)
				break;

			umint SentBytes = 0;
			bool bStuffed = false;
			bool bDisconnected = false;
			NNetwork::CSocketOperationResult CombinedResults;
			try
			{
				bDidSend = true;
				NNetwork::CSocketOperationResult Result = Internal.m_pSocket->f_SendVectored(Spans, nSpans);
				DMibLog(DebugVerbose3, " ++++ {} Sending {} resulted in {} sent", !Internal.m_bClient, nGatheredBytes, Result.m_nBytes);
#if DMibConfig_IoDebug_Enable
				if (auto *pStats = NNetwork::fg_NetIoStats())
				{
					pStats->m_nSendReadinessCalls.f_FetchAdd(1, NAtomic::gc_MemoryOrder_Relaxed);
					pStats->m_nSendReadinessBytes.f_FetchAdd(Result.m_nBytes, NAtomic::gc_MemoryOrder_Relaxed);
				}
#endif

				CombinedResults += Result;

				SentBytes = Result.m_nBytes;
				if (SentBytes != nGatheredBytes)
					bStuffed = true;
			}
			catch (NCryptography::CExceptionCryptography const &_Error)
			{
				fp_Disconnect(EAsyncSocketStatus_AbnormalClosure, NStr::fg_Format("Socket exception: {}", _Error.f_GetErrorStr()), true, EAsyncSocketCloseOrigin_Remote);
				bDisconnected = true;
			}
			catch (NNetwork::CExceptionNet const &_Error)
			{
				fp_Disconnect(EAsyncSocketStatus_AbnormalClosure, NStr::fg_Format("Socket exception: {}", _Error.f_GetErrorStr()), true, EAsyncSocketCloseOrigin_Remote);
				bDisconnected = true;
			}
			if (CombinedResults.m_bSentNetwork)
				Internal.f_OnSentData();
			if (CombinedResults.m_bReceivedNetwork)
				Internal.f_OnReceivedData();

			if (SentBytes)
				Internal.f_ConsumeSentBytes(SentBytes);

			if (bDisconnected)
				break;
			if (bStuffed)
				break;
			if (Internal.m_State == EState_Connected)
				Internal.f_WriteQueuedMessages();
		}

		if (!bDidSend && Internal.m_pSocket && Internal.m_pSocket->f_IsValid())
		{
			NNetwork::CSocketOperationResult SendResult = Internal.m_pSocket->f_Send(nullptr, 0);
			if (SendResult.m_bSentNetwork)
				Internal.f_OnSentData();
			if (SendResult.m_bReceivedNetwork)
				Internal.f_OnReceivedData();
		}

		if (Internal.m_State == EState_Disconnected && !Internal.m_nOutgoingQueuedBytes)
			fp_Shutdown();
	}

	void CAsyncSocketActor::fp_TryActivateCompletionIo()
	{
		auto &Internal = *mp_pInternal;
		if (Internal.m_bCompletionIo)
			return;

		// Completion transfers only make sense once the connection is in its steady state: the
		// upgrade check phase sniffs bytes one at a time through readiness, and a pending upgrade
		// hands the raw fd to a new socket, which an in-flight operation would pin
		if (Internal.m_State != EState_Connected || Internal.m_fCheckUpgrade || Internal.m_bUpgradeRequired)
			return;

		if (!Internal.m_pSocket || !Internal.m_pSocket->f_IsValid())
			return;

		// Decided once per connection, at establishment: by now any transport handshake beneath
		// has completed, so a null here is a socket that will never support completion transfers
		auto *pCompletionIo = Internal.m_pSocket->f_GetCompletionIo();
		if (!pCompletionIo)
			return;

		Internal.m_pCompletionIo = pCompletionIo;
		Internal.m_bCompletionIo = true;
		Internal.m_pOpTracker = fg_Construct();

		// Said before the first operation, so the socket's synchronous entry points start refusing
		// now rather than whenever one of them first happens to be refused by the kernel
		pCompletionIo->f_OnCompletionActivated();

		DMibLog(DebugVerbose3, " ++++ {} Completion transfers active", !Internal.m_bClient);

		// Starts the standing receive, which is what carries inbound payload from here on:
		// arming it is what cancels the read readiness poll, so until it exists a connection
		// that only ever sends would have nothing delivering to it
		fp_StartReceiveStream();
	}

	void CAsyncSocketActor::fp_StartReceiveStream()
	{
		auto &Internal = *mp_pInternal;

		// A stream is started at most once per socket, and once its terminal has been delivered
		// nothing arms again — a readiness edge arriving after the end of the stream would
		// otherwise ask for a second stream on a registration that already had its one
		if (Internal.m_bReceiveStreamActive || Internal.m_bReceiveStreamEnded)
			return;

		if (!Internal.m_pSocket || !Internal.m_pSocket->f_IsValid())
			return;

		// Disconnected is deliberately still eligible: a graceful local close leaves the socket
		// half open until the peer's close arrives, and the stream is what keeps the receive
		// window draining — a peer with data still to flush before its FIN would otherwise wedge
		// against a zero window. Segments arriving in that state are dropped, exactly like the
		// readiness drain does
		if (Internal.m_State != EState_Connected && Internal.m_State != EState_Disconnected)
			return;

		// Bytes buffered by readiness receives predate anything the stream delivers, so flushing
		// them first keeps the stream in order
		if (!Internal.m_IncomingData.f_IsEmpty())
			fp_ProcessIncoming();

		auto *pCompletionIo = Internal.f_GetCompletionIoReceive();
		if (!pCompletionIo)
			return;

		// The stream's flow control: buffer capacity outstanding across the whole pipeline —
		// segments in flight, payloads with the application, forwards into send queues — counted
		// down by each buffer's own destructor. When the limit parks the kernel side, the
		// release that crosses the resume threshold reschedules through this actor
		umint nBufferBytes = pCompletionIo->f_GetReceiveBufferBytes();
		auto pBackpressure = NStorage::TCSharedPointer<NSys::CIoStreamBackpressure>(fg_Construct());
		pBackpressure->m_nLimitBytes = NNetwork::fg_GetReceiveWindowBytes(*Internal.mp_pIo, nBufferBytes);
		pBackpressure->m_nResumeBytes = pBackpressure->m_nLimitBytes / 2;
		pBackpressure->m_fResume = [WeakThis = fg_ThisActor(this).f_Weak()]() mutable
			{
				if (auto This = WeakThis.f_Lock())
					This.f_Bind<&CAsyncSocketActor::fp_ReceiveWindowResume>().f_DiscardResult();
			}
		;
		Internal.m_pReceiveBackpressure = pBackpressure;

		bool bStarted = pCompletionIo->f_StartReceiveStream
			(
				fg_Move(pBackpressure)
				, [WeakThis = fg_ThisActor(this).f_Weak()](NSys::CIoStreamSegment &&_Segment) mutable
				{
					// Loop thread: hand the segment to the actor. The segment owns its buffer's
					// reference, so a job dropped mid-teardown frees it from the destructor
					if (auto This = WeakThis.f_Lock())
						This.f_Bind<&CAsyncSocketActor::fp_ReceiveSegment>(fg_Move(_Segment)).f_DiscardResult();
				}
			)
		;

		if (bStarted)
			Internal.m_bReceiveStreamActive = true;

		// A refusal means the socket is closing; the close paths take over
	}

	// A backpressure release crossing the resume threshold: the kernel side parked its ring, and
	// this is where it is rescheduled
	void CAsyncSocketActor::fp_ReceiveWindowResume()
	{
		auto &Internal = *mp_pInternal;

		if (f_IsDestroyed())
			return;

		if (Internal.m_pSocket && Internal.m_pSocket->f_IsValid() && Internal.m_pCompletionIo)
			Internal.m_pCompletionIo->f_ResumeReceiveStream();
	}

	// The transport can hold records of its own making — a key update acknowledgement, a session
	// ticket, the tail of a send it could not finish — that no message of ours will carry out.
	// Completion transfers report no write readiness, so this is where they are noticed
	void CAsyncSocketActor::fp_DrainSocketOutput()
	{
		auto &Internal = *mp_pInternal;

		auto *pCompletionIo = Internal.f_GetCompletionIoSend();
		if (!pCompletionIo)
			return;

		if (!pCompletionIo->f_HasPendingOutput())
			return;

		fp_SubmitSendOp(true);
	}

	// _bContinue carries on a transfer the socket has not finished with: it may have nothing new to
	// offer, and the operation exists to move what the socket still holds rather than what is queued
	void CAsyncSocketActor::fp_SubmitSendOp(bool _bContinue, umint _iInheritedReservation)
	{
		auto &Internal = *mp_pInternal;

		// A continuation carries on a transfer an earlier call reserved for, so it takes that
		// reservation rather than one of its own. Held from here, above every way out of this
		// function: a continuation that cannot be submitted has to give the reservation back, or
		// nothing ever will and the queue stays permanently spoken for
		umint iReservation = _bContinue ? _iInheritedReservation : Internal.mc_nMaxSendReservations;

		auto fReleaseOnFailure = NMib::g_OnScopeExit / [&]
			{
				if (iReservation >= Internal.mc_nMaxSendReservations)
					return;

				auto &Reservation = Internal.m_SendReservations[iReservation];

				// Tearing the connection down gives every reservation back at once, so an
				// operation still in flight then finds its own already accounted for
				if (!Reservation.m_bInUse)
					return;

				DMibFastCheck(Internal.m_nOutgoingSubmitted >= Reservation.m_nBytes);

				Internal.m_nOutgoingSubmitted -= Reservation.m_nBytes;
				Reservation.m_bInUse = false;
			}
		;

		if (!Internal.m_nOutgoingQueuedBytes && !_bContinue)
			return;

		if (!Internal.m_pSocket || !Internal.m_pSocket->f_IsValid())
			return;

		auto *pCompletionIo = Internal.f_GetCompletionIoSend();
		if (!pCompletionIo)
			return;

		// Nothing new may be sealed: the transport cannot take another batch, and the release
		// upcall is what re-drives this. The gate is for new plaintext only — a continuation
		// seals nothing, it moves ciphertext the transport already holds, and refusing it when
		// the send buffer is full is a deadlock: only sending makes the buffer not-full again
		if (!_bContinue && !pCompletionIo->f_CanSubmitSend())
		{
#if DMibConfig_IoDebug_Enable
			if (auto *pStats = NNetwork::fg_NetIoStats())
				pStats->m_nSendBlocked.f_FetchAdd(1, NAtomic::gc_MemoryOrder_Relaxed);
#endif

			return;
		}


		// A new batch needs a reservation slot for its bytes, and the slots outlive the socket's
		// own operation records by one drain — the chain carrier's reservation is inherited by
		// its continuation and only settles when the chain reports. When every slot is still
		// spoken for the batch waits; the completion that frees one re-drives this
		if (!_bContinue)
		{
			umint nInUse = 0;
			for (umint iSlot = 0; iSlot < Internal.mc_nMaxSendReservations; ++iSlot)
			{
				if (Internal.m_SendReservations[iSlot].m_bInUse)
					++nInUse;
			}

			if (nInUse == Internal.mc_nMaxSendReservations)
				return;

#if DMibConfig_IoDebug_Enable
			if (auto *pStats = NNetwork::fg_NetIoStats())
			{
				uint64 nOutstanding = nInUse + 1;
				uint64 nMax = pStats->m_nSendMaxOutstanding.f_Load(NAtomic::gc_MemoryOrder_Relaxed);
				while (nMax < nOutstanding && !pStats->m_nSendMaxOutstanding.f_CompareExchangeWeak(nMax, nOutstanding, NAtomic::gc_MemoryOrder_Relaxed))
				{
				}
			}
#endif
		}

		// A continuation offers nothing: the queue still holds the plaintext of the transfer the
		// socket is carrying, because that is only consumed once it reports, and gathering from it
		// again would hand the same bytes over twice
		NSys::CIoSpan Spans[NNetwork::ICSocket::mc_MaxSendSpans];
		umint nSpans = 0;
		umint nGatheredBytes = 0;
		NContainer::TCVector<NContainer::CSharedByteVector> KeepAlives;
		if (!_bContinue)
		{
			if (Internal.m_nOutgoingQueuedBytes <= Internal.m_nOutgoingSubmitted)
				return;

			nGatheredBytes = Internal.f_GatherSendSpans(Spans, nSpans, KeepAlives);
			if (!nGatheredBytes)
				return;
		}

		DMibLog(DebugVerbose3, " ++++ {} Submitting send of {}", !Internal.m_bClient, nGatheredBytes);

		// Reserved rather than consumed: the queue still holds these bytes until the operation
		// reports, because a short write leaves part of them still to send
		if (!_bContinue)
		{
			for (umint iSlot = 0; iSlot < Internal.mc_nMaxSendReservations; ++iSlot)
			{
				if (Internal.m_SendReservations[iSlot].m_bInUse)
					continue;

				iReservation = iSlot;
				break;
			}

			// The socket never carries more sends than there are slots here
			DMibFastCheck(iReservation < Internal.mc_nMaxSendReservations);
			DMibFastCheck(nGatheredBytes < (umint(1) << (sizeof(umint) * 8 - 1)));

			Internal.m_SendReservations[iReservation].m_nBytes = nGatheredBytes;
			Internal.m_SendReservations[iReservation].m_bInUse = true;
			Internal.m_nOutgoingSubmitted += nGatheredBytes;
		}

		// Each functor holds the tracker until it is destroyed — the completion and the buffer
		// release both — so the destroy fence waits until the kernel has let go of the pages,
		// not just reported. A functor the submit refuses or a throw drops releases the same way
		bool bSubmitted = pCompletionIo->f_SubmitSendVectored
			(
				Spans
				, nSpans
				, [Hold = NConcurrency::CIoCompletionOpHold(Internal.m_pOpTracker), iReservation, WeakThis = fg_ThisActor(this).f_Weak()](NSys::CIoCompletion _Result) mutable
				{
					if (auto This = WeakThis.f_Lock())
						This.f_Bind<&CAsyncSocketActor::fp_SendCompleted>(_Result, iReservation).f_DiscardResult();
				}
				,
				[Hold = NConcurrency::CIoCompletionOpHold(Internal.m_pOpTracker), KeepAlives = fg_Move(KeepAlives), WeakThis = fg_ThisActor(this).f_Weak()](umint _iTransfer) mutable
				{
					// The kernel is done with the gathered pages; the keep alives this functor
					// carried can finally go, and the socket gets its buffer back on the
					// actor's thread
					KeepAlives.f_Clear();

					if (auto This = WeakThis.f_Lock())
						This.f_Bind<&CAsyncSocketActor::fp_SendBufferReleased>(_iTransfer).f_DiscardResult();
				}
			)
		;

		if (bSubmitted)
			fReleaseOnFailure.f_Clear();
		else
		{
			// Terminal by contract, and the queue is still holding the plaintext this was meant to
			// carry. Left alone it would sit there with nothing to drive it and the send futures
			// would never resolve, so the connection ends here rather than going quiet
			fp_Disconnect(EAsyncSocketStatus_AbnormalClosure, "Socket refused a send", true, EAsyncSocketCloseOrigin_Remote);
			return;
		}

#if DMibConfig_IoDebug_Enable
		if (auto *pStats = NNetwork::fg_NetIoStats())
		{
			pStats->m_nSendSubmits.f_FetchAdd(1, NAtomic::gc_MemoryOrder_Relaxed);
			if (_bContinue)
				pStats->m_nSendContinuations.f_FetchAdd(1, NAtomic::gc_MemoryOrder_Relaxed);
		}
#endif

		++Internal.m_nSendOpsInFlight;


	}

	void CAsyncSocketActor::fp_ReceiveSegment(NSys::CIoStreamSegment &&_Segment)
	{
		auto &Internal = *mp_pInternal;

		if (f_IsDestroyed())
			return;

		auto &Segment = _Segment;
		bool bTerminal = Segment.m_Status != NSys::EIoCompletionStatus::mc_Done || !Segment.m_nBytes;

		if (bTerminal)
		{
			Internal.m_bReceiveStreamActive = false;
			Internal.m_bReceiveStreamEnded = true;
		}

#if DMibConfig_Tests_Enable
		if (Internal.m_bDebugNoProcessing && !bTerminal)
		{
			// The bytes stay unprocessed and their buffer capacity stays charged against the
			// stream's window, which pauses the stream exactly like unprocessed bytes paused the
			// readiness path; the timeout stopwatch is deliberately not restarted either
			Internal.m_DebugHeldSegments.f_Insert(fg_Move(_Segment));
			return;
		}
#endif

		bool bSocketUsable = Internal.m_pSocket && Internal.m_pSocket->f_IsValid();
		if (!bSocketUsable || !Internal.m_pCompletionIo)
		{
			Internal.f_TryReleaseDeferredTransferState();
			return;
		}

		// A socket whose segments are the payload as delivered hands them back as shared views
		// of the very buffers the kernel filled — dereferences only, kernel to callback. Bytes
		// buffered ahead of this segment go first so the stream stays in order; a disconnected
		// drain simply drops the segment, which is what frees its buffer
		if (!bTerminal)
		{
			NSys::CIoCompletion SharedResult;
			NContainer::CSharedByteVector SharedData;
			if (Internal.m_pCompletionIo->f_ResolveReceiveSegmentShared(Segment, SharedData, SharedResult))
			{
				if (Internal.m_State != EState_Connected)
					return;

				Internal.f_DeliverReceiveBuffer();
				if (!Internal.m_IncomingData.f_IsEmpty())
					fp_ProcessIncoming();

#if DMibConfig_IoDebug_Enable
				if (auto *pStats = NNetwork::fg_NetIoStats())
				{
					pStats->m_nRecvSharedDeliveries.f_FetchAdd(1, NAtomic::gc_MemoryOrder_Relaxed);
					pStats->m_nRecvSharedBytes.f_FetchAdd(SharedResult.m_nBytes, NAtomic::gc_MemoryOrder_Relaxed);
				}
#endif

				if (SharedResult.m_nBytes <= gc_CopySmallDeliveryThreshold)
				{
					// A small delivery is copied into a right sized buffer so the consumer never
					// pins the full receive buffer
					NContainer::CIOByteVector Data;
					Data.f_SetLen(SharedResult.m_nBytes, false);
					NMemory::fg_ObjectCopy(Data.f_GetArray(), SharedData.f_GetArray(), SharedResult.m_nBytes);
					SharedData.f_Clear();
					Internal.f_HandleDataMessage(NContainer::CSharedByteVector(fg_Move(Data)));
				}
				else
					Internal.f_HandleDataMessage(fg_Move(SharedData));

				Internal.f_OnReceivedData();

				if (!Internal.m_pSocket || !Internal.m_pSocket->f_IsValid())
				{
					Internal.f_TryReleaseDeferredTransferState();
					return;
				}

				fp_DrainSocketOutput();

				return;
			}
		}

		if (Segment.m_Status == NSys::EIoCompletionStatus::mc_Cancelled)
		{
			// Resolved so the socket hears the stream is over, with nothing to deliver
			NSys::CIoCompletion Result;
			Internal.m_pCompletionIo->f_ResolveReceiveSegment(Segment, nullptr, 0, Result);
			Internal.f_TryReleaseDeferredTransferState();
			return;
		}

		// What the kernel delivered becomes what the consumer asked for here, on the actor's
		// thread, so a socket that processes the bytes on the way through never runs that work
		// on the loop's. Every resolve lands in the delivery buffer; a socket that holds more
		// than one buffer's worth is drained buffer by buffer
		bool bDelivering = Internal.m_State == EState_Connected;

		umint DeliverySize = fg_Max(Internal.m_FramentationSize, umint(4096));
		bool bResolvedSegment = false;
		bool bError = false;

		for (;;)
		{
			if (Internal.m_ReceiveData.f_IsEmpty())
			{
				Internal.m_ReceiveData.f_SetLen(DeliverySize, false);
				Internal.m_nReceiveFill = 0;
			}

			umint Capacity = Internal.m_ReceiveData.f_GetLen();
			if (Internal.m_nReceiveFill >= Capacity)
			{
				Internal.f_DeliverReceiveBuffer();
				continue;
			}

			NSys::CIoCompletion Result;
			bool bProduced;
			if (!bResolvedSegment)
			{
				bProduced = Internal.m_pCompletionIo->f_ResolveReceiveSegment
					(
						Segment
						, Internal.m_ReceiveData.f_GetArray() + Internal.m_nReceiveFill
						, Capacity - Internal.m_nReceiveFill
						, Result
					)
				;
				bResolvedSegment = true;

				if (bProduced && Result.m_Status == NSys::EIoCompletionStatus::mc_Error)
				{
					bError = true;
					break;
				}
			}
			else
			{
				bProduced = Internal.m_pCompletionIo->f_ResolveHeld
					(
						Internal.m_ReceiveData.f_GetArray() + Internal.m_nReceiveFill
						, Capacity - Internal.m_nReceiveFill
						, Result
					)
				;
			}

			if (!bProduced || !Result.m_nBytes)
				break;

			DMibLog(DebugVerbose3, " ++++ {} Received stream bytes {}", !Internal.m_bClient, Result.m_nBytes);

			if (bDelivering)
			{
				Internal.m_nReceiveFill += Result.m_nBytes;

				Internal.f_OnReceivedData();

				// Readiness leftovers predate this segment's bytes, so they go first
				if (!Internal.m_IncomingData.f_IsEmpty())
					fp_ProcessIncoming();

				Internal.f_DeliverReceiveBuffer();
			}
			// A disconnected drain discards: the close callback has already run, so delivering
			// now would hand the consumer data after its close. The fill stays where it is and
			// the stream keeps the peer's receive window from wedging

			if (!Internal.m_pSocket || !Internal.m_pSocket->f_IsValid())
			{
				Internal.f_TryReleaseDeferredTransferState();
				return;
			}
		}

		if (Segment.m_Status == NSys::EIoCompletionStatus::mc_Error)
		{
			fp_Disconnect(EAsyncSocketStatus_AbnormalClosure, NStr::fg_Format("Socket receive error: {}", fg_FormatSocketIoError(Segment.m_Error)), true, EAsyncSocketCloseOrigin_Remote);
			return;
		}

		if (bError)
		{
			fp_Disconnect(EAsyncSocketStatus_AbnormalClosure, "Socket receive failed", true, EAsyncSocketCloseOrigin_Remote);
			return;
		}

		if (bTerminal)
		{
			// End of stream. The close-class states that waited for the stream to run dry are
			// honored now that everything it held has been opened and delivered
			NNetwork::ENetTCPState DeferredStates = Internal.m_DeferredCloseStates;
			Internal.m_DeferredCloseStates = NNetwork::ENetTCPState_None;
			if (DeferredStates)
				fp_ProcessState(DeferredStates);

			Internal.f_TryReleaseDeferredTransferState();
			return;
		}

		fp_DrainSocketOutput();
	}

	void CAsyncSocketActor::fp_SendCompleted(NSys::CIoCompletion _Result, umint _iReservation)
	{
		auto &Internal = *mp_pInternal;
		DMibFastCheck(Internal.m_nSendOpsInFlight);
		--Internal.m_nSendOpsInFlight;

		auto fReleaseReservation = [&]()
			{
				// Only once the transfer has actually been reported. A socket that says it is not
				// done with these bytes yet is carrying them still, and releasing here would let
				// the next gather offer them a second time. A continuation reserved nothing of its
				// own, and says so with no reservation at all
				if (_iReservation >= Internal.mc_nMaxSendReservations)
					return;

				auto &Reservation = Internal.m_SendReservations[_iReservation];

				// Tearing the connection down gives every reservation back at once, so an
				// operation still in flight then finds its own already accounted for
				if (!Reservation.m_bInUse)
					return;

				DMibFastCheck(Internal.m_nOutgoingSubmitted >= Reservation.m_nBytes);

				Internal.m_nOutgoingSubmitted -= Reservation.m_nBytes;
				Reservation.m_bInUse = false;
			}
		;

		if (f_IsDestroyed())
			return;

		// As on the receive side: a transport that frames what it sends reports the bytes that
		// left the machine, and turns them into the caller's here. Records it has produced but
		// not yet placed are why this can say the transfer is not over
		bool bSocketUsable = Internal.m_pSocket && Internal.m_pSocket->f_IsValid();
		bool bResolved = true;
		if (bSocketUsable && Internal.m_pCompletionIo)
			bResolved = Internal.m_pCompletionIo->f_ResolveSend(_Result);

		if (_Result.m_Status == NSys::EIoCompletionStatus::mc_Cancelled || !bSocketUsable)
		{
			Internal.m_nOutgoingSubmitted = 0;
			for (auto &Reservation : Internal.m_SendReservations)
				Reservation.m_bInUse = false;
			Internal.f_TryReleaseDeferredTransferState();
			return;
		}

		if (!bResolved)
		{
			// The socket still holds these bytes, so the reservation travels to the operation that
			// carries on with them
			fp_SubmitSendOp(true, _iReservation);
			return;
		}

		fReleaseReservation();

		if (_Result.m_Status == NSys::EIoCompletionStatus::mc_Error)
		{
			fp_Disconnect(EAsyncSocketStatus_AbnormalClosure, NStr::fg_Format("Socket send error: {}", fg_FormatSocketIoError(_Result.m_Error)), true, EAsyncSocketCloseOrigin_Remote);
			return;
		}

		DMibLog(DebugVerbose3, " ++++ {} Send completion {}", !Internal.m_bClient, _Result.m_nBytes);

		if (_Result.m_nBytes)
		{
			Internal.f_ConsumeSentBytes(_Result.m_nBytes);
			Internal.f_OnSentData();
		}

		// Messages may have queued while the operation was in flight, and the disconnect path
		// wants its shutdown once the queue runs dry; fp_UpdateSend's completion branch covers both
		fp_UpdateSend();
	}

	// The kernel released a send's buffers. For a socket that stages what it carries this is
	// what lets the next generation be filled, so anything parked behind the cap moves now
	void CAsyncSocketActor::fp_SendBufferReleased(umint _iTransfer)
	{
		auto &Internal = *mp_pInternal;

		if (f_IsDestroyed())
			return;

		bool bSocketUsable = Internal.m_pSocket && Internal.m_pSocket->f_IsValid();
		if (bSocketUsable && Internal.m_pCompletionIo)
			Internal.m_pCompletionIo->f_ResolveSendRelease(_iTransfer);

		if (!bSocketUsable)
			return;

		// A generation freeing is what un-parks staged ciphertext and queued plaintext alike
		fp_UpdateSend();
		fp_DrainSocketOutput();
	}


	bool CAsyncSocketActor::fp_ProcessIncomingMessage()
	{
		auto &Internal = *mp_pInternal;
		DMibLog(DebugVerbose3, " ++++ {} fp_ProcessIncomingMessage", !Internal.m_bClient);

		umint Length = Internal.m_IncomingData.f_GetLen();
		NContainer::CIOByteVector Data;
		Data.f_Reserve(Length);

		Internal.m_IncomingData.f_ReadFront
			(
				Length
				, [&](umint _iStart, uint8 const *_pData, umint _nBytes) -> bool
				{
					Data.f_Insert(_pData, _nBytes);
					return _iStart + _nBytes < Length;
				}
			)
		;

		Internal.m_IncomingData.f_RemoveFront(Length);

		Internal.f_HandleDataMessage(NContainer::CSharedByteVector(fg_Move(Data)));

		return true;
	}

	void CAsyncSocketActor::CInternal::f_HandleDataMessage(NContainer::CSharedByteVector &&_Data)
	{
		DMibLog(DebugVerbose3, " ++++ {} call m_OnReceiveData", !m_bClient);
		if (m_bDeferringCallbacks)
		{
			m_DeferredOnReciveData.f_Insert(fg_Move(_Data));
			return;
		}

		if (m_Callbacks.m_fOnReceiveData)
			m_Callbacks.m_fOnReceiveData.f_CallDiscard(fg_Move(_Data));
	}

	bool CAsyncSocketActor::CInternal::f_HasBufferedReceive() const
	{
		return m_nReceiveFill != 0;
	}

	void CAsyncSocketActor::CInternal::f_DeliverReceiveBuffer()
	{
		if (!m_nReceiveFill)
			return;

		if (m_nReceiveFill <= gc_CopySmallDeliveryThreshold)
		{
			// A small delivery is copied into a right sized buffer so the consumer never
			// pins the full receive buffer, which is kept and refilled instead
			NContainer::CIOByteVector Data;
			Data.f_SetLen(m_nReceiveFill, false);
			NMemory::fg_ObjectCopy(Data.f_GetArray(), m_ReceiveData.f_GetArray(), m_nReceiveFill);
			m_nReceiveFill = 0;
			f_HandleDataMessage(NContainer::CSharedByteVector(fg_Move(Data)));
			return;
		}

		m_ReceiveData.f_SetLen(m_nReceiveFill, false);
		m_nReceiveFill = 0;
		f_HandleDataMessage(NContainer::CSharedByteVector(fg_Move(m_ReceiveData)));
		m_ReceiveData.f_Clear();
	}

	EIncomingDataResult CAsyncSocketActor::CInternal::f_HandleIncomingData(uint8 const *_pData, umint _nBytes)
	{
		if (!_nBytes)
			return EIncomingDataResult_Continue;

		if (!m_fCheckUpgrade)
		{
			m_IncomingData.f_InsertBack(_pData, _nBytes);
			return EIncomingDataResult_Continue;
		}

		m_UpgradeCheckData.f_InsertBack(_pData, _nBytes);

		return f_CheckIncomingData();
	}

	EIncomingDataResult CAsyncSocketActor::CInternal::f_CheckIncomingData()
	{
		if (!m_fCheckUpgrade)
			return EIncomingDataResult_Continue;

		CAsyncSocketUpgradeCheckResult const CheckResult = m_fCheckUpgrade(m_UpgradeCheckData);
		if (CheckResult.m_nBytesConsumed > m_UpgradeCheckData.f_GetLen())
			DMibError("Async socket upgrade check consumed more bytes than were available");

		switch (CheckResult.m_Result)
		{
		case EAsyncSocketUpgradeCheckResult_MoreDataNeeded:
			{
				f_MoveUpgradeCheckDataToIncoming(CheckResult.m_nBytesConsumed);

				return CheckResult.m_nBytesConsumed ? EIncomingDataResult_ProcessIncoming : EIncomingDataResult_Continue;
			}
		case EAsyncSocketUpgradeCheckResult_Upgrade:
			{
				f_MoveUpgradeCheckDataToIncoming(CheckResult.m_nBytesConsumed);
				m_fCheckUpgrade.f_Clear();
				m_bUpgradeRequired = true;

				return EIncomingDataResult_StopReceiving;
			}
		case EAsyncSocketUpgradeCheckResult_UpgradeWillNeverHappen:
			{
				f_MoveUpgradeCheckDataToIncoming(CheckResult.m_nBytesConsumed);
				m_fCheckUpgrade.f_Clear();
				f_MoveAllUpgradeCheckDataToIncoming();

				return !m_IncomingData.f_IsEmpty() ? EIncomingDataResult_ProcessIncoming : EIncomingDataResult_Continue;
			}
		}

		DMibError("Invalid async socket upgrade check result");
	}

	void CAsyncSocketActor::CInternal::f_MoveUpgradeCheckDataToIncoming(umint _nBytes)
	{
		if (!_nBytes)
			return;

		DMibCheck(_nBytes <= m_UpgradeCheckData.f_GetLen());

		umint const nBytes = _nBytes;
		m_UpgradeCheckData.f_ReadFront
			(
				nBytes
				, [&](umint _iStart, uint8 const *_pData, umint _nChunkBytes) -> bool
				{
					m_IncomingData.f_InsertBack(_pData, _nChunkBytes);
					return _iStart + _nChunkBytes < nBytes;
				}
			)
		;
		m_UpgradeCheckData.f_RemoveFront(nBytes);
	}

	void CAsyncSocketActor::CInternal::f_MoveAllUpgradeCheckDataToIncoming()
	{
		f_MoveUpgradeCheckDataToIncoming(m_UpgradeCheckData.f_GetLen());
	}

	void CAsyncSocketActor::fp_ProcessIncoming()
	{
		auto &Internal = *mp_pInternal;

		bool bMoreWork = true;
		while (bMoreWork && !Internal.m_IncomingData.f_IsEmpty())
		{
			bMoreWork = false;
			switch (Internal.m_State)
			{
			case EState_Connected:
				{
					if (fp_ProcessIncomingMessage())
						bMoreWork = true;
				}
				break;
			case EState_Disconnected:
				{
					// Just drop everything that comes in
					Internal.m_IncomingData.f_RemoveFront(Internal.m_IncomingData.f_GetLen());
				}
				break;
			case EState_None:
				break; // Handshake still running
			}
		}
	}

	void CAsyncSocketActor::fp_StopDeferring()
	{
		auto &Internal = *mp_pInternal;
		Internal.m_bDeferringCallbacks = false;
		if (Internal.m_Callbacks.m_fOnReceiveData)
		{
			for (auto &pMessage : Internal.m_DeferredOnReciveData)
				Internal.m_Callbacks.m_fOnReceiveData.f_CallDiscard(fg_Move(pMessage));
			Internal.m_DeferredOnReciveData.f_Clear();
		}
		if (Internal.m_Callbacks.m_fOnClose && Internal.m_bOnCloseCalled)
			Internal.m_Callbacks.m_fOnClose.f_CallDiscard(Internal.m_DeferredNotifyClose.m_Status, Internal.m_DeferredNotifyClose.m_Message, Internal.m_DeferredNotifyClose.m_Origin);
	}

	void CAsyncSocketActor::fp_RejectConnection(NStr::CStr const &_Error)
	{
		fp_StopDeferring();

		fp_Disconnect(EAsyncSocketStatus_Rejected, NStr::fg_Format("Rejected connection: {}", _Error), false, EAsyncSocketCloseOrigin_Local);
	}

	void CAsyncSocketActor::fp_CheckHandshake(CInternal &_Internal)
	{
		if (_Internal.m_State != EState_None || !_Internal.m_pSocket || !_Internal.m_pSocket->f_IsValid())
			return;

		NNetwork::CSocketOperationResult Result = _Internal.m_pSocket->f_Send(nullptr, 0);
		if (Result.m_bSentNetwork)
			_Internal.f_OnSentData();
		if (Result.m_bReceivedNetwork)
			_Internal.f_OnReceivedData();

		if (!_Internal.m_pSocket->f_HandshakeDone())
			return;

		_Internal.m_State = EState_Connected;
		if (_Internal.m_UpgradeSocketPromise)
		{
			NStorage::TCUniquePointer<NNetwork::ICSocketConnectionInfo> pSocketInfo;
			if (_Internal.m_pSocket)
				pSocketInfo = _Internal.m_pSocket->f_GetConnectionInfo();
			_Internal.m_UpgradeSocketPromise->f_SetResult(fg_Move(pSocketInfo));
			_Internal.m_UpgradeSocketPromise.f_Clear();
		}
		else if (!_Internal.m_FinishConnectionPromise.f_IsSet())
		{
			CFinishConnectionResult Result;
			Result.m_Result = EFinishConnectionResult_Success;
			if (_Internal.m_pSocket)
				Result.m_ConnectionInfo.m_pSocketInfo = _Internal.m_pSocket->f_GetConnectionInfo();
			Result.m_ConnectionInfo.m_PeerAddress = _Internal.m_PeerAddress;

			_Internal.m_FinishConnectionPromise.f_SetResult(fg_Move(Result));
		}

		// Read submission is driven by the state processing below or the next readiness edge —
		// the poll only flips to close events once a first operation is submitted, so nothing
		// is lost by activating without arming a receive here
		fp_TryActivateCompletionIo();

		fp_UpdateSend();

		NNetwork::ENetTCPState State = NNetwork::ENetTCPState_None;
		if (_Internal.m_pSocket && _Internal.m_pSocket->f_IsValid())
			State = _Internal.m_pSocket->f_GetState();

		fp_ProcessState(State);
	}

	NConcurrency::CActorSubscription CAsyncSocketActor::fp_AcceptConnection(CAsyncSocketCallbacks _Callbacks)
	{
		auto &Internal = *mp_pInternal;
		Internal.m_Callbacks = fg_Move(_Callbacks);
		auto Subscription = NConcurrency::g_ActorSubscription / [this]() -> NConcurrency::TCFuture<void>
			{
				auto &Internal = *mp_pInternal;
				Internal.m_fCheckUpgrade.f_Clear();
				co_await (fg_Move(Internal.m_Callbacks.m_fOnClose).f_Destroy() + fg_Move(Internal.m_Callbacks.m_fOnReceiveData).f_Destroy());
				co_return {};
			}
		;

		fp_StopDeferring();
		if (!Internal.m_IncomingData.f_IsEmpty())
			fp_ProcessIncoming();

		fp_CheckHandshake(Internal);

		return fg_Move(Subscription);
	}

	void CAsyncSocketActor::fp_ProcessState(NNetwork::ENetTCPState _StateAdded)
	{
		auto &Internal = *mp_pInternal;

		if (Internal.m_bInProcessState)
		{
			// fp_CheckHandshake recurses into fp_ProcessState from the receive loop before the outer
			// frame has buffered the bytes it already received. Processing here would read newer
			// socket data first and reorder the stream, so defer to the outer invocation instead.
			Internal.m_PendingProcessState |= _StateAdded;
			return;
		}

		Internal.m_bInProcessState = true;
		auto ResetInProcessState = NMib::g_OnScopeExit / [&]
			{
				Internal.m_bInProcessState = false;
			}
		;

		while (true)
		{
			fp_ProcessStateNow(_StateAdded);

			_StateAdded = Internal.m_PendingProcessState;
			if (!_StateAdded)
				break;

			Internal.m_PendingProcessState = NNetwork::ENetTCPState_None;
		}
	}

	void CAsyncSocketActor::fp_ProcessStateNow(NNetwork::ENetTCPState _StateAdded)
	{
		auto &Internal = *mp_pInternal;

		if (!Internal.m_pSocket || !Internal.m_pSocket->f_IsValid() || f_IsDestroyed())
			return;

		if
		(
			Internal.m_bReceiveStreamActive && !Internal.m_bReceiveStreamEnded
			&& (_StateAdded & (NNetwork::ENetTCPState_Closed | NNetwork::ENetTCPState_RemoteClosed))
		)
		{
			// The stream can still hold the bytes that precede the close, and delivery order
			// between it and the poll's close events is not defined. The close states wait for
			// the stream's terminal, the completion mode form of the flush-first rule below —
			// and the stream always terminates once the peer is gone
			Internal.m_DeferredCloseStates = Internal.m_DeferredCloseStates | (_StateAdded & (NNetwork::ENetTCPState_Closed | NNetwork::ENetTCPState_RemoteClosed));
			_StateAdded = _StateAdded & ~(NNetwork::ENetTCPState_Closed | NNetwork::ENetTCPState_RemoteClosed);

			if (!_StateAdded)
				return;
		}

		if
		(
			(_StateAdded & NNetwork::ENetTCPState_Read)
#if DMibConfig_Tests_Enable
			&& !Internal.m_bDebugNoProcessing
#endif
		)
		{
			do
			{
				if (Internal.f_GetCompletionIoReceive())
				{
					// Payload arrives through receive completions and readiness reads must never
					// overlap a submitted operation; a stray readiness edge here at most makes
					// sure one is armed
					fp_StartReceiveStream();
					break;
				}

				if (Internal.m_State == EState_Connected && Internal.m_bUpgradeRequired)
				{
					Internal.m_DeferredTCPState = NNetwork::ENetTCPState_Read;
					break;
				}

				NNetwork::CSocketOperationResult CombinedResults;
				uint8 Data[4096];
				try
				{
					while (true)
					{
						// The upgrade decision settles mid drain, and a readiness receive must
						// never overlap a submitted operation, so the loop hands over as soon as
						// completion transfers activate
						fp_TryActivateCompletionIo();
						if (Internal.f_GetCompletionIoReceive())
						{
							fp_StartReceiveStream();
							break;
						}

						if (!Internal.m_fCheckUpgrade && Internal.m_State == EState_Connected && Internal.m_IncomingData.f_IsEmpty())
						{
							// Steady state: receive straight into the buffer that is delivered to
							// the callback, with no bounce buffer or paged intermediate
							umint DeliverySize = fg_Max(Internal.m_FramentationSize, umint(4096));
							auto &Buffer = Internal.m_ReceiveData;
							if (Buffer.f_IsEmpty())
							{
								Buffer.f_SetLen(DeliverySize, false);
								Internal.m_nReceiveFill = 0;
							}

							umint Capacity = Buffer.f_GetLen();
							NNetwork::CSocketOperationResult Result = Internal.m_pSocket->f_Receive
								(
									Buffer.f_GetArray() + Internal.m_nReceiveFill
									, Capacity - Internal.m_nReceiveFill
								)
							;
							CombinedResults += Result;
							Internal.m_nReceiveFill += Result.m_nBytes;

							if (Result.m_nBytes == 0 && !Result.m_bSentNetwork && !Result.m_bReceivedNetwork)
							{
								Internal.f_DeliverReceiveBuffer();
								break;
							}
							DMibLog(DebugVerbose3, " ++++ {} Received data {}", !Internal.m_bClient, Result.m_nBytes);

							if (Internal.m_nReceiveFill >= Capacity)
								Internal.f_DeliverReceiveBuffer();

							if (!Internal.m_pSocket || !Internal.m_pSocket->f_IsValid())
							{
								Internal.f_DeliverReceiveBuffer();
								return;
							}
							continue;
						}

						umint Size = Internal.m_fCheckUpgrade ? 1 : 4096;
						NNetwork::CSocketOperationResult Result = Internal.m_pSocket->f_Receive(Data, Size);
#if DMibConfig_IoDebug_Enable
						if (auto *pStats = NNetwork::fg_NetIoStats())
						{
							pStats->m_nRecvReadinessCalls.f_FetchAdd(1, NAtomic::gc_MemoryOrder_Relaxed);
							pStats->m_nRecvReadinessBytes.f_FetchAdd(Result.m_nBytes, NAtomic::gc_MemoryOrder_Relaxed);
						}
#endif
						if (Internal.m_State == EState_None)
							fp_CheckHandshake(Internal);
						CombinedResults += Result;
						if (Result.m_nBytes == 0 && !Result.m_bSentNetwork && !Result.m_bReceivedNetwork)
						{
							if (!Internal.m_fCheckUpgrade)
								fp_ProcessIncoming();
							break;
						}
						DMibLog(DebugVerbose3, " ++++ {} Received data {}", !Internal.m_bClient, Result.m_nBytes);
						EIncomingDataResult IncomingDataResult = Internal.f_HandleIncomingData(Data, Result.m_nBytes);

						if (IncomingDataResult == EIncomingDataResult_ProcessIncoming || (!Internal.m_fCheckUpgrade && Internal.m_IncomingData.f_GetLen() >= Internal.m_FramentationSize))
							fp_ProcessIncoming();

						if (IncomingDataResult == EIncomingDataResult_StopReceiving)
						{
							fp_ProcessIncoming();
							break;
						}

						if (!Internal.m_pSocket || !Internal.m_pSocket->f_IsValid())
						{
							fp_ProcessIncoming();
							return;
						}
					}
				}
				catch (NCryptography::CExceptionCryptography const &_Exception)
				{
					fp_Disconnect(EAsyncSocketStatus_AbnormalClosure, NStr::fg_Format("Socket error: {}", _Exception.f_GetErrorStr()), true, EAsyncSocketCloseOrigin_Remote);
					return;
				}
				catch (NNetwork::CExceptionNet const &_Exception)
				{
					fp_Disconnect(EAsyncSocketStatus_AbnormalClosure, NStr::fg_Format("Socket error: {}", _Exception.f_GetErrorStr()), true, EAsyncSocketCloseOrigin_Remote);
					return;
				}
				if (CombinedResults.m_bReceivedNetwork)
					Internal.f_OnReceivedData();
				if (CombinedResults.m_bSentNetwork)
					Internal.f_OnSentData();
			}
			while (false)
				;
		}

		auto fFlushIncomingBeforeClose = [&]
			{
				if (Internal.m_State != EState_Connected)
					return;

				if (Internal.m_fCheckUpgrade)
				{
					Internal.m_fCheckUpgrade.f_Clear();
					Internal.f_MoveAllUpgradeCheckDataToIncoming();
				}

				if (!Internal.m_IncomingData.f_IsEmpty())
					fp_ProcessIncoming();
			}
		;

		if (_StateAdded & NNetwork::ENetTCPState_RemoteClosed)
		{
			fFlushIncomingBeforeClose();
			if (Internal.m_State != EState_Disconnected)
				fp_Disconnect(EAsyncSocketStatus_NormalClosure, NStr::fg_Format("Socket closed: {}", Internal.m_pSocket->f_GetCloseReason()), false, EAsyncSocketCloseOrigin_Remote);
		}

		if (_StateAdded & NNetwork::ENetTCPState_Closed)
		{
			fFlushIncomingBeforeClose();
			if (Internal.m_State != EState_Disconnected)
				fp_Disconnect(EAsyncSocketStatus_AbnormalClosure, NStr::fg_Format("Socket closed: {}", Internal.m_pSocket->f_GetCloseReason()), true, EAsyncSocketCloseOrigin_Remote);
			else
			{
				Internal.m_pSocket.f_Clear();
				Internal.f_ShutdownDone(NStr::CStr());
			}
			return;
		}

		if
		(
			(_StateAdded & NNetwork::ENetTCPState_Write)
#if DMibConfig_Tests_Enable
			&& !Internal.m_bDebugNoProcessing
#endif
		)
		{
			fp_UpdateSend();
		}
	}

	void CAsyncSocketActor::fp_SetSocket(NStorage::TCUniquePointer<NNetwork::ICSocket> _pSocket)
	{
		auto &Internal = *mp_pInternal;
		Internal.m_pSocket = fg_Move(_pSocket);

		// A transport that buffers on the way through sizes that buffering from what one transfer
		// is worth here, which is the same size the receive buffer is cut to
		if (Internal.m_pSocket)
			Internal.m_pSocket->f_SetTransferSizeHint(fg_Max(Internal.m_FramentationSize, umint(4096)) + gc_SocketFramingMargin);

		NNetwork::ENetTCPState State = NNetwork::ENetTCPState_None;
		if (Internal.m_pSocket->f_IsValid())
		{
			try
			{
				NException::CDisableExceptionTraceScope DisableTrace;
				Internal.m_PeerAddress = Internal.m_pSocket->f_GetPeerAddress();
			}
			catch (NCryptography::CExceptionCryptography const &)
			{
			}
			catch (NNetwork::CExceptionNet const &)
			{
			}
			State = Internal.m_pSocket->f_GetState();
		}

		fp_ProcessState(State);
	}

	void CAsyncSocketActor::fp_SetSocketAndUpgradeCheck(NStorage::TCUniquePointer<NNetwork::ICSocket> _pSocket, FAsyncSocketUpgradeCheck &&_fCheckUpgrade)
	{
		auto &Internal = *mp_pInternal;
		Internal.m_fCheckUpgrade = fg_Move(_fCheckUpgrade);

		fp_SetSocket(fg_Move(_pSocket));
	}

	auto CAsyncSocketActor::fp_FinishConnection() -> NConcurrency::TCFuture<CFinishConnectionResult>
	{
		auto &Internal = *mp_pInternal;
		co_return co_await Internal.m_FinishConnectionPromise.f_Future();
	}

	NConcurrency::TCFuture<void> CAsyncSocketActor::f_SetTimeout(fp64 _Seconds)
	{
		if (f_IsDestroyed())
			co_return DMibErrorInstance("Destroying socket");

		auto &Internal = *mp_pInternal;
		Internal.m_Timeout = _Seconds;
		Internal.f_SetupTimeout();

		co_return {};
	}

	void CAsyncSocketActor::CInternal::f_StopTimeout()
	{
		m_TimeoutTimerSubscription.f_Clear();
	}

	void CAsyncSocketActor::CInternal::f_SetupTimeout()
	{
		f_StopTimeout();
		if (m_Timeout == 0.0)
			return; // Timeout disabled

		m_TimeoutReceivedData.f_Start();
		m_TimeoutSentData.f_Start();

		auto Sequence = ++m_TimeoutTimerSubscriptionSequence;
		fg_RegisterTimer
			(
				m_Timeout/2.0
				, [this]() -> NConcurrency::TCFuture<void>
				{
					f_UpdateTimeout();
					co_return {};
				}
				, fg_ThisActor(m_pThis)
			)
			> [this, Sequence](NConcurrency::TCAsyncResult<NConcurrency::CActorSubscription> &&_Subscription)
			{
				if (!_Subscription || m_TimeoutTimerSubscriptionSequence != Sequence)
					return;
				m_TimeoutTimerSubscription = fg_Move(*_Subscription);
			}
		;
	}

	void CAsyncSocketActor::CInternal::f_OnReceivedData()
	{
		m_TimeoutReceivedData.f_Start();
	}

	void CAsyncSocketActor::CInternal::f_OnSentData()
	{
		m_TimeoutSentData.f_Start();
	}

	void CAsyncSocketActor::CInternal::f_UpdateTimeout()
	{
		if (m_State == EState_Connected)
		{
			if (m_TimeoutReceivedData.f_GetTime() > m_Timeout)
				m_pThis->fp_Disconnect(EAsyncSocketStatus_Timeout, NStr::fg_Format("Timeout({}) receiving data", m_Timeout), true, EAsyncSocketCloseOrigin_Local);

			if (m_nOutgoingQueuedBytes)
			{
				if (m_TimeoutSentData.f_GetTime() > m_Timeout)
					m_pThis->fp_Disconnect(EAsyncSocketStatus_Timeout, NStr::fg_Format("Timeout({}) sending data", m_Timeout), true, EAsyncSocketCloseOrigin_Local);
			}
		}
		else if (m_State != EState_Disconnected)
		{
			NNetwork::ENetTCPState State = NNetwork::ENetTCPState_None;
			if (m_pSocket && m_pSocket->f_IsValid())
				State = m_pSocket->f_GetState();
			if (State)
				m_pThis->fp_ProcessState(State);

			if (m_TimeoutReceivedData.f_GetTime() > m_Timeout && m_TimeoutSentData.f_GetTime() > m_Timeout)
				m_pThis->fp_Disconnect(EAsyncSocketStatus_Timeout, NStr::fg_Format("Timeout({}) in non-connected state", m_Timeout), true, EAsyncSocketCloseOrigin_Local);
		}
	}
}
