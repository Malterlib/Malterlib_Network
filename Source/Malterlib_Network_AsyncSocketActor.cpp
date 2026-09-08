// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Concurrency/ConcurrencyManager>
#include <Mib/Concurrency/LogError>
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

		// Retains shared payload until its final byte is sent.
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
		// Indexed send reservations support out-of-order reports. Bounded gathers/windows fit 32-bit counts; free entries form an index list.
		struct CSendReservation
		{
			static constexpr uint32 mc_iNone = TCLimitsInt<uint32>::mc_Max;

			uint32 m_nBytes = 0;
			uint32 m_iNextFree = mc_iNone;
		};

		CInternal
			(
				CAsyncSocketActor *_pThis
				, bool _bClient
				, umint _MaxMessageSize
				, umint _FragmentationSize
				, umint _SendWindowBytes
				, fp64 _Timeout
				, FAsyncSocketUpgradeCheck &&_fCheckUpgrade
			)
			: m_pThis(_pThis)
			, m_IncomingData(gc_IncomingPageSize)
			, m_UpgradeCheckData(gc_IncomingPageSize)
			, m_fCheckUpgrade(fg_Move(_fCheckUpgrade))
			, m_bClient(_bClient)
			, m_MaxMessageSize(_MaxMessageSize)
			, m_FramentationSize(fg_Min(_FragmentationSize, umint(1) << 30)) // Bounded so every gather size derived from it stays well inside umint, on 32 bit platforms included
			, m_Timeout(_Timeout)
		{
			m_nSendWindowBytes = fg_Min(_SendWindowBytes, gc_SocketMaxSendWindowBytes);
			f_SizeSendReservations();
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

		umint f_SendWindowStartBytes() const;
		umint f_SendWindowBytes() const;
		void f_SizeSendReservations();
		void f_ResetSendReservations();

		// A continuation carries no reservation of its own
		static constexpr umint mc_iNoReservation = umint(-1);

		CAsyncSocketActor *m_pThis = nullptr;
		NStorage::TCUniquePointer<NNetwork::ICSocket> m_pSocket;
		NMib::NSys::CIoSubSystem *m_pIo = &NMib::NSys::fg_IoSubSystem();

		NMib::NNetwork::CNetAddress m_PeerAddress;

		EState m_State = EState_None;
		uint32 m_iFreeSendReservation = CSendReservation::mc_iNone;

		NContainer::CPagedByteVector m_IncomingData;
		NContainer::CPagedByteVector m_UpgradeCheckData;
		NContainer::CIOByteVector m_ReceiveData; // Actor-thread delivery buffer, separate from kernel-owned receive buffers.
		umint m_nReceiveFill = 0;
		FAsyncSocketUpgradeCheck m_fCheckUpgrade;
		NContainer::TCLinkedList<COutgoingSegment> m_OutgoingSegments;
		uint64 m_nOutgoingQueuedBytes = 0; // Logical bytes can exceed 32-bit allocation size when the same payload is queued repeatedly.
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
		NNetwork::ICSocketCompletionIo *m_pCompletionIo = nullptr; // Fixed at activation; use it to resolve in-flight work even after new submissions are disabled.

		NStorage::TCSharedPointer<NSys::CIoStreamBackpressure> m_pReceiveBackpressure;

		fp64 m_Timeout = 0.0;
		umint m_TimeoutTimerSubscriptionSequence = 0;
		uint64 m_nSentBytes = 0;

		umint m_MaxMessageSize = 0;
		umint m_FramentationSize = 0;

		umint m_nSendOpsInFlight = 0;
		umint m_nOutgoingSubmitted = 0; // Reserved plaintext excluded from later gathers until completion.

		NContainer::TCVector<CSendReservation> m_SendReservations; // Preallocated for the window; indexed free list avoids per-send scans or growth.
		umint m_nSendReservationsInUse = 0;
		umint m_nMaxSendReservations = 8;
		umint m_nSendBytesUnreleased = 0; // Accepted bytes whose release callback has not run.
		umint m_nSendWindowBytes = 0; // Zero selects an eight-frame ceiling.

		NNetwork::ENetTCPState m_DeferredTCPState = NNetwork::ENetTCPState_None;
		NNetwork::ENetTCPState m_PendingProcessState = NNetwork::ENetTCPState_None;
		NNetwork::ENetTCPState m_DeferredCloseStates = NNetwork::ENetTCPState_None; // Held until earlier stream bytes, including peer close frames, have been delivered.
		NNetwork::ENetTCPState m_StateBeforeSocket = NNetwork::ENetTCPState_None; // Latch reports queued during accept before socket handover, including terminal handshake failures.

		bool m_bClient = false;
		bool m_bInProcessState = false;
		bool m_bOnCloseCalled = false;
		bool m_bDeferringCallbacks = true;
		bool m_bUpgradeRequired = false;
		bool m_bShutdownCalled = false;
		bool m_bCompletionIo = false;
		bool m_bReceiveStreamActive = false; // Close states wait for the stream's one terminal segment.
		bool m_bReceiveStreamEnded = false;

		bool m_bDeferredShutdownCleanup = false;
#if DMibConfig_Tests_Enable
		bool m_bDebugNoProcessing = false;
		NContainer::TCVector<NSys::CIoStreamSegment> m_DebugHeldSegments; // Held test segments remain charged to receive backpressure.
#endif
#if DMibEnableSafeCheck > 0
		bool m_bDestroyed = false;
#endif
	};

	CAsyncSocketActor::CAsyncSocketActor(bool _bClient, umint _MaxMessageSize, umint _FragmentationSize, umint _SendWindowBytes, fp64 _Timeout, FAsyncSocketUpgradeCheck &&_fCheckUpgrade)
		: mp_pInternal(fg_Construct(this, _bClient, _MaxMessageSize, _FragmentationSize, _SendWindowBytes, _Timeout, fg_Move(_fCheckUpgrade)))
	{
		auto &Internal = *mp_pInternal;
		Internal.f_SetupTimeout();
	}

	CAsyncSocketActor::~CAsyncSocketActor()
	{
	}

	// Use the cached interface to resolve in-flight work even after new submissions stop.
	NNetwork::ICSocketCompletionIo *CAsyncSocketActor::CInternal::f_GetCompletionIo()
	{
		if (!m_bCompletionIo || !m_pSocket)
			return nullptr;

		return m_pCompletionIo;
	}

	// New submissions only; resolve existing operations through the cached interface.
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

	umint CAsyncSocketActor::CInternal::f_SendWindowStartBytes() const
	{
		return fg_Max(m_FramentationSize, umint(4096)) + gc_SocketFramingMargin;
	}

	umint CAsyncSocketActor::CInternal::f_SendWindowBytes() const
	{
		// Saturating: eight frames of a fragmentation near a 32 bit umint's limit would wrap
		return m_nSendWindowBytes ? m_nSendWindowBytes : 8 * fg_Min(f_SendWindowStartBytes(), TCLimitsInt<umint>::mc_Max / 8);
	}

	// Preallocate the bounded window's reservations so sends never grow the pool; a raised window extends the free list here.
	void CAsyncSocketActor::CInternal::f_SizeSendReservations()
	{
		umint nFrameBytes = f_SendWindowStartBytes();
		m_nMaxSendReservations = fg_Max(umint(8), f_SendWindowBytes() / nFrameBytes + 2);
		umint nEntries = m_SendReservations.f_GetLen();
		if (nEntries >= m_nMaxSendReservations)
			return;

		m_SendReservations.f_SetLen(m_nMaxSendReservations);
		CSendReservation *pReservations = m_SendReservations.f_GetArray();
		for (CSendReservation *pReservation = pReservations + nEntries, *pEnd = pReservations + m_nMaxSendReservations; pReservation != pEnd; ++pReservation)
		{
			pReservation->m_iNextFree = m_iFreeSendReservation;
			m_iFreeSendReservation = uint32(pReservation - pReservations);
		}
	}

	// Tearing the connection down gives every reservation back at once; operations still in flight then find their own already accounted for
	void CAsyncSocketActor::CInternal::f_ResetSendReservations()
	{
		m_iFreeSendReservation = CSendReservation::mc_iNone;
		CSendReservation *pReservations = m_SendReservations.f_GetArray();
		for (CSendReservation *pReservation = pReservations + m_SendReservations.f_GetLen(); pReservation != pReservations;)
		{
			--pReservation;
			pReservation->m_nBytes = 0;
			pReservation->m_iNextFree = m_iFreeSendReservation;
			m_iFreeSendReservation = uint32(pReservation - pReservations);
		}

		m_nSendReservationsInUse = 0;
		m_nSendBytesUnreleased = 0;
	}

	umint CAsyncSocketActor::CInternal::f_GatherSendSpans(NSys::CIoSpan *o_pSpans, umint &o_nSpans, NContainer::TCVector<NContainer::CSharedByteVector> &o_KeepAlives)
	{
		umint nSpans = 0;
		umint nGatheredBytes = 0;

		// Keep one full transport frame in a gather while retaining a useful minimum batch size.
		umint nMaxGatherBytes = fg_Max(umint(256 * 1024), m_FramentationSize + gc_SocketFramingMargin);

		// Skip bytes reserved by earlier operations so later gathers cannot submit them twice.
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

			// Bound spans for scalar fallbacks and SSL's signed transfer length.
			umint nSegmentBytes = fg_Min(Segment.m_Data.f_GetLen() - iStart, nMaxGatherBytes - nGatheredBytes);

			o_pSpans[nSpans].m_pData = Segment.m_Data.f_GetArray() + iStart;
			o_pSpans[nSpans].m_nBytes = nSegmentBytes;
			nGatheredBytes += nSegmentBytes;
			++nSpans;

			// Keep payload owners until buffer release, which can follow completion and queue retirement.
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
		f_ResetSendReservations();
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

		// Take deferred close states before reporting them; reporting can reenter disconnect and must not deliver them twice.
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

		// Destroy aborts outstanding output so an unresponsive peer cannot hold the buffer-release fence through retransmission timeout.
		// Callers needing graceful closure must shut down and drain before destruction.
		if (Internal.m_pSocket)
			Internal.m_pSocket->f_SetAbortOnClose();

		if (Internal.m_pOpTracker)
		{
			// Close cancels kernel work; retain payloads and actor state until the operation tracker drains across this await.
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
		{
			co_return DMibErrorInstance
				(
					"Socket upgrade requires CAsyncSocketClientActor::f_SetDefaultUpgradeCheckFactory or "
					"CAsyncSocketServerActor::f_SetDefaultUpgradeCheckFactory callback to return EAsyncSocketUpgradeCheckResult_Upgrade"
				)
			;
		}

		if
		(
			!Internal.m_IncomingData.f_IsEmpty()
			|| !Internal.m_UpgradeCheckData.f_IsEmpty()
			|| Internal.f_HasBufferedReceive()
			|| Internal.m_nOutgoingQueuedBytes
			|| !Internal.m_PendingMessages.f_IsEmpty()
			|| !Internal.m_OutgoingDataPromises.empty()
		)
		{
			co_return DMibErrorInstance("Socket upgrade requires empty incoming and outgoing buffers");
		}

		if (Internal.m_UpgradeSocketPromise)
			co_return DMibErrorInstance("Socket upgrade already in progress");

		NStorage::TCUniquePointer<NNetwork::ICSocket> pNewSocket = _SocketFactory(_Hostname);
		Internal.m_bUpgradeRequired = false;

		auto DeferredTCPState = fg_Exchange(Internal.m_DeferredTCPState, NNetwork::ENetTCPState_None);

		// Do not activate completion I/O while an upgrade can still replace the transport.
		DMibFastCheck(!Internal.m_bCompletionIo && !Internal.m_bReceiveStreamActive && !Internal.m_nSendOpsInFlight);

		// Move the platform socket without deregistering; an upgrade retains its loop and needs no inheritable handle.
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

		if (Internal.m_pSocket)
		{
			Internal.m_pSocket->f_SetTransferSizeHint(fg_Max(Internal.m_FramentationSize, umint(4096)) + gc_SocketFramingMargin);
			Internal.m_pSocket->f_SetSendWindow(Internal.f_SendWindowBytes(), Internal.m_nSendWindowBytes != 0);
		}

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

		// Disconnected actors may remain referenced; release buffers now unless kernel operations still pin them.
		if (m_nSendOpsInFlight)
			m_bDeferredShutdownCleanup = true;
		else
			f_ReleaseTransferState();

		f_StopTimeout();

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

			// A disconnected socket can still be draining before shutdown or waiting for peer FIN. Destroying it now would reset queued output.
			if (!Internal.m_pSocket)
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
		auto &Internal = *mp_pInternal;
		if (!Internal.m_pSocket)
		{
			Internal.m_StateBeforeSocket = Internal.m_StateBeforeSocket | _StateAdded;
			return;
		}

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
				// Fatal closure aborts retransmission so kernel-held pages release promptly.
				if (Internal.m_pSocket)
					Internal.m_pSocket->f_SetAbortOnClose();
				Internal.m_pSocket.f_Clear();
				Internal.f_ShutdownDone(_Reason);
			}
			return; // Already disconnected
		}

		if (Internal.m_State == EState_Connected)
		{
			// Delay write shutdown until queued and in-flight sends drain.
			if (!_bFatal && !Internal.m_nOutgoingQueuedBytes && !Internal.m_nSendOpsInFlight)
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

			if (Internal.m_pSocket)
				Internal.m_pSocket->f_SetAbortOnClose();
			Internal.m_pSocket.f_Clear();
			Internal.f_ShutdownDone(_Reason);
		}

		// Messages that were queued but not yet written can never be sent after a disconnect. Fail their promises instead of leaving them unresolved forever.
		Internal.m_PendingMessages.f_Clear();
		if (_bFatal)
			Internal.m_OutgoingDataPromises.clear();

		Internal.m_State = EState_Disconnected;

		// Keep the timeout while disconnected output drains; a peer that stops reading must not retain backlog promises forever.
		if (!Internal.m_pSocket || (!Internal.m_nOutgoingQueuedBytes && !Internal.m_nSendOpsInFlight))
			Internal.f_StopTimeout();

		// Local closure ends stream-based close deferral; route reentry through active state processing.
		if (Internal.m_DeferredCloseStates)
		{
			NNetwork::ENetTCPState DeferredStates = Internal.m_DeferredCloseStates;
			Internal.m_DeferredCloseStates = NNetwork::ENetTCPState_None;
			fp_ProcessState(DeferredStates);
		}
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

				// A TLS socket under completion sends leaves its close alert for the drain to carry
				fp_DrainSocketOutput();
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

		// Choose completion I/O per direction; readiness sends still need write edges to finish short transfers.
		if (auto *pCompletionIoSend = Internal.f_GetCompletionIoSend())
		{
			// Staging may accept new sends while earlier work remains in flight; its gate bounds buffering and loop ordering preserves the stream.
			while (Internal.m_pSocket->f_IsValid() && pCompletionIoSend->f_CanSubmitSend() && Internal.m_nOutgoingQueuedBytes > Internal.m_nOutgoingSubmitted)
			{
				umint nBefore = Internal.m_nOutgoingSubmitted;
				fp_SubmitSendOp();
				if (Internal.m_nOutgoingSubmitted == nBefore)
					break;

				if (Internal.m_State == EState_Connected)
					Internal.f_WriteQueuedMessages();
			}

			if (Internal.m_State == EState_Disconnected && !Internal.m_nOutgoingQueuedBytes && !Internal.m_nSendOpsInFlight)
				fp_Shutdown();

			fp_DrainSocketOutput();

			return;
		}

		bool bDidSend = false;
		while (Internal.m_nOutgoingQueuedBytes && Internal.m_pSocket->f_IsValid())
		{
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

		// Activate only after upgrade sniffing ends; in-flight operations would pin a transport being replaced.
		if (Internal.m_State != EState_Connected || Internal.m_fCheckUpgrade || Internal.m_bUpgradeRequired)
			return;

		if (!Internal.m_pSocket || !Internal.m_pSocket->f_IsValid())
			return;

		auto *pCompletionIo = Internal.m_pSocket->f_GetCompletionIo();
		if (!pCompletionIo)
			return;

		Internal.m_pCompletionIo = pCompletionIo;
		Internal.m_bCompletionIo = true;
		Internal.m_pOpTracker = fg_Construct();

		// Reject synchronous entry points before submitting the first operation.
		pCompletionIo->f_OnCompletionActivated();

		DMibLog(DebugVerbose3, " ++++ {} Completion transfers active", !Internal.m_bClient);

		// Start receive delivery at activation even for send-only users; no read readiness will drive it afterwards.
		fp_StartReceiveStream();
	}

	void CAsyncSocketActor::fp_StartReceiveStream()
	{
		auto &Internal = *mp_pInternal;

		// Never restart after the stream's terminal segment, even if a late readiness edge arrives.
		if (Internal.m_bReceiveStreamActive || Internal.m_bReceiveStreamEnded)
			return;

		if (!Internal.m_pSocket || !Internal.m_pSocket->f_IsValid())
			return;

		// Graceful local close must keep draining reads so the peer can flush before FIN; drop payload while disconnected.
		if (Internal.m_State != EState_Connected && Internal.m_State != EState_Disconnected)
			return;

		// Bytes buffered by readiness receives predate anything the stream delivers, so flushing
		// them first keeps the stream in order
		if (!Internal.m_IncomingData.f_IsEmpty())
			fp_ProcessIncoming();

		auto *pCompletionIo = Internal.f_GetCompletionIoReceive();
		if (!pCompletionIo)
			return;

		// Charge retained capacity across the pipeline; final buffer release reschedules this actor when backpressure clears.
		umint nBufferBytes = pCompletionIo->f_GetReceiveBufferBytes();
		auto pBackpressure = NStorage::TCSharedPointer<NSys::CIoStreamBackpressure>(fg_Construct());
		pBackpressure->m_nLimitBytes = NNetwork::fg_GetReceiveWindowBytes(*Internal.m_pIo, nBufferBytes);
		pBackpressure->m_nResumeBytes = pBackpressure->m_nLimitBytes / 2;
		pBackpressure->m_fResume = [WeakThis = fg_ThisActor(this).f_Weak()]() mutable
			{
				if (auto This = WeakThis.f_Lock())
					DMibLogWarningOrDiscardResult(This.f_Bind<&CAsyncSocketActor::fp_ReceiveWindowResume>(), "Mib/Network", "Resuming the receive window failed");
			}
		;
		Internal.m_pReceiveBackpressure = pBackpressure;

		bool bStarted = pCompletionIo->f_StartReceiveStream
			(
				fg_Move(pBackpressure)
				, [WeakThis = fg_ThisActor(this).f_Weak()](NSys::CIoStreamSegment &&_Segment) mutable
				{
					// The queued segment retains its buffer even if teardown drops the job.
					if (auto This = WeakThis.f_Lock())
						DMibLogWarningOrDiscardResult(This.f_Bind<&CAsyncSocketActor::fp_ReceiveSegment>(fg_Move(_Segment)), "Mib/Network", "Delivering a received segment failed");
				}
			)
		;

		if (bStarted)
		{
			Internal.m_bReceiveStreamActive = true;

			// Drain readiness-held bytes in a later actor job to avoid reentering the processing that started the stream.
			DMibLogWarningOrDiscardResult(fg_ThisActor(this).f_Bind<&CAsyncSocketActor::fp_DrainHeldInput>(), "Mib/Network", "Draining the input the socket held failed");
		}

	}

	void CAsyncSocketActor::fp_ReceiveWindowResume()
	{
		auto &Internal = *mp_pInternal;

		if (f_IsDestroyed())
			return;

		if (Internal.m_pSocket && Internal.m_pSocket->f_IsValid() && Internal.m_pCompletionIo)
			Internal.m_pCompletionIo->f_ResumeReceiveStream();
	}

	// Completion sends provide no write edge for transport-generated output; explicitly drain pending control records and partial sends.
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

	// A continuation advances transport-held output and may offer no new plaintext.
	void CAsyncSocketActor::fp_SubmitSendOp(bool _bContinue, umint _iInheritedReservation)
	{
		auto &Internal = *mp_pInternal;

		// A continuation inherits its reservation. Release it on every refused path or the queue remains permanently reserved.
		umint iReservation = _bContinue ? _iInheritedReservation : Internal.mc_iNoReservation;

		auto fReleaseOnFailure = NMib::g_OnScopeExit / [&]
			{
				if (iReservation == Internal.mc_iNoReservation)
					return;

				auto &Reservation = Internal.m_SendReservations[iReservation];

				if (!Reservation.m_nBytes)
					return;

				DMibFastCheck(Internal.m_nOutgoingSubmitted >= Reservation.m_nBytes);

				Internal.m_nOutgoingSubmitted -= fg_Exchange(Reservation.m_nBytes, 0);
				Reservation.m_iNextFree = Internal.m_iFreeSendReservation;
				Internal.m_iFreeSendReservation = uint32(iReservation);
				--Internal.m_nSendReservationsInUse;
			}
		;

		if (!Internal.m_nOutgoingQueuedBytes && !_bContinue)
			return;

		if (!Internal.m_pSocket || !Internal.m_pSocket->f_IsValid())
			return;

		auto *pCompletionIo = Internal.f_GetCompletionIoSend();
		if (!pCompletionIo)
			return;

		// Gate new batches only; buffer release retries when the byte window opens.
		if (!_bContinue && pCompletionIo->f_IsSendWindowFull(Internal.m_nSendBytesUnreleased, Internal.f_SendWindowStartBytes()))
		{
#if DMibConfig_IoDebug_Enable
			if (auto *pStats = NNetwork::fg_NetIoStats())
				pStats->m_nSendBlocked.f_FetchAdd(1, NAtomic::gc_MemoryOrder_Relaxed);
#endif

			return;
		}

		// Never gate continuations on staging capacity: sending held ciphertext is what frees that capacity.
		if (!_bContinue && !pCompletionIo->f_CanSubmitSend())
		{
#if DMibConfig_IoDebug_Enable
			if (auto *pStats = NNetwork::fg_NetIoStats())
				pStats->m_nSendBlocked.f_FetchAdd(1, NAtomic::gc_MemoryOrder_Relaxed);
#endif

			return;
		}


		// Reservations outlive transport records until continuation chains settle; retry new batches when a slot is released.
		if (!_bContinue)
		{
			umint nMaxReservations = pCompletionIo->f_SupportsSendStaging() ? umint(8) : Internal.m_nMaxSendReservations;
			if (Internal.m_nSendReservationsInUse >= nMaxReservations)
				return;

#if DMibConfig_IoDebug_Enable
			if (auto *pStats = NNetwork::fg_NetIoStats())
			{
				uint64 nOutstanding = Internal.m_nSendReservationsInUse + 1;
				uint64 nMax = pStats->m_nSendMaxOutstanding.f_Load(NAtomic::gc_MemoryOrder_Relaxed);
				while (nMax < nOutstanding && !pStats->m_nSendMaxOutstanding.f_CompareExchangeWeak(nMax, nOutstanding, NAtomic::gc_MemoryOrder_Relaxed))
				{
				}
			}
#endif
		}

		// Continuations offer no plaintext; the queue still holds bytes already reserved by the original transfer.
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

		if (!_bContinue)
		{
			DMibFastCheck(Internal.m_iFreeSendReservation != CInternal::CSendReservation::mc_iNone);
			iReservation = umint(Internal.m_iFreeSendReservation);
			Internal.m_iFreeSendReservation = Internal.m_SendReservations[iReservation].m_iNextFree;

			++Internal.m_nSendReservationsInUse;

			Internal.m_SendReservations[iReservation].m_nBytes = uint32(nGatheredBytes);
			Internal.m_nOutgoingSubmitted += nGatheredBytes;
		}

		// Both completion and release functors retain the tracker until destruction, including refusal and exception paths.
		NSys::FIoCompletion fOnComplete =
			[
				Hold = NConcurrency::CIoCompletionOpHold(Internal.m_pOpTracker)
				, iReservation
				, WeakThis = fg_ThisActor(this).f_Weak()
			]
			(NSys::CIoCompletion _Result) mutable
			{
				if (auto This = WeakThis.f_Lock())
					DMibLogWarningOrDiscardResult(This.f_Bind<&CAsyncSocketActor::fp_SendCompleted>(_Result, iReservation), "Mib/Network", "Completing a send failed");
			}
		;

		NNetwork::FSocketSendReleased fOnReleased =
			[
				Hold = NConcurrency::CIoCompletionOpHold(Internal.m_pOpTracker)
				, KeepAlives = fg_Move(KeepAlives)
				, WeakThis = fg_ThisActor(this).f_Weak()
				, nGatheredBytes
			]
			(umint _iTransfer) mutable
			{
				KeepAlives.f_Clear();

				if (auto This = WeakThis.f_Lock())
					DMibLogWarningOrDiscardResult(This.f_Bind<&CAsyncSocketActor::fp_SendBufferReleased>(_iTransfer, nGatheredBytes), "Mib/Network", "Releasing a send buffer failed");
			}
		;

		umint nScheduled = 0;
		bool bSubmitted;
		if (_bContinue)
			bSubmitted = pCompletionIo->f_ContinueSend(fg_Move(fOnComplete), fg_Move(fOnReleased));
		else
		{
			nScheduled = pCompletionIo->f_SubmitSendVectored(Spans, nSpans, fg_Move(fOnComplete), fg_Move(fOnReleased));
			DMibFastCheck(nScheduled <= nGatheredBytes);
			bSubmitted = nScheduled != 0;
		}

		if (bSubmitted)
		{
			fReleaseOnFailure.f_Clear();

			// Reserve only the accepted prefix; the untaken suffix remains available for the next gather.
			if (!_bContinue && nScheduled < nGatheredBytes)
			{
				Internal.m_nOutgoingSubmitted -= nGatheredBytes - nScheduled;
				Internal.m_SendReservations[iReservation].m_nBytes = nScheduled;
			}

			// Release retains the whole gather, including the untaken tail; temporary double-counting only applies backpressure early.
			Internal.m_nSendBytesUnreleased += nGatheredBytes;
		}
		else
		{
			// Refusal is terminal; leaving reserved plaintext queued would strand send futures.
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
		fp_ReceiveStreamInput(fg_Move(_Segment), false);
	}

	// Drain readiness-held TLS bytes on activation; the peer may send no further segment to trigger them.
	void CAsyncSocketActor::fp_DrainHeldInput()
	{
		fp_ReceiveStreamInput(NSys::CIoStreamSegment(), true);
	}

	void CAsyncSocketActor::fp_ReceiveStreamInput(NSys::CIoStreamSegment &&_Segment, bool _bHeldOnly)
	{
		auto &Internal = *mp_pInternal;

		if (f_IsDestroyed())
			return;

		auto &Segment = _Segment;
		bool bTerminal = !_bHeldOnly && (Segment.m_Status != NSys::EIoCompletionStatus::mc_Done || !Segment.m_nBytes);

		if (bTerminal)
		{
			Internal.m_bReceiveStreamActive = false;
			Internal.m_bReceiveStreamEnded = true;
		}

#if DMibConfig_Tests_Enable
		if (Internal.m_bDebugNoProcessing && !bTerminal && !_bHeldOnly)
		{
			// Held test segments remain charged and do not reset inactivity timeouts.
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

		// Deliver buffered bytes first; shared segments retain their kernel buffer, while disconnected drains drop them.
		if (!bTerminal && !_bHeldOnly)
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

				// A small delivery is copied into a right sized buffer so the consumer never pins the
				// full receive buffer. So is any delivery once retained buffers charge half the window:
				// a consumer that keeps what it is handed, assembling a message, must not park the stream
				bool bCopy = SharedResult.m_nBytes <= gc_CopySmallDeliveryThreshold;
				if (!bCopy && Internal.m_pReceiveBackpressure)
				{
					auto &Backpressure = *Internal.m_pReceiveBackpressure;
					bCopy = Backpressure.m_nOutstandingBytes.f_Load(NAtomic::gc_MemoryOrder_Relaxed) >= Backpressure.m_nResumeBytes;
				}

				if (bCopy)
				{
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
			NSys::CIoCompletion Result;
			Internal.m_pCompletionIo->f_ResolveReceiveSegment(Segment, nullptr, 0, Result);
			Internal.f_TryReleaseDeferredTransferState();
			return;
		}

		// Resolve transport processing on the actor thread, draining held output one delivery buffer at a time.
		bool bDelivering = Internal.m_State == EState_Connected;

		// Count ciphertext activity even when an incomplete record yields no plaintext.
		if (bDelivering)
			Internal.f_OnReceivedData();

		umint DeliverySize = fg_Max(Internal.m_FramentationSize, umint(4096));
		bool bResolvedSegment = _bHeldOnly;
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
			// After the close callback, discard payload but keep draining so the peer can finish.

			if (!Internal.m_pSocket || !Internal.m_pSocket->f_IsValid())
			{
				Internal.f_TryReleaseDeferredTransferState();
				return;
			}
		}

		// TLS close_notify can end the stream before kernel EOF. Release deferred close state now; the peer may wait for our alert before FIN.
		if (!bTerminal && Internal.m_pCompletionIo->f_ReceiveStreamEndedByProtocol())
		{
			bTerminal = true;
			Internal.m_bReceiveStreamActive = false;
			Internal.m_bReceiveStreamEnded = true;
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
				// Keep the reservation until the transport finishes or the same plaintext can be gathered twice. Continuations reserve no new bytes.
				if (_iReservation == Internal.mc_iNoReservation)
					return;

				auto &Reservation = Internal.m_SendReservations[_iReservation];

				if (!Reservation.m_nBytes)
					return;

				DMibFastCheck(Internal.m_nOutgoingSubmitted >= Reservation.m_nBytes);

				Internal.m_nOutgoingSubmitted -= Reservation.m_nBytes;
				Reservation.m_nBytes = 0;
				Reservation.m_iNextFree = Internal.m_iFreeSendReservation;
				Internal.m_iFreeSendReservation = uint32(_iReservation);
				--Internal.m_nSendReservationsInUse;
			}
		;

		if (f_IsDestroyed())
			return;

		// Resolve wire bytes to plaintext progress; pending transport records can require a continuation.
		bool bSocketUsable = Internal.m_pSocket && Internal.m_pSocket->f_IsValid();
		bool bResolved = true;
		if (bSocketUsable && Internal.m_pCompletionIo)
			bResolved = Internal.m_pCompletionIo->f_ResolveSend(_Result);

		if (_Result.m_Status == NSys::EIoCompletionStatus::mc_Cancelled || !bSocketUsable)
		{
			Internal.m_nOutgoingSubmitted = 0;
			Internal.f_ResetSendReservations();
			Internal.f_TryReleaseDeferredTransferState();
			return;
		}

		if (!bResolved)
		{
			// The socket still holds these bytes, so the reservation travels to the operation that carries on with them
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

		fp_UpdateSend();
	}

	// Buffer release unblocks staging generations and queued plaintext.
	void CAsyncSocketActor::fp_SendBufferReleased(umint _iTransfer, umint _nBytes)
	{
		auto &Internal = *mp_pInternal;

		// The window asks measure against this; a teardown may have zeroed the count already
		Internal.m_nSendBytesUnreleased -= fg_Min(_nBytes, Internal.m_nSendBytesUnreleased);

		if (f_IsDestroyed())
			return;

		bool bSocketUsable = Internal.m_pSocket && Internal.m_pSocket->f_IsValid();
		if (bSocketUsable && Internal.m_pCompletionIo)
			Internal.m_pCompletionIo->f_ResolveSendRelease(_iTransfer);

		if (!bSocketUsable)
			return;

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
			&& Internal.m_State != EState_Disconnected
			&& (_StateAdded & (NNetwork::ENetTCPState_Closed | NNetwork::ENetTCPState_RemoteClosed))
		)
		{
			// Poll close state can overtake stream bytes; defer until terminal delivery. After local closure, do not wait:
			// retained consumer buffers may park the stream before its terminal arrives.
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
			// The handshake can start the stream before its final readiness payload is buffered.
			// Flush that payload even when the stream has already started.
			auto fLeaveReadinessReceive = [&]
				{
					fp_StartReceiveStream();
					if (!Internal.m_IncomingData.f_IsEmpty())
						fp_ProcessIncoming();
				}
			;

			do
			{
				if (Internal.f_GetCompletionIoReceive())
				{
					fLeaveReadinessReceive();
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
						// Stop the readiness drain immediately when completion I/O activates.
						fp_TryActivateCompletionIo();
						if (Internal.f_GetCompletionIoReceive())
						{
							fLeaveReadinessReceive();
							break;
						}

						if (!Internal.m_fCheckUpgrade && Internal.m_State == EState_Connected && Internal.m_IncomingData.f_IsEmpty())
						{
							umint DeliverySize = fg_Max(Internal.m_FramentationSize, umint(4096));
							auto &Buffer = Internal.m_ReceiveData;
							if (Buffer.f_IsEmpty())
							{
								Buffer.f_SetLen(DeliverySize, false);
								Internal.m_nReceiveFill = 0;
							}

							umint Capacity = Buffer.f_GetLen();
							NNetwork::CSocketOperationResult Result = Internal.m_pSocket->f_Receive(Buffer.f_GetArray() + Internal.m_nReceiveFill, Capacity - Internal.m_nReceiveFill);
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

		if (Internal.m_pSocket)
		{
			Internal.m_pSocket->f_SetTransferSizeHint(fg_Max(Internal.m_FramentationSize, umint(4096)) + gc_SocketFramingMargin);
			Internal.m_pSocket->f_SetSendWindow(Internal.f_SendWindowBytes(), Internal.m_nSendWindowBytes != 0);
		}

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

		State = State | Internal.m_StateBeforeSocket;
		Internal.m_StateBeforeSocket = NNetwork::ENetTCPState_None;

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

	// Sets the adaptive ceiling in bytes; zero uses eight initial frames.
	NConcurrency::TCFuture<void> CAsyncSocketActor::f_SetSendWindow(umint _nBytes)
	{
		auto &Internal = *mp_pInternal;
		Internal.m_nSendWindowBytes = fg_Min(_nBytes, gc_SocketMaxSendWindowBytes);
		Internal.f_SizeSendReservations();
		if (Internal.m_pSocket)
			Internal.m_pSocket->f_SetSendWindow(Internal.f_SendWindowBytes(), _nBytes != 0);

		co_return {};
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
		// Disconnected output still depends on peer reads and needs a timeout.
		else if (m_State != EState_Disconnected || m_nOutgoingQueuedBytes || m_nSendOpsInFlight)
		{
			NNetwork::ENetTCPState State = NNetwork::ENetTCPState_None;
			if (m_pSocket && m_pSocket->f_IsValid())
				State = m_pSocket->f_GetState();
			if (State)
				m_pThis->fp_ProcessState(State);

			// A peer may keep writing without reading; disconnected send backlog must time out on send progress alone.
			if (m_State == EState_Disconnected && m_nOutgoingQueuedBytes && m_TimeoutSentData.f_GetTime() > m_Timeout)
			{
				m_pThis->fp_Disconnect(EAsyncSocketStatus_Timeout, NStr::fg_Format("Timeout({}) sending data", m_Timeout), true, EAsyncSocketCloseOrigin_Local);
				return;
			}

			if (m_TimeoutReceivedData.f_GetTime() > m_Timeout && m_TimeoutSentData.f_GetTime() > m_Timeout)
				m_pThis->fp_Disconnect(EAsyncSocketStatus_Timeout, NStr::fg_Format("Timeout({}) in non-connected state", m_Timeout), true, EAsyncSocketCloseOrigin_Local);
		}
	}
}
