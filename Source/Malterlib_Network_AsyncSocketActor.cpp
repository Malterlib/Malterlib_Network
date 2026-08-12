// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Concurrency/ConcurrencyManager>
#include <Mib/Concurrency/Actor/Timer>
#include <Mib/Concurrency/ActorSubscription>
#include <Mib/Container/PagedByteVector>
#include <Mib/Cryptography/Exception>

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

		enum
		{
			EIncomingPageSize = 2048
			, ECopySmallDeliveryThreshold = 1024
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
	}

	struct CAsyncSocketActor::CInternal
	{
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
			, m_IncomingData(EIncomingPageSize)
			, m_UpgradeCheckData(EIncomingPageSize)
			, m_fCheckUpgrade(fg_Move(_fCheckUpgrade))
			, m_bClient(_bClient)
			, m_MaxMessageSize(_MaxMessageSize)
			, m_FramentationSize(_FragmentationSize)
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

		void f_HandleDataMessage(NStorage::TCSharedPointer<NContainer::CIOByteVector const> &&_pData);
		void f_DeliverReceiveBuffer();
		EIncomingDataResult f_CheckIncomingData();
		EIncomingDataResult f_HandleIncomingData(uint8 const *_pData, umint _nBytes);
		void f_MoveUpgradeCheckDataToIncoming(umint _nBytes);
		void f_MoveAllUpgradeCheckDataToIncoming();
		void f_FinishConnection();

		COutgoingMessage &f_QueueMessage(NContainer::CSharedByteVector const &_Data, uint32 _Priority);
		void f_WriteQueuedMessages();

		void f_NotifyClose(EAsyncSocketStatus _Status, NStr::CStr const &_Message, EAsyncSocketCloseOrigin _Origin);

		CAsyncSocketActor *m_pThis = nullptr;
		NStorage::TCUniquePointer<NNetwork::ICSocket> m_pSocket;
		NMib::NNetwork::CNetAddress m_PeerAddress;

		EState m_State = EState_None;

		NContainer::CPagedByteVector m_IncomingData;
		NContainer::CPagedByteVector m_UpgradeCheckData;

		// Connected state receive target: bytes land straight in the buffer that is handed to
		// the receive callback, so nothing is copied between the socket and the consumer. It
		// is filled in place and only wrapped in a shared buffer when it is handed over, which
		// moves the allocation rather than the bytes
		NContainer::CIOByteVector m_ReceiveBuffer;
		umint m_nReceiveBufferFill = 0;
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
		NContainer::TCVector<NStorage::TCSharedPointer<NContainer::CIOByteVector const>> m_DeferredOnReciveData;
		CNotifyClose m_DeferredNotifyClose;

		NConcurrency::TCPromise<CFinishConnectionResult> m_FinishConnectionPromise;
		NStorage::TCOptionalClearOnMove<NConcurrency::TCPromise<NStorage::TCUniquePointer<NNetwork::ICSocketConnectionInfo>>> m_UpgradeSocketPromise;

		NConcurrency::CActorSubscription m_TimeoutTimerSubscription;
		NTime::CStopwatch m_TimeoutReceivedData;
		NTime::CStopwatch m_TimeoutSentData;
		NNetwork::ENetTCPState m_DeferredTCPState = NNetwork::ENetTCPState_None;
		NNetwork::ENetTCPState m_PendingProcessState = NNetwork::ENetTCPState_None;

		fp64 m_Timeout = 0.0;
		umint m_TimeoutTimerSubscriptionSequence = 0;
		uint64 m_nSentBytes = 0;

		umint m_MaxMessageSize = 0;
		umint m_FramentationSize = 0;

		bool m_bClient = false;
		bool m_bInProcessState = false;
		bool m_bOnCloseCalled = false;
		bool m_bDeferringCallbacks = true;
		bool m_bUpgradeRequired = false;
		bool m_bShutdownCalled = false;
#if DMibConfig_Tests_Enable
		bool m_bDebugNoProcessing = false;
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

		Internal.m_PendingMessages.f_Clear();
		Internal.m_OutgoingDataPromises.clear();
		if (Internal.m_ClosePromise)
		{
			Internal.m_ClosePromise->f_SetException(DMibErrorInstance("Abandoned close"));
			Internal.m_ClosePromise.f_Clear();
		}

		return g_Void;
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
		if (!Internal.m_IncomingData.f_IsEmpty() || !Internal.m_UpgradeCheckData.f_IsEmpty() || Internal.m_nReceiveBufferFill || Internal.m_nOutgoingQueuedBytes || !Internal.m_PendingMessages.f_IsEmpty() || !Internal.m_OutgoingDataPromises.empty())
			co_return DMibErrorInstance("Socket upgrade requires empty incoming and outgoing buffers");
		if (Internal.m_UpgradeSocketPromise)
			co_return DMibErrorInstance("Socket upgrade already in progress");

		NStorage::TCUniquePointer<NNetwork::ICSocket> pNewSocket = _SocketFactory(_Hostname);
		Internal.m_bUpgradeRequired = false;
		auto DeferredTCPState = Internal.m_DeferredTCPState;
		Internal.m_DeferredTCPState = NNetwork::ENetTCPState_None;
		void *pSocketHandle = Internal.m_pSocket->f_GiveUpForInherit();
		Internal.m_pSocket.f_Clear();

		NConcurrency::TCActor<CAsyncSocketActor> ThisActor = fg_ThisActor(this);
		pNewSocket->f_InheritHandle
			(
				pSocketHandle
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
		// allocation and each outgoing segment keeps its whole shared payload alive
		m_OutgoingSegments.f_Clear();
		m_nOutgoingQueuedBytes = 0;
		m_ReceiveBuffer.f_Clear();
		m_nReceiveBufferFill = 0;

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

		bool bDidSend = false;
		while (Internal.m_nOutgoingQueuedBytes && Internal.m_pSocket->f_IsValid())
		{
			// Gather the head segments as spans (no copy) and hand them to the socket as one
			// vectored operation: each segment references its shared message buffer in place
			NSys::CIoSpan Spans[NNetwork::ICSocket::mc_MaxSendSpans];
			umint nSpans = 0;
			umint nGatheredBytes = 0;
			constexpr umint c_MaxGatherBytes = 256 * 1024;
			for (auto &Segment : Internal.m_OutgoingSegments)
			{
				// A segment holds a whole message, so it is clamped to what is left of the
				// gather budget: sockets without a vectored implementation fall back to one
				// f_Send per span, and the SSL one takes an int length
				umint nSegmentBytes = fg_Min(Segment.m_Data.f_GetLen() - Segment.m_iSent, c_MaxGatherBytes - nGatheredBytes);

				Spans[nSpans].m_pData = Segment.m_Data.f_GetArray() + Segment.m_iSent;
				Spans[nSpans].m_nBytes = nSegmentBytes;
				nGatheredBytes += nSegmentBytes;
				++nSpans;
				if (nSpans >= NNetwork::ICSocket::mc_MaxSendSpans || nGatheredBytes >= c_MaxGatherBytes)
					break;
			}

			umint SentBytes = 0;
			bool bStuffed = false;
			bool bDisconnected = false;
			NNetwork::CSocketOperationResult CombinedResults;
			try
			{
				bDidSend = true;
				NNetwork::CSocketOperationResult Result = Internal.m_pSocket->f_SendVectored(Spans, nSpans);
				DMibLog(DebugVerbose3, " ++++ {} Sending {} resulted in {} sent", !Internal.m_bClient, nGatheredBytes, Result.m_nBytes);

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

			uint64 PrevSent = Internal.m_nSentBytes;
			Internal.m_nSentBytes += SentBytes;

			while (!Internal.m_OutgoingDataPromises.empty())
			{
				auto &Promise = Internal.m_OutgoingDataPromises.front();
				uint64 Diff = Promise.m_Position - PrevSent;
				if (Diff <= SentBytes)
				{
					Promise.m_Promise->f_SetResult();
					Promise.m_Promise.f_Clear();
					Internal.m_OutgoingDataPromises.pop_front();
					continue;
				}
				break;
			}

			// Consume the sent bytes across head segments; a fully sent segment releases its
			// keep alive on the shared message buffer
			Internal.m_nOutgoingQueuedBytes -= SentBytes;
			umint nConsumed = SentBytes;
			while (nConsumed)
			{
				auto &Head = Internal.m_OutgoingSegments.f_GetFirst();
				umint nHeadRemaining = Head.m_Data.f_GetLen() - Head.m_iSent;
				umint nThis = fg_Min(nConsumed, nHeadRemaining);
				Head.m_iSent += nThis;
				nConsumed -= nThis;

				if (Head.m_iSent == Head.m_Data.f_GetLen())
					Internal.m_OutgoingSegments.f_Remove(Head);
			}

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

		Internal.f_HandleDataMessage(fg_Construct(fg_Move(Data)));

		return true;
	}

	void CAsyncSocketActor::CInternal::f_HandleDataMessage(NStorage::TCSharedPointer<NContainer::CIOByteVector const> &&_pData)
	{
		DMibLog(DebugVerbose3, " ++++ {} call m_OnReceiveData", !m_bClient);
		if (m_bDeferringCallbacks)
		{
			m_DeferredOnReciveData.f_Insert(fg_Move(_pData));
			return;
		}

		if (m_Callbacks.m_fOnReceiveData)
			m_Callbacks.m_fOnReceiveData.f_CallDiscard(fg_Move(_pData));
	}

	void CAsyncSocketActor::CInternal::f_DeliverReceiveBuffer()
	{
		if (!m_nReceiveBufferFill)
			return;

		if (m_nReceiveBufferFill <= ECopySmallDeliveryThreshold)
		{
			// A small delivery is copied into a right sized buffer so the consumer never
			// pins the full receive buffer, which is kept and refilled instead
			NContainer::CIOByteVector Data;
			Data.f_SetLen(m_nReceiveBufferFill, false);
			NMemory::fg_ObjectCopy(Data.f_GetArray(), m_ReceiveBuffer.f_GetArray(), m_nReceiveBufferFill);
			m_nReceiveBufferFill = 0;
			f_HandleDataMessage(fg_Construct(fg_Move(Data)));
			return;
		}

		m_ReceiveBuffer.f_SetLen(m_nReceiveBufferFill, false);
		m_nReceiveBufferFill = 0;
		f_HandleDataMessage(fg_Construct(fg_Move(m_ReceiveBuffer)));
		m_ReceiveBuffer.f_Clear();
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
			(_StateAdded & NNetwork::ENetTCPState_Read)
#if DMibConfig_Tests_Enable
			&& !Internal.m_bDebugNoProcessing
#endif
		)
		{
			do
			{
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
						if (!Internal.m_fCheckUpgrade && Internal.m_State == EState_Connected && Internal.m_IncomingData.f_IsEmpty())
						{
							// Steady state: receive straight into the buffer that is delivered to
							// the callback, with no bounce buffer or paged intermediate
							umint DeliverySize = fg_Max(Internal.m_FramentationSize, umint(4096));
							auto &Buffer = Internal.m_ReceiveBuffer;
							if (Buffer.f_IsEmpty())
							{
								Buffer.f_SetLen(DeliverySize, false);
								Internal.m_nReceiveBufferFill = 0;
							}

							umint Capacity = Buffer.f_GetLen();
							NNetwork::CSocketOperationResult Result = Internal.m_pSocket->f_Receive
								(
									Buffer.f_GetArray() + Internal.m_nReceiveBufferFill
									, Capacity - Internal.m_nReceiveBufferFill
								)
							;
							CombinedResults += Result;
							Internal.m_nReceiveBufferFill += Result.m_nBytes;

							if (Result.m_nBytes == 0 && !Result.m_bSentNetwork && !Result.m_bReceivedNetwork)
							{
								Internal.f_DeliverReceiveBuffer();
								break;
							}
							DMibLog(DebugVerbose3, " ++++ {} Received data {}", !Internal.m_bClient, Result.m_nBytes);

							if (Internal.m_nReceiveBufferFill >= Capacity)
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
