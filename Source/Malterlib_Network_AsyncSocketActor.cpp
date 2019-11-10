// Copyright © 2019 Nonna Holding AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

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
typedef uint32 vec4uint32 __attribute__((ext_vector_type(4)));
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
			EOutgoingPageSize = 2048
			, EIncomingPageSize = 2048
		};

		struct COutgoingMessage
		{
			~COutgoingMessage()
			{
				if (m_pPromise)
					m_pPromise->f_SetException(DMibErrorInstance("Outgoing message abandoned"));
			}

			NStorage::TCSharedPointer<NContainer::CSecureByteVector> m_pData;
			NStorage::TCUniquePointer<NConcurrency::TCPromise<void>> m_pPromise;
			bool m_bFinished = false;
		};

		struct COutgoingDataPromise
		{
			COutgoingDataPromise() = default;
			COutgoingDataPromise(COutgoingDataPromise &&) = default;

			~COutgoingDataPromise()
			{
				if (m_pPromise)
					m_pPromise->f_SetException(DMibErrorInstance("Outgoing message abandoned"));
			}

			mint m_Position = 0;
			NStorage::TCUniquePointer<NConcurrency::TCPromise<void>> m_pPromise;
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
		CInternal(CAsyncSocketActor *_pThis, bool _bClient, mint _MaxMessageSize, mint _FragmentationSize, fp64 _Timeout)
			: m_pThis(_pThis)
			, m_IncomingData(EIncomingPageSize)
			, m_OutgoingData(EOutgoingPageSize)
			, m_bClient(_bClient)
			, m_MaxMessageSize(_MaxMessageSize)
			, m_FramentationSize(_FragmentationSize)
			, m_pLastPendingMessagesList(nullptr)
			, m_Timeout(_Timeout)
		{
		}

		~CInternal()
		{
			if (m_pClosePromise)
				m_pClosePromise->f_SetException(DMibErrorInstance("Abandoned close"));
		}

		void f_OnReceivedData();
		void f_OnSentData();

		void f_UpdateTimeout();
		void f_SetupTimeout();
		void f_StopTimeout();

		void f_ShutdownDone(NStr::CStr const &_Error);

		void f_HandleDataMessage(NContainer::CSecureByteVector &&_Data);
		void f_SendMessage(uint8 const *_pData, mint _nBytes);
		void f_FinishConnection();

		COutgoingMessage &f_QueueMessage(NStorage::TCSharedPointer<NContainer::CSecureByteVector> const &_pData, uint32 _Priority);
		COutgoingMessage &f_QueueFragmentedMessage(uint8 const *_pData, mint _nBytes, uint32 _Priority);
		void f_WriteQueuedMessages();

		void f_NotifyClose(EAsyncSocketStatus _Status, NStr::CStr const &_Message, EAsyncSocketCloseOrigin _Origin);

		CAsyncSocketActor *m_pThis = nullptr;
		NStorage::TCUniquePointer<NNetwork::ICSocket> m_pSocket;
		NMib::NNetwork::CNetAddress m_PeerAddress;

		EState m_State = EState_None;

		NContainer::CPagedByteVector m_IncomingData;
		NContainer::CPagedByteVector m_OutgoingData;
		std::deque<COutgoingDataPromise> m_OutgoingDataPromises;

		CAsyncSocketActor::CCloseInfo m_CloseInfo;

		NContainer::TCMap<uint32, NContainer::TCLinkedList<COutgoingMessage>> m_PendingMessages;
		NContainer::TCLinkedList<COutgoingMessage> *m_pLastPendingMessagesList;

		NStorage::TCUniquePointer<NConcurrency::TCPromise<CAsyncSocketActor::CCloseInfo>> m_pClosePromise;
		NContainer::TCLinkedList<NFunction::TCFunction<void (NStr::CStr const &_Error)>> m_OnShutdown;

		CAsyncSocketCallbacks m_Callbacks;
		NContainer::TCVector<NStorage::TCSharedPointer<NContainer::CSecureByteVector>> m_DeferredOnReciveData;
		CNotifyClose m_DeferredNotifyClose;

		NConcurrency::TCPromise<CFinishConnectionResult> m_FinishConnectionPromise;

		NConcurrency::CActorSubscription m_TimeoutTimerSubscription;
		NTime::CClock m_TimeoutReceivedData;
		NTime::CClock m_TimeoutSentData;

		fp64 m_Timeout = 0.0;
		mint m_TimeoutTimerSubscriptionSequence = 0;
		mint m_nSentBytes = 0;

		mint m_MaxMessageSize = 0;
		mint m_FramentationSize = 0;

		bool m_bClient = false;
		bool m_bDebugNoProcessing = false;
		bool m_bOnCloseCalled = false;
		bool m_bDeferringCallbacks = true;
		bool m_bShutdownCalled = false;
	};

	CAsyncSocketActor::CAsyncSocketActor(bool _bClient, mint _MaxMessageSize, mint _FragmentationSize, fp64 _Timeout)
		: mp_pInternal(fg_Construct(this, _bClient, _MaxMessageSize, _FragmentationSize, _Timeout))
	{
		auto &Internal = *mp_pInternal;
		Internal.f_SetupTimeout();
	}

	CAsyncSocketActor::~CAsyncSocketActor()
	{
	}

	COutgoingMessage &CAsyncSocketActor::CInternal::f_QueueMessage
		(
			NStorage::TCSharedPointer<NContainer::CSecureByteVector> const &_pData
			, uint32 _Priority
		)
	{
		auto &NewMessage = m_PendingMessages[_Priority].f_Insert();
		NewMessage.m_pData = _pData;
		NewMessage.m_bFinished = true;

		return NewMessage;
	}

	COutgoingMessage &CAsyncSocketActor::CInternal::f_QueueFragmentedMessage(uint8 const *_pData, mint _nBytes, uint32 _Priority)
	{
		COutgoingMessage *pLastMessage = nullptr;
		uint8 const *pBytes = _pData;
		mint nBytes = _nBytes;
		while (true)
		{
			mint ThisTime = fg_Min(nBytes, m_FramentationSize);
			NContainer::CSecureByteVector VectorData;
			VectorData.f_Insert(pBytes, ThisTime);
			nBytes -= ThisTime;
			pBytes += ThisTime;
			auto &NewMessage = f_QueueMessage(fg_Construct(fg_Move(VectorData)), _Priority);
			pLastMessage = &NewMessage;
			if (nBytes == 0)
				break;
			else
				NewMessage.m_bFinished = false;
		}

		return *pLastMessage;
	}

	void CAsyncSocketActor::CInternal::f_WriteQueuedMessages()
	{
		if (m_PendingMessages.f_IsEmpty())
			return;

		mint OutgoingData = m_OutgoingData.f_GetLen();

		auto pList = m_pLastPendingMessagesList;

		if (!pList)
		{
			pList = m_PendingMessages.f_FindLargest();
			DMibCheck(pList);
		}
		else
			pList = m_PendingMessages.f_FindLargest();

		DMibCheck(!pList->f_IsEmpty());

		auto *pPending = &pList->f_GetFirst();

		bool bFinished = false;

		while (true)
		{
			bFinished = pPending->m_bFinished;

			f_SendMessage(pPending->m_pData->f_GetArray(), pPending->m_pData->f_GetLen());
			OutgoingData = m_OutgoingData.f_GetLen();

			if (pPending->m_pPromise)
			{
				COutgoingDataPromise Promise;
				Promise.m_Position = m_nSentBytes + OutgoingData;
				Promise.m_pPromise = fg_Move(pPending->m_pPromise);
				m_OutgoingDataPromises.push_back(fg_Move(Promise));
			}

			pList->f_Remove(*pPending);
			if (pList->f_IsEmpty())
			{
				m_PendingMessages.f_Remove(pList);
				pList = m_PendingMessages.f_FindLargest();
				if (!pList)
				{
					pPending = nullptr;
					break;
				}
			}
			pPending = &pList->f_GetFirst();
		}

		if (bFinished)
			m_pLastPendingMessagesList = nullptr;
		else
			m_pLastPendingMessagesList = pList;
	}

	void CAsyncSocketActor::f_DebugStopProcessing()
	{
		auto &Internal = *mp_pInternal;
		Internal.m_bDebugNoProcessing = true;
	}

	NConcurrency::TCFuture<CAsyncSocketActor::CCloseInfo> CAsyncSocketActor::f_Close(EAsyncSocketStatus _Status, const NStr::CStr &_Reason)
	{
		auto &Internal = *mp_pInternal;
		if (Internal.m_pClosePromise)
			co_return DMibErrorInstance("Socket close already initiated");

		if (!Internal.m_pSocket || Internal.m_State == EState_Disconnected)
		{
			CAsyncSocketActor::CCloseInfo CloseInfo;
			CloseInfo.m_Status = EAsyncSocketStatus_AlreadyClosed;
			CloseInfo.m_Reason = "Already fully closed";
			co_return fg_Move(CloseInfo);
		}

		auto CloseFuture = (Internal.m_pClosePromise = fg_Construct())->f_Future();

		fp_Disconnect(_Status, _Reason, false, EAsyncSocketCloseOrigin_Local);

		co_await NConcurrency::ECoroutineFlag_BreakSelfReference;

 		co_return co_await fg_Move(CloseFuture);
	}

	void CAsyncSocketActor::CInternal::f_ShutdownDone(NStr::CStr const &_Error)
	{
		for (auto &fOnShutdown : m_OnShutdown)
			fOnShutdown(_Error);
		m_OnShutdown.f_Clear();
	}

	NConcurrency::TCFuture<CAsyncSocketActor::CCloseInfo> CAsyncSocketActor::f_CloseWithLinger(EAsyncSocketStatus _Status, const NStr::CStr &_Reason, fp64 _MaxLingerTime)
	{
		NConcurrency::TCPromise<CAsyncSocketActor::CCloseInfo> Promise;

		auto &Internal = *mp_pInternal;

		if (!Internal.m_pSocket || Internal.m_State == EState_Disconnected)
		{
			CAsyncSocketActor::CCloseInfo CloseInfo;
			CloseInfo.m_Status = EAsyncSocketStatus_AlreadyClosed;
			CloseInfo.m_Reason = "Already fully closed";
			return Promise <<= fg_Move(CloseInfo);
		}

		struct CState
		{
			~CState()
			{
				if (!m_bHandled)
					f_Finish();
			}

			void f_Finish()
			{
				fg_Move(m_AsyncSocketActor).f_Destroy() > NConcurrency::fg_DiscardResult();
			}

			NConcurrency::TCActor<CAsyncSocketActor> m_AsyncSocketActor;
			NAtomic::TCAtomic<bool> m_bHandled;
		};

		NStorage::TCSharedPointer<CState> pState = fg_Construct();
		pState->m_AsyncSocketActor = fg_ThisActor(this);

		auto Cleanup = NConcurrency::g_OnScopeExitActor(NConcurrency::fg_ConcurrentActor()) > [pState, Promise]
			{
				if (!pState->m_bHandled.f_Exchange(true))
				{
					Promise.f_SetException(DMibErrorInstance("Socket destroyed"));
					pState->f_Finish();
				}
			}
		;

		Internal.m_OnShutdown.f_Insert
			(
				[Cleanup, pState, Promise, this](NStr::CStr const &_Error)
				{
					auto &Internal = *mp_pInternal;
					if (!pState->m_bHandled.f_Exchange(true))
					{
						if (!_Error.f_IsEmpty())
							Promise.f_SetException(DMibErrorInstance(fg_Format("Unclean socket shutdown: {}", _Error)));
						else
							Promise.f_SetResult(fg_Move(Internal.m_CloseInfo));
						pState->f_Finish();
					}
				}
			)
		;

		f_Close(_Status, _Reason) > NConcurrency::fg_ConcurrentActor() / [pState, Promise]
			(NConcurrency::TCAsyncResult<NNetwork::CAsyncSocketActor::CCloseInfo> &&_Result)
			{
				if (!_Result)
				{
					if (!pState->m_bHandled.f_Exchange(true))
					{
						Promise.f_SetException(fg_Move(_Result));
						pState->f_Finish();
					}
				}
			}
		;

		NConcurrency::fg_Timeout(_MaxLingerTime, false)(NConcurrency::fg_ConcurrentActor()) > [Promise, pState]
			{
				if (!pState->m_bHandled.f_Exchange(true))
				{
					Promise.f_SetException(DMibErrorInstance("Timed out waiting for socket to close gracefully"));
					pState->f_Finish();
				}
			}
		;

		return Promise.f_MoveFuture();
	}

	NConcurrency::TCFuture<void> CAsyncSocketActor::f_SendData(NStorage::TCSharedPointer<NContainer::CSecureByteVector> const &_pMessage, uint32 _Priority)
	{
		NConcurrency::TCPromise<void> Result;

		auto &Internal = *mp_pInternal;
		DMibLog(DebugVerbose2, " ++++ {} f_SendBinary", !Internal.m_bClient);

		auto &Massage = *_pMessage;
		mint nBytes = Massage.f_GetLen();

		if (nBytes > Internal.m_MaxMessageSize)
			return Result <<= DMibErrorInstance("Message is bigger than max message size");

		if (_Priority == TCLimitsInt<uint32>::mc_Max)
			return Result <<= DMibErrorInstance("0xffffffff priority is reserved for internal messages");

		if (nBytes <= Internal.m_FramentationSize)
		{
			auto &NewMessage = Internal.f_QueueMessage(_pMessage, _Priority);
			NewMessage.m_pPromise = fg_Construct(Result);
			DMibLog(DebugVerbose2, " ++++ {} Queue non-fragmented", !Internal.m_bClient);
			fp_UpdateSend();
			return Result.f_MoveFuture();
		}

		Internal.f_QueueFragmentedMessage(Massage.f_GetArray(), nBytes, _Priority)
			.m_pPromise = fg_Construct(Result)
		;

		DMibLog(DebugVerbose2, " ++++ {} Queue fragmented", !Internal.m_bClient);
		fp_UpdateSend();

		return Result.f_MoveFuture();
	}

	void CAsyncSocketActor::fp_StateAdded(NNetwork::ENetTCPState _StateAdded)
	{
		fp_ProcessState(_StateAdded);
	}

	void CAsyncSocketActor::CInternal::f_SendMessage(uint8 const *_pData, mint _nBytes)
	{
		m_OutgoingData.f_InsertBack(_pData, _nBytes);
	}

	void CAsyncSocketActor::CInternal::f_NotifyClose(EAsyncSocketStatus _Status, NStr::CStr const &_Message, EAsyncSocketCloseOrigin _Origin)
	{
		if (m_bOnCloseCalled)
			return;
		m_bOnCloseCalled = true;

		if (m_Callbacks.m_fOnClose)
		{
			m_Callbacks.m_fOnClose(_Status, _Message, _Origin) > NConcurrency::fg_DiscardResult();
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
				if (Internal.m_pClosePromise)
				{
					Internal.m_pClosePromise->f_SetResult(Internal.m_CloseInfo);
					Internal.m_pClosePromise.f_Clear();
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
		}

		if (_bFatal)
		{
			Internal.m_CloseInfo.m_Status = _Status;
			Internal.m_CloseInfo.m_Reason = fg_Format("Abnormal closure: {}", _Reason);
			if (Internal.m_pClosePromise)
			{
				Internal.m_pClosePromise->f_SetResult(Internal.m_CloseInfo);
				Internal.m_pClosePromise.f_Clear();
			}
			Internal.f_NotifyClose(_Status, _Reason, _Origin);

			Internal.m_pSocket.f_Clear();
			Internal.f_ShutdownDone(_Reason);
		}

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

		if (Internal.m_bDebugNoProcessing)
			return;

		if (Internal.m_State == EState_Connected)
			Internal.f_WriteQueuedMessages();
		else
			fp_CheckHandshake(Internal);

		bool bDidSend = false;
		while (!Internal.m_OutgoingData.f_IsEmpty() && Internal.m_pSocket->f_IsValid())
		{
			mint SentBytes = 0;
			bool bStuffed = false;
			bool bDisconnected = false;
			NNetwork::CSocketOperationResult CombinedResults;
			Internal.m_OutgoingData.f_ReadFront
				(
					[&](mint _iStart, uint8 const* _pPtr, mint _nBytes) -> bool
					{
						try
						{
							bDidSend = true;
							NNetwork::CSocketOperationResult Result = Internal.m_pSocket->f_Send(_pPtr, _nBytes);
							DMibLog(DebugVerbose2, " ++++ {} Sending {} resulted in {} sent", !Internal.m_bClient, _nBytes, Result.m_nBytes);

							CombinedResults += Result;

							SentBytes += Result.m_nBytes;
							if (Result.m_nBytes != _nBytes)
							{
								bStuffed = true;
								return false;
							}
							return true;
						}
						catch (NCryptography::CExceptionCryptography const &_Error)
						{
							fp_Disconnect(EAsyncSocketStatus_AbnormalClosure, NStr::fg_Format("Socket exception: {}", _Error.f_GetErrorStr()), true, EAsyncSocketCloseOrigin_Remote);
							bDisconnected = true;
							return false;
						}
						catch (NNetwork::CExceptionNet const &_Error)
						{
							fp_Disconnect(EAsyncSocketStatus_AbnormalClosure, NStr::fg_Format("Socket exception: {}", _Error.f_GetErrorStr()), true, EAsyncSocketCloseOrigin_Remote);
							bDisconnected = true;
							return false;
						}
					}
				)
			;
			if (CombinedResults.m_bSentNetwork)
				Internal.f_OnSentData();
			if (CombinedResults.m_bReceivedNetwork)
				Internal.f_OnReceivedData();

			mint PrevSent = Internal.m_nSentBytes;
			Internal.m_nSentBytes += SentBytes;

			while (!Internal.m_OutgoingDataPromises.empty())
			{
				auto &Promise = Internal.m_OutgoingDataPromises.front();
				mint Diff = Promise.m_Position - PrevSent;
				if (Diff <= SentBytes)
				{
					Promise.m_pPromise->f_SetResult();
					Promise.m_pPromise.f_Clear();
					Internal.m_OutgoingDataPromises.pop_front();
					continue;
				}
				break;
			}

			Internal.m_OutgoingData.f_RemoveFront(SentBytes);
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

		if (Internal.m_State == EState_Disconnected && Internal.m_OutgoingData.f_IsEmpty())
			fp_Shutdown();
	}

	bool CAsyncSocketActor::fp_ProcessIncomingMessage()
	{
		auto &Internal = *mp_pInternal;
		DMibLog(DebugVerbose2, " ++++ {} fp_ProcessIncomingMessage", !Internal.m_bClient);

		mint Length = Internal.m_IncomingData.f_GetLen();
		NContainer::CSecureByteVector Data;
		Data.f_Reserve(Length);

		Internal.m_IncomingData.f_ReadFront
			(
				Length
				, [&](mint _iStart, uint8 const *_pData, mint _nBytes) -> bool
				{
					Data.f_Insert(_pData, _nBytes);
					return _iStart + _nBytes < Length;
				}
			)
		;

		Internal.m_IncomingData.f_RemoveFront(Length);

		Internal.f_HandleDataMessage(fg_Move(Data));

		return true;
	}

	void CAsyncSocketActor::CInternal::f_HandleDataMessage(NContainer::CSecureByteVector &&_Data)
	{
		DMibLog(DebugVerbose2, " ++++ {} call m_OnReceiveData", !m_bClient);
		if (m_bDeferringCallbacks)
		{
			m_DeferredOnReciveData.f_Insert(fg_Construct(fg_Construct(fg_Move(_Data))));
			return;
		}

		if (m_Callbacks.m_fOnReceiveData)
			m_Callbacks.m_fOnReceiveData(fg_Construct(fg_Move(_Data))) > NConcurrency::fg_DiscardResult();
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
				Internal.m_Callbacks.m_fOnReceiveData(pMessage) > NConcurrency::fg_DiscardResult();
			Internal.m_DeferredOnReciveData.f_Clear();
		}
		if (Internal.m_Callbacks.m_fOnClose && Internal.m_bOnCloseCalled)
		{
			Internal.m_Callbacks.m_fOnClose(Internal.m_DeferredNotifyClose.m_Status, Internal.m_DeferredNotifyClose.m_Message, Internal.m_DeferredNotifyClose.m_Origin)
				> NConcurrency::fg_DiscardResult()
			;
		}
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
		if (!_Internal.m_FinishConnectionPromise.f_IsSet())
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

	NConcurrency::CActorSubscription CAsyncSocketActor::fp_AcceptConnection(CAsyncSocketCallbacks &&_Callbacks)
	{
		auto &Internal = *mp_pInternal;
		Internal.m_Callbacks = fg_Move(_Callbacks);
		auto Subscription = NConcurrency::g_ActorSubscription / [this]() -> NConcurrency::TCFuture<void>
			{
				auto &Internal = *mp_pInternal;
				auto DestroyFutures = Internal.m_Callbacks.m_fOnClose.f_Destroy() + Internal.m_Callbacks.m_fOnReceiveData.f_Destroy();
				Internal.m_Callbacks.m_fOnClose.f_Clear();
				Internal.m_Callbacks.m_fOnReceiveData.f_Clear();
				co_await fg_Move(DestroyFutures);
				co_return {};
			}
		;

		fp_StopDeferring();

		fp_CheckHandshake(Internal);

		return fg_Move(Subscription);
	}

	void CAsyncSocketActor::fp_ProcessState(NNetwork::ENetTCPState _StateAdded)
	{
		auto &Internal = *mp_pInternal;

		if (!Internal.m_pSocket || !Internal.m_pSocket->f_IsValid())
			return;

		if ((_StateAdded & NNetwork::ENetTCPState_Read) && !Internal.m_bDebugNoProcessing)
		{
			NNetwork::CSocketOperationResult CombinedResults;
			uint8 Data[4096];
			try
			{
				while (true)
				{
					mint Size = 4096;
					NNetwork::CSocketOperationResult Result = Internal.m_pSocket->f_Receive(Data, Size);
					if (Internal.m_State == EState_None)
						fp_CheckHandshake(Internal);
					CombinedResults += Result;
					if (Result.m_nBytes == 0 && !Result.m_bSentNetwork && !Result.m_bReceivedNetwork)
					{
						fp_ProcessIncoming();
						break;
					}
					DMibLog(DebugVerbose2, " ++++ {} Received data {}", !Internal.m_bClient, Result.m_nBytes);
					Internal.m_IncomingData.f_InsertBack(Data, Result.m_nBytes);

					if (Internal.m_IncomingData.f_GetLen() >= Internal.m_FramentationSize)
						fp_ProcessIncoming();

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

		if (_StateAdded & NNetwork::ENetTCPState_RemoteClosed)
		{
			if (Internal.m_State != EState_Disconnected)
				fp_Disconnect(EAsyncSocketStatus_NormalClosure, NStr::fg_Format("Socket closed: {}", Internal.m_pSocket->f_GetCloseReason()), false, EAsyncSocketCloseOrigin_Remote);
		}

		if (_StateAdded & NNetwork::ENetTCPState_Closed)
		{
			if (Internal.m_State != EState_Disconnected)
				fp_Disconnect(EAsyncSocketStatus_AbnormalClosure, NStr::fg_Format("Socket closed: {}", Internal.m_pSocket->f_GetCloseReason()), true, EAsyncSocketCloseOrigin_Remote);
			else
			{
				Internal.m_pSocket.f_Clear();
				Internal.f_ShutdownDone(NStr::CStr());
			}
			return;
		}

		if ((_StateAdded & NNetwork::ENetTCPState_Write) && !Internal.m_bDebugNoProcessing)
			fp_UpdateSend();
	}

	void CAsyncSocketActor::fp_SetSocket(NStorage::TCUniquePointer<NNetwork::ICSocket> &&_pSocket)
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

	auto CAsyncSocketActor::fp_FinishConnection() -> NConcurrency::TCFuture<CFinishConnectionResult>
	{
		auto &Internal = *mp_pInternal;
		return Internal.m_FinishConnectionPromise.f_Future();
	}

	void CAsyncSocketActor::f_SetTimeout(fp64 _Seconds)
	{
		auto &Internal = *mp_pInternal;
		Internal.m_Timeout = _Seconds;
		Internal.f_SetupTimeout();
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

			if (!m_OutgoingData.f_IsEmpty())
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
