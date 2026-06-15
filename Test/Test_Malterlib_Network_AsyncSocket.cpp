// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Core/Core>
#include <Mib/Test/Test>
#include <Mib/Network/AsyncSocket>
#include <Mib/Network/Sockets/TCP>
#include <Mib/Network/Sockets/SSL>
#include <Mib/Cryptography/Certificate>
#include <Mib/Cryptography/RandomID>
#include <Mib/Concurrency/Actor/Timer>
#include <Mib/Concurrency/DistributedActorTestHelpers>

using namespace NMib::NNetwork;
using namespace NMib;
using namespace NMib::NTest;
using namespace NMib::NThread;
using namespace NMib::NContainer;
using namespace NMib::NStr;
using namespace NMib::NConcurrency;
using namespace NMib::NStorage;
using namespace NMib::NFunction;
using namespace NMib::NCryptography;

namespace
{
	CPublicKeySetting gc_TestTestKeySetting = CPublicKeySettings_EC_secp256r1{};
	char const *g_pCloseMessage = "Socket closed: Connection gracefully disconnected";
	fp64 g_Timeout = 30.0 * gc_TimeoutMultiplier;
}

class CAsyncSocket_Tests : public CTest
{
public:
	void fp_Test
		(
			TCFunction<TCTuple<FVirtualSocketFactory, FVirtualSocketFactory> ()> const &_fGetFactories
			, CStr const &_AcceptError
			, CStr const &_ConnectError
			, bool _bTestTimeout = false
		)
	{
		{
			DMibTestPath("IP");
			fp_TestImp(_fGetFactories, _AcceptError, _ConnectError, "localhost", _bTestTimeout);
		}
		{
			DMibTestPath("Unix");
			fp_TestImp(_fGetFactories, _AcceptError, _ConnectError, "UNIX:" + fg_GetSafeUnixSocketPath("{}/AsyncSocket.socket"_f << NFile::CFile::fs_GetProgramDirectory()), false);
		}
	}

	struct CState
	{
		struct CServerConnection
		{

			TCActorInterface<CAsyncSocketActor> m_Actor;
			CStr m_MessageBuffer;
			bool m_bFinished = false;
		};

		CState(TCSharedPointer<CDefaultRunLoop> const &_pRunLoop)
			: m_pRunLoop(_pRunLoop)
		{
		}

		~CState()
		{
			DMibLock(m_Lock);
			m_ServerActor.f_Clear();
			m_ListenCallbackReference.f_Clear();
			m_ServerConnections.f_Clear();
			m_ClientActor.f_Clear();
			m_ClientSocket.f_Clear();
			m_Messages.f_Clear();
		}

		CIntrusiveRefCountWithWeak m_RefCount;

		CMutual m_Lock;
		TCSharedPointer<CDefaultRunLoop> m_pRunLoop;
		bool m_bSignalCompletion = false;

		CStr m_ClientMessageBuffer;

		TCActor<CAsyncSocketServerActor> m_ServerActor;
		CActorSubscription m_ListenCallbackReference;

		TCMap<CStr, CServerConnection> m_ServerConnections;

		CStr m_AcceptError;
		bool m_bAcceptError = false;
		CStr m_ListenError;

		TCActor<CAsyncSocketClientActor> m_ClientActor;

		TCActorInterface<CAsyncSocketActor> m_ClientSocket;

		CStr m_ClientConnectionError;
		bool m_bClientConnectionResult = false;

		EAsyncSocketCloseOrigin m_ClientConnectionCloseOrigin = EAsyncSocketCloseOrigin_Local;
		EAsyncSocketCloseOrigin m_ServerConnectionCloseOrigin = EAsyncSocketCloseOrigin_Local;
		EAsyncSocketStatus m_ClientConnectionCloseStatus = EAsyncSocketStatus_None;
		EAsyncSocketStatus m_ServerConnectionCloseStatus = EAsyncSocketStatus_None;
		CStr m_ClientConnectionCloseMessage;
		CStr m_ServerConnectionCloseMessage;

		TCVector<CStr> m_Messages;

		bool m_bCleared = false;

		bool f_AllServerConnectionsFinished()
		{
			DMibLock(m_Lock);
			for (auto &Connection : m_ServerConnections)
			{
				if (!Connection.m_bFinished)
					return false;
			}
			return true;
		}

		void f_Signal()
		{
			DMibLock(m_Lock);
			m_bSignalCompletion = true;
			m_pRunLoop->f_Wake();
		}

		bool f_Wait()
		{
			while (true)
			{
				{
					DMibLock(m_Lock);
					if (m_bSignalCompletion)
					{
						m_bSignalCompletion = false;
						break;
					}
				}
				if (m_pRunLoop->f_WaitOnceTimeout(g_Timeout))
					return true;
			}
			return false;
		}

		void f_Clear()
		{
			TCFutureVector<void> Destroys;
			{
				DMibLock(m_Lock);
				m_bCleared = true;

				m_ClientSocket.f_Destroy() > Destroys;

				if (m_ClientSocket)
					fg_Move(m_ClientSocket).f_Destroy() > Destroys;

				if (m_ClientActor)
					fg_Move(m_ClientActor).f_Destroy() > Destroys;

				if (m_ListenCallbackReference)
				{
					m_ListenCallbackReference->f_Destroy() > Destroys;
					m_ListenCallbackReference.f_Clear();
				}

				for (auto &Connection : m_ServerConnections)
				{
					if (Connection.m_Actor)
						fg_Move(Connection.m_Actor).f_Destroy() > Destroys;
				}

				m_ServerConnections.f_Clear();
			}

			fg_AllDoneWrapped(Destroys).f_CallSync(m_pRunLoop);

			{
				DMibLock(m_Lock);
				if (m_ServerActor)
				{
					auto ServerActor = m_ServerActor;
					{
						DMibUnlock(m_Lock);
						ServerActor->f_BlockDestroy(m_pRunLoop->f_ActorDestroyLoop()); // Make sure to release listen socket
					}
					m_ServerActor.f_Clear();
				}
			}
		}

		void f_StartListen(CNetAddress _ListenAddress, FVirtualSocketFactory const &_ServerFactory)
		{
			TCWeakPointer<CState> pStateWeak = fg_Explicit(this);
			CAsyncSocketServerCallbacks ListenCallbacks;

			ListenCallbacks.m_fNewConnection = g_ActorFunctor / [pStateWeak](CAsyncSocketNewServerConnection _ConnectionInfo) -> TCFuture<void>
				{
					CAsyncSocketCallbacks Callbacks;
					CAsyncSocketNewServerConnection ConnectionInfo = fg_Move(_ConnectionInfo);
					CStr ServerConnectionID;
					{
						auto pState = pStateWeak.f_Lock();
						if (!pState)
							co_return {};
						DMibLock(pState->m_Lock);

						ServerConnectionID = fg_RandomID(pState->m_ServerConnections);

						auto &ServerConnection = pState->m_ServerConnections[ServerConnectionID];

						Callbacks.m_fOnReceiveData = g_ActorFunctor
							/ [=](TCSharedPointer<CIOByteVector> _pData) -> TCFuture<void>
							{
								auto pState = pStateWeak.f_Lock();
								if (!pState)
									co_return {};

								DMibLock(pState->m_Lock);
								auto *pServerConnection = pState->m_ServerConnections.f_FindEqual(ServerConnectionID);
								if (!pServerConnection || pState->m_bCleared)
									co_return {};

								for (auto &Connection : pState->m_ServerConnections)
								{
									if (Connection.m_Actor)
										Connection.m_Actor(&CAsyncSocketActor::f_SendData, _pData, 0).f_DiscardResult();
								}

								pServerConnection->m_MessageBuffer.f_AddStr((ch8 const *)_pData->f_GetArray(), _pData->f_GetLen());

								while (pServerConnection->m_MessageBuffer.f_FindChar('\n') >= 0)
								{
									CStr Command = fg_GetStrLineSep(pServerConnection->m_MessageBuffer);
									if (Command == "Disconnect")
									{
										DMibLock(pState->m_Lock);
										for (auto &Connection : pState->m_ServerConnections)
											Connection.m_Actor(&CAsyncSocketActor::f_Close, EAsyncSocketStatus_NormalClosure, g_pCloseMessage).f_DiscardResult();
									}
								}

								co_return {};
							}
						;

						Callbacks.m_fOnClose = g_ActorFunctor
							/ [=](EAsyncSocketStatus _Status, CStr _Message, EAsyncSocketCloseOrigin _Origin) -> TCFuture<void>
							{
								auto pState = pStateWeak.f_Lock();
								if (!pState)
									co_return {};
								DMibLock(pState->m_Lock);
								auto *pServerConnection = pState->m_ServerConnections.f_FindEqual(ServerConnectionID);
								if (!pServerConnection || pState->m_bCleared)
									co_return {};

								pState->m_ServerConnectionCloseMessage = _Message;
								pState->m_ServerConnectionCloseStatus = _Status;
								pState->m_ServerConnectionCloseOrigin = _Origin;
								pState->m_ServerConnections.f_Remove(pServerConnection);
								pState->f_Signal();

								co_return {};
							}
						;
					}

					auto Cleanup = g_OnScopeExit / [=]
						{
							auto pState = pStateWeak.f_Lock();
							if (!pState)
								return;

							DMibLock(pState->m_Lock);
							auto *pServerConnection = pState->m_ServerConnections.f_FindEqual(ServerConnectionID);
							if (!pServerConnection || pState->m_bCleared)
								return;

							pServerConnection->m_bFinished = true;
							pState->f_Signal();
						}
					;

					auto Actor = co_await ConnectionInfo.f_Accept(fg_Move(Callbacks));
					auto Cleanup2 = g_OnScopeExit / [&Actor]
						{
							if (Actor)
								fg_Move(Actor).f_Destroy().f_DiscardResult();
						}
					;

					auto pState = pStateWeak.f_Lock();
					if (!pState)
						co_return {};

					{
						DMibLock(pState->m_Lock);
						auto *pServerConnection = pState->m_ServerConnections.f_FindEqual(ServerConnectionID);
						if (!pServerConnection || pState->m_bCleared)
							co_return {};

						pServerConnection->m_Actor = fg_Move(Actor);
						Cleanup2.f_Clear();
					}

					co_return {};
				}
			;

			ListenCallbacks.m_fFailedConnection = g_ActorFunctor / [pStateWeak](CAsyncSocketActor::CConnectionInfo _ConnectionInfo) -> TCFuture<void>
				{
					auto pState = pStateWeak.f_Lock();
					if (!pState)
						co_return {};

					DMibLock(pState->m_Lock);
					pState->m_bAcceptError = true;
					pState->m_AcceptError = _ConnectionInfo.m_Error;
					pState->f_Signal();

					co_return {};
				}
			;

			m_ServerActor
				(
					&CAsyncSocketServerActor::f_StartListenAddress
					, fg_CreateVector(_ListenAddress)
					, ENetFlag_None
					, fg_Move(ListenCallbacks)
					, fg_TempCopy(_ServerFactory)
				)
				> [pStateWeak](TCAsyncResult<CAsyncSocketServerActor::CListenResult> &&_Result)
				{
					auto pState = pStateWeak.f_Lock();
					if (!pState)
						return;

					DMibLock(pState->m_Lock);
					if (_Result)
						pState->m_ListenCallbackReference = fg_Move(_Result->m_Subscription);
					else
						pState->m_ListenError = _Result.f_GetExceptionStr();
					pState->f_Signal();
				}
			;
			bool bTimedOutListenStart = f_Wait();
			DMibAssert(m_ListenError, ==, "");
			DMibAssertFalse(bTimedOutListenStart);
			DMibAssertTrue(m_ListenCallbackReference);
		}

		void f_Connect(CStr const &_Address, FVirtualSocketFactory const &_ClientFactory)
		{
			TCWeakPointer<CState> pStateWeak = fg_Explicit(this);
			m_ClientActor
				(
					&CAsyncSocketClientActor::f_Connect
					, _Address
					, ""
					, ENetAddressType_None
					, 10502
					, fg_TempCopy(_ClientFactory)
				)
				> [pStateWeak](TCAsyncResult<CAsyncSocketNewClientConnection> &&_Result)
				{
					auto pState = pStateWeak.f_Lock();
					if (!pState)
						return;
					DMibLock(pState->m_Lock);
					if (_Result)
					{
						auto &Result = *_Result;

						CAsyncSocketCallbacks Callbacks;

						Callbacks.m_fOnClose = g_ActorFunctor / [pStateWeak](EAsyncSocketStatus _Status, CStr _Message, EAsyncSocketCloseOrigin _Origin) -> TCFuture<void>
							{
								auto pState = pStateWeak.f_Lock();
								if (!pState)
									co_return {};

								DMibLock(pState->m_Lock);
								pState->m_ClientConnectionCloseMessage = _Message;
								pState->m_ClientConnectionCloseStatus = _Status;
								pState->m_ClientConnectionCloseOrigin = _Origin;
								pState->f_Signal();

								co_return {};
							}
						;

						Callbacks.m_fOnReceiveData = g_ActorFunctor / [pStateWeak](TCSharedPointer<CIOByteVector> _pData) -> TCFuture<void>
							{
								auto pState = pStateWeak.f_Lock();
								if (!pState)
									co_return {};
								DMibLock(pState->m_Lock);
								pState->m_ClientMessageBuffer.f_AddStr((ch8 const *)_pData->f_GetArray(), _pData->f_GetLen());

								while (pState->m_ClientMessageBuffer.f_FindChar('\n') >= 0)
									pState->m_Messages.f_Insert(fg_GetStrLineSep(pState->m_ClientMessageBuffer));

								pState->f_Signal();

								co_return {};
							}
						;

						auto Cleanup = g_OnScopeExitActor / [pStateWeak]
							{
								auto pState = pStateWeak.f_Lock();
								if (!pState)
									return;

								DMibLock(pState->m_Lock);
								pState->m_bClientConnectionResult = true;
								pState->f_Signal();
							}
						;

						Result.f_Accept(fg_Move(Callbacks)) > [pStateWeak, Cleanup](TCAsyncResult<TCActorInterface<CAsyncSocketActor>> &&_Socket)
							{
								if (!_Socket)
									return;

								auto pState = pStateWeak.f_Lock();
								if (!pState)
								{
									fg_Move(*_Socket).f_Destroy().f_DiscardResult();
									return;
								}

								DMibLock(pState->m_Lock);

								if (pState->m_bCleared)
								{
									fg_Move(*_Socket).f_Destroy().f_DiscardResult();
									return;
								}

								pState->m_ClientSocket = fg_Move(*_Socket);
							}
						;
					}
					else
					{
						pState->m_bClientConnectionResult = true;
						pState->m_ClientConnectionError = _Result.f_GetExceptionStr();
					}

					pState->f_Signal();
				}
			;
		}
	};

	bool fp_TestConnect(TCSharedPointerSupportWeak<CState> const &_pState, CStr const &_AcceptError, CStr const &_ConnectError)
	{
		auto pState = _pState;
		DMibTestPath("Connect");

		bool bTimedOut = false;

		while (!bTimedOut)
		{
			{
				DMibLock(pState->m_Lock);
				if (pState->m_bAcceptError && pState->m_bClientConnectionResult)
					break; // Server accept failed
				if (pState->m_bClientConnectionResult)
				{
					if
						(
							!pState->m_ClientSocket
							&&
							(
								pState->m_bAcceptError
								|| !pState->m_ServerConnections.f_IsEmpty()
								|| (!pState->m_ClientConnectionError.f_IsEmpty() && _AcceptError.f_IsEmpty())
							)
						)
					{
						break; // Client connection failed
					}

					if (pState->m_ClientSocket && !pState->m_ServerConnections.f_IsEmpty() && pState->f_AllServerConnectionsFinished())
						break; // Successfully done
				}
			}
			bTimedOut = pState->f_Wait();
		}

		DMibTest(!DMibExpr(bTimedOut));

		if (!_ConnectError.f_IsEmpty())
		{
			DMibExpect(pState->m_ClientConnectionError, ==, _ConnectError);
			return false;
		}

		if (!_AcceptError.f_IsEmpty())
		{
			DMibTest(DMibExpr(pState->m_bAcceptError));
			DMibExpect(pState->m_AcceptError, ==, _AcceptError);
			return false;
		}

		DMibTest(!DMibExpr(pState->m_bAcceptError));
		DMibTest(DMibExpr(pState->m_AcceptError) == DMibExpr(""));

		DMibTest(DMibExpr(pState->m_ClientConnectionError) == DMibExpr(""));

		DMibAssertFalse(pState->m_ServerConnections.f_IsEmpty());
		DMibAssertTrue(pState->m_ClientSocket);
		return true;
	}

	bool fp_WaitForCondition(TCFunction<bool ()> const &_fPredicate)
	{
		bool bTimedOut = false;

		NTime::CStopwatch Stopwatch;
		Stopwatch.f_Start();

		while (!_fPredicate())
		{
			NSys::fg_Thread_Sleep(0.01f);
			if (Stopwatch.f_GetTime() > 30.0)
			{
				bTimedOut = true;
				break;
			}
		}

		return bTimedOut;
	}

	static CAsyncSocketUpgradeCheckResult fp_CheckUpgradeMessage(CPagedByteVector const &_Data, CStr const &_UpgradeMessage)
	{
		CAsyncSocketUpgradeCheckResult Result;
		if (_Data.f_IsEmpty())
			return Result;

		bool bMatches = true;
		umint iData = 0;
		umint const nCompare = fg_Min(_Data.f_GetLen(), _UpgradeMessage.f_GetLen());
		_Data.f_ReadFront
			(
				nCompare
				, [&](umint _iStart, uint8 const *_pData, umint _nBytes) -> bool
				{
					if (NMemory::fg_MemCmp((uint8 const *)_UpgradeMessage.f_GetStr() + iData, _pData, _nBytes) == 0)
					{
						iData += _nBytes;
						return _iStart + _nBytes < nCompare;
					}

					bMatches = false;
					return false;
				}
			)
		;

		if (!bMatches)
		{
			Result.m_nBytesConsumed = 1;
			return Result;
		}

		if (_Data.f_GetLen() >= _UpgradeMessage.f_GetLen())
		{
			Result.m_Result = EAsyncSocketUpgradeCheckResult_Upgrade;
			Result.m_nBytesConsumed = _UpgradeMessage.f_GetLen();
		}

		return Result;
	}

	void fp_TestUpgradeCheckDeferredBytes()
	{
		DMibTestPath("Upgrade Check Deferred Bytes");

		CActorRunLoopTestHelper RunLoopHelper;
		struct CUpgradeCheckDeferredState
		{
			CMutual m_Lock;
			TCActorInterface<CAsyncSocketActor> m_ServerSocket;
			TCActorInterface<CAsyncSocketActor> m_ClientSocket;
			CStr m_ServerBuffer;
			bool m_bCheckUpgradeCalled = false;
			bool m_bServerAccepted = false;
			bool m_bServerReceivedPlain = false;
			bool m_bServerReceived = false;
		};

		TCSharedPointerSupportWeak<CUpgradeCheckDeferredState> pState = fg_Construct();
		TCWeakPointer<CUpgradeCheckDeferredState> pStateWeak = pState;
		auto fTextBuffer = [](CStr const &_Text)
			{
				TCSharedPointer<CIOByteVector> pBuffer = fg_Construct();
				pBuffer->f_Insert((uint8 const *)_Text.f_GetStr(), _Text.f_GetLen());
				return pBuffer;
			}
		;
		auto fWaitForCondition = [&](auto const &_fCondition)
			{
				NTime::CStopwatch Stopwatch;
				Stopwatch.f_Start();
				while (true)
				{
					if (_fCondition())
						return false;

					RunLoopHelper.m_pRunLoop->f_WaitOnceTimeout(0.05);
					if (Stopwatch.f_GetTime() > g_Timeout)
						return true;
				}
			}
		;

		TCActor<CAsyncSocketServerActor> ServerActor = fg_ConstructActor<CAsyncSocketServerActor>();
		TCActor<CAsyncSocketClientActor> ClientActor = fg_ConstructActor<CAsyncSocketClientActor>();
		auto Cleanup = g_OnScopeExit / [&]
			{
				pState->m_ClientSocket.f_Destroy().f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
				pState->m_ServerSocket.f_Destroy().f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
				fg_Move(ClientActor).f_Destroy().f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
				fg_Move(ServerActor).f_Destroy().f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
			}
		;

		FAsyncSocketUpgradeCheckFactory CheckUpgradeFactory = [pStateWeak]() -> FAsyncSocketUpgradeCheck
			{
				return [pStateWeak](CPagedByteVector const &_Data) -> CAsyncSocketUpgradeCheckResult
					{
						CAsyncSocketUpgradeCheckResult Result = fp_CheckUpgradeMessage(_Data, "STARTTLS");
						if (Result.m_Result == EAsyncSocketUpgradeCheckResult_Upgrade)
						{
							if (auto pState = pStateWeak.f_Lock())
							{
								DMibLock(pState->m_Lock);
								pState->m_bCheckUpgradeCalled = true;
							}
						}

						return Result;
					}
				;
			}
		;
		ServerActor(&CAsyncSocketServerActor::f_SetDefaultUpgradeCheckFactory, CheckUpgradeFactory).f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);

		CAsyncSocketServerCallbacks ServerCallbacks;
		ServerCallbacks.m_fNewConnection = g_ActorFunctor / [pStateWeak](CAsyncSocketNewServerConnection _Connection) -> TCFuture<void>
			{
				co_await NConcurrency::fg_Timeout(0.1);

				CAsyncSocketCallbacks SocketCallbacks;
				SocketCallbacks.m_fOnReceiveData = g_ActorFunctor / [pStateWeak](TCSharedPointer<CIOByteVector> _pData) -> TCFuture<void>
					{
						auto pState = pStateWeak.f_Lock();
						if (!pState)
							co_return {};

						DMibLock(pState->m_Lock);
						pState->m_ServerBuffer.f_AddStr((ch8 const *)_pData->f_GetArray(), _pData->f_GetLen());
						if (pState->m_ServerBuffer == "Plain")
						{
							pState->m_bServerReceivedPlain = true;
							pState->m_ServerBuffer.f_Clear();
						}
						else if (pState->m_ServerBuffer == "STARTTLS")
						{
							pState->m_bServerReceived = true;
							pState->m_ServerBuffer.f_Clear();
						}

						co_return {};
					}
				;

				auto Socket = co_await _Connection.f_Accept(fg_Move(SocketCallbacks));
				if (auto pState = pStateWeak.f_Lock())
				{
					DMibLock(pState->m_Lock);
					pState->m_ServerSocket = fg_Move(Socket);
					pState->m_bServerAccepted = true;
				}

				co_return {};
			}
		;

		CNetAddressTCPv4 ListenAddress;
		ListenAddress.f_SetLocalhost();
		ListenAddress.m_Port = 0;
		auto ListenResult = ServerActor
			(
				&CAsyncSocketServerActor::f_StartListenAddress
				, fg_CreateVector<CNetAddress>(ListenAddress)
				, ENetFlag_None
				, fg_Move(ServerCallbacks)
				, CSocket_TCP::fs_GetFactory()
			)
			.f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout)
		;
		auto CleanupListen = g_OnScopeExit / [&]
			{
				ListenResult.m_Subscription.f_Clear();
			}
		;
		DMibExpect(ListenResult.m_ListenPorts.f_GetLen(), ==, 1)(NTest::ETest_FailAndStop);

		CAsyncSocketNewClientConnection NewClientConnection = ClientActor
			(
				&CAsyncSocketClientActor::f_Connect
				, CStr("localhost")
				, CStr()
				, ENetAddressType_TCPv4
				, ListenResult.m_ListenPorts[0]
				, CSocket_TCP::fs_GetFactory()
			)
			.f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout)
		;
		CAsyncSocketCallbacks ClientCallbacks;
		pState->m_ClientSocket = NewClientConnection.f_Accept(fg_Move(ClientCallbacks)).f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
		pState->m_ClientSocket(&CAsyncSocketActor::f_SendData, fTextBuffer("PlainSTARTTLS"), 0).f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);

		bool bTimedOut = fWaitForCondition
			(
				[&]
				{
					DMibLock(pState->m_Lock);
					return pState->m_bServerAccepted && pState->m_bServerReceivedPlain && pState->m_bCheckUpgradeCalled && pState->m_bServerReceived;
				}
			)
		;
		DMibExpectFalse(bTimedOut);
	}

	void fp_TestUpgradeCheckRemoteCloseFlush()
	{
		DMibTestPath("Upgrade Check Remote Close Flush");

		CActorRunLoopTestHelper RunLoopHelper;
		struct CUpgradeCheckCloseState
		{
			CMutual m_Lock;
			TCActorInterface<CAsyncSocketActor> m_ServerSocket;
			TCActorInterface<CAsyncSocketActor> m_ClientSocket;
			CStr m_ServerBuffer;
			bool m_bServerCheckWaiting = false;
			bool m_bServerClosed = false;
			bool m_bServerReceivedPartial = false;
		};

		TCSharedPointerSupportWeak<CUpgradeCheckCloseState> pState = fg_Construct();
		TCWeakPointer<CUpgradeCheckCloseState> pStateWeak = pState;
		auto fTextBuffer = [](CStr const &_Text)
			{
				TCSharedPointer<CIOByteVector> pBuffer = fg_Construct();
				pBuffer->f_Insert((uint8 const *)_Text.f_GetStr(), _Text.f_GetLen());
				return pBuffer;
			}
		;
		auto fWaitForCondition = [&](auto const &_fCondition)
			{
				NTime::CStopwatch Stopwatch;
				Stopwatch.f_Start();
				while (true)
				{
					if (_fCondition())
						return false;

					RunLoopHelper.m_pRunLoop->f_WaitOnceTimeout(0.05);
					if (Stopwatch.f_GetTime() > g_Timeout)
						return true;
				}
			}
		;
		auto fCheckUpgradePrefix = [pStateWeak](CPagedByteVector const &_Data) -> CAsyncSocketUpgradeCheckResult
			{
				CAsyncSocketUpgradeCheckResult Result = fp_CheckUpgradeMessage(_Data, "STARTTLS");

				if (Result.m_Result == EAsyncSocketUpgradeCheckResult_MoreDataNeeded && !Result.m_nBytesConsumed && _Data.f_GetLen() == CStr("STAR").f_GetLen())
				{
					if (auto pState = pStateWeak.f_Lock())
					{
						DMibLock(pState->m_Lock);
						pState->m_bServerCheckWaiting = true;
					}
				}

				return Result;
			}
		;

		TCActor<CAsyncSocketServerActor> ServerActor = fg_ConstructActor<CAsyncSocketServerActor>();
		TCActor<CAsyncSocketClientActor> ClientActor = fg_ConstructActor<CAsyncSocketClientActor>();
		auto Cleanup = g_OnScopeExit / [&]
			{
				pState->m_ClientSocket.f_Destroy().f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
				pState->m_ServerSocket.f_Destroy().f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
				fg_Move(ClientActor).f_Destroy().f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
				fg_Move(ServerActor).f_Destroy().f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
			}
		;

		FAsyncSocketUpgradeCheckFactory CheckUpgradeFactory = [fCheckUpgradePrefix]() -> FAsyncSocketUpgradeCheck
			{
				return fCheckUpgradePrefix;
			}
		;
		ServerActor(&CAsyncSocketServerActor::f_SetDefaultUpgradeCheckFactory, CheckUpgradeFactory).f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);

		CAsyncSocketServerCallbacks ServerCallbacks;
		ServerCallbacks.m_fNewConnection = g_ActorFunctor / [pStateWeak](CAsyncSocketNewServerConnection _Connection) -> TCFuture<void>
			{
				CAsyncSocketCallbacks SocketCallbacks;
				SocketCallbacks.m_fOnReceiveData = g_ActorFunctor / [pStateWeak](TCSharedPointer<CIOByteVector> _pData) -> TCFuture<void>
					{
						auto pState = pStateWeak.f_Lock();
						if (!pState)
							co_return {};

						DMibLock(pState->m_Lock);
						pState->m_ServerBuffer.f_AddStr((ch8 const *)_pData->f_GetArray(), _pData->f_GetLen());
						if (pState->m_ServerBuffer == "STAR")
							pState->m_bServerReceivedPartial = true;

						co_return {};
					}
				;
				SocketCallbacks.m_fOnClose = g_ActorFunctor / [pStateWeak](EAsyncSocketStatus _Status, CStr _Message, EAsyncSocketCloseOrigin _Origin) -> TCFuture<void>
					{
						auto pState = pStateWeak.f_Lock();
						if (!pState)
							co_return {};

						DMibLock(pState->m_Lock);
						pState->m_bServerClosed = true;

						co_return {};
					}
				;

				auto Socket = co_await _Connection.f_Accept(fg_Move(SocketCallbacks));
				if (auto pState = pStateWeak.f_Lock())
				{
					DMibLock(pState->m_Lock);
					pState->m_ServerSocket = fg_Move(Socket);
				}

				co_return {};
			}
		;

		CNetAddressTCPv4 ListenAddress;
		ListenAddress.f_SetLocalhost();
		ListenAddress.m_Port = 0;
		auto ListenResult = ServerActor
			(
				&CAsyncSocketServerActor::f_StartListenAddress
				, fg_CreateVector<CNetAddress>(ListenAddress)
				, ENetFlag_None
				, fg_Move(ServerCallbacks)
				, CSocket_TCP::fs_GetFactory()
			)
			.f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout)
		;
		auto CleanupListen = g_OnScopeExit / [&]
			{
				ListenResult.m_Subscription.f_Clear();
			}
		;
		DMibExpect(ListenResult.m_ListenPorts.f_GetLen(), ==, 1)(NTest::ETest_FailAndStop);

		CAsyncSocketNewClientConnection NewClientConnection = ClientActor
			(
				&CAsyncSocketClientActor::f_Connect
				, CStr("localhost")
				, CStr()
				, ENetAddressType_TCPv4
				, ListenResult.m_ListenPorts[0]
				, CSocket_TCP::fs_GetFactory()
			)
			.f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout)
		;
		CAsyncSocketCallbacks ClientCallbacks;
		pState->m_ClientSocket = NewClientConnection.f_Accept(fg_Move(ClientCallbacks)).f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
		pState->m_ClientSocket(&CAsyncSocketActor::f_SendData, fTextBuffer("STAR"), 0).f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);

		bool bCheckTimedOut = fWaitForCondition
			(
				[&]
				{
					DMibLock(pState->m_Lock);
					return pState->m_bServerCheckWaiting;
				}
			)
		;
		DMibExpectFalse(bCheckTimedOut);

		pState->m_ClientSocket(&CAsyncSocketActor::f_Close, EAsyncSocketStatus_NormalClosure, CStr("Done")).f_DiscardResult();

		bool bCloseTimedOut = fWaitForCondition
		(
			[&]
			{
				DMibLock(pState->m_Lock);
				return pState->m_bServerReceivedPartial && pState->m_bServerClosed;
			}
		)
		;
		DMibExpectFalse(bCloseTimedOut);
		{
			DMibLock(pState->m_Lock);
			DMibExpect(pState->m_bServerReceivedPartial, ==, true);
			DMibExpect(pState->m_bServerClosed, ==, true);
			DMibExpect(pState->m_ServerBuffer, ==, CStr("STAR"));
		}
	}

	void fp_TestDeferredBytesBeforeAcceptClose()
	{
		DMibTestPath("Deferred Bytes Before Accept Close");

		CActorRunLoopTestHelper RunLoopHelper;
		struct CDeferredCloseState
		{
			CMutual m_Lock;
			TCActorInterface<CAsyncSocketActor> m_ServerSocket;
			TCActorInterface<CAsyncSocketActor> m_ClientSocket;
			CStr m_ServerBuffer;
			bool m_bServerAccepted = false;
			bool m_bServerReceived = false;
			bool m_bServerClosed = false;
		};

		TCSharedPointerSupportWeak<CDeferredCloseState> pState = fg_Construct();
		TCWeakPointer<CDeferredCloseState> pStateWeak = pState;
		auto fTextBuffer = [](CStr const &_Text)
			{
				TCSharedPointer<CIOByteVector> pBuffer = fg_Construct();
				pBuffer->f_Insert((uint8 const *)_Text.f_GetStr(), _Text.f_GetLen());
				return pBuffer;
			}
		;
		auto fWaitForCondition = [&](auto const &_fCondition)
			{
				NTime::CStopwatch Stopwatch;
				Stopwatch.f_Start();
				while (true)
				{
					if (_fCondition())
						return false;

					RunLoopHelper.m_pRunLoop->f_WaitOnceTimeout(0.05);
					if (Stopwatch.f_GetTime() > g_Timeout)
						return true;
				}
			}
		;

		TCActor<CAsyncSocketServerActor> ServerActor = fg_ConstructActor<CAsyncSocketServerActor>();
		TCActor<CAsyncSocketClientActor> ClientActor = fg_ConstructActor<CAsyncSocketClientActor>();
		auto Cleanup = g_OnScopeExit / [&]
			{
				pState->m_ClientSocket.f_Destroy().f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
				pState->m_ServerSocket.f_Destroy().f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
				fg_Move(ClientActor).f_Destroy().f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
				fg_Move(ServerActor).f_Destroy().f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
			}
		;

		CAsyncSocketServerCallbacks ServerCallbacks;
		ServerCallbacks.m_fNewConnection = g_ActorFunctor / [pStateWeak](CAsyncSocketNewServerConnection _Connection) -> TCFuture<void>
			{
				co_await NConcurrency::fg_Timeout(0.1);

				CAsyncSocketCallbacks SocketCallbacks;
				SocketCallbacks.m_fOnReceiveData = g_ActorFunctor / [pStateWeak](TCSharedPointer<CIOByteVector> _pData) -> TCFuture<void>
					{
						auto pState = pStateWeak.f_Lock();
						if (!pState)
							co_return {};

						DMibLock(pState->m_Lock);
						pState->m_ServerBuffer.f_AddStr((ch8 const *)_pData->f_GetArray(), _pData->f_GetLen());
						if (pState->m_ServerBuffer == "BeforeClose")
							pState->m_bServerReceived = true;

						co_return {};
					}
				;
				SocketCallbacks.m_fOnClose = g_ActorFunctor / [pStateWeak](EAsyncSocketStatus _Status, CStr _Message, EAsyncSocketCloseOrigin _Origin) -> TCFuture<void>
					{
						auto pState = pStateWeak.f_Lock();
						if (!pState)
							co_return {};

						DMibLock(pState->m_Lock);
						pState->m_bServerClosed = true;

						co_return {};
					}
				;

				auto Socket = co_await _Connection.f_Accept(fg_Move(SocketCallbacks));
				if (auto pState = pStateWeak.f_Lock())
				{
					DMibLock(pState->m_Lock);
					pState->m_ServerSocket = fg_Move(Socket);
					pState->m_bServerAccepted = true;
				}

				co_return {};
			}
		;

		CNetAddressTCPv4 ListenAddress;
		ListenAddress.f_SetLocalhost();
		ListenAddress.m_Port = 0;
		auto ListenResult = ServerActor
			(
				&CAsyncSocketServerActor::f_StartListenAddress
				, fg_CreateVector<CNetAddress>(ListenAddress)
				, ENetFlag_None
				, fg_Move(ServerCallbacks)
				, CSocket_TCP::fs_GetFactory()
			)
			.f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout)
		;
		auto CleanupListen = g_OnScopeExit / [&]
			{
				ListenResult.m_Subscription.f_Clear();
			}
		;
		DMibExpect(ListenResult.m_ListenPorts.f_GetLen(), ==, 1)(NTest::ETest_FailAndStop);

		CAsyncSocketNewClientConnection NewClientConnection = ClientActor
			(
				&CAsyncSocketClientActor::f_Connect
				, CStr("localhost")
				, CStr()
				, ENetAddressType_TCPv4
				, ListenResult.m_ListenPorts[0]
				, CSocket_TCP::fs_GetFactory()
			)
			.f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout)
		;
		CAsyncSocketCallbacks ClientCallbacks;
		pState->m_ClientSocket = NewClientConnection.f_Accept(fg_Move(ClientCallbacks)).f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
		pState->m_ClientSocket(&CAsyncSocketActor::f_SendData, fTextBuffer("BeforeClose"), 0).f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
		pState->m_ClientSocket(&CAsyncSocketActor::f_Close, EAsyncSocketStatus_NormalClosure, CStr("Done")).f_DiscardResult();

		bool bTimedOut = fWaitForCondition
			(
				[&]
				{
					DMibLock(pState->m_Lock);
					return pState->m_bServerAccepted && pState->m_bServerReceived && pState->m_bServerClosed;
				}
			)
		;
		DMibExpectFalse(bTimedOut);
		{
			DMibLock(pState->m_Lock);
			DMibExpect(pState->m_ServerBuffer, ==, CStr("BeforeClose"));
		}
	}

	void fp_TestImp
		(
			TCFunction<TCTuple<FVirtualSocketFactory, FVirtualSocketFactory> ()> const &_fGetFactories
			, CStr const &_AcceptError
			, CStr const &_ConnectError
			, CStr const &_Address
			, bool _bTestTimeout
		)
	{
		{
			DMibTestPath("Connection");
			CActorRunLoopTestHelper RunLoopHelper;

			auto Factories = _fGetFactories();
			auto ServerFactory = fg_Get<0>(Factories);
			auto ClientFactory = fg_Get<1>(Factories);

			CNetAddress ListenAddress;
			if (_Address == "localhost")
			{
				CNetAddressTCPv4 Address;
				Address.f_SetLocalhost();
				Address.m_Port = 10502;
				ListenAddress = Address;
			}
			else
				ListenAddress = CSocket::fs_ResolveAddress(_Address);
			{
				TCSharedPointerSupportWeak<CState> pState = fg_Construct(RunLoopHelper.m_pRunLoop);
				auto Cleanup
					= g_OnScopeExit / [&]
					{
						pState->f_Clear();
					}
				;

				pState->m_ServerActor = fg_ConstructActor<CAsyncSocketServerActor>();
				pState->f_StartListen(ListenAddress, ServerFactory);

				pState->m_ClientActor = fg_ConstructActor<CAsyncSocketClientActor>();
				pState->f_Connect(_Address, ClientFactory);

				auto fTextBuffer = [&](CStr const &_Text)
					{
						TCSharedPointer<CIOByteVector> pBuffer = fg_Construct();
						pBuffer->f_Insert((uint8 const *)_Text.f_GetStr(), _Text.f_GetLen());
						pBuffer->f_Insert('\n');
						return pBuffer;
					}
				;


				if (!fp_TestConnect(pState, _AcceptError, _ConnectError))
					return;
				{
					DMibTestPath("Messages");

					pState->m_ClientSocket(&CAsyncSocketActor::f_SendData, fTextBuffer("TestText"), 0).f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout / 3);
					pState->m_ClientSocket(&CAsyncSocketActor::f_SendData, fTextBuffer("TestBuff"), 0).f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout / 3);

					bool bTimedOut = false;
					while (!bTimedOut)
					{
						{
							DMibLock(pState->m_Lock);
							if (pState->m_Messages.f_GetLen() >= 2)
								break;
						}
						bTimedOut = pState->f_Wait();
					}

					DMibExpectFalse(bTimedOut);
					DMibExpect(pState->m_Messages.f_GetLen(), ==, 2)(NTest::ETest_FailAndStop);
					DMibExpect(pState->m_Messages[0], ==, "TestText");
					DMibExpect(pState->m_Messages[1], ==, "TestBuff");
				}

				{
					DMibTestPath("Disconnect");

					pState->m_ClientSocket(&CAsyncSocketActor::f_SendData, fTextBuffer("Disconnect"), 0).f_DiscardResult();

					bool bTimedOut = false;
					while (!bTimedOut)
					{
						{
							DMibLock(pState->m_Lock);
							if (!pState->m_ClientConnectionCloseMessage.f_IsEmpty() && pState->m_ServerConnections.f_IsEmpty())
								break; // Successfully disconnected from the server
						}
						bTimedOut = pState->f_Wait();
					}

					DMibTest(!DMibExpr(bTimedOut));
					DMibExpect(pState->m_ClientConnectionCloseMessage, !=, "");
					DMibExpect(pState->m_ServerConnectionCloseMessage, !=, "");
				}
			}

			if (_bTestTimeout)
			{
				DMibTestPath("Timeout");
				TCSharedPointerSupportWeak<CState> pState = fg_Construct(RunLoopHelper.m_pRunLoop);
				auto Cleanup
					= g_OnScopeExit / [&]
					{
						pState->f_Clear();
					}
				;

				pState->m_ServerActor = fg_ConstructActor<CAsyncSocketServerActor>();
				pState->m_ServerActor(&CAsyncSocketServerActor::f_SetDefaultTimeout, 1.0).f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
				pState->f_StartListen(ListenAddress, ServerFactory);

				pState->m_ClientActor = fg_ConstructActor<CAsyncSocketClientActor>();
				pState->m_ClientActor(&CAsyncSocketClientActor::f_SetDefaultTimeout, 1.0).f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
				pState->f_Connect(_Address, ClientFactory);

				if (!fp_TestConnect(pState, _AcceptError, _ConnectError))
					return;
				{
					DMibTestPath("Timeout");
					pState->m_ClientSocket(&CAsyncSocketActor::f_DebugStopProcessing, 1.0).f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
					bool bTimedOut = fp_WaitForCondition
						(
							[&]
							{
								DMibLock(pState->m_Lock);
								return pState->m_ServerConnectionCloseStatus == EAsyncSocketStatus_Timeout || pState->m_ClientConnectionCloseStatus == EAsyncSocketStatus_Timeout;
							}
						)
					;

					DMibExpectFalse(bTimedOut);
					DMibLock(pState->m_Lock);
					DMibTest
						(
							DMibExpr(pState->m_ServerConnectionCloseStatus) == DMibExpr(EAsyncSocketStatus_Timeout)
							|| DMibExpr(pState->m_ClientConnectionCloseStatus) == DMibExpr(EAsyncSocketStatus_Timeout)
						)
					;
				}
			}
		};
	}

	void fp_TestUpgradeToSSL()
	{
		DMibTestPath("Upgrade To SSL");

		CActorRunLoopTestHelper RunLoopHelper;

		CSSLSettings ServerSettings;
		CCertificateOptions Options;
		Options.m_CommonName = "Malterlib test Upgrade";
		Options.m_Hostnames = fg_CreateVector<CStr>("localhost");
		Options.m_KeySetting = gc_TestTestKeySetting;
		CCertificate::fs_GenerateSelfSignedCertAndKey(Options, ServerSettings.m_PublicCertificateData, ServerSettings.m_PrivateKeyData);
		TCSharedPointer<CSSLContext> pServerContext = fg_Construct(CSSLContext::EType_Server, ServerSettings);

		CSSLSettings ClientSettings;
		ClientSettings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_UseSpecificPeerCertificate;
		ClientSettings.m_CACertificateData = ServerSettings.m_PublicCertificateData;
		TCSharedPointer<CSSLContext> pClientContext = fg_Construct(CSSLContext::EType_Client, ClientSettings);

		FVirtualSocketFactory ServerSSLFactory = CSocket_SSL::fs_GetFactory(pServerContext);
		FVirtualSocketFactory ClientSSLFactory = CSocket_SSL::fs_GetFactory(pClientContext);

		struct CUpgradeState
		{
			CMutual m_Lock;
			TCActorInterface<CAsyncSocketActor> m_ServerSocket;
			TCActorInterface<CAsyncSocketActor> m_ClientSocket;
			CStr m_ServerBuffer;
			CStr m_ClientBuffer;
			CStr m_Response;
			bool m_bServerReceivedPlain = false;
			bool m_bClientReceivedPlainResponse = false;
			bool m_bServerReceivedStartTLS = false;
			bool m_bClientReadyForUpgrade = false;
			bool m_bServerReceivedEncrypted = false;
			bool m_bServerUpgraded = false;
			bool m_bClientUpgraded = false;
		};

		TCSharedPointerSupportWeak<CUpgradeState> pState = fg_Construct();
		TCWeakPointer<CUpgradeState> pStateWeak = pState;
		auto fTextBuffer = [](CStr const &_Text)
			{
				TCSharedPointer<CIOByteVector> pBuffer = fg_Construct();
				pBuffer->f_Insert((uint8 const *)_Text.f_GetStr(), _Text.f_GetLen());
				return pBuffer;
			}
		;
		auto fUpgradeCheckMessage = [](CPagedByteVector const &_Data, CStr const &_UpgradeMessage) -> CAsyncSocketUpgradeCheckResult
			{
				return fp_CheckUpgradeMessage(_Data, _UpgradeMessage);
			}
		;

		TCActor<CAsyncSocketServerActor> ServerActor = fg_ConstructActor<CAsyncSocketServerActor>();
		auto fWaitForCondition = [&](auto const &_fCondition)
			{
				NTime::CStopwatch Stopwatch;
				Stopwatch.f_Start();
				while (true)
				{
					if (_fCondition())
						return false;

					RunLoopHelper.m_pRunLoop->f_WaitOnceTimeout(0.05);
					if (Stopwatch.f_GetTime() > g_Timeout)
						return true;
				}
			}
		;
		auto CleanupServer = g_OnScopeExit / [&]
			{
				pState->m_ClientSocket.f_Destroy().f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
				pState->m_ServerSocket.f_Destroy().f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
				fg_Move(ServerActor).f_Destroy().f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
			}
		;

		FAsyncSocketUpgradeCheckFactory ServerCheckUpgradeFactory = [fUpgradeCheckMessage]() -> FAsyncSocketUpgradeCheck
			{
				return [fUpgradeCheckMessage, UpgradeMessage = CStr("STARTTLS")](CPagedByteVector const &_Data) -> CAsyncSocketUpgradeCheckResult
					{
						return fUpgradeCheckMessage(_Data, UpgradeMessage);
						}
					;
				}
		;
		ServerActor(&CAsyncSocketServerActor::f_SetDefaultUpgradeCheckFactory, ServerCheckUpgradeFactory).f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);

		CAsyncSocketServerCallbacks ServerCallbacks;
		ServerCallbacks.m_fNewConnection = g_ActorFunctor / [pStateWeak, ServerSSLFactory, fTextBuffer](CAsyncSocketNewServerConnection _Connection) -> TCFuture<void>
			{
				CAsyncSocketCallbacks SocketCallbacks;
				SocketCallbacks.m_fOnReceiveData = g_ActorFunctor / [pStateWeak, ServerSSLFactory, fTextBuffer](TCSharedPointer<CIOByteVector> _pData) -> TCFuture<void>
					{
						auto pState = pStateWeak.f_Lock();
						if (!pState)
							co_return {};

						bool bStartTLS = false;
						bool bPlainMessage = false;
						bool bEncryptedMessage = false;
						{
							DMibLock(pState->m_Lock);
							pState->m_ServerBuffer.f_AddStr((ch8 const *)_pData->f_GetArray(), _pData->f_GetLen());
							bStartTLS = pState->m_ServerBuffer == "STARTTLS";
							bPlainMessage = pState->m_ServerBuffer == "Plain";
							bEncryptedMessage = pState->m_ServerBuffer == "Encrypted";
							if (bStartTLS)
							{
								pState->m_bServerReceivedStartTLS = true;
								pState->m_ServerBuffer.f_Clear();
							}
							else if (bPlainMessage)
							{
								pState->m_bServerReceivedPlain = true;
								pState->m_ServerBuffer.f_Clear();
							}
							else if (bEncryptedMessage)
							{
								pState->m_bServerReceivedEncrypted = true;
								pState->m_ServerBuffer.f_Clear();
							}
						}

						if (bStartTLS)
						{
							(
								NConcurrency::g_Dispatch(NConcurrency::fg_ConcurrentActor())
								/ [pState, ServerSSLFactory, fTextBuffer]() -> TCFuture<void>
								{
									TCActor<CAsyncSocketActor> ServerSocket;
									NTime::CStopwatch Timeout;
									Timeout.f_Start();
									while (!ServerSocket)
									{
										{
											DMibLock(pState->m_Lock);
											ServerSocket = pState->m_ServerSocket.f_GetActor();
										}

										if (Timeout.f_GetTime() > g_Timeout)
											co_return DMibErrorInstance("Timed out waiting for server socket accept");

										if (!ServerSocket)
											co_await NConcurrency::fg_Timeout(0.001);
									}

									co_await NConcurrency::fg_Timeout(0.001);
									co_await ServerSocket(&CAsyncSocketActor::f_SendData, fTextBuffer("S"), 0);
									co_await ServerSocket(&CAsyncSocketActor::f_UpgradeSocket, ServerSSLFactory, CStr());

									DMibLock(pState->m_Lock);
									pState->m_bServerUpgraded = true;
									co_return {};
								}
							).f_DiscardResult();
						}
						else if (bPlainMessage || bEncryptedMessage)
						{
							TCActor<CAsyncSocketActor> ServerSocket;
							NTime::CStopwatch Timeout;
							Timeout.f_Start();
							while (!ServerSocket)
							{
								{
									DMibLock(pState->m_Lock);
									ServerSocket = pState->m_ServerSocket.f_GetActor();
								}

								if (Timeout.f_GetTime() > g_Timeout)
									co_return DMibErrorInstance("Timed out waiting for server socket accept");

								if (!ServerSocket)
									co_await NConcurrency::fg_Timeout(0.001);
							}

							if (bPlainMessage)
								co_await ServerSocket(&CAsyncSocketActor::f_SendData, fTextBuffer("PlainResponse"), 0);
							else
								co_await ServerSocket(&CAsyncSocketActor::f_SendData, fTextBuffer("EncryptedResponse"), 0);
						}

						co_return {};
					}
				;

				auto Socket = co_await _Connection.f_Accept(fg_Move(SocketCallbacks));
				if (auto pState = pStateWeak.f_Lock())
				{
					DMibLock(pState->m_Lock);
					pState->m_ServerSocket = fg_Move(Socket);
				}
				co_return {};
			}
		;
		ServerCallbacks.m_fFailedConnection = g_ActorFunctor / [](CAsyncSocketActor::CConnectionInfo _ConnectionInfo) -> TCFuture<void>
			{
				co_return DMibErrorInstance(_ConnectionInfo.m_Error);
			}
		;

		CNetAddressTCPv4 ListenAddress;
		ListenAddress.f_SetLocalhost();
		ListenAddress.m_Port = 0;
		auto ListenResult = ServerActor
			(
				&CAsyncSocketServerActor::f_StartListenAddress
				, fg_CreateVector<CNetAddress>(ListenAddress)
				, ENetFlag_None
				, fg_Move(ServerCallbacks)
				, CSocket_TCP::fs_GetFactory()
			)
			.f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout)
		;
		DMibExpect(ListenResult.m_ListenPorts.f_GetLen(), ==, 1)(NTest::ETest_FailAndStop);
		uint16 ListenPort = ListenResult.m_ListenPorts[0];
		auto CleanupListen = g_OnScopeExit / [&]
			{
				ListenResult.m_Subscription.f_Clear();
			}
		;

		TCActor<CAsyncSocketClientActor> ClientActor = fg_ConstructActor<CAsyncSocketClientActor>();
		auto CleanupClient = g_OnScopeExit / [&]
			{
				fg_Move(ClientActor).f_Destroy().f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
			}
		;

		FAsyncSocketUpgradeCheckFactory ClientCheckUpgradeFactory = [fUpgradeCheckMessage]() -> FAsyncSocketUpgradeCheck
			{
				return [fUpgradeCheckMessage, UpgradeMessage = CStr("S")](CPagedByteVector const &_Data) -> CAsyncSocketUpgradeCheckResult
					{
						return fUpgradeCheckMessage(_Data, UpgradeMessage);
					}
				;
			}
		;
		ClientActor(&CAsyncSocketClientActor::f_SetDefaultUpgradeCheckFactory, ClientCheckUpgradeFactory).f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);

		CAsyncSocketNewClientConnection NewClientConnection = ClientActor
			(
				&CAsyncSocketClientActor::f_Connect
				, CStr("localhost")
				, CStr()
				, ENetAddressType_TCPv4
				, ListenPort
				, CSocket_TCP::fs_GetFactory()
			)
			.f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout)
		;

		CAsyncSocketCallbacks ClientCallbacks;
		ClientCallbacks.m_fOnReceiveData = g_ActorFunctor / [pStateWeak, ClientSSLFactory, fTextBuffer](TCSharedPointer<CIOByteVector> _pData) -> TCFuture<void>
			{
				auto pState = pStateWeak.f_Lock();
				if (!pState)
					co_return {};

				bool bUpgrade = false;
				bool bPlainResponse = false;
				bool bEncryptedResponse = false;
				{
					DMibLock(pState->m_Lock);
					pState->m_ClientBuffer.f_AddStr((ch8 const *)_pData->f_GetArray(), _pData->f_GetLen());
					bUpgrade = pState->m_ClientBuffer == "S";
					bPlainResponse = pState->m_ClientBuffer == "PlainResponse";
					bEncryptedResponse = pState->m_ClientBuffer == "EncryptedResponse";
					if (bUpgrade)
					{
						pState->m_bClientReadyForUpgrade = true;
						pState->m_ClientBuffer.f_Clear();
					}
					else if (bPlainResponse)
					{
						pState->m_bClientReceivedPlainResponse = true;
						pState->m_ClientBuffer.f_Clear();
					}
					else if (bEncryptedResponse)
					{
						pState->m_Response = pState->m_ClientBuffer;
						pState->m_ClientBuffer.f_Clear();
					}
				}

				if (bUpgrade)
				{
					(
						NConcurrency::g_Dispatch(NConcurrency::fg_ConcurrentActor())
						/ [pState, ClientSSLFactory, fTextBuffer]() -> TCFuture<void>
						{
							co_await NConcurrency::fg_Timeout(0.001);
							co_await pState->m_ClientSocket(&CAsyncSocketActor::f_UpgradeSocket, ClientSSLFactory, CStr("localhost"));
							{
								DMibLock(pState->m_Lock);
								pState->m_bClientUpgraded = true;
							}
							co_await pState->m_ClientSocket(&CAsyncSocketActor::f_SendData, fTextBuffer("Encrypted"), 0);
							co_return {};
						}
					).f_DiscardResult();
				}

				co_return {};
			}
		;

		auto ClientSocket = NewClientConnection.f_Accept(fg_Move(ClientCallbacks)).f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
		pState->m_ClientSocket = fg_Move(ClientSocket);
		CStr UpgradeWithoutCheckError;
		try
		{
			pState->m_ClientSocket(&CAsyncSocketActor::f_UpgradeSocket, ClientSSLFactory, CStr("localhost")).f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
		}
		catch (NException::CExceptionBase const &_Exception)
		{
			UpgradeWithoutCheckError = _Exception.f_GetErrorStr();
		}
		DMibExpect(UpgradeWithoutCheckError, ==, CStr("Socket upgrade requires CAsyncSocketClientActor::f_SetDefaultUpgradeCheckFactory or CAsyncSocketServerActor::f_SetDefaultUpgradeCheckFactory callback to return EAsyncSocketUpgradeCheckResult_Upgrade"));

		pState->m_ClientSocket(&CAsyncSocketActor::f_SendData, fTextBuffer("Plain"), 0).f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);
		bool bPlainTimedOut = fWaitForCondition
			(
				[&]
				{
					DMibLock(pState->m_Lock);
					return pState->m_bServerReceivedPlain && pState->m_bClientReceivedPlainResponse;
				}
			)
		;
		DMibExpectFalse(bPlainTimedOut);

		pState->m_ClientSocket(&CAsyncSocketActor::f_SendData, fTextBuffer("STARTTLS"), 0).f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout);

		bool bTimedOut = fWaitForCondition
			(
				[&]
				{
					DMibLock(pState->m_Lock);
					return pState->m_bServerUpgraded && pState->m_bClientUpgraded && pState->m_Response == "EncryptedResponse";
				}
			)
		;
		DMibExpectFalse(bTimedOut);
		{
			DMibLock(pState->m_Lock);
			DMibExpect(pState->m_bServerReceivedPlain, ==, true);
			DMibExpect(pState->m_bClientReceivedPlainResponse, ==, true);
			DMibExpect(pState->m_bServerReceivedStartTLS, ==, true);
			DMibExpect(pState->m_bClientReadyForUpgrade, ==, true);
			DMibExpect(pState->m_bServerUpgraded, ==, true);
			DMibExpect(pState->m_bClientUpgraded, ==, true);
			DMibExpect(pState->m_bServerReceivedEncrypted, ==, true);
			DMibExpect(pState->m_Response, ==, CStr("EncryptedResponse"));
		}
	}

	void f_DoTests()
	{
		DMibTestSuite("Tests")
		{
			bool bTestTimeout = false;
			{
				DMibTestPath("TCP");
				fp_Test
					(
						[]() -> TCTuple<FVirtualSocketFactory, FVirtualSocketFactory>
						{
							return {nullptr, nullptr};
						}
						, ""
						, ""
						, bTestTimeout
					)
				;
			}
			{
				DMibTestPath("SSL");
				fp_Test
					(
						[]() -> TCTuple<FVirtualSocketFactory, FVirtualSocketFactory>
						{
							CSSLSettings ServerSettings;

							CCertificateOptions Options;
							Options.m_CommonName = "Malterlib test Self Signed";
							Options.m_Hostnames = fg_CreateVector<CStr>("localhost");
							Options.m_KeySetting = gc_TestTestKeySetting;

							CCertificate::fs_GenerateSelfSignedCertAndKey(Options, ServerSettings.m_PublicCertificateData, ServerSettings.m_PrivateKeyData);

							TCSharedPointer<CSSLContext> pServerContext = fg_Construct(CSSLContext::EType_Server, ServerSettings);

							CSSLSettings ClientSettings;
							ClientSettings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_UseSpecificPeerCertificate;
							ClientSettings.m_CACertificateData = ServerSettings.m_PublicCertificateData;
							TCSharedPointer<CSSLContext> pClientContext = fg_Construct(CSSLContext::EType_Client, ClientSettings);

							return {CSocket_SSL::fs_GetFactory(pServerContext), CSocket_SSL::fs_GetFactory(pClientContext)};
						}
						, ""
						, ""
						, bTestTimeout
					)
				;
			}
			fp_TestUpgradeCheckDeferredBytes();
			fp_TestUpgradeCheckRemoteCloseFlush();
			fp_TestDeferredBytesBeforeAcceptClose();
			fp_TestUpgradeToSSL();
			{
				DMibTestPath("SSL Client Certificate");
				fp_Test
					(
						[]() -> TCTuple<FVirtualSocketFactory, FVirtualSocketFactory>
						{
							CSSLSettings ServerSettings;

							CCertificateOptions ServerOptions;
							ServerOptions.m_CommonName = "Malterlib test Self Signed";
							ServerOptions.m_Hostnames = fg_CreateVector<CStr>("localhost");
							ServerOptions.m_KeySetting = gc_TestTestKeySetting;

							CCertificate::fs_GenerateSelfSignedCertAndKey(ServerOptions, ServerSettings.m_PublicCertificateData, ServerSettings.m_PrivateKeyData);
							ServerSettings.m_CACertificateData = ServerSettings.m_PublicCertificateData;

							TCSharedPointer<CSSLContext> pServerContext = fg_Construct(CSSLContext::EType_Server, ServerSettings);

							CSSLSettings ClientSettings;
							ClientSettings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_UseSpecificPeerCertificate;
							ClientSettings.m_CACertificateData = ServerSettings.m_PublicCertificateData;

							CByteVector CertificateRequestData;

							CCertificateOptions ClientOptions;
							ClientOptions.m_CommonName = "Test Client";
							ClientOptions.m_KeySetting = gc_TestTestKeySetting;

							CCertificate::fs_GenerateClientCertificateRequest(ClientOptions, CertificateRequestData, ClientSettings.m_PrivateKeyData);
							CCertificate::fs_SignClientCertificate(ServerSettings.m_PublicCertificateData, ServerSettings.m_PrivateKeyData, CertificateRequestData, ClientSettings.m_PublicCertificateData);

							TCSharedPointer<CSSLContext> pClientContext = fg_Construct(CSSLContext::EType_Client, ClientSettings);

							return {CSocket_SSL::fs_GetFactory(pServerContext), CSocket_SSL::fs_GetFactory(pClientContext)};
						}
						, ""
						, ""
					)
				;
			}
			{
				DMibTestPath("SSL Client Certificate Chain Without Intermediate CA");
				fp_Test
					(
						[]() -> TCTuple<FVirtualSocketFactory, FVirtualSocketFactory>
						{
							CSSLSettings ServerSettings;

							CCertificateOptions ServerOptions;
							ServerOptions.m_CommonName = "Malterlib test Self Signed";
							ServerOptions.m_Hostnames = fg_CreateVector<CStr>("localhost");
							ServerOptions.m_KeySetting = gc_TestTestKeySetting;

							CCertificate::fs_GenerateSelfSignedCertAndKey(ServerOptions, ServerSettings.m_PublicCertificateData, ServerSettings.m_PrivateKeyData);
							ServerSettings.m_CACertificateData = ServerSettings.m_PublicCertificateData;

							TCSharedPointer<CSSLContext> pServerContext = fg_Construct(CSSLContext::EType_Server, ServerSettings);

							CSSLSettings ClientSettings;
							ClientSettings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_UseSpecificPeerCertificate;

							CCertificateOptions ClientOptions;
							ClientOptions.m_CommonName = "Test Client";
							ClientOptions.m_KeySetting = gc_TestTestKeySetting;

							CByteVector CertificateRequestData;
							CCertificate::fs_GenerateClientCertificateRequest(ClientOptions, CertificateRequestData, ClientSettings.m_PrivateKeyData);
							CCertificate::fs_SignClientCertificate(ServerSettings.m_PublicCertificateData, ServerSettings.m_PrivateKeyData, CertificateRequestData, ClientSettings.m_PublicCertificateData);

							CSSLSettings ClientSettings2;
							ClientSettings2.m_VerificationFlags |= CSSLSettings::EVerificationFlag_UseSpecificPeerCertificate;
							ClientSettings2.m_CACertificateData = ServerSettings.m_PublicCertificateData;

							CCertificateOptions ClientOptions2;
							ClientOptions2.m_CommonName = "Test Client";
							ClientOptions2.m_KeySetting = gc_TestTestKeySetting;

							CByteVector CertificateRequestData2;
							CCertificate::fs_GenerateClientCertificateRequest(ClientOptions2, CertificateRequestData2, ClientSettings2.m_PrivateKeyData);
							CCertificate::fs_SignClientCertificate(ClientSettings.m_PublicCertificateData, ClientSettings.m_PrivateKeyData, CertificateRequestData2, ClientSettings2.m_PublicCertificateData);

							TCSharedPointer<CSSLContext> pClientContext = fg_Construct(CSSLContext::EType_Client, ClientSettings2);

							return {CSocket_SSL::fs_GetFactory(pServerContext), CSocket_SSL::fs_GetFactory(pClientContext)};
						}
						, "Socket closed: The certificate is self signed and cannot be found in the list of trusted certificates"
						, ""
					)
				;
			}
			{
				DMibTestPath("SSL Client Certificate Incorrect");
				fp_Test
					(
						[]() -> TCTuple<FVirtualSocketFactory, FVirtualSocketFactory>
						{
							CSSLSettings ServerSettings;

							CCertificateOptions ServerOptions;
							ServerOptions.m_CommonName = "Malterlib test Self Signed";
							ServerOptions.m_Hostnames = fg_CreateVector<CStr>("localhost");
							ServerOptions.m_KeySetting = gc_TestTestKeySetting;

							CCertificate::fs_GenerateSelfSignedCertAndKey(ServerOptions, ServerSettings.m_PublicCertificateData, ServerSettings.m_PrivateKeyData);

							ServerSettings.m_CACertificateData = ServerSettings.m_PublicCertificateData;

							TCSharedPointer<CSSLContext> pServerContext = fg_Construct(CSSLContext::EType_Server, ServerSettings);

							CSSLSettings ClientSettings;
							ClientSettings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_UseSpecificPeerCertificate;
							ClientSettings.m_CACertificateData = ServerSettings.m_PublicCertificateData;

							CCertificateOptions ClientOptions;
							ClientOptions.m_CommonName = "Test Client";
							ClientOptions.m_KeySetting = gc_TestTestKeySetting;
							ClientOptions.m_Hostnames = fg_CreateVector<CStr>("localhost");

							CCertificate::fs_GenerateSelfSignedCertAndKey(ClientOptions, ClientSettings.m_PublicCertificateData, ClientSettings.m_PrivateKeyData);

							TCSharedPointer<CSSLContext> pClientContext = fg_Construct(CSSLContext::EType_Client, ClientSettings);

							return {CSocket_SSL::fs_GetFactory(pServerContext), CSocket_SSL::fs_GetFactory(pClientContext)};
						}
						, "Socket closed: The certificate is self signed and cannot be found in the list of trusted certificates"
						, ""
					)
				;
			}
			{
				DMibTestPath("SSL Client Certificate Missing");
				fp_Test
					(
						[]() -> TCTuple<FVirtualSocketFactory, FVirtualSocketFactory>
						{
							CSSLSettings ServerSettings;

							CCertificateOptions ServerOptions;
							ServerOptions.m_CommonName = "Malterlib test Self Signed";
							ServerOptions.m_Hostnames = fg_CreateVector<CStr>("localhost");
							ServerOptions.m_KeySetting = gc_TestTestKeySetting;

							CCertificate::fs_GenerateSelfSignedCertAndKey(ServerOptions, ServerSettings.m_PublicCertificateData, ServerSettings.m_PrivateKeyData);

							ServerSettings.m_CACertificateData = ServerSettings.m_PublicCertificateData;

							TCSharedPointer<CSSLContext> pServerContext = fg_Construct(CSSLContext::EType_Server, ServerSettings);

							CSSLSettings ClientSettings;
							ClientSettings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_UseSpecificPeerCertificate;
							ClientSettings.m_CACertificateData = ServerSettings.m_PublicCertificateData;

							TCSharedPointer<CSSLContext> pClientContext = fg_Construct(CSSLContext::EType_Client, ClientSettings);

							return {CSocket_SSL::fs_GetFactory(pServerContext), CSocket_SSL::fs_GetFactory(pClientContext)};
						}
						, "Socket closed: PEER_DID_NOT_RETURN_A_CERTIFICATE"
						, ""
					)
				;
			}
			{
				DMibTestPath("SSL Client Certificate Allow Missing");
				fp_Test
					(
						[]() -> TCTuple<FVirtualSocketFactory, FVirtualSocketFactory>
						{
							CSSLSettings ServerSettings;

							CCertificateOptions ServerOptions;
							ServerOptions.m_CommonName = "Malterlib test Self Signed";
							ServerOptions.m_Hostnames = fg_CreateVector<CStr>("localhost");
							ServerOptions.m_KeySetting = gc_TestTestKeySetting;

							CCertificate::fs_GenerateSelfSignedCertAndKey(ServerOptions, ServerSettings.m_PublicCertificateData, ServerSettings.m_PrivateKeyData);
							ServerSettings.m_CACertificateData = ServerSettings.m_PublicCertificateData;
							ServerSettings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_AllowMissingPeerCertificate;

							TCSharedPointer<CSSLContext> pServerContext = fg_Construct(CSSLContext::EType_Server, ServerSettings);

							CSSLSettings ClientSettings;
							ClientSettings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_UseSpecificPeerCertificate;
							ClientSettings.m_CACertificateData = ServerSettings.m_PublicCertificateData;

							TCSharedPointer<CSSLContext> pClientContext = fg_Construct(CSSLContext::EType_Client, ClientSettings);

							return {CSocket_SSL::fs_GetFactory(pServerContext), CSocket_SSL::fs_GetFactory(pClientContext)};
						}
						, ""
						, ""
					)
				;
			}
			{
				DMibTestPath("SSL Client Certificate Incorrect Allow Missing");
				fp_Test
					(
						[]() -> TCTuple<FVirtualSocketFactory, FVirtualSocketFactory>
						{
							CSSLSettings ServerSettings;

							CCertificateOptions ServerOptions;
							ServerOptions.m_CommonName = "Malterlib test Self Signed";
							ServerOptions.m_Hostnames = fg_CreateVector<CStr>("localhost");
							ServerOptions.m_KeySetting = gc_TestTestKeySetting;

							CCertificate::fs_GenerateSelfSignedCertAndKey(ServerOptions, ServerSettings.m_PublicCertificateData, ServerSettings.m_PrivateKeyData);
							ServerSettings.m_CACertificateData = ServerSettings.m_PublicCertificateData;
							ServerSettings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_AllowMissingPeerCertificate;

							TCSharedPointer<CSSLContext> pServerContext = fg_Construct(CSSLContext::EType_Server, ServerSettings);

							CSSLSettings ClientSettings;
							ClientSettings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_UseSpecificPeerCertificate;
							ClientSettings.m_CACertificateData = ServerSettings.m_PublicCertificateData;

							CCertificateOptions ClientOptions;
							ClientOptions.m_CommonName = "Test Client";
							ClientOptions.m_KeySetting = gc_TestTestKeySetting;
							ClientOptions.m_Hostnames = fg_CreateVector<CStr>("localhost");

							CCertificate::fs_GenerateSelfSignedCertAndKey(ClientOptions, ClientSettings.m_PublicCertificateData, ClientSettings.m_PrivateKeyData);

							TCSharedPointer<CSSLContext> pClientContext = fg_Construct(CSSLContext::EType_Client, ClientSettings);

							return {CSocket_SSL::fs_GetFactory(pServerContext), CSocket_SSL::fs_GetFactory(pClientContext)};
						}
						, "Socket closed: The certificate is self signed and cannot be found in the list of trusted certificates"
						, ""
					)
				;
			}
			{
				DMibTestPath("SSL Server Certificate Incorrect");
				fp_Test
					(
						[]() -> TCTuple<FVirtualSocketFactory, FVirtualSocketFactory>
						{
							CSSLSettings ServerSettings;

							CCertificateOptions ServerOptions;
							ServerOptions.m_CommonName = "Malterlib test Self Signed";
							ServerOptions.m_Hostnames = fg_CreateVector<CStr>("localhost");
							ServerOptions.m_KeySetting = gc_TestTestKeySetting;

							CCertificate::fs_GenerateSelfSignedCertAndKey(ServerOptions, ServerSettings.m_PublicCertificateData, ServerSettings.m_PrivateKeyData);

							CSSLSettings ServerSettings2;
							CCertificateOptions ServerOptions2;
							ServerOptions2.m_CommonName = "Malterlib test Self Signed";
							ServerOptions2.m_Hostnames = fg_CreateVector<CStr>("localhost");
							ServerOptions2.m_KeySetting = gc_TestTestKeySetting;
							CCertificate::fs_GenerateSelfSignedCertAndKey(ServerOptions2, ServerSettings2.m_PublicCertificateData, ServerSettings2.m_PrivateKeyData);

							TCSharedPointer<CSSLContext> pServerContext = fg_Construct(CSSLContext::EType_Server, ServerSettings);

							CSSLSettings ClientSettings;
							ClientSettings.m_CACertificateData = ServerSettings2.m_PublicCertificateData;

							TCSharedPointer<CSSLContext> pClientContext = fg_Construct(CSSLContext::EType_Client, ClientSettings);

							return {CSocket_SSL::fs_GetFactory(pServerContext), CSocket_SSL::fs_GetFactory(pClientContext)};
						}
						, ""
						, "Socket closed: The certificate is self signed and cannot be found in the list of trusted certificates"
					)
				;
			}
			{
				DMibTestPath("SSL Server Certificate Self Signed");
				fp_Test
					(
						[]() -> TCTuple<FVirtualSocketFactory, FVirtualSocketFactory>
						{
							CSSLSettings ServerSettings;

							CCertificateOptions ServerOptions;
							ServerOptions.m_CommonName = "Malterlib test Self Signed";
							ServerOptions.m_Hostnames = fg_CreateVector<CStr>("localhost");
							ServerOptions.m_KeySetting = gc_TestTestKeySetting;

							CCertificate::fs_GenerateSelfSignedCertAndKey(ServerOptions, ServerSettings.m_PublicCertificateData, ServerSettings.m_PrivateKeyData);

							TCSharedPointer<CSSLContext> pServerContext = fg_Construct(CSSLContext::EType_Server, ServerSettings);

							CSSLSettings ClientSettings;
							ClientSettings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_UseOSStoreIfNoCASpecified;
							TCSharedPointer<CSSLContext> pClientContext = fg_Construct(CSSLContext::EType_Client, ClientSettings);

							return {CSocket_SSL::fs_GetFactory(pServerContext), CSocket_SSL::fs_GetFactory(pClientContext)};
						}
						, ""
						, "Socket closed: The certificate is self signed and cannot be found in the list of trusted certificates"
					)
				;
			}
			{
				DMibTestPath("SSL Server Certificate Child Cert");
				fp_Test
					(
						[]() -> TCTuple<FVirtualSocketFactory, FVirtualSocketFactory>
						{
							CSSLSettings ServerSettings;
							CByteVector RootCertData;
							CSecureByteVector RootKeyData;

							CCertificateOptions ServerOptions;
							ServerOptions.m_CommonName = "Malterlib test Self Signed";
							ServerOptions.m_Hostnames = fg_CreateVector<CStr>("localhost");
							ServerOptions.m_KeySetting = gc_TestTestKeySetting;

							CCertificate::fs_GenerateSelfSignedCertAndKey(ServerOptions, RootCertData, RootKeyData);

							CByteVector ChildCertData;
							CSecureByteVector ChildKeyData;
							CByteVector RequestData;

							CCertificateOptions RequestOptions;
							RequestOptions.m_CommonName = "Malterlib test request";
							RequestOptions.m_Hostnames = fg_CreateVector<CStr>("localhost");
							RequestOptions.m_KeySetting = gc_TestTestKeySetting;

							CCertificate::fs_GenerateClientCertificateRequest(RequestOptions, RequestData, ChildKeyData);

							CCertificate::fs_SignClientCertificate(RootCertData, RootKeyData, RequestData, ChildCertData);

							ServerSettings.m_PublicCertificateData = ChildCertData;
							ServerSettings.m_PrivateKeyData = ChildKeyData;

							TCSharedPointer<CSSLContext> pServerContext = fg_Construct(CSSLContext::EType_Server, ServerSettings);

							CSSLSettings ClientSettings;
							ClientSettings.m_CACertificateData = RootCertData;

							TCSharedPointer<CSSLContext> pClientContext = fg_Construct(CSSLContext::EType_Client, ClientSettings);

							return {CSocket_SSL::fs_GetFactory(pServerContext), CSocket_SSL::fs_GetFactory(pClientContext)};
						}
						, ""
						, ""
					)
				;
			}
			{
				DMibTestPath("SSL Server Certificate Incorrect Specific");
				fp_Test
					(
						[]() -> TCTuple<FVirtualSocketFactory, FVirtualSocketFactory>
						{
							CSSLSettings ServerSettings;
							CByteVector RootCertData;
							CSecureByteVector RootKeyData;

							CCertificateOptions ServerOptions;
							ServerOptions.m_CommonName = "Malterlib test Self Signed";
							ServerOptions.m_Hostnames = fg_CreateVector<CStr>("localhost");
							ServerOptions.m_KeySetting = gc_TestTestKeySetting;

							CCertificate::fs_GenerateSelfSignedCertAndKey(ServerOptions, RootCertData, RootKeyData);

							CByteVector ChildCertData;
							CSecureByteVector ChildKeyData;
							CByteVector RequestData;

							CCertificateOptions RequestOptions;
							RequestOptions.m_CommonName = "Malterlib test request";
							RequestOptions.m_Hostnames = fg_CreateVector<CStr>("localhost");
							RequestOptions.m_KeySetting = gc_TestTestKeySetting;

							CCertificate::fs_GenerateClientCertificateRequest(RequestOptions, RequestData, ChildKeyData);

							CCertificate::fs_SignClientCertificate(RootCertData, RootKeyData, RequestData, ChildCertData);

							ServerSettings.m_PublicCertificateData = ChildCertData;
							ServerSettings.m_PrivateKeyData = ChildKeyData;

							TCSharedPointer<CSSLContext> pServerContext = fg_Construct(CSSLContext::EType_Server, ServerSettings);

							CSSLSettings ClientSettings;
							ClientSettings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_UseSpecificPeerCertificate;
							ClientSettings.m_CACertificateData = RootCertData;

							TCSharedPointer<CSSLContext> pClientContext = fg_Construct(CSSLContext::EType_Client, ClientSettings);

							return {CSocket_SSL::fs_GetFactory(pServerContext), CSocket_SSL::fs_GetFactory(pClientContext)};
						}
						, ""
						, "Socket closed: Mismatching specific certificate"
					)
				;
			};
		};
	}
};

DMibTestRegister(CAsyncSocket_Tests, Malterlib::Network);
