// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Core/Core>
#include <Mib/Test/Test>
#include <Mib/Network/AsyncSocket>
#include <Mib/Network/Sockets/SSL>
#include <Mib/Cryptography/Certificate>
#include <Mib/Cryptography/RandomID>

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
			TCActorResultVector<void> Destroys;
			{
				DMibLock(m_Lock);
				m_bCleared = true;

				m_ClientSocket.f_Destroy() > Destroys.f_AddResult();

				if (m_ClientSocket)
					fg_Move(m_ClientSocket).f_Destroy() > Destroys.f_AddResult();

				if (m_ClientActor)
					fg_Move(m_ClientActor).f_Destroy() > Destroys.f_AddResult();

				if (m_ListenCallbackReference)
				{
					m_ListenCallbackReference->f_Destroy() > Destroys.f_AddResult();
					m_ListenCallbackReference.f_Clear();
				}

				for (auto &Connection : m_ServerConnections)
				{
					if (Connection.m_Actor)
						fg_Move(Connection.m_Actor).f_Destroy() > Destroys.f_AddResult();
				}

				m_ServerConnections.f_Clear();
			}

			Destroys.f_GetResults().f_CallSync(m_pRunLoop);

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

			ListenCallbacks.m_fNewConnection = g_ActorFunctor / [pStateWeak](CAsyncSocketNewServerConnection &&_ConnectionInfo) -> TCFuture<void>
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
							/ [=](TCSharedPointer<CSecureByteVector> const &_pData) -> TCFuture<void>
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
										Connection.m_Actor(&CAsyncSocketActor::f_SendData, _pData, 0) > fg_DiscardResult();
								}

								pServerConnection->m_MessageBuffer.f_AddStr((ch8 const *)_pData->f_GetArray(), _pData->f_GetLen());

								while (pServerConnection->m_MessageBuffer.f_FindChar('\n') >= 0)
								{
									CStr Command = fg_GetStrLineSep(pServerConnection->m_MessageBuffer);
									if (Command == "Disconnect")
									{
										DMibLock(pState->m_Lock);
										for (auto &Connection : pState->m_ServerConnections)
											Connection.m_Actor(&CAsyncSocketActor::f_Close, EAsyncSocketStatus_NormalClosure, g_pCloseMessage) > fg_DiscardResult();
									}
								}

								co_return {};
							}
						;

						Callbacks.m_fOnClose = g_ActorFunctor
							/ [=](EAsyncSocketStatus _Status, CStr const &_Message, EAsyncSocketCloseOrigin _Origin) -> TCFuture<void>
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
								fg_Move(Actor).f_Destroy() > fg_DiscardResult();
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

			ListenCallbacks.m_fFailedConnection = g_ActorFunctor / [pStateWeak](CAsyncSocketActor::CConnectionInfo &&_ConnectionInfo) -> TCFuture<void>
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

						Callbacks.m_fOnClose = g_ActorFunctor / [pStateWeak](EAsyncSocketStatus _Status, CStr const &_Message, EAsyncSocketCloseOrigin _Origin) -> TCFuture<void>
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

						Callbacks.m_fOnReceiveData = g_ActorFunctor / [pStateWeak](TCSharedPointer<CSecureByteVector> const &_pData) -> TCFuture<void>
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
									fg_Move(*_Socket).f_Destroy() > fg_DiscardResult();
									return;
								}

								DMibLock(pState->m_Lock);

								if (pState->m_bCleared)
								{
									fg_Move(*_Socket).f_Destroy() > fg_DiscardResult();
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

		NTime::CClock Clock;
		Clock.f_Start();

		while (!_fPredicate())
		{
			NSys::fg_Thread_Sleep(0.01f);
			if (Clock.f_GetTime() > 30.0)
			{
				bTimedOut = true;
				break;
			}
		}

		return bTimedOut;
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
			TCSharedPointer<CDefaultRunLoop> pRunLoop = fg_Construct();
			auto CleanupRunLoop = g_OnScopeExit / [&]
				{
					while (pRunLoop->m_RefCount.f_Get() > 0)
						pRunLoop->f_WaitOnceTimeout(0.1);
				}
			;
			TCActor<CDispatchingActor> HelperActor(fg_Construct(), pRunLoop->f_Dispatcher());
			auto CleanupHelperActor = g_OnScopeExit / [&]
				{
					HelperActor->f_BlockDestroy(pRunLoop->f_ActorDestroyLoop());
				}
			;
			CCurrentlyProcessingActorScope CurrentActor{HelperActor};
			
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
				TCSharedPointerSupportWeak<CState> pState = fg_Construct(pRunLoop);
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
						TCSharedPointer<CSecureByteVector> pBuffer = fg_Construct();
						pBuffer->f_Insert((uint8 const *)_Text.f_GetStr(), _Text.f_GetLen());
						pBuffer->f_Insert('\n');
						return pBuffer;
					}
				;


				if (!fp_TestConnect(pState, _AcceptError, _ConnectError))
					return;
				{
					DMibTestPath("Messages");

					pState->m_ClientSocket(&CAsyncSocketActor::f_SendData, fTextBuffer("TestText"), 0).f_CallSync(g_Timeout / 3);
					pState->m_ClientSocket(&CAsyncSocketActor::f_SendData, fTextBuffer("TestBuff"), 0).f_CallSync(g_Timeout / 3);

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

					pState->m_ClientSocket(&CAsyncSocketActor::f_SendData, fTextBuffer("Disconnect"), 0) > fg_DiscardResult();
					
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
				TCSharedPointerSupportWeak<CState> pState = fg_Construct(pRunLoop);
				auto Cleanup 
					= g_OnScopeExit / [&]
					{
						pState->f_Clear();
					}
				;
				
				pState->m_ServerActor = fg_ConstructActor<CAsyncSocketServerActor>();
				pState->m_ServerActor(&CAsyncSocketServerActor::f_SetDefaultTimeout, 1.0).f_CallSync(pRunLoop, g_Timeout);
				pState->f_StartListen(ListenAddress, ServerFactory);
				
				pState->m_ClientActor = fg_ConstructActor<CAsyncSocketClientActor>();
				pState->m_ClientActor(&CAsyncSocketClientActor::f_SetDefaultTimeout, 1.0).f_CallSync(pRunLoop, g_Timeout);
				pState->f_Connect(_Address, ClientFactory);
				
				if (!fp_TestConnect(pState, _AcceptError, _ConnectError))
					return;
				{
					DMibTestPath("Timeout");
					pState->m_ClientSocket(&CAsyncSocketActor::f_DebugStopProcessing, 1.0).f_CallSync(pRunLoop, g_Timeout);
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
