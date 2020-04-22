// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Core/Core>
#include <Mib/Test/Test>
#include <Mib/Network/AsyncSocket>
#include <Mib/Network/Sockets/SSL>
#include <Mib/Cryptography/Certificate>

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
	fp64 g_Timeout = 5.0;
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
		DMibTestCategory("IP")
		{
			fp_TestImp(_fGetFactories, _AcceptError, _ConnectError, "localhost", _bTestTimeout);
		};
		DMibTestCategory("Unix")
		{
			fp_TestImp(_fGetFactories, _AcceptError, _ConnectError, "UNIX:" + fg_GetSafeUnixSocketPath("{}/AsyncSocket.socket"_f << NFile::CFile::fs_GetProgramDirectory()), false);
		};
	}

	struct CState : public TCSharedPointerIntrusiveBase<ESharedPointerOption_SupportWeakPointer>
	{
		struct CServerConnection
		{
			~CServerConnection()
			{
				*m_pDeleted = true;
			}

			TCActorInterface<CAsyncSocketActor> m_Actor;
			CStr m_MessageBuffer;
			TCSharedPointer<bool> m_pDeleted = fg_Construct();
			bool m_bFinished = false;
		};
		
		CMutual m_Lock;
		CEventAutoReset m_Event;

		CStr m_ClientMessageBuffer;

		TCActor<CAsyncSocketServerActor> m_ServerActor;
		CActorSubscription m_ListenCallbackReference;

		TCLinkedList<CServerConnection> m_ServerConnections;
		
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

			Destroys.f_GetResults().f_CallSync();

			{
				DMibLock(m_Lock);
				if (m_ServerActor)
				{
					auto ServerActor = m_ServerActor;
					{
						DMibUnlock(m_Lock);
						ServerActor->f_BlockDestroy(); // Make sure to release listen socket
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
					CState::CServerConnection *pServerConnection;
					TCSharedPointer<bool> pDeleted;
					{
						auto pState = pStateWeak.f_Lock();
						if (!pState)
							co_return {};
						DMibLock(pState->m_Lock);

						pServerConnection = &pState->m_ServerConnections.f_Insert();

						Callbacks.m_fOnReceiveData = g_ActorFunctor
							/ [=, pDeleted = pServerConnection->m_pDeleted](TCSharedPointer<CSecureByteVector> const &_pData) -> TCFuture<void>
							{
								auto pState = pStateWeak.f_Lock();
								if (!pState)
									co_return {};

								DMibLock(pState->m_Lock);
								if (*pDeleted || pState->m_bCleared)
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
							/ [=, pDeleted = pServerConnection->m_pDeleted](EAsyncSocketStatus _Status, CStr const &_Message, EAsyncSocketCloseOrigin _Origin) -> TCFuture<void>
							{
								auto pState = pStateWeak.f_Lock();
								if (!pState)
									co_return {};
								DMibLock(pState->m_Lock);
								if (*pDeleted || pState->m_bCleared)
									co_return {};
								pState->m_ServerConnectionCloseMessage = _Message;
								pState->m_ServerConnectionCloseStatus = _Status;
								pState->m_ServerConnectionCloseOrigin = _Origin;
								pState->m_ServerConnections.f_Remove(*pServerConnection);
								pState->m_Event.f_Signal();

								co_return {};
							}
						;

						pDeleted = pServerConnection->m_pDeleted;
					}

					auto Cleanup = g_OnScopeExit > [=, pDeleted = pServerConnection->m_pDeleted]
						{
							auto pState = pStateWeak.f_Lock();
							if (!pState)
								return;
							if (*pDeleted || pState->m_bCleared)
								return;
							pServerConnection->m_bFinished = true;
							pState->m_Event.f_Signal();
						}
					;

					auto Actor = co_await ConnectionInfo.f_Accept(fg_Move(Callbacks));
					{
						auto pState = pStateWeak.f_Lock();
						if (!pState)
							co_return {};

						if (*pDeleted || pState->m_bCleared)
							co_return {};
					}

					auto pState = pStateWeak.f_Lock();
					if (!pState)
						co_return {};

					{
						DMibLock(pState->m_Lock);
						pServerConnection->m_Actor = fg_Move(Actor);
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
					pState->m_Event.f_Signal();

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
					pState->m_Event.f_Signal();
				}
			;			
			bool bTimedOutListenStart = m_Event.f_WaitTimeout(g_Timeout);
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
								pState->m_Event.f_Signal();

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

								pState->m_Event.f_Signal();

								co_return {};
							}
						;

						auto Cleanup = g_OnScopeExitActor > [pStateWeak]
							{
								auto pState = pStateWeak.f_Lock();
								if (!pState)
									return;

								DMibLock(pState->m_Lock);
								pState->m_bClientConnectionResult = true;
								pState->m_Event.f_Signal();
							}
						;

						Result.f_Accept(fg_Move(Callbacks)) > [pStateWeak, Cleanup](TCAsyncResult<TCActorInterface<CAsyncSocketActor>> &&_Socket)
							{
								if (!_Socket)
									return;

								auto pState = pStateWeak.f_Lock();
								if (!pState)
									return;

								DMibLock(pState->m_Lock);

								if (pState->m_bCleared)
									return;

								pState->m_ClientSocket = fg_Move(*_Socket);
							}
						;
					}
					else
					{
						pState->m_bClientConnectionResult = true;
						pState->m_ClientConnectionError = _Result.f_GetExceptionStr();
					}

					pState->m_Event.f_Signal();
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
			bTimedOut = pState->m_Event.f_WaitTimeout(g_Timeout);
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

	void fp_TestImp
		(
			TCFunction<TCTuple<FVirtualSocketFactory, FVirtualSocketFactory> ()> const &_fGetFactories
			, CStr const &_AcceptError
			, CStr const &_ConnectError
			, CStr const &_Address
		 	, bool _bTestTimeout
		)
	{
		DMibTestSuite("Connection")
		{
			TCActor<CSeparateThreadActor> ProcessingActor{fg_Construct(), "Test processing"};
			auto Cleanup = g_OnScopeExit > [&]
				{
					ProcessingActor->f_BlockDestroy();
				}
			;
			CCurrentlyProcessingActorScope CurrentActorScope(ProcessingActor);
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
				TCSharedPointerSupportWeak<CState> pState = fg_Construct();
				auto Cleanup 
					= g_OnScopeExit > [&]
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

					pState->m_ClientSocket(&CAsyncSocketActor::f_SendData, fTextBuffer("TestText"), 0).f_CallSync(20.0);
					pState->m_ClientSocket(&CAsyncSocketActor::f_SendData, fTextBuffer("TestBuff"), 0).f_CallSync(20.0);

					bool bTimedOut = false;
					while (!bTimedOut)
					{
						{
							DMibLock(pState->m_Lock);
							if (pState->m_Messages.f_GetLen() >= 2)
								break;
						}
						bTimedOut = pState->m_Event.f_WaitTimeout(g_Timeout);
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
						bTimedOut = pState->m_Event.f_WaitTimeout(g_Timeout);
					}

					DMibTest(!DMibExpr(bTimedOut));
					DMibExpect(pState->m_ClientConnectionCloseMessage, !=, "");
					DMibExpect(pState->m_ServerConnectionCloseMessage, !=, "");
				}
			}

			if (_bTestTimeout)
			{
				DMibTestPath("Timeout");
				TCSharedPointerSupportWeak<CState> pState = fg_Construct();
				auto Cleanup 
					= g_OnScopeExit > [&]
					{
						pState->f_Clear();
					}
				;
				
				pState->m_ServerActor = fg_ConstructActor<CAsyncSocketServerActor>();
				pState->m_ServerActor(&CAsyncSocketServerActor::f_SetDefaultTimeout, 1.0).f_CallSync(g_Timeout);
				pState->f_StartListen(ListenAddress, ServerFactory);
				
				pState->m_ClientActor = fg_ConstructActor<CAsyncSocketClientActor>();
				pState->m_ClientActor(&CAsyncSocketClientActor::f_SetDefaultTimeout, 1.0).f_CallSync(g_Timeout);
				pState->f_Connect(_Address, ClientFactory);
				
				if (!fp_TestConnect(pState, _AcceptError, _ConnectError))
					return;
				{
					DMibTestPath("Timeout");
					pState->m_ClientSocket(&CAsyncSocketActor::f_DebugStopProcessing, 1.0).f_CallSync(g_Timeout);
					NSys::fg_Thread_Sleep(2.0);
					
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
		bool bTestTimeout = false;
		DMibTestCategory("TCP")
		{
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
		};
		DMibTestCategory("SSL")
		{
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
		};
		DMibTestCategory("SSL Client Certificate")
		{
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
		};
		DMibTestCategory("SSL Client Certificate Chain Without Intermediate CA")
		{
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
		};
		DMibTestCategory("SSL Client Certificate Incorrect")
		{
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
		};
		DMibTestCategory("SSL Client Certificate Missing")
		{
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
		};
		DMibTestCategory("SSL Client Certificate Allow Missing")
		{
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
		};
		DMibTestCategory("SSL Client Certificate Incorrect Allow Missing")
		{
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
		};
		DMibTestCategory("SSL Server Certificate Incorrect")
		{
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
		};
		DMibTestCategory("SSL Server Certificate Self Signed")
		{
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
		};
		DMibTestCategory("SSL Server Certificate Child Cert")
		{
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
		};
		DMibTestCategory("SSL Server Certificate Incorrect Specific")
		{
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
	}
};

DMibTestRegister(CAsyncSocket_Tests, Malterlib::Network);
