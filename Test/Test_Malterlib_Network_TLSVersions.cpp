// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Network/AsyncSocket>
#include <Mib/Network/Sockets/SSL>
#include <Mib/Concurrency/AsyncDestroy>
#include <Mib/Cryptography/Certificate>
#include <Mib/Test/Exception>

namespace
{
	using namespace NMib;
	using namespace NMib::NNetwork;
	using namespace NMib::NConcurrency;
	using namespace NMib::NStorage;
	using namespace NMib::NStr;

	struct CTLSVersions_Tests : NTest::CTest
	{
		void f_DoTests()
		{
			DMibTestSuite("Negotiation") -> TCFuture<void>
			{
				CSSLSettings ServerSettings;
				ServerSettings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_AllowMissingPeerCertificate;
				NCryptography::CCertificateOptions Options;
				Options.m_CommonName = "TLS negotiation test";
				Options.m_Hostnames = NContainer::fg_CreateVector<CStr>("localhost");
				Options.m_KeySetting = NCryptography::CPublicKeySettings_EC_secp256r1{};
				NCryptography::CCertificate::fs_GenerateSelfSignedCertAndKey(Options, ServerSettings.m_PublicCertificateData, ServerSettings.m_PrivateKeyData);
				CSSLSettings ClientSettings;
				ClientSettings.m_CACertificateData = ServerSettings.m_PublicCertificateData;

				struct CCase
				{
					ch8 const *m_Name;
					CSSLSettings::EProtocol m_Client;
					CSSLSettings::EProtocol m_Server;
					ch8 const *m_Expected;
				};
				CCase Cases[] =
				{
					{"Default", CSSLSettings::EProtocol_TLS, CSSLSettings::EProtocol_TLS, "TLSv1.3"},
					{"TLS12Server", CSSLSettings::EProtocol_TLS, CSSLSettings::EProtocol_TLS_1_2, "TLSv1.2"},
					{"TLS12Client", CSSLSettings::EProtocol_TLS_1_2, CSSLSettings::EProtocol_TLS, "TLSv1.2"},
					{"TLS13Server", CSSLSettings::EProtocol_TLS, CSSLSettings::EProtocol_TLS_1_3, "TLSv1.3"},
					{"TLS13Client", CSSLSettings::EProtocol_TLS_1_3, CSSLSettings::EProtocol_TLS, "TLSv1.3"},
				};

				for (auto const &Case : Cases)
				{
					DMibTestPath(Case.m_Name);
					ClientSettings.m_Protocol = Case.m_Client;
					ServerSettings.m_Protocol = Case.m_Server;
					TCSharedPointer<CSSLContext> pServerContext = fg_Construct(CSSLContext::EType_Server, ServerSettings);
					TCSharedPointer<CSSLContext> pClientContext = fg_Construct(CSSLContext::EType_Client, ClientSettings);
					auto Server = fg_ConstructActor<CAsyncSocketServerActor>();
					auto Client = fg_ConstructActor<CAsyncSocketClientActor>();
					auto DestroyServer = co_await fg_AsyncDestroy(Server);
					auto DestroyClient = co_await fg_AsyncDestroy(Client);
					TCPromise<CStr> ServerVersion;
					TCPromise<TCActorInterface<CAsyncSocketActor>> ServerAccepted;
					CAsyncSocketServerCallbacks Callbacks;
					Callbacks.m_fNewConnection = g_ActorFunctor / [ServerVersion, ServerAccepted](CAsyncSocketNewServerConnection Connection) -> TCFuture<void>
						{
							auto *pInfo = static_cast<CSocketConnectionInfo_SSL *>(Connection.m_Info.m_pSocketInfo.f_Get());
							DMibRequire(pInfo);
							ServerVersion.f_SetResult(pInfo->m_ProtocolVersion);
							ServerAccepted.f_SetResult(co_await Connection.f_Accept({}));
							co_return {};
						}
					;

					CNetAddressTCPv4 Address;
					Address.f_SetLocalhost();
					Address.m_Port = 0;
					auto Listen = co_await Server
						(
							&CAsyncSocketServerActor::f_StartListenAddress
							, NContainer::fg_CreateVector<CNetAddress>(Address)
							, ENetFlag_None
							, fg_Move(Callbacks)
							, CSocket_SSL::fs_GetFactory(pServerContext)
						)
					;
					auto Connection = co_await Client
						(
							&CAsyncSocketClientActor::f_Connect
							, CStr("localhost")
							, CStr{}
							, ENetAddressType_TCPv4
							, Listen.m_ListenPorts[0]
							, CSocket_SSL::fs_GetFactory(pClientContext)
						)
					;
					auto *pInfo = static_cast<CSocketConnectionInfo_SSL *>(Connection.m_pSocketInfo.f_Get());
					DMibAssertTrue(pInfo != nullptr);
					DMibExpect(pInfo->m_ProtocolVersion, ==, CStr(Case.m_Expected));
					auto ClientSocket = co_await Connection.f_Accept({});
					auto DestroyClientSocket = co_await fg_AsyncDestroy(ClientSocket);
					auto ServerSocket = co_await ServerAccepted.f_Future().f_Timeout(10.0 * NTest::gc_TimeoutMultiplier, "TLS server did not accept");
					auto DestroyServerSocket = co_await fg_AsyncDestroy(ServerSocket);
					auto Version = co_await ServerVersion.f_Future();
					DMibExpect(Version, ==, CStr(Case.m_Expected));
					co_await Listen.m_Subscription->f_Destroy();
				}

				co_return {};
			};
		}
	};
}

DMibTestRegister(CTLSVersions_Tests, Malterlib::Network);
