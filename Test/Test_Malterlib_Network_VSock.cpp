// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Core/Core>
#include <Mib/Test/Test>
#include <Mib/Test/Exception>
#include <Mib/Network/AsyncSocket>
#include <Mib/Network/ResolveActor>
#include <Mib/Concurrency/Actor/Timer>
#include <Mib/Concurrency/AsyncDestroy>

#if defined(DPlatformFamily_macOS)
#	include <sys/socket.h>
#	include <sys/vsock.h>
#	include <unistd.h>
#elif defined(DPlatformFamily_Linux)
#	include <sys/socket.h>
#	include <linux/vm_sockets.h>
#	include <unistd.h>
#endif

using namespace NMib;
using namespace NMib::NConcurrency;
using namespace NMib::NContainer;
using namespace NMib::NNetwork;
using namespace NMib::NStorage;
using namespace NMib::NStr;

namespace
{
	fp64 g_Timeout = 30.0 * NMib::NTest::gc_TimeoutMultiplier;

	CNetAddress fg_VSockAddress(uint32 _ContextID, uint32 _Port)
	{
		return CNetAddress(CNetAddressVSock{.m_ContextID = _ContextID, .m_Port = _Port});
	}

#ifndef DPlatformFamily_Windows
	// Whether a virtio socket connects to a listener of the same machine. Returns empty when it does, or why it doesn't
	CStr fg_VSockLoopbackUnavailable(uint32 _Port)
	{
		auto fError = [](ch8 const *_pOperation)
			{
				return CStr("{}: {}"_f << _pOperation << strerror(errno));
			}
		;

		int ListenFile = socket(AF_VSOCK, SOCK_STREAM, 0);
		if (ListenFile < 0)
			return fError("socket");

		auto CloseListen = g_OnScopeExit / [&]
			{
				close(ListenFile);
			}
		;

		sockaddr_vm Address = {};
#	ifdef DPlatformFamily_macOS
		Address.svm_len = sizeof(Address);
#	endif
		Address.svm_family = AF_VSOCK;
		Address.svm_cid = CNetAddressVSock::mc_ContextID_Any;
		Address.svm_port = _Port;

		if (bind(ListenFile, (sockaddr const *)&Address, sizeof(Address)) != 0)
			return fError("bind");

		if (listen(ListenFile, 1) != 0)
			return fError("listen");

		int ConnectFile = socket(AF_VSOCK, SOCK_STREAM, 0);
		if (ConnectFile < 0)
			return fError("socket");

		auto CloseConnect = g_OnScopeExit / [&]
			{
				close(ConnectFile);
			}
		;

		Address.svm_cid = CNetAddressVSock::mc_ContextID_Local;
		if (connect(ConnectFile, (sockaddr const *)&Address, sizeof(Address)) != 0)
			return fError("connect");

		return {};
	}
#endif

	struct CPeerState
	{
		CStr m_Received;
	};

	CAsyncSocketCallbacks fg_PeerCallbacks(TCSharedPointer<CPeerState> const &_pState)
	{
		CAsyncSocketCallbacks Callbacks;
		Callbacks.m_fOnReceiveData = g_ActorFunctor / [_pState](CSharedByteVector _Data) -> TCFuture<void>
			{
				_pState->m_Received += CStr((ch8 const *)_Data.f_GetArray(), _Data.f_GetLen());
				co_return {};
			}
		;
		Callbacks.m_fOnClose = g_ActorFunctor / [](EAsyncSocketStatus _Reason, CStr _Message, EAsyncSocketCloseOrigin _Origin) -> TCFuture<void>
			{
				co_return {};
			}
		;

		return Callbacks;
	}

	CSharedByteVector fg_Bytes(CStr const &_String)
	{
		CIOByteVector Data;
		Data.f_Insert((uint8 const *)_String.f_GetStr(), _String.f_GetLen());
		return CSharedByteVector(fg_Move(Data));
	}

	// Polls every 10 ms until _fDone returns true, for at most g_Timeout. Returns whether it did
	TCFuture<bool> fg_WaitUntil(NFunction::TCFunction<bool ()> _fDone)
	{
		for (fp64 Waited = 0.0; Waited < g_Timeout; Waited += 0.01)
		{
			if (_fDone())
				co_return true;

			co_await fg_Timeout(0.01);
		}

		co_return _fDone();
	}
}

struct CVSock_Tests : public NMib::NTest::CTest
{
	void f_DoTests();
};

void CVSock_Tests::f_DoTests()
{
	DMibTestSuite("Addresses")
	{
		{
			DMibTestPath("Parse");

			CNetAddress Address = CSocket::fs_ResolveAddress("VSOCK:2:1024");
			DMibExpect(Address.f_GetType(), ==, ENetAddressType_VSock);

			CNetAddressVSock VSock;
			DMibAssertTrue(Address.f_Get(VSock));
			DMibExpect(VSock.m_ContextID, ==, CNetAddressVSock::mc_ContextID_Host);
			DMibExpect(VSock.m_Port, ==, 1024u);

			CNetAddressTCPv4 AddressTCPv4;
			DMibExpectFalse(Address.f_Get(AddressTCPv4));

			// Ports of virtio sockets are 32 bits, so they are only read and set through CNetAddressVSock
			DMibExpect(Address.f_GetPort(), ==, 0);
			DMibExpectFalse(Address.f_SetPort(80));

			CNetAddress Largest = CSocket::fs_ResolveAddress("VSOCK:4294967295:4294967295");
			DMibAssertTrue(Largest.f_Get(VSock));
			DMibExpect(VSock.m_ContextID, ==, CNetAddressVSock::mc_ContextID_Any);
			DMibExpect(VSock.m_Port, ==, CNetAddressVSock::mc_Port_Any);
		}
		{
			DMibTestPath("Invalid");

			for
			(
				ch8 const *pInvalid :
				{
					"VSOCK:"
					, "VSOCK:2"
					, "VSOCK:2:"
					, "VSOCK::1"
					, "VSOCK:x:1"
					, "VSOCK:2:1:3"
					, "VSOCK:-1:1"
					, "VSOCK:+2:1"
					, "VSOCK:2: 1"
					, "VSOCK:4294967296:1"
					, "VSOCK:2:99999999999"
				}
			)
			{
				DMibTestPath(pInvalid);
				DMibExpectExceptionType(CSocket::fs_ResolveAddress(pInvalid), CExceptionNet);
			}
		}
		{
			DMibTestPath("Format");

			CNetAddress Address = fg_VSockAddress(3, 5000);
			DMibExpect(fg_Format("{}", Address), ==, "VSOCK:3:5000");
			DMibExpect(Address.f_GetString(ENetAddressStringFlag_None), ==, "3");
			DMibExpect(Address.f_GetString(ENetAddressStringFlag_IncludePort), ==, "3:5000");
			DMibExpect(Address.f_GetString(ENetAddressStringFlag_IncludeType | ENetAddressStringFlag_IncludePort), ==, "VSOCK:3:5000");
			DMibExpect(CSocket::fs_ResolveAddress(fg_Format("{}", Address)), ==, Address);
		}
		{
			DMibTestPath("Compare");

			CNetAddress Address = fg_VSockAddress(3, 5000);
			DMibExpect(Address, ==, CSocket::fs_ResolveAddress("VSOCK:3:5000"));
			DMibExpect(Address, <, fg_VSockAddress(3, 5001));
			DMibExpect(Address, <, fg_VSockAddress(4, 5000));
			DMibExpect(Address, !=, CSocket::fs_ResolveAddress("127.0.0.1:5000"));
			DMibExpect(CSocket::fs_ResolveAddress("127.0.0.1:5000"), <, Address);

			CNetAddress Copy = Address;
			DMibExpect(Copy, ==, Address);

			CNetAddress Set;
			DMibExpectTrue(Set.f_Set(CNetAddressVSock{.m_ContextID = 3, .m_Port = 5000}));
			DMibExpect(Set, ==, Address);
		}
		{
			DMibTestPath("Async Resolve");

			TCSharedPointer<NThread::CEventAutoReset> pResolved = fg_Construct();

			CAsyncResolver Resolver;
			Resolver.f_Open
				(
					"VSOCK:2:1024"
					, ENetAddressType_None
					, [pResolved]
					{
						pResolved->f_Signal();
					}
				)
			;

			DMibAssertFalse(pResolved->f_WaitTimeout(g_Timeout));

			CNetAddress Resolved;
			CStr Error;
			DMibExpectTrue(Resolver.f_GetResult(Resolved, Error));
			DMibExpect(Error, ==, "");
			DMibExpect(Resolved, ==, fg_VSockAddress(2, 1024));
		}
	};

	DMibTestSuite("Resolve Actor") -> TCFuture<void>
	{
		auto Resolver = fg_ConstructActor<CResolveActor>();
		auto ResolverDestroy = co_await fg_AsyncDestroy(Resolver);

		{
			DMibTestPath("Valid");

			auto Lookup = co_await Resolver.f_Bind<&CResolveActor::f_Resolve>(CStr("VSOCK:2:1024"), ENetAddressType_None);
			auto Addresses = co_await fg_Move(Lookup.m_Result);
			DMibAssert(Addresses.f_GetLen(), ==, 1u);
			DMibExpect(Addresses[0], ==, fg_VSockAddress(2, 1024));
		}
		{
			DMibTestPath("Invalid");

			auto Lookup = co_await Resolver.f_Bind<&CResolveActor::f_Resolve>(CStr("VSOCK:2"), ENetAddressType_None);
			auto Result = co_await fg_Move(Lookup.m_Result).f_Wrap();
			DMibExpectFalse(Result);
		}

		co_return {};
	};

	DMibTestSuite("Loopback") -> TCFuture<void>
	{
		constexpr uint32 c_Port = 30517;

#ifdef DPlatformFamily_Windows
		{
			DMibTestPath("Unsupported");

			CNetAddress Address = fg_VSockAddress(CNetAddressVSock::mc_ContextID_Local, c_Port);

			CSocket Connect;
			DMibExpectException(Connect.f_Connect(Address), DMibImpExceptionInstance(CExceptionNet, "Virtio sockets (VSOCK:) are not supported on Windows"));

			CSocket Listen;
			DMibExpectException(Listen.f_Listen(Address, nullptr, ENetFlag_None), DMibImpExceptionInstance(CExceptionNet, "Virtio sockets (VSOCK:) are not supported on Windows"));
		}
#else
		// Needs a transport that loops back within the machine, such as vsock_loopback on Linux, or a VM guest
		CStr Unavailable;
		{
			auto BlockingActorCheckout = fg_BlockingActor();
			Unavailable = co_await
				(
					g_Dispatch(BlockingActorCheckout) / []() -> CStr
					{
						return fg_VSockLoopbackUnavailable(c_Port);
					}
				)
			;
		}

		if (!Unavailable.f_IsEmpty())
		{
			DMibConOut("Virtio socket loopback skipped: {}\n", Unavailable);
			co_return {};
		}

		TCActor<CAsyncSocketServerActor> Server = fg_ConstructActor<CAsyncSocketServerActor>();
		auto ServerDestroy = co_await fg_AsyncDestroy(Server);

		TCActor<CAsyncSocketClientActor> Client = fg_ConstructActor<CAsyncSocketClientActor>();
		auto ClientDestroy = co_await fg_AsyncDestroy(Client);

		TCPromiseFuturePair<CAsyncSocketNewServerConnection> ServerConnection;

		CAsyncSocketServerCallbacks ServerCallbacks;
		ServerCallbacks.m_fNewConnection = g_ActorFunctor / [Promise = ServerConnection.m_Promise](CAsyncSocketNewServerConnection _Connection) -> TCFuture<void>
			{
				if (!Promise.f_IsSet())
					Promise.f_SetResult(fg_Move(_Connection));

				co_return {};
			}
		;

		auto Listen = co_await Server
			(
				&CAsyncSocketServerActor::f_StartListenAddress
				, fg_CreateVector(CSocket::fs_ResolveAddress("VSOCK:4294967295:{}"_f << c_Port))
				, ENetFlag_None
				, fg_Move(ServerCallbacks)
				, nullptr
			)
		;
		DMibAssert(Listen.m_ListenPorts.f_GetLen(), ==, 1u);
		DMibExpect(Listen.m_ListenPorts[0], ==, c_Port);

		CAsyncSocketNewClientConnection Connected = co_await Client(&CAsyncSocketClientActor::f_Connect, CStr("VSOCK:1:{}"_f << c_Port), CStr(), ENetAddressType_None, uint16(0), nullptr)
			.f_Timeout(g_Timeout, "Timed out connecting")
		;
		CAsyncSocketNewServerConnection Accepted = co_await fg_Move(ServerConnection.m_Future).f_Timeout(g_Timeout, "Timed out accepting");

		{
			DMibTestPath("Peer Addresses");

			DMibExpect(Connected.m_PeerAddress, ==, fg_VSockAddress(CNetAddressVSock::mc_ContextID_Local, c_Port));
			DMibExpect(Accepted.m_Info.m_PeerAddress.f_GetType(), ==, ENetAddressType_VSock);
		}

		TCSharedPointer<CPeerState> pClientState = fg_Construct();
		TCSharedPointer<CPeerState> pServerState = fg_Construct();

		TCActorInterface<CAsyncSocketActor> ClientSocket = co_await Connected.f_Accept(fg_PeerCallbacks(pClientState));
		TCActorInterface<CAsyncSocketActor> ServerSocket = co_await Accepted.f_Accept(fg_PeerCallbacks(pServerState));

		{
			DMibTestPath("Data Both Ways");

			co_await ClientSocket(&CAsyncSocketActor::f_SendData, fg_Bytes("ping"), uint32(0)).f_Timeout(g_Timeout, "Timed out sending");
			DMibExpectTrue
				(
					co_await fg_WaitUntil
					(
						[pServerState]
						{
							return pServerState->m_Received == "ping";
						}
					)
				)
			;

			co_await ServerSocket(&CAsyncSocketActor::f_SendData, fg_Bytes("pong"), uint32(0)).f_Timeout(g_Timeout, "Timed out sending");
			DMibExpectTrue
				(
					co_await fg_WaitUntil
					(
						[pClientState]
						{
							return pClientState->m_Received == "pong";
						}
					)
				)
			;
		}

		co_await ClientSocket.f_Destroy();
		co_await ServerSocket.f_Destroy();
#endif

		co_return {};
	};
}

DMibTestRegister(CVSock_Tests, Malterlib::Network);
