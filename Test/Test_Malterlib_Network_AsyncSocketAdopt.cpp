// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Core/Core>
#include <Mib/Test/Test>
#include <Mib/Network/AsyncSocket>
#include <Mib/Network/Sockets/TCP>
#include <Mib/Concurrency/Actor/Timer>
#include <Mib/Concurrency/AsyncDestroy>
#include <Mib/File/File>

#ifndef DPlatformFamily_Windows
#	include <sys/socket.h>
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

	// Used only on the test actor, which runs the callbacks
	struct CPeerState
	{
		CStr m_Received;
		bool m_bClosed = false;
	};

	CAsyncSocketCallbacks fg_PeerCallbacks(TCSharedPointer<CPeerState> const &_pState)
	{
		CAsyncSocketCallbacks Callbacks;
		Callbacks.m_fOnReceiveData = g_ActorFunctor / [_pState](CSharedByteVector _Data) -> TCFuture<void>
			{
				if (_pState->m_Received.f_GetLen() < 64)
					_pState->m_Received += CStr((ch8 const *)_Data.f_GetArray(), _Data.f_GetLen());

				co_return {};
			}
		;
		Callbacks.m_fOnClose = g_ActorFunctor / [_pState](EAsyncSocketStatus _Reason, CStr _Message, EAsyncSocketCloseOrigin _Origin) -> TCFuture<void>
			{
				_pState->m_bClosed = true;
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

	// Connects a plain socket and hands its descriptor over, as an API that connected the socket itself would
	TCFuture<CInheritedSocketHandle> fg_ConnectHandle(CNetAddress _Address)
	{
		auto BlockingActorCheckout = fg_BlockingActor();

		co_return co_await
			(
				g_Dispatch(BlockingActorCheckout) / [_Address]() -> TCFuture<CInheritedSocketHandle>
				{
					co_await ECoroutineFlag_CaptureExceptions;

					CSocket Socket;
					Socket.f_Connect(_Address, nullptr, g_Timeout);

					TCPromiseFuturePair<CInheritedSocketHandle> Handle;
					Socket.f_GiveUpForInheritAsync
						(
							[Promise = fg_Move(Handle.m_Promise)](void *_pSocketHandle) mutable
							{
								Promise.f_SetResult(CInheritedSocketHandle(_pSocketHandle));
							}
						)
					;

					co_return co_await fg_Move(Handle.m_Future);
				}
			)
		;
	}
}

struct CAsyncSocketAdopt_Tests : public NMib::NTest::CTest
{
	void f_DoTests();
};

void CAsyncSocketAdopt_Tests::f_DoTests()
{
	DMibTestSuite("Adopt Connection") -> TCFuture<void>
	{
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
				, fg_CreateVector(CSocket::fs_ResolveAddress("127.0.0.1:0"))
				, ENetFlag_None
				, fg_Move(ServerCallbacks)
				, nullptr
			)
		;
		DMibAssert(Listen.m_ListenPorts.f_GetLen(), ==, 1u);

		CInheritedSocketHandle Handle = co_await fg_ConnectHandle(CSocket::fs_ResolveAddress("127.0.0.1:{}"_f << Listen.m_ListenPorts[0]));
		CAsyncSocketNewClientConnection Adopted = co_await Client(&CAsyncSocketClientActor::f_AdoptConnection, fg_Move(Handle), nullptr).f_Timeout(g_Timeout, "Timed out adopting");
		CAsyncSocketNewServerConnection Accepted = co_await fg_Move(ServerConnection.m_Future).f_Timeout(g_Timeout, "Timed out accepting");

		TCSharedPointer<CPeerState> pAdoptedState = fg_Construct();
		TCSharedPointer<CPeerState> pServerState = fg_Construct();

		TCActorInterface<CAsyncSocketActor> AdoptedSocket = co_await Adopted.f_Accept(fg_PeerCallbacks(pAdoptedState));
		TCActorInterface<CAsyncSocketActor> ServerSocket = co_await Accepted.f_Accept(fg_PeerCallbacks(pServerState));

		{
			DMibTestPath("Data Both Ways");

			co_await AdoptedSocket(&CAsyncSocketActor::f_SendData, fg_Bytes("ping"), uint32(0)).f_Timeout(g_Timeout, "Timed out sending");
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
						[pAdoptedState]
						{
							return pAdoptedState->m_Received == "pong";
						}
					)
				)
			;
		}

		{
			DMibTestPath("Close Reaches The Peer");

			auto CloseResult = co_await AdoptedSocket(&CAsyncSocketActor::f_CloseWithLinger, EAsyncSocketStatus_NormalClosure, CStr("Done"), 5.0).f_Wrap();
			DMibExpect(CloseResult ? CStr() : CloseResult.f_GetExceptionStr(), ==, "");
			DMibExpectTrue
				(
					co_await fg_WaitUntil
					(
						[pServerState]
						{
							return pServerState->m_bClosed;
						}
					)
				)
			;
		}

		co_return {};
	};

#ifndef DPlatformFamily_Windows
	DMibTestSuite("Blocking Descriptor") -> TCFuture<void>
	{
		TCActor<CAsyncSocketClientActor> Client = fg_ConstructActor<CAsyncSocketClientActor>();
		auto ClientDestroy = co_await fg_AsyncDestroy(Client);

		int Files[2];
		DMibAssert(socketpair(AF_UNIX, SOCK_STREAM, 0, Files), ==, 0);

		int PeerFile = Files[1];
		auto ClosePeer = g_OnScopeExit / [&]
			{
				if (PeerFile >= 0)
					close(PeerFile);
			}
		;

		// The peer sends nothing, so a descriptor that stayed blocking would block the first read of the adopted socket
		auto Adopted = co_await Client(&CAsyncSocketClientActor::f_AdoptConnection, CInheritedSocketHandle((void *)umint(Files[0])), nullptr)
			.f_Timeout(5.0 * NMib::NTest::gc_TimeoutMultiplier, "Timed out adopting")
			.f_Wrap()
		;
		DMibAssert(Adopted ? CStr() : Adopted.f_GetExceptionStr(), ==, "");

		TCSharedPointer<CPeerState> pAdoptedState = fg_Construct();
		TCActorInterface<CAsyncSocketActor> AdoptedSocket = co_await Adopted->f_Accept(fg_PeerCallbacks(pAdoptedState));

		DMibAssert(write(PeerFile, "ping", 4), ==, ssize_t(4));
		DMibExpectTrue
			(
				co_await fg_WaitUntil
				(
					[pAdoptedState]
					{
						return pAdoptedState->m_Received == "ping";
					}
				)
			)
		;

		co_return {};
	};
#endif
}

DMibTestRegister(CAsyncSocketAdopt_Tests, Malterlib::Network);
