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

// A connection that a client adopted, not yet accepted, and the end of it that the server accepted. Outside the anonymous namespace, since futures
// identify their types by name
struct CAsyncSocketAdoptTestPair
{
	CAsyncSocketNewClientConnection m_Adopted;
	CAsyncSocketNewServerConnection m_Accepted;
};

namespace
{
	fp64 g_Timeout = 30.0 * NMib::NTest::gc_TimeoutMultiplier;

	// Used only on the test actor, which runs the callbacks
	struct CPeerState
	{
		TCVector<TCPromise<void>> m_HeldReceives;
		CStr m_Received;
		uint64 m_nReceived = 0;
		bool m_bHoldReceives = false;
		bool m_bClosed = false;
	};

	CAsyncSocketCallbacks fg_PeerCallbacks(TCSharedPointer<CPeerState> const &_pState, umint _nMaxUnhandledReceiveBytes)
	{
		CAsyncSocketCallbacks Callbacks;
		Callbacks.m_nMaxUnhandledReceiveBytes = _nMaxUnhandledReceiveBytes;
		Callbacks.m_fOnReceiveData = g_ActorFunctor / [_pState](CSharedByteVector _Data) -> TCFuture<void>
			{
				_pState->m_nReceived += _Data.f_GetLen();
				if (_pState->m_Received.f_GetLen() < 64)
					_pState->m_Received += CStr((ch8 const *)_Data.f_GetArray(), _Data.f_GetLen());

				if (!_pState->m_bHoldReceives)
					co_return {};

				TCPromiseFuturePair<void> Held;
				_pState->m_HeldReceives.f_Insert(fg_Move(Held.m_Promise));
				co_await fg_Move(Held.m_Future);

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

	// Listens on a TCP loopback port with _Server and connects to it with an adopted descriptor
	TCFuture<CAsyncSocketAdoptTestPair> fg_ConnectAdopted(TCActor<CAsyncSocketServerActor> _Server, TCActor<CAsyncSocketClientActor> _Client)
	{
		TCPromiseFuturePair<CAsyncSocketNewServerConnection> ServerConnection;

		CAsyncSocketServerCallbacks ServerCallbacks;
		ServerCallbacks.m_fNewConnection = g_ActorFunctor / [Promise = ServerConnection.m_Promise](CAsyncSocketNewServerConnection _Connection) -> TCFuture<void>
			{
				if (!Promise.f_IsSet())
					Promise.f_SetResult(fg_Move(_Connection));

				co_return {};
			}
		;

		auto Listen = co_await _Server
			(
				&CAsyncSocketServerActor::f_StartListenAddress
				, fg_CreateVector(CSocket::fs_ResolveAddress("127.0.0.1:0"))
				, ENetFlag_None
				, fg_Move(ServerCallbacks)
				, nullptr
			)
		;
		if (Listen.m_ListenPorts.f_GetLen() != 1)
			co_return DMibErrorInstance("Expected one listen port");

		CInheritedSocketHandle Handle = co_await fg_ConnectHandle(CSocket::fs_ResolveAddress("127.0.0.1:{}"_f << Listen.m_ListenPorts[0]));

		CAsyncSocketAdoptTestPair Pair
			{
				.m_Adopted = co_await _Client(&CAsyncSocketClientActor::f_AdoptConnection, fg_Move(Handle), nullptr).f_Timeout(g_Timeout, "Timed out adopting")
				, .m_Accepted = co_await fg_Move(ServerConnection.m_Future).f_Timeout(g_Timeout, "Timed out accepting")
			}
		;

		co_return fg_Move(Pair);
	}

	// Resolves the receives that _pState holds, every 10 ms, until _fDone returns true, for at most g_Timeout. Returns whether it did
	TCFuture<bool> fg_ReleaseHeldReceivesUntil(TCSharedPointer<CPeerState> _pState, NFunction::TCFunction<bool ()> _fDone)
	{
		for (fp64 Waited = 0.0; Waited < g_Timeout; Waited += 0.01)
		{
			auto HeldReceives = fg_Move(_pState->m_HeldReceives);
			for (auto &Promise : HeldReceives)
				Promise.f_SetResult();

			if (_fDone())
				co_return true;

			co_await fg_Timeout(0.01);
		}

		co_return _fDone();
	}

	CSharedByteVector fg_ZeroBytes(umint _nBytes)
	{
		CIOByteVector Data;
		Data.f_SetLen(_nBytes);
		NMemory::fg_MemClear(Data.f_GetArray(), Data.f_GetLen());
		return CSharedByteVector(fg_Move(Data));
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
		constexpr umint c_nMaxUnhandledReceiveBytes = 256 * 1024;
		constexpr umint c_nChunkBytes = 1024 * 1024;
		constexpr umint c_nChunks = 32;

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

		TCActorInterface<CAsyncSocketActor> AdoptedSocket = co_await Adopted.f_Accept(fg_PeerCallbacks(pAdoptedState, c_nMaxUnhandledReceiveBytes));
		TCActorInterface<CAsyncSocketActor> ServerSocket = co_await Accepted.f_Accept(fg_PeerCallbacks(pServerState, 0));

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
			DMibTestPath("Receive Future Stops Reading");

			pAdoptedState->m_bHoldReceives = true;
			pAdoptedState->m_nReceived = 0;

			CIOByteVector Chunk;
			Chunk.f_SetLen(c_nChunkBytes);
			NMemory::fg_MemClear(Chunk.f_GetArray(), Chunk.f_GetLen());
			CSharedByteVector SharedChunk(fg_Move(Chunk));

			TCFutureVector<void> Sends;
			for (umint iChunk = 0; iChunk < c_nChunks; ++iChunk)
				ServerSocket(&CAsyncSocketActor::f_SendData, fg_TempCopy(SharedChunk), uint32(0)) > Sends;

			// Reading stops once the unresolved receives hold the limit, so what arrives stays within the limit and one delivery
			uint64 nReceived = 0;
			for (umint iStable = 0; iStable < 50;)
			{
				co_await fg_Timeout(0.01);
				if (pAdoptedState->m_nReceived == nReceived)
					++iStable;
				else
				{
					nReceived = pAdoptedState->m_nReceived;
					iStable = 0;
				}
			}

			DMibExpect(nReceived, >=, uint64(c_nMaxUnhandledReceiveBytes));
			DMibExpect(nReceived, <, uint64(2 * c_nMaxUnhandledReceiveBytes + c_nChunkBytes));

			pAdoptedState->m_bHoldReceives = false;
			auto HeldReceives = fg_Move(pAdoptedState->m_HeldReceives);
			for (auto &Promise : HeldReceives)
				Promise.f_SetResult();

			DMibExpectTrue
				(
					co_await fg_WaitUntil
					(
						[pAdoptedState]
						{
							return pAdoptedState->m_nReceived == uint64(c_nChunks * c_nChunkBytes);
						}
					)
				)
			;
			DMibExpect(pAdoptedState->m_nReceived, ==, uint64(c_nChunks * c_nChunkBytes));

			co_await fg_AllDone(Sends).f_Timeout(g_Timeout, "Timed out sending");
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

	DMibTestSuite("Data Before Close") -> TCFuture<void>
	{
		constexpr umint c_nConnections = 20;

		TCActor<CAsyncSocketServerActor> Server = fg_ConstructActor<CAsyncSocketServerActor>();
		auto ServerDestroy = co_await fg_AsyncDestroy(Server);

		TCSharedPointer<TCVector<CAsyncSocketNewServerConnection>> pConnections = fg_Construct();

		CAsyncSocketServerCallbacks ServerCallbacks;
		ServerCallbacks.m_fNewConnection = g_ActorFunctor / [pConnections](CAsyncSocketNewServerConnection _Connection) -> TCFuture<void>
			{
				pConnections->f_Insert(fg_Move(_Connection));
				co_return {};
			}
		;

		// A Unix domain socket that closes reports the end of both directions at once
		CNetAddress Address = CSocket::fs_ResolveAddress("UNIX:" + fg_GetSafeUnixSocketPath("{}/AsyncSocketAdopt.socket"_f << NFile::CFile::fs_GetProgramDirectory()));

		auto Listen = co_await Server(&CAsyncSocketServerActor::f_StartListenAddress, fg_CreateVector(Address), ENetFlag_None, fg_Move(ServerCallbacks), nullptr);

		umint nComplete = 0;
		for (umint iConnection = 0; iConnection < c_nConnections; ++iConnection)
		{
			// The peer writes and closes at once, so its close can be reported before its data
			auto BlockingActorCheckout = fg_BlockingActor();
			co_await
				(
					g_Dispatch(BlockingActorCheckout) / [Address]()
					{
						CSocket Socket;
						Socket.f_Connect(Address, nullptr, g_Timeout);
						Socket.f_Send("last", 4);
						Socket.f_Close();
					}
				)
			;

			if
			(
				!co_await fg_WaitUntil
				(
					[pConnections]
					{
						return !pConnections->f_IsEmpty();
					}
				)
			)
			{
				break;
			}

			CAsyncSocketNewServerConnection Accepted = fg_Move(pConnections->f_GetFirst());
			pConnections->f_Remove(0);

			TCSharedPointer<CPeerState> pState = fg_Construct();
			TCActorInterface<CAsyncSocketActor> Socket = co_await Accepted.f_Accept(fg_PeerCallbacks(pState, 0));

			co_await fg_WaitUntil
				(
					[pState]
					{
						return pState->m_bClosed;
					}
				)
			;
			if (pState->m_Received == "last")
				++nComplete;

			co_await Socket.f_Destroy();
		}

		DMibExpect(nComplete, ==, c_nConnections);

		co_return {};
	};

	DMibTestSuite("Reading Stops Before Accept") -> TCFuture<void>
	{
		constexpr umint c_nChunkBytes = 1024 * 1024;
		constexpr umint c_nChunks = 32;

		TCActor<CAsyncSocketServerActor> Server = fg_ConstructActor<CAsyncSocketServerActor>();
		auto ServerDestroy = co_await fg_AsyncDestroy(Server);

		TCActor<CAsyncSocketClientActor> Client = fg_ConstructActor<CAsyncSocketClientActor>();
		auto ClientDestroy = co_await fg_AsyncDestroy(Client);

		CAsyncSocketAdoptTestPair Pair = co_await fg_ConnectAdopted(Server, Client);

		TCSharedPointer<CPeerState> pAdoptedState = fg_Construct();
		TCSharedPointer<CPeerState> pServerState = fg_Construct();

		TCActorInterface<CAsyncSocketActor> ServerSocket = co_await Pair.m_Accepted.f_Accept(fg_PeerCallbacks(pServerState, 0));

		TCSharedPointer<NAtomic::TCAtomic<umint>> pSent = fg_Construct(0);
		CSharedByteVector Chunk = fg_ZeroBytes(c_nChunkBytes);
		for (umint iChunk = 0; iChunk < c_nChunks; ++iChunk)
		{
			ServerSocket(&CAsyncSocketActor::f_SendData, fg_TempCopy(Chunk), uint32(0)).f_Call().f_OnResultSet
				(
					[pSent](TCAsyncResult<void> &&_Result)
					{
						if (_Result)
							pSent->f_FetchAdd(1);
					}
				)
			;
		}

		// An adopted connection that isn't accepted reads one delivery and leaves the rest to the kernel, which takes less than all the chunks
		umint nSent = 0;
		for (umint iStable = 0; iStable < 50;)
		{
			co_await fg_Timeout(0.01);
			if (pSent->f_Load() == nSent)
				++iStable;
			else
			{
				nSent = pSent->f_Load();
				iStable = 0;
			}
		}

		DMibExpect(nSent, <, c_nChunks);

		TCActorInterface<CAsyncSocketActor> AdoptedSocket = co_await Pair.m_Adopted.f_Accept(fg_PeerCallbacks(pAdoptedState, 0));

		DMibExpectTrue
			(
				co_await fg_WaitUntil
				(
					[pAdoptedState, pSent]
					{
						return pAdoptedState->m_nReceived == uint64(c_nChunks * c_nChunkBytes) && pSent->f_Load() == c_nChunks;
					}
				)
			)
		;
		DMibExpect(pAdoptedState->m_nReceived, ==, uint64(c_nChunks * c_nChunkBytes));

		co_return {};
	};

	DMibTestSuite("Close After Paused Read") -> TCFuture<void>
	{
		constexpr umint c_nMaxUnhandledReceiveBytes = 64 * 1024;
		constexpr umint c_nDeliveryBytes = 4096;

		// Reading pauses at the limit having read less than one delivery past it, so the rest stays unread with the close. All of it has to fit in the
		// kernel's socket buffers before the accept, which are small with the default Linux settings
		constexpr umint c_nBytes = c_nMaxUnhandledReceiveBytes + c_nDeliveryBytes;

		TCActor<CAsyncSocketServerActor> Server = fg_ConstructActor<CAsyncSocketServerActor>();
		auto ServerDestroy = co_await fg_AsyncDestroy(Server);

		TCActor<CAsyncSocketClientActor> Client = fg_ConstructActor<CAsyncSocketClientActor>();
		auto ClientDestroy = co_await fg_AsyncDestroy(Client);

		co_await Client(&CAsyncSocketClientActor::f_SetDefaultFragmentationSize, c_nDeliveryBytes);

		CAsyncSocketAdoptTestPair Pair = co_await fg_ConnectAdopted(Server, Client);

		TCSharedPointer<CPeerState> pAdoptedState = fg_Construct();
		TCSharedPointer<CPeerState> pServerState = fg_Construct();

		TCActorInterface<CAsyncSocketActor> ServerSocket = co_await Pair.m_Accepted.f_Accept(fg_PeerCallbacks(pServerState, 0));

		// The peer's data and its close wait in the kernel until the accept, so the first read after it reaches the limit with the close reported
		co_await ServerSocket(&CAsyncSocketActor::f_SendData, fg_ZeroBytes(c_nBytes), uint32(0)).f_Timeout(g_Timeout, "Timed out sending");

		// The close of the server's socket finishes when the adopted socket closes too
		TCFutureVector<CAsyncSocketActor::CCloseInfo> ServerClose;
		ServerSocket(&CAsyncSocketActor::f_CloseWithLinger, EAsyncSocketStatus_NormalClosure, CStr("Done"), g_Timeout) > ServerClose;

		co_await fg_Timeout(0.2);

		pAdoptedState->m_bHoldReceives = true;
		TCActorInterface<CAsyncSocketActor> AdoptedSocket = co_await Pair.m_Adopted.f_Accept(fg_PeerCallbacks(pAdoptedState, c_nMaxUnhandledReceiveBytes));

		DMibExpectTrue
			(
				co_await fg_ReleaseHeldReceivesUntil
				(
					pAdoptedState
					, [pAdoptedState]
					{
						return pAdoptedState->m_bClosed;
					}
				)
			)
		;
		DMibExpect(pAdoptedState->m_nReceived, ==, uint64(c_nBytes));

		auto ServerCloseResults = co_await fg_AllDoneWrapped(ServerClose).f_Timeout(g_Timeout, "Timed out closing");
		for (auto &CloseResult : ServerCloseResults)
			DMibExpect(CloseResult ? CStr() : CloseResult.f_GetExceptionStr(), ==, "");

		co_return {};
	};

	DMibTestSuite("Local Close While Paused") -> TCFuture<void>
	{
		constexpr umint c_nMaxUnhandledReceiveBytes = 64 * 1024;
		constexpr umint c_nDeliveryBytes = 4096;

		// The deliveries reach the limit, and reading pauses there having read less than one delivery past it, so the rest stays unread in the kernel
		constexpr umint c_nBytes = c_nMaxUnhandledReceiveBytes + c_nDeliveryBytes;

		TCActor<CAsyncSocketServerActor> Server = fg_ConstructActor<CAsyncSocketServerActor>();
		auto ServerDestroy = co_await fg_AsyncDestroy(Server);

		TCActor<CAsyncSocketClientActor> Client = fg_ConstructActor<CAsyncSocketClientActor>();
		auto ClientDestroy = co_await fg_AsyncDestroy(Client);

		co_await Client(&CAsyncSocketClientActor::f_SetDefaultFragmentationSize, c_nDeliveryBytes);

		CAsyncSocketAdoptTestPair Pair = co_await fg_ConnectAdopted(Server, Client);

		TCSharedPointer<CPeerState> pAdoptedState = fg_Construct();
		TCSharedPointer<CPeerState> pServerState = fg_Construct();

		pAdoptedState->m_bHoldReceives = true;
		TCActorInterface<CAsyncSocketActor> AdoptedSocket = co_await Pair.m_Adopted.f_Accept(fg_PeerCallbacks(pAdoptedState, c_nMaxUnhandledReceiveBytes));
		TCActorInterface<CAsyncSocketActor> ServerSocket = co_await Pair.m_Accepted.f_Accept(fg_PeerCallbacks(pServerState, 0));

		TCFuture<void> Send = ServerSocket(&CAsyncSocketActor::f_SendData, fg_ZeroBytes(c_nBytes), uint32(0)).f_Call();
		DMibExpectTrue
			(
				co_await fg_WaitUntil
				(
					[pAdoptedState]
					{
						return pAdoptedState->m_nReceived >= c_nMaxUnhandledReceiveBytes;
					}
				)
			)
		;
		co_await fg_Move(Send).f_Timeout(g_Timeout, "Timed out sending");

		// The handlers still hold their data, so the close must not wait for them to finish
		auto CloseResult = co_await AdoptedSocket(&CAsyncSocketActor::f_CloseWithLinger, EAsyncSocketStatus_NormalClosure, CStr("Done"), 5.0).f_Wrap();
		DMibExpect(CloseResult ? CStr() : CloseResult.f_GetExceptionStr(), ==, "");

		DMibExpectTrue
			(
				co_await fg_ReleaseHeldReceivesUntil
				(
					pAdoptedState
					, [pServerState]
					{
						return pServerState->m_bClosed;
					}
				)
			)
		;

		co_return {};
	};

	DMibTestSuite("Release While Handler Waits") -> TCFuture<void>
	{
		TCActor<CAsyncSocketServerActor> Server = fg_ConstructActor<CAsyncSocketServerActor>();
		auto ServerDestroy = co_await fg_AsyncDestroy(Server);

		TCActor<CAsyncSocketClientActor> Client = fg_ConstructActor<CAsyncSocketClientActor>();
		auto ClientDestroy = co_await fg_AsyncDestroy(Client);

		CAsyncSocketAdoptTestPair Pair = co_await fg_ConnectAdopted(Server, Client);

		TCSharedPointer<CPeerState> pAdoptedState = fg_Construct();
		TCSharedPointer<CPeerState> pServerState = fg_Construct();

		TCActorInterface<CAsyncSocketActor> ServerSocket = co_await Pair.m_Accepted.f_Accept(fg_PeerCallbacks(pServerState, 0));

		{
			CAsyncSocketNewClientConnection Adopted = fg_Move(Pair.m_Adopted);

			pAdoptedState->m_bHoldReceives = true;
			TCActorInterface<CAsyncSocketActor> AdoptedSocket = co_await Adopted.f_Accept(fg_PeerCallbacks(pAdoptedState, 64 * 1024));

			co_await ServerSocket(&CAsyncSocketActor::f_SendData, fg_Bytes("ping"), uint32(0)).f_Timeout(g_Timeout, "Timed out sending");
			DMibExpectTrue
				(
					co_await fg_WaitUntil
					(
						[pAdoptedState]
						{
							return !pAdoptedState->m_HeldReceives.f_IsEmpty();
						}
					)
				)
			;
		}

		// The last reference to the adopted socket is gone, so it closes although its handler still holds the data
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

		auto HeldReceives = fg_Move(pAdoptedState->m_HeldReceives);
		for (auto &Promise : HeldReceives)
			Promise.f_SetResult();

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
		TCActorInterface<CAsyncSocketActor> AdoptedSocket = co_await Adopted->f_Accept(fg_PeerCallbacks(pAdoptedState, 0));

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

	DMibTestSuite("Upgrade Check Factory Throws") -> TCFuture<void>
	{
		TCActor<CAsyncSocketServerActor> Server = fg_ConstructActor<CAsyncSocketServerActor>();
		auto ServerDestroy = co_await fg_AsyncDestroy(Server);

		TCActor<CAsyncSocketClientActor> Client = fg_ConstructActor<CAsyncSocketClientActor>();
		auto ClientDestroy = co_await fg_AsyncDestroy(Client);

		CAsyncSocketServerCallbacks ServerCallbacks;
		ServerCallbacks.m_fNewConnection = g_ActorFunctor / [](CAsyncSocketNewServerConnection _Connection) -> TCFuture<void>
			{
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

		FAsyncSocketUpgradeCheckFactory fCheckUpgradeFactory = []() -> FAsyncSocketUpgradeCheck
			{
				DMibError("Upgrade check factory failed");
			}
		;
		co_await Client(&CAsyncSocketClientActor::f_SetDefaultUpgradeCheckFactory, fCheckUpgradeFactory);

		CInheritedSocketHandle Handle = co_await fg_ConnectHandle(CSocket::fs_ResolveAddress("127.0.0.1:{}"_f << Listen.m_ListenPorts[0]));

		// The adoption fails with the error of the factory instead of ending the process
		auto Adopted = co_await Client(&CAsyncSocketClientActor::f_AdoptConnection, fg_Move(Handle), nullptr).f_Timeout(g_Timeout, "Timed out adopting").f_Wrap();
		DMibAssert(Adopted ? CStr() : Adopted.f_GetExceptionStr(), !=, "");
		DMibExpect(Adopted.f_GetExceptionStr().f_Find("Upgrade check factory failed"), >=, 0);

		co_return {};
	};
}

DMibTestRegister(CAsyncSocketAdopt_Tests, Malterlib::Network);
