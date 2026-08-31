// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Core/Core>
#include <Mib/Test/Performance>
#include <Mib/Network/AsyncSocket>
#include <Mib/Network/Sockets/TCP>
#include <Mib/Network/Sockets/SSL>
#include <Mib/Cryptography/Certificate>
#include <Mib/Concurrency/DistributedActorTestHelpers>
#include <Mib/File/File>
#include <Mib/Time/Stopwatch>

using namespace NMib;
using namespace NMib::NNetwork;
using namespace NMib::NTest;
using namespace NMib::NThread;
using namespace NMib::NContainer;
using namespace NMib::NStr;
using namespace NMib::NConcurrency;
using namespace NMib::NStorage;
using namespace NMib::NCryptography;

namespace
{
	fp64 g_Timeout = 60.0 * gc_TimeoutMultiplier;

	// Measures the raw async socket actor pair: a ping over an echoing server for round trip
	// latency and a client to server upload for throughput, over a plain unix socket, plain
	// loopback TCP, and the unix socket under TLS so the comparison mirrors the transport
	// benchmark and covers the send window machinery’s plain TCP path
	struct CBenchState
	{
		CBenchState(TCSharedPointer<CDefaultRunLoop> const &_pRunLoop, bool _bEcho, uint64 _AckTargetBytes)
			: m_pRunLoop(_pRunLoop)
			, m_bEcho(_bEcho)
			, m_AckTargetBytes(_AckTargetBytes)
		{
		}

		~CBenchState()
		{
			TCFutureVector<void> Destroys;
			{
				DMibLock(m_Lock);
				if (m_ClientSocket)
					fg_Move(m_ClientSocket).f_Destroy() > Destroys;
				if (m_ServerConnection)
					fg_Move(m_ServerConnection).f_Destroy() > Destroys;
				if (m_ClientActor)
					fg_Move(m_ClientActor).f_Destroy() > Destroys;
				if (m_ListenSubscription)
				{
					m_ListenSubscription->f_Destroy() > Destroys;
					m_ListenSubscription.f_Clear();
				}
			}
			fg_AllDoneWrapped(Destroys).f_CallSync(m_pRunLoop, g_Timeout);

			if (m_ServerActor)
			{
				m_ServerActor->f_BlockDestroy(m_pRunLoop->f_ActorDestroyLoop());
				m_ServerActor.f_Clear();
			}
		}

		// Resolving a promise can resume the waiting coroutine inline on this thread, and it comes
		// straight back here for the next round trip. m_Lock is recursive, so it would let that
		// re-entrant call install a new promise over a member this frame is still about to clear.
		// Detaching the promise under the lock and resolving it outside keeps the member consistent
		// for whatever the resumption does
		void f_ClientReceived(umint _nBytes)
		{
			TCUniquePointer<TCPromise<void>> pPromise;
			{
				DMibLock(m_Lock);
				m_nClientReceivedBytes += _nBytes;
				if (m_pClientWaitPromise && m_nClientReceivedBytes >= m_ClientWaitTargetBytes)
					pPromise = fg_Move(m_pClientWaitPromise);
			}

			if (pPromise)
				pPromise->f_SetResult();
		}

		// Data is delivered from inside f_Accept, before the accept side has assigned
		// m_ServerConnection. The returned future resolves once it exists, so a receive that lands
		// in that window waits rather than finding a null connection and dropping its reply
		TCFuture<void> f_WaitServerConnection()
		{
			TCUniquePointer<TCPromise<void>> pPromise = fg_Construct();
			TCFuture<void> Future = pPromise->f_Future();

			{
				DMibLock(m_Lock);
				if (!m_ServerConnection)
				{
					m_ServerConnectionWaiters.f_InsertLast(fg_Move(pPromise));
					return Future;
				}
			}

			pPromise->f_SetResult();

			return Future;
		}

		// The returned future resolves once the client has received _TargetBytes in total
		TCFuture<void> f_WaitClientReceived(uint64 _TargetBytes)
		{
			// The promise is built before the lock so the already satisfied case can resolve it
			// after releasing, for the same reason f_ClientReceived detaches before resolving
			TCUniquePointer<TCPromise<void>> pPromise = fg_Construct();
			TCFuture<void> Future = pPromise->f_Future();

			{
				DMibLock(m_Lock);
				DMibCheck(!m_pClientWaitPromise);

				m_ClientWaitTargetBytes = _TargetBytes;

				// The echoed reply can land before the caller gets here. That case resolves the
				// promise rather than returning a default constructed future, which carries no
				// promise data and would dereference null when awaited
				if (m_nClientReceivedBytes < _TargetBytes)
					m_pClientWaitPromise = fg_Move(pPromise);
			}

			if (pPromise)
				pPromise->f_SetResult();

			return Future;
		}

		CIntrusiveRefCountWithWeak m_RefCount;

		CMutual m_Lock;
		TCSharedPointer<CDefaultRunLoop> m_pRunLoop;

		bool m_bEcho = false;
		uint64 m_AckTargetBytes = 0;
		uint64 m_nServerReceivedBytes = 0;

		TCActor<CAsyncSocketServerActor> m_ServerActor;
		CActorSubscription m_ListenSubscription;
		TCActorInterface<CAsyncSocketActor> m_ServerConnection;

		TCActor<CAsyncSocketClientActor> m_ClientActor;
		TCActorInterface<CAsyncSocketActor> m_ClientSocket;

		// Waiters for m_ServerConnection, resolved when the accept side assigns it
		TCVector<TCUniquePointer<TCPromise<void>>> m_ServerConnectionWaiters;

		uint64 m_nClientReceivedBytes = 0;
		uint64 m_ClientWaitTargetBytes = 0;
		TCUniquePointer<TCPromise<void>> m_pClientWaitPromise;
	};

	// The callback host: replies and receive counting run on a pool actor of the chosen
	// priority — never on the ambient test actor, which is in no pool. The normal variant
	// measures the cross pool hop, the high CPU one stays in the socket actors’ pool
	template <EPriority t_Priority>
	struct TCBenchHandlerActor : public CActor
	{
		static constexpr EPriority mc_Priority = t_Priority;
	};

	using CBenchHandlerActor = TCBenchHandlerActor<EPriority_Normal>;
	using CBenchHandlerActorHighCpu = TCBenchHandlerActor<EPriority_NormalHighCPU>;

	// The upload ack target travels in band as a tiny control message, so the loopback and the
	// cross machine suites share one driver and one server callback: eight magic bytes and the
	// payload byte count the server answers with an eight byte ack
	constexpr uint64 gc_BenchControlMagic = 0x68636E654262694Dull; // "MibBench"
	constexpr umint gc_BenchControlBytes = 16;

	CSharedByteVector fg_BenchControlMessage(uint64 _AckTargetBytes)
	{
		CIOByteVector Message;
		Message.f_SetLen(gc_BenchControlBytes);

		uint64 Magic = gc_BenchControlMagic;
		NMemory::fg_ObjectCopy(Message.f_GetArray(), (uint8 const *)&Magic, sizeof(Magic));
		NMemory::fg_ObjectCopy(Message.f_GetArray() + sizeof(Magic), (uint8 const *)&_AckTargetBytes, sizeof(_AckTargetBytes));

		return CSharedByteVector(fg_Move(Message));
	}

	bool fg_BenchParseControl(uint8 const *_pData, umint _nBytes, uint64 &o_AckTargetBytes)
	{
		if (_nBytes != gc_BenchControlBytes)
			return false;

		uint64 Magic = 0;
		NMemory::fg_ObjectCopy((uint8 *)&Magic, _pData, sizeof(Magic));
		if (Magic != gc_BenchControlMagic)
			return false;

		NMemory::fg_ObjectCopy((uint8 *)&o_AckTargetBytes, _pData + sizeof(Magic), sizeof(o_AckTargetBytes));

		return true;
	}

	// The server half on its own, so the cross machine serve side can stand one up without a
	// client in the same process; returns the bound port for listens on an ephemeral one
	template <typename t_CHandler>
	uint16 fg_SetupServer
		(
			CActorRunLoopTestHelper &_RunLoopHelper
			, TCSharedPointerSupportWeak<CBenchState> const &_pState
			, CNetAddress const &_ListenAddress
			, FVirtualSocketFactory const &_ServerFactory
			, TCActor<t_CHandler> const &_HandlerActor
		)
	{
		TCWeakPointer<CBenchState> pStateWeak = _pState;

		_pState->m_ServerActor = fg_ConstructActor<CAsyncSocketServerActor>();
		_pState->m_ServerActor(&CAsyncSocketServerActor::f_SetDefaultFragmentationSize, 1024 * 1024).f_DiscardResult();

		CAsyncSocketServerCallbacks ListenCallbacks;

		// Bound to the handler actor: an unbound functor runs on the ambient test actor, whose
		// thread the cross machine serve parks in a sleep loop instead of pumping the run loop
		ListenCallbacks.m_fNewConnection = g_ActorFunctor(_HandlerActor) / [pStateWeak, _HandlerActor](CAsyncSocketNewServerConnection _ConnectionInfo) -> TCFuture<void>
			{
				CAsyncSocketNewServerConnection ConnectionInfo = fg_Move(_ConnectionInfo);

				CAsyncSocketCallbacks Callbacks;
				auto fOnReceiveData = [pStateWeak](CSharedByteVector _Data) -> TCFuture<void>
					{
						auto pState = pStateWeak.f_Lock();
						if (!pState)
							co_return {};

						co_await pState->f_WaitServerConnection();

						DMibLock(pState->m_Lock);

						uint64 ControlTarget = 0;
						if (fg_BenchParseControl(_Data.f_GetArray(), _Data.f_GetLen(), ControlTarget))
						{
							pState->m_AckTargetBytes = ControlTarget;
							pState->m_nServerReceivedBytes = 0;
							co_return {};
						}

						if (pState->m_bEcho)
						{
							// The received buffer is forwarded by reference; the zero copy send
							// queue keeps it alive until it is back on the wire
							pState->m_ServerConnection(&CAsyncSocketActor::f_SendData, fg_Move(_Data), 0).f_DiscardResult();
							co_return {};
						}

						pState->m_nServerReceivedBytes += _Data.f_GetLen();
						if (pState->m_nServerReceivedBytes >= pState->m_AckTargetBytes && pState->m_ServerConnection)
						{
							pState->m_nServerReceivedBytes -= pState->m_AckTargetBytes;

							CIOByteVector Ack;
							Ack.f_SetLen(8);
							NMemory::fg_ObjectSet(Ack.f_GetArray(), (uint8)0xA5, 8);
							pState->m_ServerConnection(&CAsyncSocketActor::f_SendData, CSharedByteVector(fg_Move(Ack)), 0).f_DiscardResult();
						}

						co_return {};
					}
				;

				Callbacks.m_fOnReceiveData = g_ActorFunctor(_HandlerActor) / fOnReceiveData;

				auto Socket = co_await ConnectionInfo.f_Accept(fg_Move(Callbacks));

				if (auto pState = pStateWeak.f_Lock())
				{
					TCVector<TCUniquePointer<TCPromise<void>>> Waiters;
					{
						DMibLock(pState->m_Lock);
						pState->m_ServerConnection = fg_Move(Socket);
						Waiters = fg_Move(pState->m_ServerConnectionWaiters);
					}

					// Resolved outside the lock: resuming a waiter runs receive handling that takes
					// the same lock again
					for (auto &pWaiter : Waiters)
						pWaiter->f_SetResult();
				}

				co_return {};
			}
		;

		auto ListenResult = _pState->m_ServerActor
			(
				&CAsyncSocketServerActor::f_StartListenAddress
				, fg_CreateVector(_ListenAddress)
				, ENetFlag_None
				, fg_Move(ListenCallbacks)
				, fg_TempCopy(_ServerFactory)
			)
			.f_CallSync(_RunLoopHelper.m_pRunLoop, g_Timeout)
		;
		_pState->m_ListenSubscription = fg_Move(ListenResult.m_Subscription);

		return ListenResult.m_ListenPorts.f_IsEmpty() ? uint16(0) : ListenResult.m_ListenPorts[0];
	}

	// The client half: connect, receive counting, and the send window override
	template <typename t_CHandler>
	void fg_SetupClient
		(
			CActorRunLoopTestHelper &_RunLoopHelper
			, TCSharedPointerSupportWeak<CBenchState> const &_pState
			, CStr const &_ConnectAddress
			, FVirtualSocketFactory const &_ClientFactory
			, TCActor<t_CHandler> const &_HandlerActor
		)
	{
		TCWeakPointer<CBenchState> pStateWeak = _pState;

		_pState->m_ClientActor = fg_ConstructActor<CAsyncSocketClientActor>();
		_pState->m_ClientActor(&CAsyncSocketClientActor::f_SetDefaultFragmentationSize, 1024 * 1024).f_DiscardResult();

		auto NewClientConnection = _pState->m_ClientActor
			(
				&CAsyncSocketClientActor::f_Connect
				, _ConnectAddress
				, ""
				, ENetAddressType_None
				, 0
				, fg_TempCopy(_ClientFactory)
			)
			.f_CallSync(_RunLoopHelper.m_pRunLoop, g_Timeout)
		;

		CAsyncSocketCallbacks ClientCallbacks;
		auto fOnClientReceiveData = [pStateWeak](CSharedByteVector _Data) -> TCFuture<void>
			{
				if (auto pState = pStateWeak.f_Lock())
					pState->f_ClientReceived(_Data.f_GetLen());
				co_return {};
			}
		;

		ClientCallbacks.m_fOnReceiveData = g_ActorFunctor(_HandlerActor) / fOnClientReceiveData;

		_pState->m_ClientSocket = NewClientConnection.f_Accept(fg_Move(ClientCallbacks)).f_CallSync(_RunLoopHelper.m_pRunLoop, g_Timeout);

		// SendWindow=<bytes> raises the adaptive window’s ceiling for the plain schemes, the way
		// the transport benchmark takes it
		if (umint nSendWindow = fg_GetSys()->f_GetEnvironmentVariable("SendWindow").f_ToInt(umint(0)))
			_pState->m_ClientSocket(&CAsyncSocketActor::f_SetSendWindow, nSendWindow).f_CallSync(_RunLoopHelper.m_pRunLoop, g_Timeout);
	}

	template <typename t_CHandler>
	void fg_SetupConnection
		(
			CActorRunLoopTestHelper &_RunLoopHelper
			, TCSharedPointerSupportWeak<CBenchState> const &_pState
			, CStr const &_Address
			, FVirtualSocketFactory const &_ServerFactory
			, FVirtualSocketFactory const &_ClientFactory
			, TCActor<t_CHandler> const &_HandlerActor
		)
	{
		uint16 ListenPort = fg_SetupServer(_RunLoopHelper, _pState, CSocket::fs_ResolveAddress(_Address), _ServerFactory, _HandlerActor);

		// A TCP address listening on port 0 gets its port from the kernel; the client connects
		// to the bound one
		CStr ConnectAddress = _Address;
		if (_Address.f_EndsWith(":0") && ListenPort != 0)
			ConnectAddress = "{}{}"_f << _Address.f_Left(_Address.f_GetLen() - 1) << ListenPort;

		fg_SetupClient(_RunLoopHelper, _pState, ConnectAddress, _ClientFactory, _HandlerActor);
	}

	// Drives the benchmark from a coroutine so each iteration costs actor scheduling, not test
	// thread synchronization. The priority picks the pool the driver runs in: the normal pool
	// hops to the socket actors’ high CPU pool every round trip, the high CPU variant stays
	// inside it
	template <EPriority t_Priority>
	struct TCBenchDriverActor : public CActor
	{
		static constexpr EPriority mc_Priority = t_Priority;

		TCFuture<void> f_RunPing(TCSharedPointerSupportWeak<CBenchState> _pState, umint _nRoundTrips)
		{
			CIOByteVector Ping;
			Ping.f_SetLen(8);
			NMemory::fg_ObjectSet(Ping.f_GetArray(), (uint8)0x5A, 8);
			CSharedByteVector Chunk(fg_Move(Ping));

			uint64 TargetBytes = 0;
			{
				DMibLock(_pState->m_Lock);
				TargetBytes = _pState->m_nClientReceivedBytes;
			}

			for (umint i = 0; i < _nRoundTrips; ++i)
			{
				TargetBytes += 8;
				_pState->m_ClientSocket(&CAsyncSocketActor::f_SendData, fg_TempCopy(Chunk), 0).f_DiscardResult();
				co_await _pState->f_WaitClientReceived(TargetBytes);
			}

			co_return {};
		}

		TCFuture<void> f_RunUpload(TCSharedPointerSupportWeak<CBenchState> _pState, CSharedByteVector _Chunk, uint64 _nBytes)
		{
			umint ChunkSize = _Chunk.f_GetLen();

			// Tells the server how many payload bytes this run covers before any of them are
			// queued; sends on one connection stay ordered
			_pState->m_ClientSocket(&CAsyncSocketActor::f_SendData, fg_BenchControlMessage(_nBytes), 0).f_DiscardResult();

			uint64 AckTargetBytes = 0;
			{
				DMibLock(_pState->m_Lock);
				AckTargetBytes = _pState->m_nClientReceivedBytes + 8;
			}

			// Keep a pipeline of sends in flight so the socket never idles between chunks,
			// mirroring the transport benchmark's pipeline depth
			umint PipelineLength = fg_GetSys()->f_GetEnvironmentVariable("PipelineLength").f_ToInt(umint(16));

			uint64 nChunks = (_nBytes + ChunkSize - 1) / ChunkSize;
			uint64 nQueued = 0;

			TCVector<TCFuture<void>> InFlight;
			while (nQueued < nChunks && InFlight.f_GetLen() < PipelineLength)
			{
				InFlight.f_InsertLast(_pState->m_ClientSocket(&CAsyncSocketActor::f_SendData, fg_TempCopy(_Chunk), 0));
				++nQueued;
			}

			for (uint64 iChunk = 0; iChunk < nChunks; ++iChunk)
			{
				umint iSlot = umint(iChunk % InFlight.f_GetLen());
				co_await fg_Move(InFlight[iSlot]);

				if (nQueued < nChunks)
				{
					InFlight[iSlot] = _pState->m_ClientSocket(&CAsyncSocketActor::f_SendData, fg_TempCopy(_Chunk), 0);
					++nQueued;
				}
			}

			co_await _pState->f_WaitClientReceived(AckTargetBytes);

			co_return {};
		}
	};

	using CBenchDriverActor = TCBenchDriverActor<EPriority_Normal>;
	using CBenchDriverActorHighCpu = TCBenchDriverActor<EPriority_NormalHighCPU>;

	template <typename t_CDriver, typename t_CHandler>
	void fg_MeasurePing
		(
			CActorRunLoopTestHelper &_RunLoopHelper
			, CTestPerformance &_PerfTest
			, CStr const &_Name
			, CStr const &_Address
			, FVirtualSocketFactory const &_ServerFactory
			, FVirtualSocketFactory const &_ClientFactory
			, umint _nPingRoundTrips
			, umint _nRepetitions
		)
	{
		TCSharedPointerSupportWeak<CBenchState> pState = fg_Construct(_RunLoopHelper.m_pRunLoop, true, uint64(0));
		fg_SetupConnection(_RunLoopHelper, pState, _Address, _ServerFactory, _ClientFactory, fg_ConstructActor<t_CHandler>());

		TCActor<t_CDriver> Driver = fg_ConstructActor<t_CDriver>();

		Driver(&t_CDriver::f_RunPing, pState, _nPingRoundTrips / 8)
			.f_CallSync(_RunLoopHelper.m_pRunLoop, g_Timeout)
		;

		CTestPerformanceMeasure Time(_Name);
		for (umint iRepetition = 0; iRepetition < _nRepetitions; ++iRepetition)
		{
			Time.f_Start();
			Driver(&t_CDriver::f_RunPing, pState, _nPingRoundTrips)
				.f_CallSync(_RunLoopHelper.m_pRunLoop, g_Timeout)
			;
			Time.f_Stop(_nPingRoundTrips);
		}
		_PerfTest.f_Add(Time);

		Driver->f_BlockDestroy(_RunLoopHelper.m_pRunLoop->f_ActorDestroyLoop());
	}

	// The measured upload loop on an already connected state, shared by the loopback suites and
	// the cross machine client
	void fg_MeasureUpload
		(
			CActorRunLoopTestHelper &_RunLoopHelper
			, CTestPerformance &_PerfTest
			, TCSharedPointerSupportWeak<CBenchState> const &_pState
			, CStr const &_MeasureName
			, uint64 _nTransferBytes
			, uint32 _ChunkSize
			, umint _nRepetitions
			, fp64 _CallTimeout
		)
	{
		TCActor<CBenchDriverActor> Driver = fg_ConstructActor<CBenchDriverActor>();

		// The chunk is created once outside the measured path and sent by reference every time,
		// so the benchmark measures the transport rather than buffer creation
		CIOByteVector ChunkData;
		ChunkData.f_SetLen(_ChunkSize);
		NMemory::fg_ObjectSet(ChunkData.f_GetArray(), (uint8)0x3C, _ChunkSize);
		CSharedByteVector Chunk(fg_Move(ChunkData));

		Driver(&CBenchDriverActor::f_RunUpload, _pState, Chunk, uint64(_ChunkSize))
			.f_CallSync(_RunLoopHelper.m_pRunLoop, _CallTimeout)
		;

		CTestPerformanceMeasure Time(_MeasureName);
		for (umint iRepetition = 0; iRepetition < _nRepetitions; ++iRepetition)
		{
			Time.f_Start();
			Driver(&CBenchDriverActor::f_RunUpload, _pState, Chunk, _nTransferBytes)
				.f_CallSync(_RunLoopHelper.m_pRunLoop, _CallTimeout)
			;
			Time.f_Stop(_nTransferBytes);
		}
		_PerfTest.f_Add(Time);

		Driver->f_BlockDestroy(_RunLoopHelper.m_pRunLoop->f_ActorDestroyLoop());
	}

	class CAsyncSocketPerformance_Tests : public CTest
	{
#if defined(DMibDebug) || defined(DMibSanitizerEnabled)
		constexpr static uint64 mc_nTransferBytes = 8ull << 20;
		constexpr static umint mc_nPingRoundTrips = 128;
		constexpr static umint mc_nRepetitions = 3;
#else
		constexpr static uint64 mc_nTransferBytes = 8 * (1024ull << 20);
		constexpr static umint mc_nPingRoundTrips = 4 * 16384;
		constexpr static umint mc_nRepetitions = 5;
#endif
		constexpr static uint32 mc_ChunkSize = NFile::gc_IdealIoSize;

		template <typename tf_FMeasure>
		static void fs_MeasureTransports(CTestPerformance &_PerfTest, tf_FMeasure const &_fMeasure)
		{
			CStr RootDirectory = NFile::CFile::fs_GetProgramDirectory() / "AsyncSocketPerf";
			fg_TestAddCleanupPath(RootDirectory);

			auto fAddress = [&](CStr const &_Tag)
				{
					return "UNIX:" + fg_GetSafeUnixSocketPath("{}/AsyncSocketPerf_{}.socket"_f << RootDirectory << _Tag);
				}
			;

			_fMeasure("unix", fAddress("unix"), FVirtualSocketFactory(), FVirtualSocketFactory());

			// Plain TCP over loopback: completion sends with no TLS transport gating ahead — the
			// path the send window ask and the dynamic reservations bound
			_fMeasure("tcp", "127.0.0.1:0", FVirtualSocketFactory(), FVirtualSocketFactory());

			CSSLSettings ServerSettings;
			CCertificateOptions Options;
			Options.m_CommonName = "Malterlib async socket benchmark";
			Options.m_Hostnames = fg_CreateVector<CStr>("localhost");
			Options.m_KeySetting = CPublicKeySettings_EC_secp256r1{};
			CCertificate::fs_GenerateSelfSignedCertAndKey(Options, ServerSettings.m_PublicCertificateData, ServerSettings.m_PrivateKeyData);
			TCSharedPointer<CSSLContext> pServerContext = fg_Construct(CSSLContext::EType_Server, ServerSettings);

			CSSLSettings ClientSettings;
			ClientSettings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_UseSpecificPeerCertificate;
			ClientSettings.m_CACertificateData = ServerSettings.m_PublicCertificateData;
			TCSharedPointer<CSSLContext> pClientContext = fg_Construct(CSSLContext::EType_Client, ClientSettings);

			_fMeasure("tls", fAddress("tls"), CSocket_SSL::fs_GetFactory(pServerContext), CSocket_SSL::fs_GetFactory(pClientContext));

			DMibExpectTrue(_PerfTest);
		}

	public:
		void f_DoTests()
		{
			DMibTestSuite(CTestCategory("AsyncSocketPing") << CTestGroup("Performance"))
			{
				CActorRunLoopTestHelper RunLoopHelper;

				CTestPerformance PerfTest(0.015);

				fs_MeasureTransports
					(
						PerfTest
						, [&](CStr const &_Tag, CStr const &_Address, FVirtualSocketFactory const &_ServerFactory, FVirtualSocketFactory const &_ClientFactory)
						{
							DMibTestPath(_Tag);

							fg_MeasurePing<CBenchDriverActor, CBenchHandlerActor>(RunLoopHelper, PerfTest, "Ping_{}"_f << _Tag, _Address, _ServerFactory, _ClientFactory, mc_nPingRoundTrips, mc_nRepetitions);

							// The high CPU variant keeps the driver and the receive handling in the
							// socket actors’ pool, so a round trip never hops pools
							fg_MeasurePing<CBenchDriverActorHighCpu, CBenchHandlerActorHighCpu>(RunLoopHelper, PerfTest, "PingHigh_{}"_f << _Tag, _Address, _ServerFactory, _ClientFactory, mc_nPingRoundTrips, mc_nRepetitions);
						}
					)
				;
			};

			DMibTestSuite(CTestCategory("AsyncSocketThroughput") << CTestGroup("Performance"))
			{
				CActorRunLoopTestHelper RunLoopHelper;

				CTestPerformance PerfTest(0.015);

				fs_MeasureTransports
					(
						PerfTest
						, [&](CStr const &_Tag, CStr const &_Address, FVirtualSocketFactory const &_ServerFactory, FVirtualSocketFactory const &_ClientFactory)
						{
							DMibTestPath(_Tag);

							TCSharedPointerSupportWeak<CBenchState> pState = fg_Construct(RunLoopHelper.m_pRunLoop, false, uint64(0));
							fg_SetupConnection(RunLoopHelper, pState, _Address, _ServerFactory, _ClientFactory, fg_ConstructActor<CBenchHandlerActor>());

							fg_MeasureUpload(RunLoopHelper, PerfTest, pState, "Thr_{}"_f << _Tag, mc_nTransferBytes, mc_ChunkSize, mc_nRepetitions, g_Timeout);
						}
					)
				;
			};

			// The cross machine pair, mirroring the transport benchmark's remote suites: the
			// same upload benchmark split over two processes on two hosts. The serve side
			// listens on a routable address and writes its connect URL as the ticket; the
			// ticket is carried to the client host, and the client connects from it and runs
			// the same measured loop as the loopback suites — the ticket reading side is the
			// SENDER, so run the client on the machine whose send path is measured. One client
			// at a time. Both sides are quiet no-ops without their required environment.
			//
			//   serve:  BenchHost=<routable address> [BenchPort=39301] [BenchSchemes=tls|tcp]
			//           [BenchTicketFile=<program dir>/AsyncSocketBench.ticket]
			//           [BenchServeSeconds=600]
			//   client: BenchTicketFile=<carried ticket> (or BenchTicket=<url>)
			//           plus TransferBytes/ChunkSize/PipelineLength/SendWindow exactly as the
			//           loopback suites, and [BenchCallTimeout=600] to cover one upload on a
			//           slow link
			DMibTestSuite(CTestCategory("AsyncSocketRemoteServe") << CTestGroup("Performance"))
			{
				CStr Host = fg_GetSys()->f_GetEnvironmentVariable("BenchHost");
				if (!Host.f_IsEmpty())
				{
					CStr Scheme = fg_GetSys()->f_GetEnvironmentVariable("BenchSchemes");
					if (Scheme.f_IsEmpty())
						Scheme = "tls";
					uint32 Port = fg_GetSys()->f_GetEnvironmentVariable("BenchPort").f_ToInt(uint32(39301));
					CStr TicketFile = fg_GetSys()->f_GetEnvironmentVariable("BenchTicketFile");
					if (TicketFile.f_IsEmpty())
						TicketFile = NFile::CFile::fs_GetProgramDirectory() / "AsyncSocketBench.ticket";
					fp64 ServeSeconds = fg_GetSys()->f_GetEnvironmentVariable("BenchServeSeconds").f_ToFloat(fp64(600.0));

					CActorRunLoopTestHelper RunLoopHelper;

					FVirtualSocketFactory ServerFactory;
					if (Scheme == "tls")
					{
						CSSLSettings ServerSettings;
						CCertificateOptions Options;
						Options.m_CommonName = "Malterlib async socket benchmark";
						Options.m_Hostnames = fg_CreateVector<CStr>(Host);
						Options.m_KeySetting = CPublicKeySettings_EC_secp256r1{};
						CCertificate::fs_GenerateSelfSignedCertAndKey(Options, ServerSettings.m_PublicCertificateData, ServerSettings.m_PrivateKeyData);
						TCSharedPointer<CSSLContext> pServerContext = fg_Construct(CSSLContext::EType_Server, ServerSettings);
						ServerFactory = CSocket_SSL::fs_GetFactory(pServerContext);
					}

					TCSharedPointerSupportWeak<CBenchState> pState = fg_Construct(RunLoopHelper.m_pRunLoop, false, uint64(0));

					// Chunk counting is the serve side's hot path, so its receive handling stays
					// in the socket actors' pool
					fg_SetupServer(RunLoopHelper, pState, CSocket::fs_ResolveAddress("{}:{}"_f << Host << Port), ServerFactory, fg_ConstructActor<CBenchHandlerActorHighCpu>());

					CStr TicketString = "{}://{}:{}"_f << Scheme << Host << Port;
					NFile::CFile::fs_WriteStringToFile(TicketFile, TicketString, false);

					NSys::fg_ConsoleOutput(CStr("AsyncSocketRemoteServe: {} for {} seconds, ticket at {}\n"_f << TicketString << ServeSeconds << TicketFile));

					// Removing the ticket file ends the serve early, which is how a driver
					// script releases the server the moment its client is done
					NTime::CStopwatch Serving(true);
					while (Serving.f_GetTime() < ServeSeconds && NFile::CFile::fs_FileExists(TicketFile))
						NSys::fg_Thread_Sleep(0.25);
				}
			};

			DMibTestSuite(CTestCategory("AsyncSocketRemoteThroughput") << CTestGroup("Performance"))
			{
				CStr TicketString = fg_GetSys()->f_GetEnvironmentVariable("BenchTicket");
				CStr TicketFile = fg_GetSys()->f_GetEnvironmentVariable("BenchTicketFile");
				if (TicketString.f_IsEmpty() && !TicketFile.f_IsEmpty())
					TicketString = NFile::CFile::fs_ReadStringFromFile(TicketFile);

				if (!TicketString.f_IsEmpty())
				{
					CStr Scheme = "tcp";
					CStr Address = TicketString;
					if (TicketString.f_StartsWith("tls://"))
					{
						Scheme = "tls";
						Address = TicketString.f_Right(TicketString.f_GetLen() - 6);
					}
					else if (TicketString.f_StartsWith("tcp://"))
						Address = TicketString.f_Right(TicketString.f_GetLen() - 6);

					uint32 ChunkSize = fg_GetSys()->f_GetEnvironmentVariable("ChunkSize").f_ToInt(mc_ChunkSize);
					uint64 TransferBytes = fg_GetSys()->f_GetEnvironmentVariable("TransferBytes").f_ToInt(mc_nTransferBytes);
					fp64 CallTimeout = fg_GetSys()->f_GetEnvironmentVariable("BenchCallTimeout").f_ToFloat(fp64(600.0));

					CActorRunLoopTestHelper RunLoopHelper;

					CTestPerformance PerfTest(0.015);

					FVirtualSocketFactory ClientFactory;
					if (Scheme == "tls")
					{
						// The serve side's certificate is self signed and per run; the client
						// accepts it outright — a benchmark link, with the handshake and record
						// crypto still fully measured
						CSSLSettings ClientSettings;
						ClientSettings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_IgnoreVerificationFailures;
						ClientSettings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_IgnoreTrustFailures;
						TCSharedPointer<CSSLContext> pClientContext = fg_Construct(CSSLContext::EType_Client, ClientSettings);
						ClientFactory = CSocket_SSL::fs_GetFactory(pClientContext);
					}

					TCSharedPointerSupportWeak<CBenchState> pState = fg_Construct(RunLoopHelper.m_pRunLoop, false, uint64(0));
					fg_SetupClient(RunLoopHelper, pState, Address, ClientFactory, fg_ConstructActor<CBenchHandlerActor>());

					DMibTestPath("Remote");
					fg_MeasureUpload(RunLoopHelper, PerfTest, pState, "ThrRemote_{}"_f << Scheme, TransferBytes, ChunkSize, mc_nRepetitions, CallTimeout);

					DMibExpectTrue(PerfTest);
				}
			};
		}
	};

	DMibTestRegister(CAsyncSocketPerformance_Tests, Malterlib::Network);
}
