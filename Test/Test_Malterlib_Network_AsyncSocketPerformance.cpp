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

	// A callback host on the high CPU pool, so the high variants handle receives where the
	// socket actors already run
	struct CBenchHandlerActor : public CActor
	{
		static constexpr EPriority mc_Priority = EPriority_NormalHighCPU;
	};

	void fg_SetupConnection
		(
			CActorRunLoopTestHelper &_RunLoopHelper
			, TCSharedPointerSupportWeak<CBenchState> const &_pState
			, CStr const &_Address
			, FVirtualSocketFactory const &_ServerFactory
			, FVirtualSocketFactory const &_ClientFactory
			, TCActor<CBenchHandlerActor> const &_HandlerActor
		)
	{
		TCWeakPointer<CBenchState> pStateWeak = _pState;

		CNetAddress ListenAddress = CSocket::fs_ResolveAddress(_Address);

		_pState->m_ServerActor = fg_ConstructActor<CAsyncSocketServerActor>();
		_pState->m_ServerActor(&CAsyncSocketServerActor::f_SetDefaultFragmentationSize, 1024 * 1024).f_DiscardResult();

		CAsyncSocketServerCallbacks ListenCallbacks;
		ListenCallbacks.m_fNewConnection = g_ActorFunctor / [pStateWeak, _HandlerActor](CAsyncSocketNewServerConnection _ConnectionInfo) -> TCFuture<void>
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

				if (_HandlerActor)
					Callbacks.m_fOnReceiveData = g_ActorFunctor(_HandlerActor) / fOnReceiveData;
				else
					Callbacks.m_fOnReceiveData = g_ActorFunctor / fOnReceiveData;

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
				, fg_CreateVector(ListenAddress)
				, ENetFlag_None
				, fg_Move(ListenCallbacks)
				, fg_TempCopy(_ServerFactory)
			)
			.f_CallSync(_RunLoopHelper.m_pRunLoop, g_Timeout)
		;
		_pState->m_ListenSubscription = fg_Move(ListenResult.m_Subscription);

		// A TCP address listening on port 0 gets its port from the kernel; the client connects
		// to the bound one
		CStr ConnectAddress = _Address;
		if (_Address.f_EndsWith(":0") && !ListenResult.m_ListenPorts.f_IsEmpty())
			ConnectAddress = "{}{}"_f << _Address.f_Left(_Address.f_GetLen() - 1) << ListenResult.m_ListenPorts[0];

		_pState->m_ClientActor = fg_ConstructActor<CAsyncSocketClientActor>();
		_pState->m_ClientActor(&CAsyncSocketClientActor::f_SetDefaultFragmentationSize, 1024 * 1024).f_DiscardResult();

		auto NewClientConnection = _pState->m_ClientActor
			(
				&CAsyncSocketClientActor::f_Connect
				, ConnectAddress
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

		if (_HandlerActor)
			ClientCallbacks.m_fOnReceiveData = g_ActorFunctor(_HandlerActor) / fOnClientReceiveData;
		else
			ClientCallbacks.m_fOnReceiveData = g_ActorFunctor / fOnClientReceiveData;

		_pState->m_ClientSocket = NewClientConnection.f_Accept(fg_Move(ClientCallbacks)).f_CallSync(_RunLoopHelper.m_pRunLoop, g_Timeout);

		// SendWindow=<bytes> raises the adaptive window’s ceiling for the plain schemes, the way
		// the transport benchmark takes it
		if (umint nSendWindow = fg_GetSys()->f_GetEnvironmentVariable("SendWindow").f_ToInt(umint(0)))
			_pState->m_ClientSocket(&CAsyncSocketActor::f_SetSendWindow, nSendWindow).f_CallSync(_RunLoopHelper.m_pRunLoop, g_Timeout);
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

			uint64 AckTargetBytes = 0;
			{
				DMibLock(_pState->m_Lock);
				AckTargetBytes = _pState->m_nClientReceivedBytes + 8;
			}

			// Keep a pipeline of sends in flight so the socket never idles between chunks,
			// mirroring the transport benchmark's pipeline depth
			umint PipelineLength = fg_GetSys()->f_GetEnvironmentVariable("PipelineLength").f_ToInt(umint(2));

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

	template <typename t_CDriver>
	void fg_MeasurePing
		(
			CActorRunLoopTestHelper &_RunLoopHelper
			, CTestPerformance &_PerfTest
			, CStr const &_Name
			, CStr const &_Address
			, FVirtualSocketFactory const &_ServerFactory
			, FVirtualSocketFactory const &_ClientFactory
			, TCActor<CBenchHandlerActor> const &_HandlerActor
			, umint _nPingRoundTrips
			, umint _nRepetitions
		)
	{
		TCSharedPointerSupportWeak<CBenchState> pState = fg_Construct(_RunLoopHelper.m_pRunLoop, true, uint64(0));
		fg_SetupConnection(_RunLoopHelper, pState, _Address, _ServerFactory, _ClientFactory, _HandlerActor);

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

							fg_MeasurePing<CBenchDriverActor>(RunLoopHelper, PerfTest, "Ping_{}"_f << _Tag, _Address, _ServerFactory, _ClientFactory, {}, mc_nPingRoundTrips, mc_nRepetitions);

							// The high CPU variant keeps the driver and the receive handling in the
							// socket actors’ pool, so a round trip never hops pools
							fg_MeasurePing<CBenchDriverActorHighCpu>(RunLoopHelper, PerfTest, "PingHigh_{}"_f << _Tag, _Address, _ServerFactory, _ClientFactory, fg_ConstructActor<CBenchHandlerActor>(), mc_nPingRoundTrips, mc_nRepetitions);
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

							TCSharedPointerSupportWeak<CBenchState> pState = fg_Construct(RunLoopHelper.m_pRunLoop, false, mc_nTransferBytes);
							fg_SetupConnection(RunLoopHelper, pState, _Address, _ServerFactory, _ClientFactory, {});

							TCActor<CBenchDriverActor> Driver = fg_ConstructActor<CBenchDriverActor>();

							// The chunk is created once outside the measured path and sent by
							// reference every time, so the benchmark measures the transport
							// rather than buffer creation
							CIOByteVector ChunkData;
							ChunkData.f_SetLen(mc_ChunkSize);
							NMemory::fg_ObjectSet(ChunkData.f_GetArray(), (uint8)0x3C, mc_ChunkSize);
							CSharedByteVector Chunk(fg_Move(ChunkData));

							{
								DMibLock(pState->m_Lock);
								pState->m_AckTargetBytes = uint64(mc_ChunkSize);
							}
							Driver(&CBenchDriverActor::f_RunUpload, pState, Chunk, uint64(mc_ChunkSize))
								.f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout)
							;

							{
								DMibLock(pState->m_Lock);
								pState->m_AckTargetBytes = mc_nTransferBytes;
							}

							CTestPerformanceMeasure Time("Thr_{}"_f << _Tag);
							for (umint iRepetition = 0; iRepetition < mc_nRepetitions; ++iRepetition)
							{
								Time.f_Start();
								Driver(&CBenchDriverActor::f_RunUpload, pState, Chunk, mc_nTransferBytes)
									.f_CallSync(RunLoopHelper.m_pRunLoop, g_Timeout)
								;
								Time.f_Stop(mc_nTransferBytes);
							}
							PerfTest.f_Add(Time);

							Driver->f_BlockDestroy(RunLoopHelper.m_pRunLoop->f_ActorDestroyLoop());
						}
					)
				;
			};
		}
	};

	DMibTestRegister(CAsyncSocketPerformance_Tests, Malterlib::Network);
}
