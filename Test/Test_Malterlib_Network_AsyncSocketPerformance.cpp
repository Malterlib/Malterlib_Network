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

	struct CBenchState
	{
		CBenchState(TCSharedPointer<CDefaultRunLoop> const &_pRunLoop, bool _bEcho)
			: m_pRunLoop(_pRunLoop)
			, m_bEcho(_bEcho)
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

		// Detach the promise under lock and resolve outside it: inline resumption can install another promise before this frame returns.
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

		// Accept can deliver data before assigning the connection; wait for that assignment before replying.
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

		TCFuture<void> f_WaitClientReceived(uint64 _TargetBytes)
		{
			// Resolve after unlocking because waiters can resume inline and reenter this state.
			TCUniquePointer<TCPromise<void>> pPromise = fg_Construct();
			TCFuture<void> Future = pPromise->f_Future();

			{
				DMibLock(m_Lock);
				DMibCheck(!m_pClientWaitPromise);

				m_ClientWaitTargetBytes = _TargetBytes;

				// Already-arrived data still needs a ready promise; a default future has no awaitable state.
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
		uint64 m_nServerPayloadBytes = 0; // That are left of what the last control message said would follow it
		TCVector<uint8> m_ServerControl; // The bytes of a control message that have been received so far
		bool m_bServerLostTrack = false; // What was received where a control message should be was not one

		TCActor<CAsyncSocketServerActor> m_ServerActor;
		CActorSubscription m_ListenSubscription;
		TCActorInterface<CAsyncSocketActor> m_ServerConnection;

		TCActor<CAsyncSocketClientActor> m_ClientActor;
		TCActorInterface<CAsyncSocketActor> m_ClientSocket;
		TCVector<TCUniquePointer<TCPromise<void>>> m_ServerConnectionWaiters; // Resolved after accept assigns m_ServerConnection.

		uint64 m_nClientReceivedBytes = 0;
		uint64 m_ClientWaitTargetBytes = 0;
		TCUniquePointer<TCPromise<void>> m_pClientWaitPromise;
	};

	// Host callbacks on a pool actor; the ambient test actor is not in a pool.
	template <EPriority t_Priority>
	struct TCBenchHandlerActor : public CActor
	{
		static constexpr EPriority mc_Priority = t_Priority;
	};

	using CBenchHandlerActor = TCBenchHandlerActor<EPriority_Normal>;
	using CBenchHandlerActorHighCpu = TCBenchHandlerActor<EPriority_NormalHighCPU>;

	// Control wire format: eight magic bytes, then expected payload bytes; acknowledgement is an eight-byte count.
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

	CSharedByteVector fg_BenchAck()
	{
		CIOByteVector Ack;
		Ack.f_SetLen(8);
		NMemory::fg_ObjectSet(Ack.f_GetArray(), (uint8)0xA5, 8);

		return CSharedByteVector(fg_Move(Ack));
	}

	// Download wire format: eight magic bytes, then the fields of CBenchDownload in their order. The server answers with the chunks.
	// What is received is a stream of bytes, where a control message is followed by the payload bytes that it says.
	constexpr uint64 gc_BenchDownloadMagic = 0x6E776F446269424Dull; // "MBibDown"
	constexpr uint32 gc_BenchMaxDownloadChunkSize = 64 * 1024 * 1024;
	constexpr uint32 gc_BenchMaxPipelineLength = 1024;

	struct CBenchDownload
	{
		uint64 m_nChunks = 0;
		uint64 m_SendWindow = 0; // 0 keeps the one that the socket has
		uint32 m_ChunkSize = 0;
		uint32 m_PipelineLength = 0;
	};

	constexpr umint gc_BenchDownloadBytes = sizeof(uint64) + sizeof(CBenchDownload);

	CSharedByteVector fg_BenchDownloadMessage(CBenchDownload const &_Download)
	{
		CIOByteVector Message;
		Message.f_SetLen(gc_BenchDownloadBytes);

		uint64 Magic = gc_BenchDownloadMagic;
		NMemory::fg_ObjectCopy(Message.f_GetArray(), (uint8 const *)&Magic, sizeof(Magic));
		NMemory::fg_ObjectCopy(Message.f_GetArray() + sizeof(Magic), (uint8 const *)&_Download, sizeof(_Download));

		return CSharedByteVector(fg_Move(Message));
	}

	// The request is from the network, so what it asks for is limited to what a benchmark needs
	bool fg_BenchParseDownload(uint8 const *_pData, umint _nBytes, CBenchDownload &o_Download)
	{
		if (_nBytes != gc_BenchDownloadBytes)
			return false;

		uint64 Magic = 0;
		NMemory::fg_ObjectCopy((uint8 *)&Magic, _pData, sizeof(Magic));
		if (Magic != gc_BenchDownloadMagic)
			return false;

		NMemory::fg_ObjectCopy((uint8 *)&o_Download, _pData + sizeof(Magic), sizeof(o_Download));

		o_Download.m_ChunkSize = fg_Clamp(o_Download.m_ChunkSize, uint32(1), gc_BenchMaxDownloadChunkSize);
		o_Download.m_PipelineLength = fg_Clamp(o_Download.m_PipelineLength, uint32(1), gc_BenchMaxPipelineLength);

		return true;
	}

	enum class EBenchSender
	{
		mc_Client
		, mc_Server
	};

	// The connection of the server is assigned by accept, so it is used under the lock
	TCFuture<void> fg_BenchSendChunk(CBenchState &_State, EBenchSender _Sender, CSharedByteVector const &_Chunk)
	{
		if (_Sender == EBenchSender::mc_Client)
			return _State.m_ClientSocket(&CAsyncSocketActor::f_SendData, fg_TempCopy(_Chunk), 0);

		DMibLock(_State.m_Lock);

		return _State.m_ServerConnection(&CAsyncSocketActor::f_SendData, fg_TempCopy(_Chunk), 0);
	}

	// Keeps _PipelineLength sends outstanding, to avoid measuring per-chunk idle gaps.
	TCFuture<void> fg_BenchSendChunks
		(
			TCSharedPointerSupportWeak<CBenchState> _pState
			, EBenchSender _Sender
			, CSharedByteVector _Chunk
			, uint64 _nChunks
			, umint _PipelineLength
		)
	{
		uint64 nQueued = 0;

		TCVector<TCFuture<void>> InFlight;
		while (nQueued < _nChunks && InFlight.f_GetLen() < _PipelineLength)
		{
			InFlight.f_InsertLast(fg_BenchSendChunk(*_pState, _Sender, _Chunk));
			++nQueued;
		}

		for (uint64 iChunk = 0; iChunk < _nChunks; ++iChunk)
		{
			umint iSlot = umint(iChunk % InFlight.f_GetLen());
			co_await fg_Move(InFlight[iSlot]);

			if (nQueued < _nChunks)
			{
				InFlight[iSlot] = fg_BenchSendChunk(*_pState, _Sender, _Chunk);
				++nQueued;
			}
		}

		co_return {};
	}

	CSharedByteVector fg_BenchChunk(uint32 _ChunkSize)
	{
		CIOByteVector ChunkData;
		ChunkData.f_SetLen(_ChunkSize);
		NMemory::fg_ObjectSet(ChunkData.f_GetArray(), (uint8)0x3C, _ChunkSize);

		return CSharedByteVector(fg_Move(ChunkData));
	}

	struct CBenchReceived
	{
		umint m_nAcks = 0;
		TCVector<CBenchDownload> m_Downloads;
	};

	// Takes what the server received, which is control messages and the payload that follows them, in pieces of any size.
	// Called with the lock of the state.
	CBenchReceived fg_BenchServerReceive(CBenchState &_State, uint8 const *_pData, umint _nBytes)
	{
		CBenchReceived Received;

		while (_nBytes && !_State.m_bServerLostTrack)
		{
			if (_State.m_nServerPayloadBytes)
			{
				umint nPayload = umint(fg_Min(uint64(_nBytes), _State.m_nServerPayloadBytes));

				_pData += nPayload;
				_nBytes -= nPayload;
				_State.m_nServerPayloadBytes -= nPayload;

				if (!_State.m_nServerPayloadBytes)
					++Received.m_nAcks;

				continue;
			}

			auto &Control = _State.m_ServerControl;

			// The magic says how long the message is
			umint nWanted = sizeof(uint64);
			if (Control.f_GetLen() >= sizeof(uint64))
			{
				uint64 Magic = 0;
				NMemory::fg_ObjectCopy((uint8 *)&Magic, Control.f_GetArray(), sizeof(Magic));

				if (Magic == gc_BenchControlMagic)
					nWanted = gc_BenchControlBytes;
				else if (Magic == gc_BenchDownloadMagic)
					nWanted = gc_BenchDownloadBytes;
				else
				{
					_State.m_bServerLostTrack = true;
					break;
				}
			}

			umint nControl = fg_Min(_nBytes, nWanted - Control.f_GetLen());
			Control.f_Insert(_pData, nControl);

			_pData += nControl;
			_nBytes -= nControl;

			if (Control.f_GetLen() < nWanted || nWanted == sizeof(uint64))
				continue;

			uint64 AckTargetBytes = 0;
			CBenchDownload Download;

			if (fg_BenchParseControl(Control.f_GetArray(), Control.f_GetLen(), AckTargetBytes))
			{
				_State.m_nServerPayloadBytes = AckTargetBytes;
				if (!AckTargetBytes)
					++Received.m_nAcks;
			}
			else if (fg_BenchParseDownload(Control.f_GetArray(), Control.f_GetLen(), Download))
				Received.m_Downloads.f_Insert(Download);

			Control.f_Clear();
		}

		return Received;
	}

	constexpr umint gc_BenchLocalFragmentationSize = 1024 * 1024 + 4096; // Local frames reduce per-frame overhead; remote frames retain the interleaving bound.
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

		if (_ListenAddress.f_GetType() == ENetAddressType_Unix || fg_IsLoopbackAddress(_ListenAddress))
			_pState->m_ServerActor(&CAsyncSocketServerActor::f_SetDefaultFragmentationSize, gc_BenchLocalFragmentationSize).f_DiscardResult();

		CAsyncSocketServerCallbacks ListenCallbacks;

		// Bind callbacks to the handler actor; the remote server parks the ambient test thread without pumping it.
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

						CBenchReceived Received;
						TCFutureVector<void> Sends;
						{
							DMibLock(pState->m_Lock);

							if (pState->m_bEcho)
							{
								pState->m_ServerConnection(&CAsyncSocketActor::f_SendData, fg_Move(_Data), 0).f_DiscardResult();
								co_return {};
							}

							bool bLostTrack = pState->m_bServerLostTrack;
							Received = fg_BenchServerReceive(*pState, _Data.f_GetArray(), _Data.f_GetLen());

							if (pState->m_bServerLostTrack && !bLostTrack)
								NSys::fg_ConsoleOutput(CStr("What was received is not from this benchmark, and what follows it is not answered\n"));

							for (umint iAck = 0; iAck < Received.m_nAcks; ++iAck)
								pState->m_ServerConnection(&CAsyncSocketActor::f_SendData, fg_BenchAck(), 0).f_DiscardResult();

							for (auto &Download : Received.m_Downloads)
							{
								if (Download.m_SendWindow)
									pState->m_ServerConnection(&CAsyncSocketActor::f_SetSendWindow, umint(Download.m_SendWindow)) > Sends;
							}
						}

						if (!Sends.f_IsEmpty())
							co_await fg_AllDone(Sends);

						// The socket waits for this function before it goes on, so the chunks are sent after it
						for (auto &Download : Received.m_Downloads)
						{
							fg_BenchSendChunks(pState, EBenchSender::mc_Server, fg_BenchChunk(Download.m_ChunkSize), Download.m_nChunks, Download.m_PipelineLength)
								> [](TCAsyncResult<void> &&_Result)
								{
									if (!_Result)
										NSys::fg_ConsoleOutput(CStr("Failed to send what was asked for: {}\n"_f << _Result.f_GetExceptionStr()));
								}
							;
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

					// Resolve outside the lock because resumed receive handling reacquires it.
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

		CNetAddress ResolvedAddress = CSocket::fs_ResolveAddress(_ConnectAddress);
		if (ResolvedAddress.f_GetType() == ENetAddressType_Unix || fg_IsLoopbackAddress(ResolvedAddress))
			_pState->m_ClientActor(&CAsyncSocketClientActor::f_SetDefaultFragmentationSize, gc_BenchLocalFragmentationSize).f_DiscardResult();

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

		CStr ConnectAddress = _Address;
		if (_Address.f_EndsWith(":0") && ListenPort != 0)
			ConnectAddress = "{}{}"_f << _Address.f_Left(_Address.f_GetLen() - 1) << ListenPort;

		fg_SetupClient(_RunLoopHelper, _pState, ConnectAddress, _ClientFactory, _HandlerActor);
	}

	// Coroutine-driven timing measures actor scheduling; priority controls whether the socket hop crosses pools.
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
			uint64 nChunks = (_nBytes + ChunkSize - 1) / ChunkSize;

			// The server finds the next control message after the bytes that this one says
			_pState->m_ClientSocket(&CAsyncSocketActor::f_SendData, fg_BenchControlMessage(nChunks * ChunkSize), 0).f_DiscardResult();

			uint64 AckTargetBytes = 0;
			{
				DMibLock(_pState->m_Lock);
				AckTargetBytes = _pState->m_nClientReceivedBytes + 8;
			}

			umint PipelineLength = fg_GetSys()->f_GetEnvironmentVariable("PipelineLength").f_ToInt(umint(16));

			co_await fg_BenchSendChunks(_pState, EBenchSender::mc_Client, fg_Move(_Chunk), nChunks, PipelineLength);

			co_await _pState->f_WaitClientReceived(AckTargetBytes);

			co_return {};
		}

		// The server sends and the client receives, which is the other direction on the same connection
		TCFuture<void> f_RunDownload(TCSharedPointerSupportWeak<CBenchState> _pState, uint32 _ChunkSize, uint64 _nBytes)
		{
			CBenchDownload Download;
			Download.m_ChunkSize = _ChunkSize;
			Download.m_nChunks = (_nBytes + _ChunkSize - 1) / _ChunkSize;
			Download.m_PipelineLength = fg_GetSys()->f_GetEnvironmentVariable("PipelineLength").f_ToInt(uint32(16));
			Download.m_SendWindow = fg_GetSys()->f_GetEnvironmentVariable("SendWindow").f_ToInt(uint64(0));

			uint64 TargetBytes = 0;
			{
				DMibLock(_pState->m_Lock);
				TargetBytes = _pState->m_nClientReceivedBytes + Download.m_nChunks * _ChunkSize;
			}

			_pState->m_ClientSocket(&CAsyncSocketActor::f_SendData, fg_BenchDownloadMessage(Download), 0).f_DiscardResult();

			co_await _pState->f_WaitClientReceived(TargetBytes);

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
		TCSharedPointerSupportWeak<CBenchState> pState = fg_Construct(_RunLoopHelper.m_pRunLoop, true);
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

		// Allocate once outside timing so throughput excludes payload creation.
		CSharedByteVector Chunk = fg_BenchChunk(_ChunkSize);

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

	void fg_MeasureDownload
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

		Driver(&CBenchDriverActor::f_RunDownload, _pState, _ChunkSize, uint64(_ChunkSize))
			.f_CallSync(_RunLoopHelper.m_pRunLoop, _CallTimeout)
		;

		CTestPerformanceMeasure Time(_MeasureName);
		for (umint iRepetition = 0; iRepetition < _nRepetitions; ++iRepetition)
		{
			Time.f_Start();
			Driver(&CBenchDriverActor::f_RunDownload, _pState, _ChunkSize, _nTransferBytes)
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

		static bool fs_BenchSchemeEnabled(CStr const &_Tag)
		{
			CStr Schemes = fg_GetSys()->f_GetEnvironmentVariable("BenchSchemes");
			if (Schemes.f_IsEmpty())
				return true;

			return ("," + Schemes + ",").f_Find("," + _Tag + ",") >= 0;
		}

		template <typename tf_FMeasure>
		static void fs_MeasureTransports(CStr const &_SuiteTag, CTestPerformance &_PerfTest, tf_FMeasure const &_fMeasure)
		{
			CStr RootDirectory = NFile::CFile::fs_GetProgramDirectory() / ("AsyncSocketPerf_{}"_f << _SuiteTag);
			fg_TestAddCleanupPath(RootDirectory);

			auto fAddress = [&](CStr const &_Tag)
				{
					return "UNIX:" + fg_GetSafeUnixSocketPath("{}/{}_{}.socket"_f << RootDirectory << _SuiteTag << _Tag);
				}
			;

			if (fs_BenchSchemeEnabled("unix"))
				_fMeasure("unix", fAddress("unix"), FVirtualSocketFactory(), FVirtualSocketFactory());

			if (fs_BenchSchemeEnabled("tcp"))
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

			if (fs_BenchSchemeEnabled("tls"))
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
						"Ping"
						, PerfTest
						, [&](CStr const &_Tag, CStr const &_Address, FVirtualSocketFactory const &_ServerFactory, FVirtualSocketFactory const &_ClientFactory)
						{
							DMibTestPath(_Tag);

							fg_MeasurePing<CBenchDriverActor, CBenchHandlerActor>
								(
									RunLoopHelper
									, PerfTest
									, "Ping_{}"_f << _Tag
									, _Address
									, _ServerFactory
									, _ClientFactory
									, mc_nPingRoundTrips
									, mc_nRepetitions
								)
							;

							fg_MeasurePing<CBenchDriverActorHighCpu, CBenchHandlerActorHighCpu>
								(
									RunLoopHelper
									, PerfTest
									, "PingHigh_{}"_f << _Tag
									, _Address
									, _ServerFactory
									, _ClientFactory
									, mc_nPingRoundTrips
									, mc_nRepetitions
								)
							;
						}
					)
				;
			};

			DMibTestSuite(CTestCategory("AsyncSocketThroughput") << CTestGroup("Performance"))
			{
				CActorRunLoopTestHelper RunLoopHelper;

				CTestPerformance PerfTest(0.015);

				uint32 ChunkSize = fg_GetSys()->f_GetEnvironmentVariable("ChunkSize").f_ToInt(mc_ChunkSize);
				uint64 TransferBytes = fg_GetSys()->f_GetEnvironmentVariable("TransferBytes").f_ToInt(mc_nTransferBytes);

				fs_MeasureTransports
					(
						"Thr"
						, PerfTest
						, [&](CStr const &_Tag, CStr const &_Address, FVirtualSocketFactory const &_ServerFactory, FVirtualSocketFactory const &_ClientFactory)
						{
							DMibTestPath(_Tag);

							TCSharedPointerSupportWeak<CBenchState> pState = fg_Construct(RunLoopHelper.m_pRunLoop, false);
							fg_SetupConnection(RunLoopHelper, pState, _Address, _ServerFactory, _ClientFactory, fg_ConstructActor<CBenchHandlerActor>());

							fg_MeasureUpload(RunLoopHelper, PerfTest, pState, "Thr_{}"_f << _Tag, TransferBytes, ChunkSize, mc_nRepetitions, g_Timeout);
							fg_MeasureDownload(RunLoopHelper, PerfTest, pState, "ThrDown_{}"_f << _Tag, TransferBytes, ChunkSize, mc_nRepetitions, g_Timeout);
						}
					)
				;
			};

			DMibTestSuite(CTestCategory("AsyncSocketRemoteServe") << CTestGroup("Manual"))
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

					TCSharedPointerSupportWeak<CBenchState> pState = fg_Construct(RunLoopHelper.m_pRunLoop, false);

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

			DMibTestSuite(CTestCategory("AsyncSocketRemoteThroughput") << CTestGroup("Manual"))
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

					CStr Direction = fg_GetSys()->f_GetEnvironmentVariable("BenchDirection");
					if (Direction.f_IsEmpty())
						Direction = "upload";

					DMibAssertTrue(Direction == "upload" || Direction == "download");

					CActorRunLoopTestHelper RunLoopHelper;

					CTestPerformance PerfTest(0.015);

					FVirtualSocketFactory ClientFactory;
					if (Scheme == "tls")
					{
						// The per-run self-signed certificate is accepted explicitly by this benchmark client.
						CSSLSettings ClientSettings;
						ClientSettings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_IgnoreVerificationFailures;
						ClientSettings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_IgnoreTrustFailures;
						TCSharedPointer<CSSLContext> pClientContext = fg_Construct(CSSLContext::EType_Client, ClientSettings);
						ClientFactory = CSocket_SSL::fs_GetFactory(pClientContext);
					}

					TCSharedPointerSupportWeak<CBenchState> pState = fg_Construct(RunLoopHelper.m_pRunLoop, false);
					fg_SetupClient(RunLoopHelper, pState, Address, ClientFactory, fg_ConstructActor<CBenchHandlerActor>());

					DMibTestPath("Remote");
					if (Direction == "download")
						fg_MeasureDownload(RunLoopHelper, PerfTest, pState, "ThrRemoteDown_{}"_f << Scheme, TransferBytes, ChunkSize, mc_nRepetitions, CallTimeout);
					else
						fg_MeasureUpload(RunLoopHelper, PerfTest, pState, "ThrRemote_{}"_f << Scheme, TransferBytes, ChunkSize, mc_nRepetitions, CallTimeout);

					DMibExpectTrue(PerfTest);
				}
			};
		}
	};

	DMibTestRegister(CAsyncSocketPerformance_Tests, Malterlib::Network);
}
