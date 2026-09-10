// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Network_ResolveActor_Internal.h"

namespace NMib::NNetwork
{
	using namespace NConcurrency;
	using namespace NStorage;

	namespace
	{
		struct CCaresLibrary
		{
			CCaresLibrary();
			~CCaresLibrary();
		};

		CCaresLibrary::CCaresLibrary()
		{
			int Status = ares_library_init(ARES_LIB_INIT_ALL);
			if (Status != ARES_SUCCESS)
				DMibErrorNet(ares_strerror(Status));
		}

		CCaresLibrary::~CCaresLibrary()
		{
			ares_library_cleanup();
		}

		constinit TCAggregate<CCaresLibrary, 129> g_CaresLibrary = {DAggregateInit};
	}

	CResolveActor::CInternal::CChannel::~CChannel()
	{
		if (m_pChannel)
			ares_destroy(m_pChannel);
	}

	void CResolveActor::CInternal::CDrain::f_Release()
	{
		if (m_Pending.f_FetchSub(1) == 1)
			m_Done.f_SetResult();
	}

	CResolveActor::CInternal::CQuery::CQuery(TCPromise<CAddresses> const &_Result)
		: m_Result(_Result)
	{
	}

	auto CResolveActor::CInternal::fs_CreateChannel(NStr::CStr const &_NameServer) -> TCUniquePointer<CChannel>
	{
		*g_CaresLibrary;

		TCUniquePointer<CChannel> Channel = fg_Construct();
		ares_options Options{};
		Options.sock_state_cb = &fs_SocketState;
		Options.sock_state_cb_data = Channel.f_Get();
		int Status = ares_init_options(&Channel->m_pChannel, &Options, ARES_OPT_SOCK_STATE_CB);
		if (Status != ARES_SUCCESS)
			DMibErrorNet(ares_strerror(Status));

		if (!_NameServer.f_IsEmpty())
		{
			Status = ares_set_servers_ports_csv(Channel->m_pChannel, _NameServer.f_GetStr());
			if (Status != ARES_SUCCESS)
				DMibErrorNet(ares_strerror(Status));
		}

		hostent *pHost = nullptr;
		Status = ares_gethostbyname_file(Channel->m_pChannel, "localhost", AF_INET, &pHost);
		if (pHost)
			ares_free_hostent(pHost);
		if (Status == ARES_ENOMEM)
			DMibErrorNet(ares_strerror(Status));

		return Channel;
	}

	void CResolveActor::CInternal::fs_SocketState(void *_pData, ares_socket_t _Socket, int _Readable, int _Writable) noexcept
	{
		auto *pOwner = static_cast<CChannel *>(_pData)->m_pOwner;
		if (!pOwner)
			return;

		try
		{
			auto Interest = NSys::EIoLoopEvent::mc_None;
			if (_Readable)
				Interest |= NSys::EIoLoopEvent::mc_Read;
			if (_Writable)
				Interest |= NSys::EIoLoopEvent::mc_Write;

			pOwner->f_UpdateSocket(_Socket, Interest);
		}
		catch (...)
		{
			pOwner->m_pFailure = NException::fg_CurrentException();
		}
	}

	void CResolveActor::CInternal::f_UpdateSocket(ares_socket_t _Socket, NSys::EIoLoopEvent _Interest)
	{
		auto *pFound = m_Sockets.f_FindEqual(_Socket);
		if (!pFound && _Interest == NSys::EIoLoopEvent::mc_None)
			return;

		if (!pFound)
		{
			auto &Socket = m_Sockets[_Socket];
			Socket = fg_Construct();
			Socket->m_Handle = _Socket;
			Socket->m_Generation = ++m_NextSocketGeneration;
			Socket->m_Actor = fg_ThisActor(m_pActor).f_Weak();
			Socket->m_pRegistration = m_pLoop->f_Register
				(
					NSys::CIoLoopHandle(_Socket)
					, Socket.f_Get()
					, NSys::EIoLoopEvent::mc_Read | NSys::EIoLoopEvent::mc_Write
					, [](void *_pToken, NSys::EIoLoopEvent _Events, int _Error)
					{
						auto &Socket = *static_cast<CSocket *>(_pToken);
						if (auto Actor = Socket.m_Actor.f_Lock())
							Actor.f_Bind<&CResolveActor::fp_SocketReady>(smint(Socket.m_Handle), Socket.m_Generation, _Events, _Error).f_DiscardResult();
					}
					, false
					, {.m_bReadinessOnly = true, .m_bLevelReadiness = true}
				)
			;

			if (!Socket->m_pRegistration)
				DMibErrorNet("Could not register DNS socket");

			pFound = &Socket;
		}

		(*pFound)->m_Interest = _Interest;
		if ((*pFound)->m_pRegistration)
			m_pLoop->f_RequestReadiness((*pFound)->m_pRegistration, _Interest);
	}

	void CResolveActor::CInternal::fs_CloseSocket(ares_socket_t _Socket, void *_pData) noexcept
	{
		auto &Owner = *static_cast<CChannel *>(_pData)->m_pOwner;
		auto *pFound = Owner.m_Sockets.f_FindEqual(_Socket);
		if (!pFound)
		{
			NSys::NNetwork::fg_CloseSocketHandle(reinterpret_cast<void *>(umint(_Socket)));

			return;
		}

		auto Socket = fg_Move(*pFound);
		Owner.m_Sockets.f_Remove(_Socket);
		if (!Socket->m_pRegistration)
		{
			NSys::NNetwork::fg_CloseSocketHandle(reinterpret_cast<void *>(umint(_Socket)));

			return;
		}

		auto *pRegistration = Socket->m_pRegistration;
		Owner.m_Drain->m_Pending.f_FetchAdd(1);
		Owner.m_pLoop->f_DeregisterAsync
			(
				pRegistration
				, [Socket = fg_Move(Socket), Drain = Owner.m_Drain]
				{
					NSys::NNetwork::fg_CloseSocketHandle(reinterpret_cast<void *>(umint(Socket->m_Handle)));
					Drain->f_Release();
				}
			)
		;
	}

	void CResolveActor::CInternal::fs_Reply(void *_pData, int _Status, int, ares_addrinfo *_pResult) noexcept
	{
		TCUniquePointer<CQuery> Query = fg_Explicit(static_cast<CQuery *>(_pData));
		auto Cleanup = g_OnScopeExit / [_pResult]
			{
				if (_pResult)
					ares_freeaddrinfo(_pResult);
			}
		;

		try
		{
			if (_Status != ARES_SUCCESS)
				DMibErrorNet(ares_strerror(_Status));

			CAddresses Addresses;
			for (auto *pAddress = _pResult->nodes; pAddress; pAddress = pAddress->ai_next)
				Addresses.f_Insert(CNetAddress(NSys::NNetwork::fg_CreateAddressFromNative(pAddress->ai_addr, pAddress->ai_addrlen)));

			if (Addresses.f_IsEmpty())
				DMibErrorNet("Name resolution returned no IP addresses");

			Query->m_Result.f_SetResult(fg_Move(Addresses));
		}
		catch (...)
		{
			Query->m_Result.f_SetException(NException::fg_CurrentException());
		}
	}

	void CResolveActor::CInternal::f_Process(ares_fd_events_t const *_pEvents, umint _Count)
	{
		int Status = ares_process_fds(m_Channel->m_pChannel, _pEvents, _Count, ARES_PROCESS_FLAG_NONE);
		if (Status != ARES_SUCCESS)
			m_pFailure = DMibErrorInstance(ares_strerror(Status));

		if (m_pFailure)
			ares_cancel(m_Channel->m_pChannel);

		for (auto const &Socket : m_Sockets)
			m_pLoop->f_RequestReadiness(Socket->m_pRegistration, Socket->m_Interest);

		f_UpdateTimer();
	}

	void CResolveActor::CInternal::f_UpdateTimer()
	{
		timeval Timeout;
		auto *pTimeout = ares_timeout(m_Channel->m_pChannel, nullptr, &Timeout);
		fp64 Seconds = pTimeout ? fp64(pTimeout->tv_sec) + fp64(pTimeout->tv_usec) / 1000000.0 : -1.0;
		m_pActor->fp_SetTimer(++m_TimerGeneration, Seconds).f_DiscardResult();
	}

	TCFuture<void> CResolveActor::fp_Initialize()
	{
		auto &Internal = *mp_pInternal;
		if (Internal.m_State == CInternal::EState::mc_Ready)
			co_return {};
		if (Internal.m_pFailure)
			co_return Internal.m_pFailure;

		TCPromise<void> Promise;
		Internal.m_InitWaiters.f_Insert(Promise);
		if (Internal.m_State == CInternal::EState::mc_Uninitialized)
		{
			Internal.m_State = CInternal::EState::mc_Initializing;
			auto Sequence = co_await mp_Sequencer.f_Sequence();
			auto BlockingActorCheckout = fg_BlockingActor();
			auto Result = co_await
				(
					g_Dispatch(BlockingActorCheckout) / [NameServer = Internal.m_NameServer, Sequence = fg_Move(Sequence)]
					{
						return CInternal::fs_CreateChannel(NameServer);
					}
				)
				.f_Wrap()
			;

			if (Result)
			{
				Internal.m_Channel = fg_Move(*Result);
				Internal.m_Channel->m_pOwner = &Internal;
				ares_set_socket_close_callback(Internal.m_Channel->m_pChannel, &CInternal::fs_CloseSocket, Internal.m_Channel.f_Get());
				Internal.m_State = CInternal::EState::mc_Ready;
			}
			else
			{
				Internal.m_pFailure = Result.f_GetException();
				Internal.m_State = CInternal::EState::mc_Failed;
			}

			auto Waiters = fg_Move(Internal.m_InitWaiters);
			for (auto &Waiter : Waiters)
			{
				if (Internal.m_pFailure)
					Waiter.f_SetException(Internal.m_pFailure);
				else
					Waiter.f_SetResult();
			}
		}

		co_return co_await Promise.f_Future();
	}

	auto CResolveActor::fp_ResolveHost(uint64 _ID, NStr::CStr _Host, ENetAddressType _PreferType) -> TCFuture<CAddresses>
	{
		if (mp_fHostResolver || !mp_pInternal->m_pLoop || _Host.f_FindChar('%') >= 0)
		{
			co_return co_await fp_Resolve<CAddresses>
				(
					_ID
					, [Host = fg_Move(_Host), _PreferType, fHostResolver = mp_fHostResolver]
					{
						return fHostResolver ? fHostResolver(Host, _PreferType) : CSocket::fs_ResolveHost(Host, _PreferType);
					}
				)
			;
		}

		co_await fp_Initialize();
		if (!mp_Pending.f_FindEqual(_ID))
			co_return DMibErrorInstance("Lookup cancelled");

		auto &Internal = *mp_pInternal;
		if (Internal.m_pFailure)
			co_return Internal.m_pFailure;

		TCPromise<CAddresses> Promise;
		auto Future = Promise.f_Future();
		auto *pQuery = TCUniquePointer<CInternal::CQuery>(fg_Construct(Promise)).f_Detach();
		ares_addrinfo_hints Hints{};
		Hints.ai_family = _PreferType == ENetAddressType_TCPv4 ? AF_INET : _PreferType == ENetAddressType_TCPv6 ? AF_INET6 : AF_UNSPEC;
		Hints.ai_socktype = SOCK_STREAM;
		ares_getaddrinfo(Internal.m_Channel->m_pChannel, _Host.f_GetStr(), nullptr, &Hints, &CInternal::fs_Reply, pQuery);
		if (Internal.m_pFailure)
			ares_cancel(Internal.m_Channel->m_pChannel);
		Internal.f_UpdateTimer();

		auto Result = co_await fg_Move(Future).f_Wrap();
		if (Internal.m_pFailure)
			co_return Internal.m_pFailure;

		co_return Result;
	}

	void CResolveActor::fp_SocketReady(smint _Socket, uint64 _Generation, NSys::EIoLoopEvent _Events, int _Error)
	{
		auto &Internal = *mp_pInternal;
		if (Internal.m_State != CInternal::EState::mc_Ready)
			return;

		auto *pSocket = Internal.m_Sockets.f_FindEqual(ares_socket_t(_Socket));
		if (!pSocket || (*pSocket)->m_Generation != _Generation)
			return;

		ares_fd_events_t Event{};
		Event.fd = ares_socket_t(_Socket);
		auto ReadEvents = NSys::EIoLoopEvent::mc_Read | NSys::EIoLoopEvent::mc_ReadClosed
			| NSys::EIoLoopEvent::mc_WriteClosed | NSys::EIoLoopEvent::mc_Hup | NSys::EIoLoopEvent::mc_Error
		;
		if (_Error || (_Events & ReadEvents) != NSys::EIoLoopEvent::mc_None)
			Event.events |= ARES_FD_EVENT_READ;
		if (fg_IsSet(_Events, NSys::EIoLoopEvent::mc_Write))
			Event.events |= ARES_FD_EVENT_WRITE;

		Internal.f_Process(&Event, 1);
	}

	TCFuture<void> CResolveActor::fp_SetTimer(uint64 _Generation, fp64 _Seconds)
	{
		auto &Internal = *mp_pInternal;
		if (Internal.m_State != CInternal::EState::mc_Ready || _Generation != Internal.m_TimerGeneration)
			co_return {};

		Internal.m_Timer.f_Clear();
		if (_Seconds < 0)
			co_return {};

		auto Timer = co_await fg_OneshotTimerAbortable
			(
				_Seconds
				, [this, _Generation]() -> TCFuture<void>
				{
					if (mp_pInternal->m_State == CInternal::EState::mc_Ready && _Generation == mp_pInternal->m_TimerGeneration)
						mp_pInternal->f_Process(nullptr, 0);

					co_return {};
				}
			)
		;

		if (Internal.m_State == CInternal::EState::mc_Ready && _Generation == Internal.m_TimerGeneration)
			Internal.m_Timer = fg_Move(Timer);

		co_return {};
	}
}
