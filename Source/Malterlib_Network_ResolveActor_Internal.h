// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include "Malterlib_Network_ResolveActor.h"
#include <Mib/Concurrency/WeakActor>
#include <Mib/Core/IoLoop>
#include <ares.h>

namespace NMib::NNetwork
{
	struct CResolveActor::CInternal
	{
		enum class EState : umint
		{
			mc_Uninitialized
			, mc_Initializing
			, mc_Ready
			, mc_Failed
			, mc_Stopping
		};

		struct CPreparedAddress
		{
			NSys::NNetwork::CResolveAddressParameters m_Parameters;
			CNetAddress m_Address;
		};

		struct CChannel
		{
			~CChannel();

			ares_channel_t *m_pChannel = nullptr;
			CInternal *m_pOwner = nullptr;
		};

		struct CSocket
		{
			uint64 m_Generation = 0;
			NConcurrency::TCWeakActor<CResolveActor> m_Actor;
			NSys::CIoLoopRegistration *m_pRegistration = nullptr;
			ares_socket_t m_Handle = ARES_SOCKET_BAD;
			NSys::EIoLoopEvent m_Interest = NSys::EIoLoopEvent::mc_None;
		};

		struct CDrain
		{
			void f_Release();

			NAtomic::TCAtomic<umint> m_Pending{1}; // Includes the channel until its destruction has initiated every close.
			NConcurrency::TCPromise<void> m_Done;
		};

		struct CQuery
		{
			CQuery(NConcurrency::TCPromise<CAddresses> const &_Result);

			NConcurrency::TCPromise<CAddresses> m_Result;
		};

		static NStorage::TCUniquePointer<CChannel> fs_CreateChannel(NStr::CStr const &_NameServer);
		static void fs_SocketState(void *_pData, ares_socket_t _Socket, int _Readable, int _Writable) noexcept;
		static void fs_CloseSocket(ares_socket_t _Socket, void *_pData) noexcept;
		static void fs_Reply(void *_pData, int _Status, int _Timeouts, ares_addrinfo *_pResult) noexcept;

		void f_UpdateSocket(ares_socket_t _Socket, NSys::EIoLoopEvent _Interest);
		void f_Process(ares_fd_events_t const *_pEvents, umint _Count);
		void f_UpdateTimer();

		uint64 m_NextSocketGeneration = 0;
		uint64 m_TimerGeneration = 0;
		CResolveActor *m_pActor = nullptr;
		NSys::ICIoLoop *m_pLoop = nullptr;
		NStorage::TCUniquePointer<CChannel> m_Channel;
		NStorage::TCSharedPointer<CDrain> m_Drain = fg_Construct();
		NContainer::TCMap<ares_socket_t, NStorage::TCUniquePointer<CSocket>> m_Sockets;
		NContainer::TCVector<NConcurrency::TCPromise<void>> m_InitWaiters;
		NStr::CStr m_NameServer;
		NException::CExceptionPointer m_pFailure;
		NConcurrency::CActorSubscription m_Timer;
		EState m_State = EState::mc_Uninitialized;
	};
}

#include "Malterlib_Network_ResolveActor_Internal.hpp"
