// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Concurrency/ConcurrencyManager>

#include "Malterlib_Network_AsyncSocket.h"
#include "Malterlib_Network_AsyncSocketServerActor_Internal_Listen.h"

namespace NMib::NNetwork::NAsyncSocket
{
	CListenActor::CListenActor
		(
			NConcurrency::TCActor<CAsyncSocketServerActor> const &_Server
			, umint _MaxMesageSize
			, umint _FragmentationSize
			, fp64 _Timeout
			, NStorage::TCSharedPointer<FAsyncSocketUpgradeCheckFactory> const &_pCheckUpgradeFactory
			, umint _ListenID
		)
		: mp_Timeout(_Timeout)
		, mp_Server(_Server)
		, mp_MaxMessageSize(_MaxMesageSize)
		, mp_FragmentationSize(_FragmentationSize)
		, mp_pCheckUpgradeFactory(_pCheckUpgradeFactory)
		, mp_ListenID(_ListenID)
	{
	}

	CListenActor::~CListenActor()
	{
	}

	void CListenActor::f_SetSocket(NStorage::TCUniquePointer<NNetwork::ICSocket> _pSocket)
	{
		mp_pSocket = fg_Move(_pSocket);
		fp_ProcessState();
	}

	NConcurrency::TCFuture<void> CListenActor::fp_Destroy()
	{
		if (mp_pSocket)
			mp_pSocket.f_Clear();
		co_return {};
	}

	void CListenActor::f_StateAdded(NNetwork::ENetTCPState _StateAdded)
	{
		if (mp_pSocket && mp_pSocket->f_IsValid())
			fp_ProcessState();
	}

	void CListenActor::fp_ProcessState()
	{
		DMibFastCheck(mp_pSocket && mp_pSocket->f_IsValid());
		auto StateAdded = mp_pSocket->f_GetState();
		if (StateAdded & NNetwork::ENetTCPState_Connection)
		{
			while (true)
			{
				// The socket registers with a pool thread's event loop below, so an arriving
				// message is reported on that thread and the actor call it enqueues stays on the
				// local queue there. The actor's own manager, so a server hosted off the global
				// one gets loops whose threads run its pool
				auto Binding = f_ConcurrencyManager().f_PickIoLoopBinding(CAsyncSocketActor::mc_Priority);

				try
				{
					NConcurrency::CIoLoopCreateScope IoLoopScope(Binding);

					FAsyncSocketUpgradeCheck fEmptyCheckUpgrade;

					// The actor's own manager, matching the loop the socket binds to
					NConcurrency::TCActor<CAsyncSocketActor> ConnectionActor = f_ConcurrencyManager().f_ConstructActor(fg_Construct<CAsyncSocketActor>(false, mp_MaxMessageSize, mp_FragmentationSize, mp_Timeout, fg_Move(fEmptyCheckUpgrade)));

					// Seed the scheduler placement to the bound queue so even the first job runs
					// where the loop reports the socket's events; no pinning — every later job
					// keeps the marker fresh and migration under pressure stays free
					if (Binding.m_pLoop)
						ConnectionActor->f_SetInitialQueue(Binding.m_iQueue);
					NConcurrency::TCWeakActor<CAsyncSocketActor> WeakConnectionActor = ConnectionActor;
					NStorage::TCUniquePointer<NNetwork::ICSocket> pAcceptedSocket = mp_pSocket->f_Accept
						(
							[WeakConnectionActor](NNetwork::ENetTCPState _StateAdded)
							{
								auto ConnectionActor = WeakConnectionActor.f_Lock();
								if (ConnectionActor)
									ConnectionActor.f_Bind<&CAsyncSocketActor::fp_StateAdded>(_StateAdded).f_DiscardResult();
							}
						)
					;

					if (!pAcceptedSocket)
						break;

					FAsyncSocketUpgradeCheck fCheckUpgrade;
					if (mp_pCheckUpgradeFactory && *mp_pCheckUpgradeFactory)
						fCheckUpgrade = (*mp_pCheckUpgradeFactory)();

					ConnectionActor.f_Bind<&CAsyncSocketActor::fp_SetSocketAndUpgradeCheck>(fg_Move(pAcceptedSocket), fg_Move(fCheckUpgrade)).f_DiscardResult();

					auto Server = mp_Server.f_Lock();

					if (!Server)
						return;

					Server.f_Bind<&CAsyncSocketServerActor::fp_AddConnection>(fg_Move(ConnectionActor), mp_ListenID).f_DiscardResult();
				}
				catch (NException::CException const &)
				{
				}
			}
		}
	}
}
