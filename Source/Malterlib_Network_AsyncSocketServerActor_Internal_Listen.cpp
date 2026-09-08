// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Concurrency/ConcurrencyManager>
#include <Mib/Concurrency/LogError>

#include "Malterlib_Network_AsyncSocket.h"
#include "Malterlib_Network_AsyncSocketServerActor_Internal_Listen.h"

namespace NMib::NNetwork::NAsyncSocket
{
	CListenActor::CListenActor
		(
			NConcurrency::TCActor<CAsyncSocketServerActor> const &_Server
			, umint _MaxMesageSize
			, umint _FragmentationSize
			, umint _SendWindowBytes
			, fp64 _Timeout
			, NStorage::TCSharedPointer<FAsyncSocketUpgradeCheckFactory> const &_pCheckUpgradeFactory
			, umint _ListenID
		)
		: mp_Timeout(_Timeout)
		, mp_Server(_Server)
		, mp_MaxMessageSize(_MaxMesageSize)
		, mp_FragmentationSize(_FragmentationSize)
		, mp_SendWindowBytes(_SendWindowBytes)
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
		{
			// Wait for asynchronous deregistration before listener destruction completes.
			NConcurrency::TCPromise<void> ClosedPromise;
			auto Closed = ClosedPromise.f_Future();

			mp_pSocket->f_CloseAsync
				(
					[ClosedPromise = fg_Move(ClosedPromise)]() mutable
					{
						ClosedPromise.f_SetResult();
					}
				)
			;
			mp_pSocket.f_Clear();

			co_await fg_Move(Closed);
		}

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
				// Bind accepts through the actor's manager so loop and connection lifetimes agree.
				auto Binding = f_ConcurrencyManager().f_PickIoLoopBinding(CAsyncSocketActor::mc_Priority);

				try
				{
					NConcurrency::CIoLoopCreateScope IoLoopScope(Binding);

					FAsyncSocketUpgradeCheck fEmptyCheckUpgrade;

					NConcurrency::TCActor<CAsyncSocketActor> ConnectionActor = f_ConcurrencyManager().f_ConstructActor
						(
							fg_Construct<CAsyncSocketActor>(false, mp_MaxMessageSize, mp_FragmentationSize, mp_SendWindowBytes, mp_Timeout, fg_Move(fEmptyCheckUpgrade))
						)
					;

					// Seed first-job placement on the bound loop queue without pinning later scheduling.
					if (Binding.m_pLoop)
						ConnectionActor->f_SetInitialQueue(Binding.m_iQueue);

					NStorage::TCUniquePointer<NNetwork::ICSocket> pAcceptedSocket = mp_pSocket->f_Accept
						(
							[WeakConnectionActor = ConnectionActor.f_Weak()](NNetwork::ENetTCPState _StateAdded)
							{
								auto ConnectionActor = WeakConnectionActor.f_Lock();
								if (ConnectionActor)
								{
									DMibLogWarningOrDiscardResult
										(
											ConnectionActor.f_Bind<&CAsyncSocketActor::fp_StateAdded>(_StateAdded)
											, "Mib/Network"
											, "Reporting the socket state to the connection actor failed"
										)
									;
								}
							}
						)
					;

					if (!pAcceptedSocket)
						break;

					FAsyncSocketUpgradeCheck fCheckUpgrade;
					if (mp_pCheckUpgradeFactory && *mp_pCheckUpgradeFactory)
						fCheckUpgrade = (*mp_pCheckUpgradeFactory)();

					DMibLogWarningOrDiscardResult
						(
							ConnectionActor.f_Bind<&CAsyncSocketActor::fp_SetSocketAndUpgradeCheck>(fg_Move(pAcceptedSocket), fg_Move(fCheckUpgrade))
							, "Mib/Network"
							, "Handing the accepted socket to the connection actor failed"
						)
					;

					auto Server = mp_Server.f_Lock();

					if (!Server)
						return;

					DMibLogWarningOrDiscardResult
						(
							Server.f_Bind<&CAsyncSocketServerActor::fp_AddConnection>(fg_Move(ConnectionActor), mp_ListenID)
							, "Mib/Network"
							, "Adding the accepted connection to the server failed"
						)
					;
				}
				catch (NException::CException const &_Exception)
				{
					DMibLogWithCategory(Mib/Network, Warning, "Accepting a connection failed: {}", _Exception);
				}
			}
		}
	}
}
