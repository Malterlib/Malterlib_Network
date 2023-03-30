// Copyright © 2019 Nonna Holding AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Concurrency/ConcurrencyManager>
#include <Mib/Concurrency/ActorSubscription>

#include "Malterlib_Network_AsyncSocket.h"
#include "Malterlib_Network_AsyncSocketServerActor_Internal.h"
#include "Malterlib_Network_AsyncSocketServerActor_Internal_Listen.h"

#include <Mib/Network/Sockets/TCP>

namespace NMib::NNetwork
{
	using namespace NAsyncSocket;
	CAsyncSocketServerActor::CAsyncSocketServerActor()
		: mp_pInternal(fg_Construct(this))
	{
	}

	CAsyncSocketServerActor::~CAsyncSocketServerActor()
	{
	}

	void CAsyncSocketServerActor::f_SetDefaultMaxMessageSize(mint _MaxMessageSize)
	{
		mp_pInternal->m_MaxMessageSize = _MaxMessageSize;
	}

	void CAsyncSocketServerActor::f_SetDefaultFragmentationSize(mint _FragmentationSize)
	{
		mp_pInternal->m_FragmentationSize = _FragmentationSize;
	}

	void CAsyncSocketServerActor::f_SetDefaultTimeout(fp64 _Timeout)
	{
		mp_pInternal->m_Timeout = _Timeout;
	}

	auto CAsyncSocketServerActor::f_StartListenAddress
		(
			NContainer::TCVector<NNetwork::CNetAddress> &&_AddressesToListenTo
			, NMib::NNetwork::ENetFlag _ListenFlags
			, CAsyncSocketServerCallbacks &&_Callbacks
			, NNetwork::FVirtualSocketFactory &&_SocketFactory
		)
		-> NConcurrency::TCFuture<CListenResult>
	{
		NNetwork::FVirtualSocketFactory SocketFactory = fg_Move(_SocketFactory);
		if (!SocketFactory)
			SocketFactory = NNetwork::CSocket_TCP::fs_GetFactory();

		auto CaptureScope = co_await NConcurrency::g_CaptureExceptions;

		NConcurrency::TCActorResultVector<void> SetSocketResults;
		CListenResult ListenResults;
		{
			auto &Internal = *mp_pInternal;

			auto ListenID = ++Internal.m_ListenID;
			auto &Listen = Internal.m_Listens[ListenID];

			ListenResults.m_Subscription = NConcurrency::g_ActorSubscription / [this, ListenID]() -> NConcurrency::TCFuture<void>
				{
					auto &Internal = *mp_pInternal;
					auto pListen = Internal.m_Listens.f_FindEqual(ListenID);
					if (!pListen)
						co_return {};

					NConcurrency::TCActorResultVector<void> DestroyResults;
					{
						fg_Move(pListen->m_fOnNewConnection).f_Destroy() > DestroyResults.f_AddResult();
						fg_Move(pListen->m_fOnFailedConnection).f_Destroy() > DestroyResults.f_AddResult();
						for (auto &ListenSocket : pListen->m_ListenSockets)
							fg_Move(ListenSocket).f_Destroy() > DestroyResults.f_AddResult();
					}

					Internal.m_Listens.f_Remove(ListenID);
					co_await DestroyResults.f_GetResults();

					co_return {};
				}
			;

			Listen.m_fOnNewConnection = fg_Move(_Callbacks.m_fNewConnection);
			Listen.m_fOnFailedConnection = fg_Move(_Callbacks.m_fFailedConnection);


			mint nListenTo = _AddressesToListenTo.f_GetLen();

			Listen.m_ListenSockets.f_SetLen(nListenTo);

			for (mint i = 0; i < nListenTo; ++i)
			{
				NNetwork::CNetAddress &Address = _AddressesToListenTo[i];

				NConcurrency::TCActor<CListenActor> &ListenActor = Listen.m_ListenSockets[i];
				ListenActor = NConcurrency::fg_ConstructActor<CListenActor>
					(
						fg_ThisActor(this)
						, mp_pInternal->m_MaxMessageSize
						, mp_pInternal->m_FragmentationSize
						, mp_pInternal->m_Timeout
						, ListenID
					)
				;

				NConcurrency::TCWeakActor<CListenActor> WeakListenActor = ListenActor;

				NStorage::TCUniquePointer<NNetwork::ICSocket> pListenSocket = SocketFactory("");
				NException::CDisableExceptionTraceScope DisableExceptionTrace;
				pListenSocket->f_Listen
					(
						Address
						, [WeakListenActor](NNetwork::ENetTCPState _StateAdded)
						{
							auto ListenActor = WeakListenActor.f_Lock();
							if (!ListenActor)
								return;

							ListenActor(&CListenActor::f_StateAdded, _StateAdded) > NConcurrency::fg_DiscardResult();
						}
						, _ListenFlags
					)
				;

				ListenResults.m_ListenPorts.f_Insert(pListenSocket->f_GetListenPort());

				ListenActor(&CListenActor::f_SetSocket, fg_Move(pListenSocket)) > SetSocketResults.f_AddResult();
			}
		}

		co_await (co_await SetSocketResults.f_GetResults() | NConcurrency::g_Unwrap);

		co_return fg_Move(ListenResults);
	}

	auto CAsyncSocketServerActor::f_StartListen
		(
			uint16 _StartListen
			, uint16 _nListen
			, NMib::NNetwork::ENetFlag _ListenFlags
			, CAsyncSocketServerCallbacks &&_Callbacks
			, NNetwork::FVirtualSocketFactory &&_SocketFactory
		)
		-> NConcurrency::TCFuture<CListenResult>
	{
		NContainer::TCVector<NNetwork::CNetAddress> AddressesToListenTo;
		for (mint i = 0; i < _nListen; ++i)
		{
			NNetwork::CNetAddressTCPv4 AnyAddress;
			AnyAddress.m_Port = _StartListen + i;
			NNetwork::CNetAddress Address;
			Address.f_Set(AnyAddress);
			AddressesToListenTo.f_Insert(fg_Move(Address));
		}

		co_return co_await self(&CAsyncSocketServerActor::f_StartListenAddress, fg_Move(AddressesToListenTo), _ListenFlags, fg_Move(_Callbacks), fg_Move(_SocketFactory));
	}

	NConcurrency::TCFuture<void> CAsyncSocketServerActor::fp_Destroy()
	{
		auto &Internal = *mp_pInternal;
		NConcurrency::TCActorResultVector<void> Results;

		for (auto &Listen : Internal.m_Listens)
		{
			fg_Move(Listen.m_fOnNewConnection).f_Destroy() > Results.f_AddResult();
			fg_Move(Listen.m_fOnFailedConnection).f_Destroy() > Results.f_AddResult();

			for (auto &ListenSocket : Listen.m_ListenSockets)
				ListenSocket.f_Destroy() > Results.f_AddResult();
		}

		co_await (co_await Results.f_GetResults() | NConcurrency::g_Unwrap);

		co_return {};
	}

	void CAsyncSocketServerActor::fp_AddConnection(NConcurrency::TCActor<CAsyncSocketActor> &&_Connection, mint _ListenID)
	{
		self / [this, Connection = fg_Move(_Connection), _ListenID]() mutable -> NConcurrency::TCFuture<void>
			{
				auto ConnectionResult = co_await Connection(&CAsyncSocketActor::fp_FinishConnection);
				auto &Internal = *mp_pInternal;

				auto pListen = Internal.m_Listens.f_FindEqual(_ListenID);
				if (!pListen)
					co_return DMibErrorInstance("Listen no longer exists");

				switch (ConnectionResult.m_Result)
				{
				case CAsyncSocketActor::EFinishConnectionResult_Error:
					{
						if (pListen->m_fOnFailedConnection)
							pListen->m_fOnFailedConnection(fg_Move(ConnectionResult.m_ConnectionInfo)) > NConcurrency::fg_DiscardResult();
					}
					break;
				case CAsyncSocketActor::EFinishConnectionResult_Success:
					{
						if (pListen->m_fOnNewConnection)
							pListen->m_fOnNewConnection(CAsyncSocketNewServerConnection(fg_Move(ConnectionResult.m_ConnectionInfo), Connection)) > NConcurrency::fg_DiscardResult();
					}
					break;
				default:
					DMibPDebugBreak;
					break;
				}
				co_return {};
			}
			> NConcurrency::fg_DiscardResult()
		;
	}
}
