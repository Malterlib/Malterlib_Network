// Copyright © 2019 Nonna Holding AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Concurrency/ConcurrencyManager>
#include <Mib/Concurrency/ActorCallbackManager>

#include "Malterlib_Network_AsyncSocket.h"
#include "Malterlib_Network_AsyncSocketServerActor_Internal_Listen.h"

namespace NMib::NNetwork
{
	struct CAsyncSocketServerActor::CInternal
	{
		CInternal(CAsyncSocketServerActor *_pThis)
			: m_pThis(_pThis)
			, m_MaxMessageSize(24*1024*1024)
			, m_FragmentationSize(32*1024)
			, m_Timeout(0.0)
		{
		}

	public:

		struct CListen
		{
			NConcurrency::TCActorFunctor<NConcurrency::TCFuture<void> (CAsyncSocketNewServerConnection &&_NewConnection)> m_fOnNewConnection;
			NConcurrency::TCActorFunctor<NConcurrency::TCFuture<void> (CAsyncSocketActor::CConnectionInfo && _ConnectionInfo)> m_fOnFailedConnection;
			NContainer::TCVector<NConcurrency::TCActor<NAsyncSocket::CListenActor>> m_ListenSockets;
		};

		NContainer::TCMap<mint, CListen> m_Listens;

		CAsyncSocketServerActor *m_pThis;
		fp64 m_Timeout;
		mint m_MaxMessageSize;
		mint m_FragmentationSize;
		mint m_ListenID = 0;
	};
}
