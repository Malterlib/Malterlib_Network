// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Concurrency/ConcurrencyManager>

#include "Malterlib_Network_AsyncSocket.h"
#include "Malterlib_Network_AsyncSocketServerActor_Internal_Listen.h"

namespace NMib::NNetwork
{
	struct CAsyncSocketServerActor::CInternal
	{
		struct CListen
		{
			NConcurrency::TCActorFunctor<NConcurrency::TCFuture<void> (CAsyncSocketNewServerConnection _NewConnection)> m_fOnNewConnection;
			NConcurrency::TCActorFunctor<NConcurrency::TCFuture<void> (CAsyncSocketActor::CConnectionInfo _ConnectionInfo)> m_fOnFailedConnection;
			NContainer::TCVector<NConcurrency::TCActor<NAsyncSocket::CListenActor>> m_ListenSockets;
		};

		CInternal(CAsyncSocketServerActor *_pThis);

		NContainer::TCMap<umint, CListen> m_Listens;

		CAsyncSocketServerActor *m_pThis;
		NStorage::TCSharedPointer<FAsyncSocketUpgradeCheckFactory> m_pCheckUpgradeFactory;
		fp64 m_Timeout;
		umint m_MaxMessageSize;
		umint m_FragmentationSize;
		umint m_SendWindowBytes;
		umint m_ListenID = 0;
	};
}
