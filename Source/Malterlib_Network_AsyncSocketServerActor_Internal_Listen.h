// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include <Mib/Concurrency/ConcurrencyDefines>
#include <Mib/Concurrency/WeakActor>

#include "Malterlib_Network_AsyncSocket.h"

namespace NMib::NNetwork::NAsyncSocket
{
	class CListenActor : public NConcurrency::CActor
	{
	public:
		CListenActor
			(
				NConcurrency::TCActor<CAsyncSocketServerActor> const &_Server
				, umint _MaxMesageSize
				, umint _FragmentationSize
				, fp64 _Timeout
				, NStorage::TCSharedPointer<FAsyncSocketUpgradeCheckFactory> const &_pCheckUpgradeFactory
				, umint _ListenID
			)
		;
		~CListenActor();

		void f_SetSocket(NStorage::TCUniquePointer<NNetwork::ICSocket> _pSocket);
		void f_StateAdded(NNetwork::ENetTCPState _StateAdded);

	private:
		NConcurrency::TCFuture<void> fp_Destroy();
		void fp_ProcessState();

	private:
		fp64 mp_Timeout;
		NStorage::TCUniquePointer<NNetwork::ICSocket> mp_pSocket;
		NConcurrency::TCWeakActor<CAsyncSocketServerActor> mp_Server;
		umint mp_MaxMessageSize;
		umint mp_FragmentationSize;
		NStorage::TCSharedPointer<FAsyncSocketUpgradeCheckFactory> mp_pCheckUpgradeFactory;
		umint mp_ListenID;
	};
}
