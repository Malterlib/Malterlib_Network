// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include <Mib/Core/Core>
#include <Mib/Concurrency/ConcurrencyManager>
#include <Mib/Concurrency/ActorFunctor>
#include <Mib/Concurrency/ActorSubscription>

namespace NMib::NNetwork
{
	NContainer::TCVector<CNetInterfaceAddressIPv4> fg_GetInterfaceAddressesIPv4();
	auto fg_SubscribeInterfaceAddressChangesIPv4(NConcurrency::CActorFunctorCoalesced _fOnChange) -> NConcurrency::TCFuture<NConcurrency::CActorSubscription>;
}
