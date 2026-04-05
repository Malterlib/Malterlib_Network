// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include "Malterlib_Network.h"
#include <Mib/Concurrency/ConcurrencyManager>

namespace NMib::NNetwork
{
	class CResolveActor : public NConcurrency::CActor
	{
	public:
		NConcurrency::TCFuture<NMib::NNetwork::CNetAddress> f_Resolve(NStr::CStr _Address, NNetwork::ENetAddressType _PreferType);

	private:
		NContainer::TCLinkedList<NNetwork::CAsyncResolver> mp_PendingResolves;
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
