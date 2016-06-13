#pragma once

#include "Malterlib_Network.h"
#include <Mib/Concurrency/ConcurrencyManager>

namespace NMib
{
	namespace NNet
	{
		class CResolveActor : public NConcurrency::CActor
		{
		public:
			NConcurrency::TCContinuation<NMib::NNet::CNetAddress> f_Resolve(NStr::CStr const &_Address, NNet::ENetAddressType _PreferType);
			
		private:
			NContainer::TCLinkedList<NNet::CAsyncResolver> mp_PendingResolves;
		};
	}
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNet;
#endif
