
#include "Malterlib_Network_ResolveActor.h"
#include <Mib/Concurrency/WeakActor>

namespace NMib::NNetwork
{
	NConcurrency::TCFuture<NMib::NNetwork::CNetAddress> CResolveActor::f_Resolve(NStr::CStr const &_Address, NNetwork::ENetAddressType _PreferType)
	{
		NConcurrency::TCPromise<NMib::NNetwork::CNetAddress> Promise;

		if (_Address.f_IsEmpty())
		{
			Promise.f_SetResult(NMib::NNetwork::CNetAddress());
			return Promise.f_MoveFuture();
		}
		auto &Resolve = mp_PendingResolves.f_Insert();

		auto *pResolve = &Resolve;

		auto ThisWeak = fg_ThisActor(this).f_Weak();

		Resolve.f_Open
			(
				_Address
				, _PreferType
				, [this, ThisWeak, pResolve, Promise]()
				{
					auto This = ThisWeak.f_Lock();
					if (!This)
					{
						Promise.f_SetException(DMibErrorInstance("Resolve actor was deleted"));
						return;
					}

					This
						(
							&CActor::f_Dispatch
							, [this, pResolve, Promise]
							{
								NNetwork::CNetAddress Address;
								NStr::CStr Error;
								if (pResolve->f_GetResult(Address, Error))
									Promise.f_SetResult(fg_Move(Address));
								else
									Promise.f_SetException(DMibErrorInstance(NStr::CStr(Error)));

								mp_PendingResolves.f_Remove(*pResolve);
							}
						)
						> NConcurrency::fg_DiscardResult()
					;
				}
			)
		;

		return Promise.f_MoveFuture();
	}
}
