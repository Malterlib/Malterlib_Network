
#include "Malterlib_Network_ResolveActor.h"
#include <Mib/Concurrency/WeakActor>

namespace NMib::NNetwork
{
	NConcurrency::TCContinuation<NMib::NNetwork::CNetAddress> CResolveActor::f_Resolve(NStr::CStr const &_Address, NNetwork::ENetAddressType _PreferType)
	{
		NConcurrency::TCContinuation<NMib::NNetwork::CNetAddress> Continuation;

		if (_Address.f_IsEmpty())
		{
			Continuation.f_SetResult(NMib::NNetwork::CNetAddress());
			return Continuation;
		}
		auto &Resolve = mp_PendingResolves.f_Insert();

		auto *pResolve = &Resolve;

		auto ThisWeak = fg_ThisActor(this).f_Weak();

		Resolve.f_Open
			(
				_Address
				, _PreferType
				, [this, ThisWeak, pResolve, Continuation]()
				{
					auto This = ThisWeak.f_Lock();
					if (!This)
					{
						Continuation.f_SetException(DMibErrorInstance("Resolve actor was deleted"));
						return;
					}

					This
						(
							&CActor::f_Dispatch
							, [this, pResolve, Continuation]
							{
								NNetwork::CNetAddress Address;
								NStr::CStr Error;
								if (pResolve->f_GetResult(Address, Error))
									Continuation.f_SetResult(fg_Move(Address));
								else
									Continuation.f_SetException(DMibErrorInstance(NStr::CStr(Error)));

								mp_PendingResolves.f_Remove(*pResolve);
							}
						)
						> NConcurrency::fg_DiscardResult()
					;
				}
			)
		;

		return Continuation;
	}
}
