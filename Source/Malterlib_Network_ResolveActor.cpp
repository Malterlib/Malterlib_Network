
#include "Malterlib_Network_ResolveActor.h"
#include <Mib/Concurrency/WeakActor>

namespace NMib::NNetwork
{
	NConcurrency::TCFuture<NMib::NNetwork::CNetAddress> CResolveActor::f_Resolve(NStr::CStr _Address, NNetwork::ENetAddressType _PreferType)
	{
		if (_Address.f_IsEmpty())
			co_return {};

		auto &Resolve = mp_PendingResolves.f_Insert();

		auto *pResolve = &Resolve;

		auto ThisWeak = fg_ThisActor(this).f_Weak();

		NConcurrency::TCPromiseFuturePair<NMib::NNetwork::CNetAddress> Promise;

		Resolve.f_Open
			(
				_Address
				, _PreferType
				, [this, ThisWeak, pResolve, Promise = fg_Move(Promise.m_Promise)]() mutable
				{
					auto This = ThisWeak.f_Lock();
					if (!This)
					{
						Promise.f_SetException(DMibErrorInstance("Resolve actor was deleted"));
						return;
					}

					This.f_Bind<&CActor::f_Dispatch>
						(
							[this, pResolve = fg_Move(pResolve), Promise = fg_Move(Promise)]
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
						.f_DiscardResult()
					;
				}
			)
		;

		co_return co_await fg_Move(Promise.m_Future);
	}
}
