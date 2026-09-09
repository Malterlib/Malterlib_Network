// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Network_ResolveActor.h"

namespace NMib::NNetwork
{
	using namespace NConcurrency;
	using namespace NStorage;

	// Each lookup owns its copy of the optional blocking provider.
	CResolveActor::CResolveActor(FHostResolver const &_fHostResolver, umint _MaxConcurrent)
		: mp_Sequencer("ResolveActor", _MaxConcurrent)
		, mp_fHostResolver(_fHostResolver)
	{
		DMibRequire(_MaxConcurrent > 0);
	}

	template <typename t_CResult, typename tf_FResolve>
	auto CResolveActor::fp_Start(tf_FResolve &&_fResolve) -> TCLookup<t_CResult>
	{
		TCPromise<t_CResult> Promise;
		TCLookup<t_CResult> Lookup;
		Lookup.m_Result = Promise.f_Future();

		if (f_IsDestroyed())
		{
			Promise.f_SetException(DMibErrorInstance("Resolver shutting down"));

			return Lookup;
		}

		auto ID = ++mp_NextID;
		mp_Pending[ID] = [Promise]() mutable
			{
				Promise.f_SetException(DMibErrorInstance("Lookup cancelled"));
			}
		;

		Lookup.m_Cancel = g_ActorSubscription / [this, ID]
			{
				fp_Cancel(ID);
			}
		;

		fp_Resolve<t_CResult>(ID, fg_Forward<tf_FResolve>(_fResolve)) > [this, ID, Promise](TCAsyncResult<t_CResult> &&_Result)
			{
				if (!mp_Pending.f_FindEqual(ID))
					return;

				mp_Pending.f_Remove(ID);
				Promise.f_SetResult(fg_Move(_Result));
			}
		;

		return Lookup;
	}

	template <typename t_CResult, typename tf_FResolve>
	TCFuture<t_CResult> CResolveActor::fp_Resolve(uint64 _ID, tf_FResolve _fResolve)
	{
		auto Sequence = co_await mp_Sequencer.f_Sequence();
		if (!mp_Pending.f_FindEqual(_ID))
			co_return DMibErrorInstance("Lookup cancelled");

		auto BlockingActorCheckout = fg_BlockingActor();

		// The worker retains the slot until the native lookup returns, including when
		// cancellation destroys this coroutine and releases the blocking actor checkout.
		co_return co_await
			(
				g_Dispatch(BlockingActorCheckout) / [fResolve = fg_Move(_fResolve), Sequence = fg_Move(Sequence)]() mutable
				{
					return fResolve();
				}
			)
		;
	}

	void CResolveActor::fp_Cancel(uint64 _ID)
	{
		if (auto *pCancel = mp_Pending.f_FindEqual(_ID))
		{
			(*pCancel)();
			mp_Pending.f_Remove(_ID);
		}
	}

	TCFuture<void> CResolveActor::fp_Destroy()
	{
		for (auto &fCancel : mp_Pending)
			fCancel();

		mp_Pending.f_Clear();

		co_return {};
	}

	// Success contains at least one address; entry zero matches CSocket::fs_ResolveAddress.
	// Empty input resolves immediately to one empty address.
	auto CResolveActor::f_Resolve(NStr::CStr _Address, ENetAddressType _PreferType) -> TCFuture<CLookup>
	{
		if (_Address.f_IsEmpty())
			co_return CLookup{.m_Result = CAddresses{CNetAddress{}}};

		co_return fp_Start<CAddresses>
			(
				[Address = fg_Move(_Address), _PreferType]
				{
					return CSocket::fs_ResolveAddresses(Address, _PreferType);
				}
			)
		;
	}

	auto CResolveActor::f_ResolveHost(NStr::CStr _Host, ENetAddressType _PreferType) -> TCFuture<CLookup>
	{
		co_return fp_Start<CAddresses>
			(
				[Host = fg_Move(_Host), _PreferType, fHostResolver = mp_fHostResolver]
				{
					if (fHostResolver)
						return fHostResolver(Host, _PreferType);

					return CSocket::fs_ResolveHost(Host, _PreferType);
				}
			)
		;
	}
}
