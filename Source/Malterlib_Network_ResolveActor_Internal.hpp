// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

namespace NMib::NNetwork
{
	using namespace NConcurrency;
	using namespace NStorage;

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

		_fResolve(ID) > [this, ID, Promise](TCAsyncResult<t_CResult> &&_Result)
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

}
