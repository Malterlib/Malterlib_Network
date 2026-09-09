// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include "Malterlib_Network.h"
#include <Mib/Concurrency/ConcurrencyManager>
#include <Mib/Concurrency/ActorSubscription>
#include <Mib/Concurrency/ActorSequencerActor>

namespace NMib::NNetwork
{
	struct CResolveActor : public NConcurrency::CActor
	{
		using CAddresses = NContainer::TCVector<CNetAddress>;
		using FHostResolver = NFunction::TCFunction<CAddresses (NStr::CStr const &, ENetAddressType)>;

		CResolveActor(FHostResolver const &_fHostResolver = {}, umint _MaxConcurrent = 4);

		template <typename t_CResult>
		struct TCLookup
		{
			NConcurrency::TCFuture<t_CResult> m_Result;

			NConcurrency::CActorSubscription m_Cancel; // Releasing this cancels delivery without waiting for the backend.
		};

		using CLookup = TCLookup<CAddresses>;

		NConcurrency::TCFuture<CLookup> f_Resolve(NStr::CStr _Address, ENetAddressType _PreferType);
		NConcurrency::TCFuture<CLookup> f_ResolveHost(NStr::CStr _Host, ENetAddressType _PreferType = ENetAddressType_None);

	private:
		template <typename t_CResult, typename tf_FResolve>
		TCLookup<t_CResult> fp_Start(tf_FResolve &&_fResolve);

		template <typename t_CResult, typename tf_FResolve>
		NConcurrency::TCFuture<t_CResult> fp_Resolve(uint64 _ID, tf_FResolve _fResolve);

		void fp_Cancel(uint64 _ID);
		NConcurrency::TCFuture<void> fp_Destroy() override;

		NConcurrency::CSequencer mp_Sequencer;
		FHostResolver mp_fHostResolver;
		uint64 mp_NextID = 0;
		NContainer::TCMap<uint64, NFunction::TCFunctionMovable<void ()>> mp_Pending;
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
