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
		static constexpr NConcurrency::EPriority mc_Priority = NConcurrency::EPriority_NormalHighCPU;

		using CAddresses = NContainer::TCVector<CNetAddress>;
		using FHostResolver = NFunction::TCFunction<CAddresses (NStr::CStr const &, ENetAddressType)>;

		CResolveActor(FHostResolver const &_fHostResolver = {}, umint _MaxConcurrent = 4, CNetAddress const &_NameServer = {});
		~CResolveActor();

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
		struct CInternal;

		void fp_Construct() override;
		NConcurrency::TCFuture<void> fp_Initialize();
		NConcurrency::TCFuture<CAddresses> fp_ResolveAddress(uint64 _ID, NStr::CStr _Address, ENetAddressType _PreferType);
		NConcurrency::TCFuture<CAddresses> fp_ResolveHost(uint64 _ID, NStr::CStr _Host, ENetAddressType _PreferType);
		void fp_SocketReady(smint _Socket, uint64 _Generation, NSys::EIoLoopEvent _Events, int _Error);
		NConcurrency::TCFuture<void> fp_SetTimer(uint64 _Generation, fp64 _Seconds);

		template <typename t_CResult, typename tf_FResolve>
		TCLookup<t_CResult> fp_Start(tf_FResolve &&_fResolve);

		template <typename t_CResult, typename tf_FResolve>
		NConcurrency::TCFuture<t_CResult> fp_Resolve(uint64 _ID, tf_FResolve _fResolve);

		void fp_Cancel(uint64 _ID);
		NConcurrency::TCFuture<void> fp_Destroy() override;

		NStorage::TCUniquePointer<CInternal> mp_pInternal;
		NConcurrency::CSequencer mp_Sequencer;
		FHostResolver mp_fHostResolver;
		NContainer::TCMap<uint64, NFunction::TCFunctionMovable<void ()>> mp_Pending;
		uint64 mp_NextID = 0;
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
