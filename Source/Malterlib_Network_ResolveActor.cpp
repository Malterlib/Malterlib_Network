// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Network_ResolveActor_Internal.h"

namespace NMib::NNetwork
{
	using namespace NConcurrency;
	using namespace NStorage;

	// Each lookup owns its copy of the optional blocking provider. An empty name server uses the system configuration.
	CResolveActor::CResolveActor(FHostResolver const &_fHostResolver, umint _MaxConcurrent, CNetAddress const &_NameServer)
		: mp_pInternal(fg_Construct())
		, mp_Sequencer("ResolveActor", _MaxConcurrent)
		, mp_fHostResolver(_fHostResolver)
	{
		DMibRequire(_MaxConcurrent > 0);
		DMibRequire(_NameServer.f_IsEmpty() || _NameServer.f_GetType() == ENetAddressType_TCPv4 || _NameServer.f_GetType() == ENetAddressType_TCPv6);
		mp_pInternal->m_NameServer = _NameServer.f_GetString(ENetAddressStringFlag_IncludePort);
		if (_NameServer.f_GetScopeID())
		{
			mp_pInternal->m_NameServer = NStr::fg_Format
				(
					"{}%{}]:{}"
					, _NameServer.f_GetString(ENetAddressStringFlag_None).f_RemoveSuffix("]")
					, _NameServer.f_GetScopeID()
					, _NameServer.f_GetPort()
				)
			;
		}
	}

	CResolveActor::~CResolveActor() = default;

	void CResolveActor::fp_Construct()
	{
		auto &Internal = *mp_pInternal;
		Internal.m_pActor = this;
		if (!mp_fHostResolver)
		{
			auto Binding = f_ConcurrencyManager().f_PickIoLoopBinding(self.m_pThis->f_GetPriority());
			Internal.m_pLoop = Binding ? Binding.m_pLoop : NSys::fg_GetSharedIoLoop();
			if (Binding)
				self.m_pThis->f_SetInitialQueue(Binding.m_iQueue);
		}
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

		auto &Internal = *mp_pInternal;
		Internal.m_State = CInternal::EState::mc_Stopping;
		++Internal.m_TimerGeneration;
		Internal.m_Timer.f_Clear();
		for (auto &Waiter : Internal.m_InitWaiters)
			Waiter.f_SetException(DMibErrorInstance("Resolver shutting down"));
		Internal.m_InitWaiters.f_Clear();

		Internal.m_Channel.f_Clear();

		DMibFastCheck(Internal.m_Sockets.f_IsEmpty());

		Internal.m_Drain->f_Release();
		co_await Internal.m_Drain->m_Done.f_Future();

		co_return {};
	}

	// Success contains at least one address. Unspecified families try IPv4 before IPv6.
	// Empty input resolves immediately to one empty address.
	auto CResolveActor::f_Resolve(NStr::CStr _Address, ENetAddressType _PreferType) -> TCFuture<CLookup>
	{
		if (_Address.f_IsEmpty())
			co_return CLookup{.m_Result = CAddresses{CNetAddress{}}};

		co_return fp_Start<CAddresses>
			(
				[this, Address = fg_Move(_Address), _PreferType](uint64 _ID) mutable
				{
					return fp_ResolveAddress(_ID, fg_Move(Address), _PreferType);
				}
			)
		;
	}

	auto CResolveActor::fp_ResolveAddress(uint64 _ID, NStr::CStr _Address, ENetAddressType _PreferType) -> TCFuture<CAddresses>
	{
		auto Prepared = co_await fp_Resolve<CInternal::CPreparedAddress>
			(
				_ID
				, [Address = fg_Move(_Address), _PreferType]
				{
					CInternal::CPreparedAddress Prepared;
					Prepared.m_Parameters.m_PreferType = _PreferType;
					Prepared.m_Address = CNetAddress(NSys::NNetwork::fg_PrepareResolveAddress(Address, Prepared.m_Parameters));

					return Prepared;
				}
			)
		;

		if (!mp_Pending.f_FindEqual(_ID))
			co_return DMibErrorInstance("Lookup cancelled");
		if (!Prepared.m_Address.f_IsEmpty())
			co_return CAddresses{fg_Move(Prepared.m_Address)};

		auto &Parameters = Prepared.m_Parameters;
		if (Parameters.m_Host.f_IsEmpty())
			co_return DMibErrorInstance("Address contains no hostname");

		auto PreferType = Parameters.m_PreferType;
		auto Result = co_await fp_ResolveHost(_ID, Parameters.m_Host, PreferType == ENetAddressType_TCPv6 ? ENetAddressType_TCPv6 : ENetAddressType_TCPv4).f_Wrap();
		if (!Result && PreferType == ENetAddressType_None && mp_Pending.f_FindEqual(_ID))
			Result = co_await fp_ResolveHost(_ID, Parameters.m_Host, ENetAddressType_TCPv6).f_Wrap();

		if (Result)
		{
			if (Result->f_IsEmpty())
				co_return DMibErrorInstance("Name resolution returned no IP addresses");

			for (auto &Address : *Result)
				Address.f_SetPort(uint16(Parameters.m_Port));
		}

		co_return Result;
	}

	auto CResolveActor::f_ResolveHost(NStr::CStr _Host, ENetAddressType _PreferType) -> TCFuture<CLookup>
	{
		co_return fp_Start<CAddresses>
			(
				[this, Host = fg_Move(_Host), _PreferType](uint64 _ID) mutable
				{
					return fp_ResolveHost(_ID, fg_Move(Host), _PreferType);
				}
			)
		;
	}
}
