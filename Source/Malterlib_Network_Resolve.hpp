// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

namespace NMib::NNetwork
{
	inline void CAsyncResolver::fp_CheckValid() const
	{
		if (!mp_pResolver)
			DMibErrorNet("Resolver is not valid");
	}

	inline CAsyncResolver::CAsyncResolver(CAsyncResolver &&_Other)
		: mp_pResolver(_Other.mp_pResolver)
	{
		_Other.mp_pResolver = nullptr;
	}

	inline CAsyncResolver &CAsyncResolver::operator = (CAsyncResolver &&_Other)
	{
		f_CloseAsync({});
		mp_pResolver = _Other.mp_pResolver;
		_Other.mp_pResolver = nullptr;

		return *this;
	}

	inline CAsyncResolver::CAsyncResolver()
	{
		mp_pResolver = nullptr;
	}

	inline CAsyncResolver::~CAsyncResolver()
	{
		f_CloseAsync({});
	}

	// Waits for completion. Use f_CloseAsync on actor threads and in resolver callbacks.
	inline void CAsyncResolver::f_Close()
	{
		if (mp_pResolver)
			NMib::NSys::NNetwork::fg_AsyncResolveAddress_Close(mp_pResolver);
		mp_pResolver = nullptr;
	}

	// Consumes the lookup immediately. Completion runs after the lookup and any active
	// finish callback have returned, on the worker for active requests, inline otherwise.
	inline void CAsyncResolver::f_CloseAsync(NMib::NFunction::TCFunctionMovable<void ()> &&_fOnClosed)
	{
		auto *pResolver = fg_Exchange(mp_pResolver, nullptr);
		if (pResolver)
			NMib::NSys::NNetwork::fg_AsyncResolveAddress_CloseAsync(pResolver, fg_Move(_fOnClosed));
		else if (_fOnClosed)
			_fOnClosed();
	}

	inline void CAsyncResolver::f_Open(const NMib::NStr::CStr &_Address, ::NMib::NNetwork::ENetAddressType _PreferType, NMib::NFunction::TCFunctionMutable<void ()> &&_fOnFinish)
	{
		f_CloseAsync({});
		mp_pResolver = NMib::NSys::NNetwork::fg_AsyncResolveAddress_Open(_Address, _PreferType, fg_Move(_fOnFinish));
	}

	inline void CAsyncResolver::f_Open(const NMib::NStr::CStr &_Address, ::NMib::NNetwork::ENetAddressType _PreferType, NMib::NThread::CSemaphoreAggregate *_pReportTo)
	{
		f_CloseAsync({});
		mp_pResolver = NMib::NSys::NNetwork::fg_AsyncResolveAddress_Open
			(
				_Address
				, _PreferType
				, [_pReportTo]()
				{
					_pReportTo->f_Signal();
				}
			)
		;
	}

	inline bool CAsyncResolver::f_GetResult(NMib::NNetwork::CNetAddress &_Address, NStr::CStr &_Error)
	{
		fp_CheckValid();
		NMib::NSys::NNetwork::CAddress Address;
		if (NMib::NSys::NNetwork::fg_AsyncResolveAddress_GetResult(mp_pResolver, Address, _Error))
		{
			_Address = NMib::NNetwork::CNetAddress(Address);
			return true;
		}
		else
			return false;
	}

	inline uint32 CNetAddress::f_GetScopeID() const
	{
		return mp_Address ? NMib::NSys::NNetwork::fg_GetAddressScopeID(mp_Address) : 0;
	}

	// The first result is the address selected by fs_ResolveAddress.
	inline NContainer::TCVector<CNetAddress> CSocket::fs_ResolveAddresses(NStr::CStr const &_Address, ENetAddressType _PreferType)
	{
		return fsp_AdoptAddresses(NMib::NSys::NNetwork::fg_ResolveAddresses(_Address, _PreferType));
	}

	inline NContainer::TCVector<CNetAddress> CSocket::fs_ResolveHost(NStr::CStr const &_Host, ENetAddressType _PreferType)
	{
		return fsp_AdoptAddresses(NMib::NSys::NNetwork::fg_ResolveHost(_Host, _PreferType));
	}

	inline NContainer::TCVector<CNetAddress> CSocket::fsp_AdoptAddresses(NContainer::TCVector<NMib::NSys::NNetwork::CAddress> &&_Addresses)
	{
		auto Cleanup = g_OnScopeExit / [&_Addresses]
			{
				for (auto Address : _Addresses)
					NMib::NSys::NNetwork::fg_FreeAddress(Address);
			}
		;

		NContainer::TCVector<CNetAddress> Result;
		for (auto &Address : _Addresses)
			Result.f_Insert(CNetAddress(fg_Exchange(Address, nullptr)));

		return Result;
	}
}
