// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include "Malterlib_Network.h"

namespace NMib::NNetwork
{
	struct ICSocketConnectionInfo
	{
		virtual ~ICSocketConnectionInfo()
		{
		}
	};

	class ICSocket
	{
	public:
		virtual ~ICSocket()
		{
		}

		virtual bool f_IsValid() const = 0;
		virtual bool f_HandshakeDone() const = 0;
		virtual void f_Close() = 0;
		virtual void f_Shutdown() = 0;
		virtual void f_Connect
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
				, CNetAddress const &_BindAddress = NMib::NNetwork::CNetAddress()
			) = 0
		;
		virtual void f_AsyncConnect
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
				, CNetAddress const &_BindAddress = NMib::NNetwork::CNetAddress()
			) = 0
		;
		virtual void f_Listen(NMib::NNetwork::CNetAddress const &_Address, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange, ENetFlag _Flags) = 0;
		virtual void f_ListenDatagram
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
				, ENetFlag _Flags
			) = 0
		;
		virtual NStorage::TCUniquePointer<ICSocket> f_Accept(NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange) = 0;
		virtual void f_InheritHandle(void *_pSocketHandle, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange) = 0;
		virtual void *f_GiveUpForInherit() = 0;
		virtual void *f_GetOSSocket() = 0;
		virtual void f_SetOnStateChange(NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange) = 0;
		virtual ENetTCPState f_GetState() = 0;
		virtual NStr::CStr f_GetCloseReason() = 0;
		virtual CSocketOperationResult f_Receive(void *_pData, umint _DataLen) = 0;
		virtual CSocketOperationResult f_Send(const void *_pData, umint _DataLen) = 0;

		// Sends the spans in order, as one kernel operation where the platform and socket
		// implementation support it. The result byte count is total progress across the
		// spans and may end mid span. Zero length spans are skipped
		virtual CSocketOperationResult f_SendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans);
		virtual umint f_SendDatagram(NMib::NNetwork::CNetAddress const &_Address, const void *_pData, umint _DataLen) = 0;
		virtual umint f_ReceiveDatagram(NMib::NNetwork::CNetAddress &_Address, void *_pData, umint _DataLen) = 0;
		virtual NMib::NNetwork::CNetAddress f_GetPeerAddress() const = 0;
		virtual uint32 f_GetListenPort() const = 0;
		virtual NStorage::TCUniquePointer<ICSocketConnectionInfo> f_GetConnectionInfo() const = 0;

		// The number of spans every implementation is required to handle in one call. Passing more
		// than this is not supported: an implementation may consume them, stop at this many, or
		// stop earlier, so callers gather at most this many spans per send
		static constexpr umint mc_MaxSendSpans = 64;
	};

	using FVirtualSocketFactory = NFunction::TCFunction<NStorage::TCUniquePointer<ICSocket> (NStr::CStr const &_Hostname)>;
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
