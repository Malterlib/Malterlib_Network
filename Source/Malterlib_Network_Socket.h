#pragma once

#include "Malterlib_Network.h"

namespace NMib
{
	namespace NNet
	{
		class ICSocket
		{
		public:
			virtual ~ICSocket()
			{
			}

			virtual bool f_IsValid() const = 0;
			virtual void f_Close() = 0;
			virtual void f_Connect(NMib::NNet::CNetAddress const& _Address, NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange, NMib::NNet::CNetAddress const &_BindAddress = NMib::NNet::CNetAddress()) = 0;
			virtual void f_AsyncConnect(NMib::NNet::CNetAddress const& _Address, NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange, NMib::NNet::CNetAddress const &_BindAddress = NMib::NNet::CNetAddress()) = 0;
			virtual void f_Listen(NMib::NNet::CNetAddress const& _Address, NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange) = 0;
			virtual void f_ListenDatagram(NMib::NNet::CNetAddress const& _Address, NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange) = 0;
			virtual NPtr::TCUniquePointer<ICSocket> f_Accept(NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange) = 0;
			virtual void f_InheritHandle(void *_pSocketHandle, NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange) = 0;
			virtual void *f_GiveUpForInherit() = 0;
			virtual void *f_GetOSSocket() = 0;
			virtual void f_SetOnStateChange(NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange) = 0;
			virtual ENetTCPState f_GetState() = 0;
			virtual NStr::CStr f_GetCloseReason() = 0;
			virtual mint f_Receive(void *_pData, mint _DataLen) = 0;
			virtual mint f_Send(const void *_pData, mint _DataLen) = 0;
			virtual mint f_SendDatagram(NMib::NNet::CNetAddress const& _Address, const void *_pData, mint _DataLen) = 0;
			virtual mint f_ReceiveDatagram(NMib::NNet::CNetAddress &_Address, void *_pData, mint _DataLen) = 0;
			virtual NMib::NNet::CNetAddress f_GetPeerAddress() const = 0;
			virtual uint32 f_GetListenPort() const = 0;
		};
		
		using FVirtualSocketFactory = NFunction::TCFunction<NPtr::TCUniquePointer<ICSocket> ()>;
	}
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNet;
#endif
