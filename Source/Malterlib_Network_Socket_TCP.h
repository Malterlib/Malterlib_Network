#pragma once

#include "Malterlib_Network_Socket.h"
#include "Malterlib_Network.h"

namespace NMib
{
	namespace NNet
	{
		class CSocket_TCP final : public ICSocket
		{
			DMibClassNoCopyAllowed(CSocket_TCP);

		public:
			CSocket_TCP();
			virtual ~CSocket_TCP() override;
			CSocket_TCP(CSocket_TCP &&_Other);
			CSocket_TCP &operator =(CSocket_TCP &&_Other);

			virtual bool f_IsValid() const override;
			virtual void f_Close() override;
			virtual void f_Shutdown() override;
			virtual void f_Connect(NMib::NNet::CNetAddress const& _Address, NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange, NMib::NNet::CNetAddress const &_BindAddress = NMib::NNet::CNetAddress()) override;
			virtual void f_AsyncConnect(NMib::NNet::CNetAddress const& _Address, NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange, NMib::NNet::CNetAddress const &_BindAddress = NMib::NNet::CNetAddress()) override;
			virtual void f_Listen(NMib::NNet::CNetAddress const& _Address, NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange) override;
			virtual void f_ListenDatagram(NMib::NNet::CNetAddress const& _Address, NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange) override;
			virtual NPtr::TCUniquePointer<ICSocket> f_Accept(NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange) override;
			virtual void f_InheritHandle(void *_pSocketHandle, NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange) override;
			virtual void *f_GiveUpForInherit() override;
			virtual void *f_GetOSSocket() override;
			virtual void f_SetOnStateChange(NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange) override;
			virtual ENetTCPState f_GetState() override;
			virtual NStr::CStr f_GetCloseReason() override;
			virtual mint f_Receive(void *_pData, mint _DataLen) override;
			virtual mint f_Send(const void *_pData, mint _DataLen) override;
			virtual mint f_SendDatagram(NMib::NNet::CNetAddress const &_Address, const void *_pData, mint _DataLen) override;
			virtual mint f_ReceiveDatagram(NMib::NNet::CNetAddress &_Address, void *_pData, mint _DataLen) override;
			virtual NMib::NNet::CNetAddress f_GetPeerAddress() const override;
			virtual uint32 f_GetListenPort() const override;

			static FVirtualSocketFactory fs_GetFactory();

		private:
			CSocket mp_Socket;
		};
	}
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNet;
#endif
