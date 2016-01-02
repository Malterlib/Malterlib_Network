
#include "Malterlib_Network_Socket_TCP.h"

namespace NMib
{
	namespace NNet
	{
		CSocket_TCP::CSocket_TCP()
		{
		}

		CSocket_TCP::~CSocket_TCP()
		{
		}

		CSocket_TCP::CSocket_TCP(CSocket_TCP &&_Other)
			: mp_Socket(fg_Move(_Other.mp_Socket))
		{
		}

		CSocket_TCP &CSocket_TCP::operator =(CSocket_TCP &&_Other)
		{
			mp_Socket = fg_Move(_Other.mp_Socket);
			return *this;
		}

		bool CSocket_TCP::f_IsValid() const
		{
			return mp_Socket.f_IsValid();
		}

		void CSocket_TCP::f_Close()
		{
			return mp_Socket.f_Close();
		}

		void CSocket_TCP::f_Connect(NMib::NNet::CNetAddress const& _Address, NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange, NMib::NNet::CNetAddress const &_BindAddress)
		{
			return mp_Socket.f_Connect(_Address, fg_Move(_OnStateChange), _BindAddress);
		}

		void CSocket_TCP::f_AsyncConnect(NMib::NNet::CNetAddress const& _Address, NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange, NMib::NNet::CNetAddress const &_BindAddress)
		{
			return mp_Socket.f_AsyncConnect(_Address, fg_Move(_OnStateChange), _BindAddress);
		}

		void CSocket_TCP::f_Listen(NMib::NNet::CNetAddress const& _Address, NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange)
		{
			return mp_Socket.f_Listen(_Address, fg_Move(_OnStateChange));
		}

		void CSocket_TCP::f_ListenDatagram(NMib::NNet::CNetAddress const& _Address, NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange)
		{
			return mp_Socket.f_ListenDatagram(_Address, fg_Move(_OnStateChange));
		}

		NPtr::TCUniquePointer<ICSocket> CSocket_TCP::f_Accept(NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange)
		{
			NPtr::TCUniquePointer<CSocket_TCP> pSocket = fg_Construct();
			pSocket->mp_Socket.f_Accept(&mp_Socket, fg_Move(_OnStateChange));
			return fg_Move(pSocket);
		}

		void CSocket_TCP::f_InheritHandle(void *_pSocketHandle, NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange)
		{
			return mp_Socket.f_InheritHandle2(_pSocketHandle, fg_Move(_OnStateChange));
		}

		void *CSocket_TCP::f_GiveUpForInherit()
		{
			return mp_Socket.f_GiveUpForInherit();
		}

		void *CSocket_TCP::f_GetOSSocket()
		{
			return mp_Socket.f_GetOSSocket();
		}

		void CSocket_TCP::f_SetOnStateChange(NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange)
		{
			return mp_Socket.f_SetOnStateChange(fg_Move(_OnStateChange));
		}

		ENetTCPState CSocket_TCP::f_GetState()
		{
			return mp_Socket.f_GetState();
		}

		NStr::CStr CSocket_TCP::f_GetCloseReason()
		{
			return mp_Socket.f_GetCloseReason();
		}

		mint CSocket_TCP::f_Receive(void *_pData, mint _DataLen)
		{
			return mp_Socket.f_Receive(_pData, _DataLen);
		}

		mint CSocket_TCP::f_Send(const void *_pData, mint _DataLen)
		{
			return mp_Socket.f_Send(_pData, _DataLen);
		}

		mint CSocket_TCP::f_SendDatagram(NMib::NNet::CNetAddress const &_Address, const void *_pData, mint _DataLen)
		{
			return mp_Socket.f_SendDatagram(_Address, _pData, _DataLen);
		}

		mint CSocket_TCP::f_ReceiveDatagram(NMib::NNet::CNetAddress &_Address, void *_pData, mint _DataLen)
		{
			return mp_Socket.f_ReceiveDatagram(_Address, _pData, _DataLen);
		}

		NMib::NNet::CNetAddress CSocket_TCP::f_GetPeerAddress() const
		{
			return mp_Socket.f_GetPeerAddress();
		}

		uint32 CSocket_TCP::f_GetListenPort() const
		{
			return mp_Socket.f_GetListenPort();
		}
		
		FVirtualSocketFactory CSocket_TCP::fs_GetFactory()
		{
			return []() -> NPtr::TCUniquePointer<ICSocket>
				{
					return fg_Construct<CSocket_TCP>();
				}
			;
		}
	}
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNet;
#endif
