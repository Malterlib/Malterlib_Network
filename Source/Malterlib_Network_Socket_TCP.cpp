// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Network_Socket_TCP.h"

namespace NMib::NNetwork
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

	bool CSocket_TCP::f_HandshakeDone() const
	{
		return true;
	}

	void CSocket_TCP::f_Close()
	{
		return mp_Socket.f_Close();
	}

	void CSocket_TCP::f_Shutdown()
	{
		return mp_Socket.f_Shutdown();
	}

	void CSocket_TCP::f_Connect
		(
			NMib::NNetwork::CNetAddress const &_Address
			, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
			, NMib::NNetwork::CNetAddress const &_BindAddress
		)
	{
		return mp_Socket.f_Connect(_Address, fg_Move(_fOnStateChange), _BindAddress);
	}

	void CSocket_TCP::f_AsyncConnect
		(
			NMib::NNetwork::CNetAddress const &_Address
			, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
			, NMib::NNetwork::CNetAddress const &_BindAddress
		)
	{
		return mp_Socket.f_AsyncConnect(_Address, fg_Move(_fOnStateChange), _BindAddress);
	}

	void CSocket_TCP::f_Listen
		(
			NMib::NNetwork::CNetAddress const &_Address
			, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
			, NMib::NNetwork::ENetFlag _Flags
		)
	{
		return mp_Socket.f_Listen(_Address, fg_Move(_fOnStateChange), _Flags);
	}

	void CSocket_TCP::f_ListenDatagram
		(
			NMib::NNetwork::CNetAddress const &_Address
			, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
			, NMib::NNetwork::ENetFlag _Flags
		)
	{
		return mp_Socket.f_ListenDatagram(_Address, fg_Move(_fOnStateChange), _Flags);
	}

	NStorage::TCUniquePointer<ICSocket> CSocket_TCP::f_Accept(NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		NStorage::TCUniquePointer<CSocket_TCP> pSocket = fg_Construct();
		pSocket->mp_Socket.f_Accept(&mp_Socket, fg_Move(_fOnStateChange));
		if (!pSocket->mp_Socket.f_IsValid())
			return nullptr;
		return fg_Move(pSocket);
	}

	void CSocket_TCP::f_InheritHandle(void *_pSocketHandle, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		return mp_Socket.f_InheritHandle2(_pSocketHandle, fg_Move(_fOnStateChange));
	}

	void *CSocket_TCP::f_GiveUpForInherit()
	{
		return mp_Socket.f_GiveUpForInherit();
	}

	void *CSocket_TCP::f_GetOSSocket()
	{
		return mp_Socket.f_GetOSSocket();
	}

	void CSocket_TCP::f_SetOnStateChange(NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		return mp_Socket.f_SetOnStateChange(fg_Move(_fOnStateChange));
	}

	ENetTCPState CSocket_TCP::f_GetState()
	{
		return mp_Socket.f_GetState();
	}

	NStr::CStr CSocket_TCP::f_GetCloseReason()
	{
		return mp_Socket.f_GetCloseReason();
	}

	CSocketOperationResult CSocket_TCP::f_Receive(void *_pData, umint _DataLen)
	{
		CSocketOperationResult Result;
		Result.m_nBytes = mp_Socket.f_Receive(_pData, _DataLen);
		if (Result.m_nBytes != 0)
			Result.m_bReceivedNetwork = true;
		return Result;
	}

	CSocketOperationResult CSocket_TCP::f_Send(const void *_pData, umint _DataLen)
	{
		if (!_DataLen)
			return {};
		CSocketOperationResult Result;
		Result.m_nBytes = mp_Socket.f_Send(_pData, _DataLen);
		if (Result.m_nBytes != 0)
			Result.m_bSentNetwork = true;
		return Result;
	}

	umint CSocket_TCP::f_SendDatagram(NMib::NNetwork::CNetAddress const &_Address, const void *_pData, umint _DataLen)
	{
		return mp_Socket.f_SendDatagram(_Address, _pData, _DataLen);
	}

	umint CSocket_TCP::f_ReceiveDatagram(NMib::NNetwork::CNetAddress &_Address, void *_pData, umint _DataLen)
	{
		return mp_Socket.f_ReceiveDatagram(_Address, _pData, _DataLen);
	}

	NMib::NNetwork::CNetAddress CSocket_TCP::f_GetPeerAddress() const
	{
		return mp_Socket.f_GetPeerAddress();
	}

	uint32 CSocket_TCP::f_GetListenPort() const
	{
		return mp_Socket.f_GetListenPort();
	}

	NStorage::TCUniquePointer<ICSocketConnectionInfo> CSocket_TCP::f_GetConnectionInfo() const
	{
		return nullptr;
	}

	FVirtualSocketFactory CSocket_TCP::fs_GetFactory()
	{
		return [](NStr::CStr const &_Hostname) -> NStorage::TCUniquePointer<ICSocket>
			{
				return fg_Construct<CSocket_TCP>();
			}
		;
	}
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
