
#include "Malterlib_Network_Socket_SSL.h"

namespace NMib::NNetwork
{
	CSocket_SSL::CSocket_SSL
		(
			NStorage::TCSharedPointer<CSSLContext> const &_pContext
			, CSSLConnection::FAuthenticationResultCallback const &_AuthenticationResultCallback
			, CSSLConnection::FUserTrustDecisionCallback const &_UserTrustDecisionCallback
			, NStr::CStr const &_Hostname
		)
		: mp_pSSLContext(_pContext)
		, mp_AuthenticationResultCallback(_AuthenticationResultCallback)
		, mp_UserTrustDecisionCallback(_UserTrustDecisionCallback)
		, mp_SSLConnection(_pContext, fg_TempCopy(_AuthenticationResultCallback), fg_TempCopy(_UserTrustDecisionCallback), _Hostname)
	{
	}

	CSocket_SSL::~CSocket_SSL()
	{
	}

	bool CSocket_SSL::f_IsValid() const
	{
		return mp_Socket.f_IsValid();
	}

	bool CSocket_SSL::f_HandshakeDone() const
	{
		return mp_State == EState_Done;
	}

	void CSocket_SSL::f_Close()
	{
		return mp_Socket.f_Close();
	}

	void CSocket_SSL::f_Shutdown()
	{
		mp_State = EState_Shutdown;
		if (mp_SSLConnection.f_Shutdown())
		{
			mp_State = EState_ShutdownSocket;
			mp_Socket.f_Shutdown();
		}
	}

	NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> CSocket_SSL::fp_SharedOnStateChange()
	{
		return [this](ENetTCPState _StateAdded)
			{
				DMibLock(mp_fOnStateChangeLock);
				mp_fOnStateChange(_StateAdded);
			}
		;
	}

	void CSocket_SSL::f_Connect
		(
		 	NMib::NNetwork::CNetAddress const &_Address
		 	, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
		 	, NMib::NNetwork::CNetAddress const &_BindAddress
		)
	{
		if (!mp_pSSLContext->f_IsClientContext())
			DMibErrorNet("SSL context is not a client context when trying to connect");

		mp_fOnStateChange = fg_Move(_fOnStateChange);
		mp_Socket.f_Connect(_Address, fp_SharedOnStateChange(), _BindAddress);
		mp_State = EState_Connect;
		fp_HandleHandshake();
	}

	void CSocket_SSL::f_AsyncConnect
		(
		 	NMib::NNetwork::CNetAddress const &_Address
		 	, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
		 	, NMib::NNetwork::CNetAddress const &_BindAddress
		)
	{
		if (!mp_pSSLContext->f_IsClientContext())
			DMibErrorNet("SSL context is not a client context when trying to connect");

		mp_State = EState_Connect;
		mp_fOnStateChange = fg_Move(_fOnStateChange);
		return mp_Socket.f_AsyncConnect
			(
				_Address
				, [this](ENetTCPState _StateAdded)
				{
					{
						DMibLock(mp_fOnStateChangeLock);
						mp_fOnStateChange(_StateAdded);
					}
					if (_StateAdded == ENetTCPState_Connected)
						fp_AddTCPState(ENetTCPState_Read); // Kickstart process so user calls f_Receive to do the handshake
				}
				, _BindAddress
			)
		;
	}

	void CSocket_SSL::f_Listen
		(
		 	NMib::NNetwork::CNetAddress const &_Address
		 	, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
		 	, NMib::NNetwork::ENetFlag _Flags
		)
	{
		if (!mp_pSSLContext->f_IsServerContext())
			DMibErrorNet("SSL context is not a server context when trying to listen");

		mp_State = EState_Listen;
		mp_fOnStateChange = fg_Move(_fOnStateChange);
		return mp_Socket.f_Listen(_Address, fp_SharedOnStateChange(), _Flags);
	}

	void CSocket_SSL::f_ListenDatagram
		(
		 	NMib::NNetwork::CNetAddress const &_Address
		 	, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
		 	, NMib::NNetwork::ENetFlag _Flags
		)
	{
		DMibErrorNet("Datagrams not supported");
	}

	NStorage::TCUniquePointer<ICSocket> CSocket_SSL::f_Accept(NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		NStorage::TCUniquePointer<CSocket_SSL> pSocket = fg_Construct(mp_pSSLContext, mp_AuthenticationResultCallback, mp_UserTrustDecisionCallback, "");
		pSocket->mp_fOnStateChange = fg_Move(_fOnStateChange);
		pSocket->mp_Socket.f_Accept(&mp_Socket, pSocket->fp_SharedOnStateChange());
		if (!pSocket->mp_Socket.f_IsValid())
			return nullptr;
		pSocket->mp_State = EState_Accept;
		pSocket->mp_SSLConnection.f_GiveSocket(pSocket->mp_Socket.f_GetOSSocket());
		pSocket->fp_HandleHandshake();
		return fg_Move(pSocket);
	}

	void CSocket_SSL::f_InheritHandle(void *_pSocketHandle, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		DMibErrorNet("Not implemented");
	}

	void *CSocket_SSL::f_GiveUpForInherit()
	{
		DMibErrorNet("Not implemented");
		return nullptr;
	}

	void *CSocket_SSL::f_GetOSSocket()
	{
		return mp_Socket.f_GetOSSocket();
	}

	void CSocket_SSL::f_SetOnStateChange(NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		{
			DMibLock(mp_fOnStateChangeLock);
			mp_fOnStateChange = fg_Move(_fOnStateChange);
		}
	}

	ENetTCPState CSocket_SSL::f_GetState()
	{
		return mp_Socket.f_GetState() | (ENetTCPState)mp_ExtraState.f_Exchange(0);
	}

	NStr::CStr CSocket_SSL::f_GetCloseReason()
	{
		NStr::CStr Ret;

		NStr::CStr SSLErrors = mp_SSLConnection.f_GetConnectionResult().f_GetErrorMessage();

		if (!SSLErrors.f_IsEmpty())
			NStr::fg_AddStrSep(Ret, SSLErrors, ", ");

		NStr::CStr LastError = mp_SSLConnection.f_GetLastError();
		if (!LastError.f_IsEmpty())
			NStr::fg_AddStrSep(Ret, LastError, ", ");

		if (Ret.f_IsEmpty())
			Ret = mp_Socket.f_GetCloseReason();

		return Ret;
	}

	void CSocket_SSL::fp_CheckBrokenState()
	{
		if (mp_bBrokenStateReported)
			return;
		if (mp_SSLConnection.f_BrokenState())
		{
			fp_AddTCPState(ENetTCPState_Closed);
			mp_bBrokenStateReported = true;
		}
	}

	CSocketOperationResult CSocket_SSL::f_Receive(void *_pData, mint _DataLen)
	{
		if (!fp_HandleHandshake())
			return {};
		if (mp_SSLConnection.f_BrokenState())
		{
			fp_CheckBrokenState();
			return {};
		}

		CSocketOperationResult Return = mp_SSLConnection.f_Receive(_pData, _DataLen);
		if (!Return.m_nBytes)
			fp_CheckBrokenState();

		return Return;
	}

	CSocketOperationResult CSocket_SSL::f_Send(const void *_pData, mint _DataLen)
	{
		if (!fp_HandleHandshake())
		{
			DMibLog(DebugVerbose2, " **** CSocket_SSL handshake not done");
			return {};
		}
		if (mp_SSLConnection.f_BrokenState())
		{
			fp_CheckBrokenState();
			DMibLog(DebugVerbose2, " **** CSocket_SSL broken state");
			return {};
		}
		if (!_DataLen)
			return {};

		CSocketOperationResult Return = mp_SSLConnection.f_Send(_pData, _DataLen);
		if (!Return.m_nBytes)
			fp_CheckBrokenState();
		return Return;
	}

	mint CSocket_SSL::f_SendDatagram(NMib::NNetwork::CNetAddress const &_Address, const void *_pData, mint _DataLen)
	{
		DMibErrorNet("Datagrams not supported");
		return 0;
	}
	mint CSocket_SSL::f_ReceiveDatagram(NMib::NNetwork::CNetAddress &_Address, void *_pData, mint _DataLen)
	{
		DMibErrorNet("Datagrams not supported");
		return 0;
	}

	NMib::NNetwork::CNetAddress CSocket_SSL::f_GetPeerAddress() const
	{
		return mp_Socket.f_GetPeerAddress();
	}

	uint32 CSocket_SSL::f_GetListenPort() const
	{
		return mp_Socket.f_GetListenPort();
	}

	FVirtualSocketFactory CSocket_SSL::fs_GetFactory
		(
			NStorage::TCSharedPointer<CSSLContext> const &_pContext
			, CSSLConnection::FAuthenticationResultCallback const &_AuthenticationResultCallback
			, CSSLConnection::FUserTrustDecisionCallback const &_UserTrustDecisionCallback
		)
	{
		return [=](NStr::CStr const &_Hostname) -> NStorage::TCUniquePointer<ICSocket>
			{
				return fg_Construct<CSocket_SSL>(_pContext, _AuthenticationResultCallback, _UserTrustDecisionCallback, _Hostname);
			}
		;
	}

	void CSocket_SSL::fp_HandleHandshakeDone()
	{
		mp_State = EState_Done;
		fp_AddTCPState(ENetTCPState_Read | ENetTCPState_Write); // Allow user the chance to send or receive any deferred data
	}

	bool CSocket_SSL::fp_HandleHandshake()
	{
		switch (mp_State)
		{
		case EState_ShutdownSocket:
			return false;
		case EState_Shutdown:
			if (mp_SSLConnection.f_Shutdown())
			{
				mp_State = EState_ShutdownSocket;
				mp_Socket.f_Shutdown();
			}
			return false;
		case EState_Done:
			return true;
		case EState_Disconnected:
			return false;
		case EState_Connect:
			{
				mp_State = EState_Connected;
				mp_SSLConnection.f_GiveSocket(mp_Socket.f_GetOSSocket());
			}
			break;
		}

		switch (mp_State)
		{
		case EState_Connected:
			{
				if (mp_SSLConnection.f_Connect())
				{
					fp_HandleHandshakeDone();
					return true;
				}
			}
			break;
		case EState_Accept:
			{
				if (mp_SSLConnection.f_Accept())
				{
					fp_HandleHandshakeDone();
					return true;
				}
			}
			break;
		default:
			DMibNeverGetHere;
		}
		if (mp_SSLConnection.f_HandshakeInProgress())
			return false;

		fp_AddTCPState(ENetTCPState_Closed);
		mp_State = EState_Disconnected;

		return false;
	}

	void CSocket_SSL::fp_AddTCPState(ENetTCPState _ToAdd)
	{
		mp_ExtraState.f_FetchOr(_ToAdd);
		{
			DMibLock(mp_fOnStateChangeLock);
			if (mp_fOnStateChange)
				mp_fOnStateChange(_ToAdd);
		}
	}

	NStorage::TCUniquePointer<ICSocketConnectionInfo> CSocket_SSL::f_GetConnectionInfo() const
	{
		NStorage::TCUniquePointer<CSocketConnectionInfo_SSL> pReturn = fg_Construct();

		auto &Result = mp_SSLConnection.f_GetConnectionResult();
		pReturn->m_PeerCertificate = Result.f_GetPeerCertificate();
		pReturn->m_CertificateChain = Result.f_GetCertificateChain();

		return fg_Move(pReturn);
	}
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
