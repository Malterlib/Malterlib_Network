
#include "Malterlib_Network_Socket_SSL.h"

namespace NMib
{
	namespace NNet
	{
		CSocket_SSL::CSocket_SSL
			(
				NPtr::TCSharedPointer<CSSLContext> const &_pContext
				, CSSLConnection::FAuthenticationResultCallback const &_AuthenticationResultCallback
				, CSSLConnection::FUserTrustDecisionCallback const &_UserTrustDecisionCallback
			)
			: mp_pSSLContext(_pContext)
			, mp_AuthenticationResultCallback(_AuthenticationResultCallback)
			, mp_UserTrustDecisionCallback(_UserTrustDecisionCallback)
			, mp_SSLConnection(_pContext, fg_TempCopy(_AuthenticationResultCallback), fg_TempCopy(_UserTrustDecisionCallback))
		{
		}

		CSocket_SSL::~CSocket_SSL()
		{
		}
		
		bool CSocket_SSL::f_IsValid() const
		{
			return mp_Socket.f_IsValid();
		}

		void CSocket_SSL::f_Close()
		{
			return mp_Socket.f_Close();
		}

		void CSocket_SSL::f_Shutdown()
		{
			return mp_Socket.f_Shutdown();
		}

		NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)> CSocket_SSL::fp_SharedOnStateChange()
		{
			return [this](ENetTCPState _StateAdded)
				{
					DMibLock(mp_OnStateChangeLock);
					mp_OnStateChange(_StateAdded);
				}
			;
		}

		void CSocket_SSL::f_Connect(NMib::NNet::CNetAddress const& _Address, NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange, NMib::NNet::CNetAddress const &_BindAddress)
		{
			if (!mp_pSSLContext->f_IsClientContext())
				DMibErrorNet("SSL context is not a client context when trying to connect");

			mp_OnStateChange = fg_Move(_OnStateChange);
			mp_Socket.f_Connect(_Address, fp_SharedOnStateChange(), _BindAddress);
			mp_State = EState_Connect;
			fp_HandleHandshake();
		}

		void CSocket_SSL::f_AsyncConnect(NMib::NNet::CNetAddress const& _Address, NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange, NMib::NNet::CNetAddress const &_BindAddress)
		{
			if (!mp_pSSLContext->f_IsClientContext())
				DMibErrorNet("SSL context is not a client context when trying to connect");
			
			mp_State = EState_Connect;
			mp_OnStateChange = fg_Move(_OnStateChange);
			return mp_Socket.f_AsyncConnect
				(
					_Address
					, [this](ENetTCPState _StateAdded)
					{
						{
							DMibLock(mp_OnStateChangeLock);
							mp_OnStateChange(_StateAdded);
						}
						if (_StateAdded == ENetTCPState_Connected)
							fp_AddTCPState(ENetTCPState_Read); // Kickstart process so user calls f_Receive to do the handshake
					}
					, _BindAddress
				)
			;
		}

		void CSocket_SSL::f_Listen(NMib::NNet::CNetAddress const& _Address, NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange)
		{
			if (!mp_pSSLContext->f_IsServerContext())
				DMibErrorNet("SSL context is not a server context when trying to listen");

			mp_State = EState_Listen;
			mp_OnStateChange = fg_Move(_OnStateChange);
			return mp_Socket.f_Listen(_Address, fp_SharedOnStateChange());
		}

		void CSocket_SSL::f_ListenDatagram(NMib::NNet::CNetAddress const& _Address, NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange)
		{
			DMibErrorNet("Datagrams not supported");
		}

		NPtr::TCUniquePointer<ICSocket> CSocket_SSL::f_Accept(NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange)
		{
			NPtr::TCUniquePointer<CSocket_SSL> pSocket = fg_Construct(mp_pSSLContext, mp_AuthenticationResultCallback, mp_UserTrustDecisionCallback);
			pSocket->mp_OnStateChange = fg_Move(_OnStateChange);
			pSocket->mp_Socket.f_Accept(&mp_Socket, pSocket->fp_SharedOnStateChange());
			if (!pSocket->mp_Socket.f_IsValid())
				return nullptr;
			pSocket->mp_State = EState_Accept;
			pSocket->mp_SSLConnection.f_GiveSocket(pSocket->mp_Socket.f_GetOSSocket());
			pSocket->fp_HandleHandshake();
			return fg_Move(pSocket);
		}

		void CSocket_SSL::f_InheritHandle(void *_pSocketHandle, NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange)
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

		void CSocket_SSL::f_SetOnStateChange(NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)>&& _OnStateChange)
		{
			{
				DMibLock(mp_OnStateChangeLock);
				mp_OnStateChange = fg_Move(_OnStateChange);
			}
		}

		ENetTCPState CSocket_SSL::f_GetState()
		{
			return mp_Socket.f_GetState() | (ENetTCPState)mp_ExtraState.f_Exchange(0);
		}

		NStr::CStr CSocket_SSL::f_GetCloseReason()
		{
			NStr::CStr Ret;
			
			NStr::CStr CloseReason = mp_Socket.f_GetCloseReason();
			
			if (!CloseReason.f_IsEmpty())
				NStr::fg_AddStrSep(Ret, CloseReason, ", ");
			
			NStr::CStr SSLErrors = mp_SSLConnection.f_GetConnectionResult().f_GetErrorMessage();
			
			if (!SSLErrors.f_IsEmpty())
				NStr::fg_AddStrSep(Ret, SSLErrors, ", ");
			
			NStr::CStr LastError = mp_SSLConnection.f_GetLastError();
			if (!LastError.f_IsEmpty())
				NStr::fg_AddStrSep(Ret, LastError, ", ");
			
			return Ret;
		}
		

		mint CSocket_SSL::f_Receive(void *_pData, mint _DataLen)
		{
			if (!fp_HandleHandshake())
				return 0;
			if (mp_SSLConnection.f_BrokenState())
				return 0;
			return mp_SSLConnection.f_Receive(_pData, _DataLen);
		}

		mint CSocket_SSL::f_Send(const void *_pData, mint _DataLen)
		{
			if (!fp_HandleHandshake())
				return 0;
			if (mp_SSLConnection.f_BrokenState())
				return 0;
			return mp_SSLConnection.f_Send(_pData, _DataLen);
		}

		mint CSocket_SSL::f_SendDatagram(NMib::NNet::CNetAddress const &_Address, const void *_pData, mint _DataLen)
		{
			DMibErrorNet("Datagrams not supported");
			return 0;
		}
		mint CSocket_SSL::f_ReceiveDatagram(NMib::NNet::CNetAddress &_Address, void *_pData, mint _DataLen)
		{
			DMibErrorNet("Datagrams not supported");
			return 0;
		}

		NMib::NNet::CNetAddress CSocket_SSL::f_GetPeerAddress() const
		{
			return mp_Socket.f_GetPeerAddress();
		}

		uint32 CSocket_SSL::f_GetListenPort() const
		{
			return mp_Socket.f_GetListenPort();
		}
		
		FVirtualSocketFactory CSocket_SSL::fs_GetFactory
			(
				NPtr::TCSharedPointer<CSSLContext> const &_pContext
				, CSSLConnection::FAuthenticationResultCallback const &_AuthenticationResultCallback
				, CSSLConnection::FUserTrustDecisionCallback const &_UserTrustDecisionCallback
			)
		{
			return [=]() -> NPtr::TCUniquePointer<ICSocket>
				{
					return fg_Construct<CSocket_SSL>(_pContext, _AuthenticationResultCallback, _UserTrustDecisionCallback);
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
				DMibLock(mp_OnStateChangeLock);
				if (mp_OnStateChange)
					mp_OnStateChange(_ToAdd);
			}
		}
		
		NPtr::TCUniquePointer<ICSocketConnectionInfo> CSocket_SSL::f_GetConnectionInfo() const
		{
			NPtr::TCUniquePointer<CSocketConnectionInfo_SSL> pReturn = fg_Construct();
			
			auto &Result = mp_SSLConnection.f_GetConnectionResult();
			pReturn->m_PeerCertificate = Result.f_GetPeerCertificate();
			pReturn->m_PeerCertificateName = Result.f_GetPeerCertificateName();
			pReturn->m_PeerCertificateFingerprint = Result.f_GetPeerCertificateFingerprint();
			
			return fg_Move(pReturn);
		}
	}
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNet;
#endif
