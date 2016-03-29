#pragma once

#include "Malterlib_Network_Socket.h"
#include "Malterlib_Network.h"
#include "Malterlib_Network_SSL.h"

namespace NMib
{
	namespace NNet
	{
		struct CSocketConnectionInfo_SSL final : public ICSocketConnectionInfo
		{
			NContainer::TCVector<uint8> m_PeerCertificate;
			NStr::CStr m_PeerCertificateName;
		};
		
		class CSocket_SSL final : public ICSocket
		{
			DMibClassNoCopyAllowed(CSocket_SSL);

		public:
			CSocket_SSL
				(
					NPtr::TCSharedPointer<CSSLContext> const &_pContext
					, CSSLConnection::FAuthenticationResultCallback const &_AuthenticationResultCallback
					, CSSLConnection::FUserTrustDecisionCallback const &_UserTrustDecisionCallback
				)
			;
			virtual ~CSocket_SSL() override;

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
			virtual NPtr::TCUniquePointer<ICSocketConnectionInfo> f_GetConnectionInfo() const override;

			static FVirtualSocketFactory fs_GetFactory
				(
					NPtr::TCSharedPointer<CSSLContext> const &_pContext
					, CSSLConnection::FAuthenticationResultCallback const &_AuthenticationResultCallback = fg_Default()
					, CSSLConnection::FUserTrustDecisionCallback const &_UserTrustDecisionCallback = fg_Default()
				)
			;

		private:
			enum EState
			{
				EState_None
				, EState_Connect
				, EState_Connected
				, EState_Accept
				, EState_Listen
				, EState_Done
				, EState_Disconnected
			};
			
			bool fp_HandleHandshake();
			void fp_HandleHandshakeDone();
			void fp_AddTCPState(ENetTCPState _ToAdd);
			NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)> fp_SharedOnStateChange();

			NAtomic::TCAtomic<uint32> mp_ExtraState;
			NMib::NFunction::TCFunction<void (ENetTCPState _StateAdded)> mp_OnStateChange;
			NThread::CMutual mp_OnStateChangeLock;
			CSocket mp_Socket;
			NPtr::TCSharedPointer<CSSLContext> mp_pSSLContext;
			CSSLConnection::FAuthenticationResultCallback mp_AuthenticationResultCallback;
			CSSLConnection::FUserTrustDecisionCallback mp_UserTrustDecisionCallback;
			
			CSSLConnection mp_SSLConnection;

			EState mp_State = EState_None;
		};
	}
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNet;
#endif
