#pragma once

#include <Mib/Core/Core>
#include "Malterlib_Network_Socket.h"
#include "Malterlib_Network.h"
#include "Malterlib_Network_SSL.h"

namespace NMib::NNetwork
{
	struct CSocketConnectionInfo_SSL final : public ICSocketConnectionInfo
	{
		NContainer::CByteVector m_PeerCertificate;
		NContainer::TCVector<NContainer::CByteVector> m_CertificateChain;
	};

	class CSocket_SSL final : public ICSocket
	{
		CSocket_SSL(CSocket_SSL const &) = delete;
		CSocket_SSL &operator = (CSocket_SSL const &) = delete;

	public:
		CSocket_SSL
			(
				NStorage::TCSharedPointer<CSSLContext> const &_pContext
				, CSSLConnection::FAuthenticationResultCallback const &_AuthenticationResultCallback
				, CSSLConnection::FUserTrustDecisionCallback const &_UserTrustDecisionCallback
				, NStr::CStr const &_Hostname
			)
		;
		virtual ~CSocket_SSL() override;

		virtual bool f_IsValid() const override;
		virtual bool f_HandshakeDone() const override;
		virtual void f_Close() override;
		virtual void f_Shutdown() override;
		virtual void f_Connect
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
				, NMib::NNetwork::CNetAddress const &_BindAddress = NMib::NNetwork::CNetAddress()
			) override
		;
		virtual void f_AsyncConnect
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
				, NMib::NNetwork::CNetAddress const &_BindAddress = NMib::NNetwork::CNetAddress()
			) override
		;
		virtual void f_Listen
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
				, NMib::NNetwork::ENetFlag _Flags
			) override
		;
		virtual void f_ListenDatagram
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
				, NMib::NNetwork::ENetFlag _Flags
			) override
		;
		virtual NStorage::TCUniquePointer<ICSocket> f_Accept(NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange) override;
		virtual void f_InheritHandle(void *_pSocketHandle, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange) override;
		virtual void *f_GiveUpForInherit() override;
		virtual void *f_GetOSSocket() override;
		virtual void f_SetOnStateChange(NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange) override;
		virtual ENetTCPState f_GetState() override;
		virtual NStr::CStr f_GetCloseReason() override;
		virtual CSocketOperationResult f_Receive(void *_pData, mint _DataLen) override;
		virtual CSocketOperationResult f_Send(const void *_pData, mint _DataLen) override;
		virtual mint f_SendDatagram(NMib::NNetwork::CNetAddress const &_Address, const void *_pData, mint _DataLen) override;
		virtual mint f_ReceiveDatagram(NMib::NNetwork::CNetAddress &_Address, void *_pData, mint _DataLen) override;
		virtual NMib::NNetwork::CNetAddress f_GetPeerAddress() const override;
		virtual uint32 f_GetListenPort() const override;
		virtual NStorage::TCUniquePointer<ICSocketConnectionInfo> f_GetConnectionInfo() const override;

		static FVirtualSocketFactory fs_GetFactory
			(
				NStorage::TCSharedPointer<CSSLContext> const &_pContext
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
			, EState_Shutdown
			, EState_ShutdownSocket
			, EState_Disconnected
		};

		bool fp_HandleHandshake();
		void fp_HandleHandshakeDone();
		void fp_CheckBrokenState();
		void fp_AddTCPState(ENetTCPState _ToAdd);
		NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> fp_SharedOnStateChange();

		NAtomic::TCAtomic<uint32> mp_ExtraState;
		NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> mp_fOnStateChange;
		NThread::CMutual mp_fOnStateChangeLock;
		CSocket mp_Socket;
		NStorage::TCSharedPointer<CSSLContext> mp_pSSLContext;
		CSSLConnection::FAuthenticationResultCallback mp_AuthenticationResultCallback;
		CSSLConnection::FUserTrustDecisionCallback mp_UserTrustDecisionCallback;

		CSSLConnection mp_SSLConnection;

		EState mp_State = EState_None;
		bool mp_bBrokenStateReported = false;
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
