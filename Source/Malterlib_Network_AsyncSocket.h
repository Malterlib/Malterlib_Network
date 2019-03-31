// Copyright © 2019 Nonna Holding AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#pragma once

#include <Mib/Core/Core>
#include <Mib/Concurrency/ConcurrencyManager>
#include <Mib/Concurrency/ActorInterface>
#include <Mib/Concurrency/ActorFunctor>
#include <Mib/Network/Socket>
#include <Mib/Memory/Allocators/Secure>
#include <Mib/Network/ResolveActor>

namespace NMib::NNetwork
{
	enum EAsyncSocketStatus : uint16
	{
		EAsyncSocketStatus_None = 0
		, EAsyncSocketStatus_NormalClosure
		, EAsyncSocketStatus_AbnormalClosure
		, EAsyncSocketStatus_Timeout
		, EAsyncSocketStatus_Rejected
		, EAsyncSocketStatus_AlreadyClosed
	};

	enum EAsyncSocketCloseOrigin
	{
		EAsyncSocketCloseOrigin_Local
		, EAsyncSocketCloseOrigin_Remote
	};

	namespace NAsyncSocket
	{
		class CListenActor;
	}
	class CAsyncSocketServerActor;
	class CAsyncSocketClientActor;

	struct CAsyncSocketNewConnection;
	struct CAsyncSocketNewServerConnection;
	struct CAsyncSocketNewClientConnection;

	struct CAsyncSocketCallbacks
	{
		NConcurrency::TCActorFunctor<NConcurrency::TCFuture<void> (NStorage::TCSharedPointer<NContainer::CSecureByteVector> const &_Message)> m_fOnReceiveData;
		NConcurrency::TCActorFunctor<NConcurrency::TCFuture<void> (EAsyncSocketStatus _Reason, NStr::CStr const &_Message, EAsyncSocketCloseOrigin _Origin)> m_fOnClose;
	};

	class CAsyncSocketActor : public NConcurrency::CActor
	{
	public:
		struct CCloseInfo
		{
			EAsyncSocketStatus m_Status = EAsyncSocketStatus_None;
			NStr::CStr m_Reason;
		};

		struct CConnectionInfo
		{
			NStorage::TCUniquePointer<NNetwork::ICSocketConnectionInfo> m_pSocketInfo;
			NMib::NNetwork::CNetAddress m_PeerAddress;
			NStr::CStr m_Error;
			EAsyncSocketStatus m_ErrorStatus = EAsyncSocketStatus_None;
		};

	public:
		struct CInternal;

		CAsyncSocketActor(bool _bClient, mint _MaxMessageSize, mint _FragmentationSize, fp64 _Timeout);
		~CAsyncSocketActor();

		void f_SetTimeout(fp64 _Seconds);

		NConcurrency::TCFuture<void> f_SendData(NStorage::TCSharedPointer<NContainer::CSecureByteVector> const &_pMessage, uint32 _Priority);
		NConcurrency::TCFuture<CCloseInfo> f_Close(EAsyncSocketStatus _Status, const NStr::CStr &_Reason);
		NConcurrency::TCFuture<CCloseInfo> f_CloseWithLinger(EAsyncSocketStatus _Status, const NStr::CStr &_Reason, fp64 _MaxLingerTime);

		void f_DebugStopProcessing();

	private:
		friend class NAsyncSocket::CListenActor;
		friend class CAsyncSocketServerActor;
		friend struct CAsyncSocketNewConnection;
		friend struct CAsyncSocketNewServerConnection;
		friend struct CAsyncSocketNewClientConnection;
		friend class CAsyncSocketClientActor;

		enum EFinishConnectionResult
		{
			EFinishConnectionResult_Error
			, EFinishConnectionResult_Success
		};

		struct CFinishConnectionResult
		{
			EFinishConnectionResult m_Result = EFinishConnectionResult_Error;
			CConnectionInfo m_ConnectionInfo;
		};

		NConcurrency::CActorSubscription fp_SetOnClose(NConcurrency::TCActor<NConcurrency::CActor> &&_Actor);

		void fp_StateAdded(NNetwork::ENetTCPState _StateAdded);
		void fp_Disconnect(EAsyncSocketStatus _Status, NStr::CStr const &_Reason, bool _bFatal, EAsyncSocketCloseOrigin _Origin);
		void fp_SetSocket(NStorage::TCUniquePointer<NNetwork::ICSocket> &&_pSocket);
		void fp_ProcessIncoming();
		bool fp_ProcessIncomingMessage();
		void fp_ProcessState(NNetwork::ENetTCPState _StateAdded);
		void fp_UpdateSend();
		void fp_Shutdown();
		NConcurrency::CActorSubscription fp_AcceptConnection(CAsyncSocketCallbacks &&_Callbacks);
		void fp_CheckHandshake(CInternal &_Internal);
		void fp_RejectServerConnection(NStr::CStr const &_Error, NStr::CStr const &_Content = NStr::CStr());
		void fp_StopDeferring();
		void fp_TryStopDeferring();
		void fp_RejectConnection(NStr::CStr const &_Error);
		NConcurrency::TCFuture<CFinishConnectionResult> fp_FinishConnection();

	private:
		NStorage::TCUniquePointer<CInternal> mp_pInternal;
	};

	struct CAsyncSocketNewConnection
	{
		CAsyncSocketNewConnection(NConcurrency::TCActor<CAsyncSocketActor> const &_Connection);
		CAsyncSocketNewConnection(CAsyncSocketNewConnection &&_Other);
		~CAsyncSocketNewConnection();

		NConcurrency::TCFuture<NConcurrency::TCActorInterface<CAsyncSocketActor>> f_Accept(CAsyncSocketCallbacks &&_Callbacks);
		void f_Reject(NStr::CStr const &_Error) const;

	protected:
		struct CRepliedHelper
		{
			NConcurrency::TCActor<CAsyncSocketActor> m_Connection;
			NAtomic::TCAtomic<bool> m_bRepliedToConnection;

			CRepliedHelper(NConcurrency::TCActor<CAsyncSocketActor> const &_Connection);
			~CRepliedHelper();
		};

		NConcurrency::TCActor<CAsyncSocketActor> mp_Connection;
		NStorage::TCSharedPointer<CRepliedHelper> mp_pHelper;
	};

	struct CAsyncSocketNewClientConnection : public CAsyncSocketNewConnection
	{
		NStorage::TCUniquePointer<NNetwork::ICSocketConnectionInfo> m_pSocketInfo;
		NMib::NNetwork::CNetAddress m_PeerAddress;

		CAsyncSocketNewClientConnection
			(
				NConcurrency::TCActor<CAsyncSocketActor> const &_Connection
				, NStorage::TCUniquePointer<NNetwork::ICSocketConnectionInfo> &&_pSocketInfo
				, NMib::NNetwork::CNetAddress const &_PeerAddress
			)
		;
		CAsyncSocketNewClientConnection(CAsyncSocketNewClientConnection &&_Other);

	private:
		CAsyncSocketNewClientConnection &operator =(CAsyncSocketNewClientConnection const &);
		CAsyncSocketNewClientConnection &operator =(CAsyncSocketNewClientConnection &&);
		CAsyncSocketNewClientConnection(CAsyncSocketNewClientConnection const &_Other);
	};

	struct CAsyncSocketNewServerConnection : public CAsyncSocketNewConnection
	{
		CAsyncSocketActor::CConnectionInfo m_Info;

		CAsyncSocketNewServerConnection(CAsyncSocketActor::CConnectionInfo &&_ConnectionInfo, NConcurrency::TCActor<CAsyncSocketActor> const &_Connection);
		CAsyncSocketNewServerConnection(CAsyncSocketNewServerConnection &&_Other);

	private:
		CAsyncSocketNewServerConnection &operator =(CAsyncSocketNewServerConnection const &);
		CAsyncSocketNewServerConnection &operator =(CAsyncSocketNewServerConnection &&);
		CAsyncSocketNewServerConnection(CAsyncSocketNewServerConnection const &_Other);
	};

	class CAsyncSocketClientActor : public NConcurrency::CActor
	{
	public:

		CAsyncSocketClientActor();
		~CAsyncSocketClientActor();

		void f_SetDefaultMaxMessageSize(mint _MaxMessageSize);
		void f_SetDefaultFragmentationSize(mint _FragmentationSize);
		void f_SetDefaultTimeout(fp64 _Timeout);

		NConcurrency::TCFuture<CAsyncSocketNewClientConnection> f_Connect
			(
				NStr::CStr const &_ConnectToAddress	// The server to connect to
				, NStr::CStr const &_BindAddress	// The src address to bind to. Leave empty to not bind
				, NMib::NNetwork::ENetAddressType _PreferAddress // The preferred type of address to connect to
				, uint16 _Port	// The port to connect to
				, NNetwork::FVirtualSocketFactory &&_SocketFactory // The factory to use for creating the sockets. If empty/nullptr it will default to CSocket_TCP::fs_GetFactory()
			)
		; // You will receive an exception if connection fails

	private:
		NConcurrency::TCFuture<void> fp_Destroy() override;

		struct CPendingConnection
		{
			~CPendingConnection();

			NStorage::TCUniquePointer<NNetwork::ICSocket> m_pSocket;
			NStorage::TCSharedPointer<bool> m_pDeleted = fg_Construct(false);
		};
		NContainer::TCLinkedList<CPendingConnection> mp_PendingConnects;
		NConcurrency::TCActor<NNetwork::CResolveActor> mp_AddressResolver;
		mint mp_MaxMessageSize;
		mint mp_FragmentationSize;
		fp64 mp_Timeout;
	};

	struct CAsyncSocketServerCallbacks
	{
		NConcurrency::TCActorFunctor<NConcurrency::TCFuture<void> (CAsyncSocketNewServerConnection &&_Connection)> m_fNewConnection;
		NConcurrency::TCActorFunctor<NConcurrency::TCFuture<void> (CAsyncSocketActor::CConnectionInfo &&_ConnectionInfo)> m_fFailedConnection;
	};

	class CAsyncSocketServerActor : public NConcurrency::CActor
	{
		friend class NAsyncSocket::CListenActor;
	public:

		CAsyncSocketServerActor();
		~CAsyncSocketServerActor();

		struct CListenResult
		{
			NConcurrency::CActorSubscription m_Subscription;
			NContainer::TCVector<uint16> m_ListenPorts;
		};

		NConcurrency::TCFuture<CListenResult> f_StartListen
			(
				uint16 _StartListen		// The port to listen to
				, uint16 _nListen		// The number of ports to listen to. In consecutive order from the _StartListen port
				, NMib::NNetwork::ENetFlag _ListenFlags
				, CAsyncSocketServerCallbacks &&_Callbacks
				, NNetwork::FVirtualSocketFactory &&_SocketFactory // The factory to use for creating the sockets. If empty/nullptr it will default to CSocket_TCP::fs_GetFactory()
			)
		;

		NConcurrency::TCFuture<CListenResult> f_StartListenAddress
			(
				NContainer::TCVector<NNetwork::CNetAddress> &&_AddressesToListenTo // The addresses to listen to
				, NMib::NNetwork::ENetFlag _ListenFlags
				, CAsyncSocketServerCallbacks &&_Callbacks
				, NNetwork::FVirtualSocketFactory &&_SocketFactory // The factory to use for creating the sockets. If empty/nullptr it will default to CSocket_TCP::fs_GetFactory()
			)
		;

		void f_SetDefaultMaxMessageSize(mint _MaxMessageSize);
		void f_SetDefaultFragmentationSize(mint _FragmentationSize);
		void f_SetDefaultTimeout(fp64 _Timeout);

	private:
		NConcurrency::TCFuture<void> fp_Destroy() override;

		void fp_AddConnection(NConcurrency::TCActor<CAsyncSocketActor> &&_Connection, mint _ListenID);

	public:
		struct CInternal;

	private:
		NStorage::TCUniquePointer<CInternal> mp_pInternal;
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
