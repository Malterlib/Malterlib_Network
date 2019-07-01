// Copyright © 2019 Nonna Holding AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Concurrency/ConcurrencyManager>
#include <Mib/Concurrency/WeakActor>
#include <Mib/Network/Sockets/TCP>
#include <Mib/Cryptography/Exception>

#include "Malterlib_Network_AsyncSocket.h"

namespace NMib::NNetwork
{
	CAsyncSocketClientActor::CAsyncSocketClientActor()
		: mp_MaxMessageSize(24*1024*1024)
		, mp_FragmentationSize(32*1024)
		, mp_Timeout(60.0)
	{
	}

	CAsyncSocketClientActor::~CAsyncSocketClientActor()
	{
	}

	void CAsyncSocketClientActor::f_SetDefaultMaxMessageSize(mint _MaxMessageSize)
	{
		mp_MaxMessageSize = _MaxMessageSize;
	}

	void CAsyncSocketClientActor::f_SetDefaultFragmentationSize(mint _FragmentationSize)
	{
		mp_FragmentationSize = _FragmentationSize;
	}

	void CAsyncSocketClientActor::f_SetDefaultTimeout(fp64 _Timeout)
	{
		mp_Timeout = _Timeout;
	}

	NConcurrency::TCFuture<void> CAsyncSocketClientActor::fp_Destroy()
	{
		mp_PendingConnects.f_Clear();
		return fg_Explicit();
	}

	CAsyncSocketClientActor::CPendingConnection::~CPendingConnection()
	{
		*m_pDeleted = true;
	}

	NConcurrency::TCFuture<CAsyncSocketNewClientConnection> CAsyncSocketClientActor::f_Connect
		(
			NStr::CStr const& _ConnectToAddress
			, NStr::CStr const& _BindToAddress
			, NMib::NNetwork::ENetAddressType _PreferAddress
			, uint16 _Port
			, NNetwork::FVirtualSocketFactory &&_SocketFactory
		)
	{
		if (!_SocketFactory)
			_SocketFactory = NNetwork::CSocket_TCP::fs_GetFactory();

		if (_ConnectToAddress.f_IsEmpty())
			co_return DMibErrorInstance("Connect to address cannot be empty");

		if (!mp_AddressResolver)
			mp_AddressResolver = NConcurrency::fg_ConstructActor<NNetwork::CResolveActor>();

		auto [ConnectToAdress, BindToAddress] = co_await
			(
			 	mp_AddressResolver(&NNetwork::CResolveActor::f_Resolve, _ConnectToAddress, _PreferAddress)
			 	+ mp_AddressResolver(&NNetwork::CResolveActor::f_Resolve, _BindToAddress, _PreferAddress)
			)
		;

		CPendingConnection *pPending;
		{
			CPendingConnection &Pending = mp_PendingConnects.f_Insert();
			pPending = &Pending;
			Pending.m_pSocket = _SocketFactory(_ConnectToAddress);
		}

		auto CleanupPending = NConcurrency::g_OnScopeExitActor > [this, pPendingDeleted = pPending->m_pDeleted, pPending]
			{
				if (*pPendingDeleted)
					return;
				mp_PendingConnects.f_Remove(*pPending);
			}
		;

		ConnectToAdress.f_SetPort(_Port);

		NConcurrency::TCPromise<CAsyncSocketNewClientConnection> Promise;

		try
		{
			NException::CDisableExceptionTraceScope DisableExceptionTrace;
			auto pReplied = NStorage::TCSharedPointer<NAtomic::TCAtomic<bool>>(fg_Construct(false));
			pPending->m_pSocket->f_AsyncConnect
				(
					ConnectToAdress
					,
				 	[
					 	pReplied
					 	, pPending
					 	, pPendingDeleted = pPending->m_pDeleted
					 	, WeakThis = fg_ThisActor(this).f_Weak()
					 	, Promise
					 	, this
					 	, CleanupPending = fg_Move(CleanupPending)
					]
				 	(::NMib::NNetwork::ENetTCPState _StateAdded) mutable
					{
						if (_StateAdded & NNetwork::ENetTCPState_Closed)
						{
							if (!pReplied->f_Exchange(true))
							{
								NStr::CStr Error;
								if (!*pPendingDeleted)
									Error = pPending->m_pSocket->f_GetCloseReason();
								else
									Error = "Client connection actor was deleted";

								Promise.f_SetException(DMibErrorInstance(Error));
							}

							CleanupPending.f_Clear();
						}
						else if (_StateAdded & NNetwork::ENetTCPState_Connected)
						{
							if (pReplied->f_Exchange(true))
							{
								CleanupPending.f_Clear();
								return;
							}

							auto This = WeakThis.f_Lock();
							if (!This || *pPendingDeleted)
								return Promise.f_SetException(DMibErrorInstance("Client connection actor was deleted"));

							NStorage::TCUniquePointer<NNetwork::ICSocket> pNewSocket = fg_Move(pPending->m_pSocket);
							CleanupPending.f_Clear();

							NConcurrency::TCActor<CAsyncSocketActor> ConnectionActor
								= NConcurrency::fg_ConstructActor<CAsyncSocketActor>(true, mp_MaxMessageSize, mp_FragmentationSize, mp_Timeout)
							;

							auto fFinishConnection = [&ConnectionActor, &pNewSocket, Promise]() mutable
								{
									ConnectionActor(&CAsyncSocketActor::fp_SetSocket, fg_Move(pNewSocket)) > NConcurrency::fg_DiscardResult();

									NConcurrency::g_Dispatch(NConcurrency::fg_ConcurrentActor())
										/ [ConnectionActor]() mutable -> NConcurrency::TCFuture<CAsyncSocketNewClientConnection>
										{
											auto ConnectionResult = co_await ConnectionActor(&CAsyncSocketActor::fp_FinishConnection);

											if (ConnectionResult.m_Result == CAsyncSocketActor::EFinishConnectionResult_Error)
												co_return DMibErrorInstance(ConnectionResult.m_ConnectionInfo.m_Error);

											co_return CAsyncSocketNewClientConnection
												(
													fg_Move(ConnectionActor)
													, fg_Move(ConnectionResult.m_ConnectionInfo.m_pSocketInfo)
													, ConnectionResult.m_ConnectionInfo.m_PeerAddress
												)
											;
										}
										> Promise
									;
								}
							;

							// Lambda will be destroyed when this is called, this is why we capture everything in fFinishConnection
							pNewSocket->f_SetOnStateChange
								(
									[WeakConnectionActor = ConnectionActor.f_Weak()](NNetwork::ENetTCPState _StateAdded)
									{
										auto ConnectionActor = WeakConnectionActor.f_Lock();
										if (!ConnectionActor)
											return;
										ConnectionActor(&CAsyncSocketActor::fp_StateAdded, _StateAdded) > NConcurrency::fg_DiscardResult();
									}
								)
							;

							fFinishConnection();
						}
					}
					, BindToAddress
				)
			;
			pReplied.f_Clear();
		}
		catch (NCryptography::CExceptionCryptography const &_Exception)
		{
			co_return _Exception.f_ExceptionPointer();
		}
		catch (NNetwork::CExceptionNet const &_Exception)
		{
			co_return _Exception.f_ExceptionPointer();
		}

		co_return co_await Promise.f_MoveFuture();
	}
}
