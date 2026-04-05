// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Concurrency/ConcurrencyManager>

#include "Malterlib_Network_AsyncSocket.h"

namespace NMib::NNetwork
{
	///
	/// Shared
	///	======

	CAsyncSocketNewConnection::CAsyncSocketNewConnection(NConcurrency::TCActor<CAsyncSocketActor> const &_Connection)
		: mp_Connection(_Connection)
		, mp_pHelper(fg_Construct(_Connection))
	{
	}

	CAsyncSocketNewConnection::CAsyncSocketNewConnection(CAsyncSocketNewConnection &&_Other) = default;

	CAsyncSocketNewConnection::~CAsyncSocketNewConnection()
	{
		mp_pHelper.f_Clear();
	}

	void CAsyncSocketNewConnection::f_Reject(NStr::CStr const &_Error) const
	{
		if (!mp_pHelper->m_bRepliedToConnection.f_Exchange(true))
		{
			mp_Connection.f_Bind<&CAsyncSocketActor::fp_RejectConnection>(_Error).f_DiscardResult();
		}
	}

	NConcurrency::TCUnsafeFuture<NConcurrency::TCActorInterface<CAsyncSocketActor>> CAsyncSocketNewConnection::f_Accept(CAsyncSocketCallbacks _Callbacks)
	{
		if (mp_pHelper->m_bRepliedToConnection.f_Exchange(true))
			co_return DMibErrorInstance("Connection already accepted or rejected");

		auto Connection = fg_Move(mp_Connection);

		auto Subscription = co_await Connection(&CAsyncSocketActor::fp_AcceptConnection, fg_Move(_Callbacks));
		co_return NConcurrency::TCActorInterface<CAsyncSocketActor>(fg_Move(Connection), fg_Move(Subscription));
	}

	CAsyncSocketNewConnection::CRepliedHelper::CRepliedHelper(NConcurrency::TCActor<CAsyncSocketActor> const &_Connection)
		: m_Connection(_Connection)
	{
	}

	CAsyncSocketNewConnection::CRepliedHelper::~CRepliedHelper()
	{
		if (!m_bRepliedToConnection.f_Exchange(true))
			m_Connection.f_Bind<&CAsyncSocketActor::fp_RejectConnection>("Abandoned").f_DiscardResult();
	}

	///
	/// Server connection
	/// =================

	CAsyncSocketNewServerConnection::CAsyncSocketNewServerConnection
		(
			CAsyncSocketActor::CConnectionInfo &&_ConnectionInfo
			, NConcurrency::TCActor<CAsyncSocketActor> const &_Connection
		)
		: CAsyncSocketNewConnection(_Connection)
		, m_Info(fg_Move(_ConnectionInfo))
	{

	}

	CAsyncSocketNewServerConnection::CAsyncSocketNewServerConnection(CAsyncSocketNewServerConnection &&_Other) = default;

	///
	/// Client connection
	/// =================

	CAsyncSocketNewClientConnection::CAsyncSocketNewClientConnection
		(
			NConcurrency::TCActor<CAsyncSocketActor> const &_Connection
			, NStorage::TCUniquePointer<NNetwork::ICSocketConnectionInfo> &&_pSocketInfo
			, NMib::NNetwork::CNetAddress const &_PeerAddress
		)
		: CAsyncSocketNewConnection(_Connection)
		, m_pSocketInfo(fg_Move(_pSocketInfo))
		, m_PeerAddress(_PeerAddress)
	{
	}

	CAsyncSocketNewClientConnection::CAsyncSocketNewClientConnection(CAsyncSocketNewClientConnection &&_Other) = default;
}
