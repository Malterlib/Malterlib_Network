// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Network_InterfaceAddresses.h"
#include "Malterlib_Network_AsyncSocket.h"

#include <Mib/Concurrency/LogError>

namespace NMib::NNetwork::NPrivate
{
	// Reads the notifications of a handle of fg_OpenInterfaceAddressChangesIPv4. The actor shares the queue of the io loop that its socket reports to
	struct CInterfaceAddressChangesActor : public NConcurrency::CActor
	{
		CInterfaceAddressChangesActor(NConcurrency::CActorFunctorCoalesced &&_fOnChange);
		~CInterfaceAddressChangesActor();

		NConcurrency::TCFuture<void> f_Start(NConcurrency::CIoLoopBinding _Binding);

		static constexpr NConcurrency::EPriority mc_Priority = CAsyncSocketActor::mc_Priority;

	protected:
		NConcurrency::TCFuture<void> fp_Destroy() override;

	private:
		void fp_Read();

		static constexpr umint mcp_MessageBufferBytes = 2048; // A longer message is truncated, which counts as a change
		static constexpr umint mcp_nMessagesPerRead = 64;     // Other work of the queue runs between the reads of a burst of messages

		NConcurrency::CActorFunctorCoalesced mp_fOnChange;
		NContainer::TCVector<uint8> mp_MessageBuffer;
		CSocket mp_Socket;
		bool mp_bFailed = false;
	};

	CInterfaceAddressChangesActor::CInterfaceAddressChangesActor(NConcurrency::CActorFunctorCoalesced &&_fOnChange)
		: mp_fOnChange(fg_Move(_fOnChange))
	{
	}

	CInterfaceAddressChangesActor::~CInterfaceAddressChangesActor() = default;

	// The socket is created on the io loop of _Binding, whose queue this actor starts on, so its reports reach the actor without waking another
	// thread
	NConcurrency::TCFuture<void> CInterfaceAddressChangesActor::f_Start(NConcurrency::CIoLoopBinding _Binding)
	{
		auto CaptureScope = co_await (NConcurrency::g_CaptureExceptions % "Failed to watch the interface addresses");

		mp_MessageBuffer.f_SetLen(mcp_MessageBufferBytes);

		{
			NConcurrency::CIoLoopCreateScope IoLoopScope(_Binding);

			mp_Socket.f_InheritDatagramHandle
				(
					NSys::NNetwork::fg_OpenInterfaceAddressChangesIPv4()
					, [WeakThis = fg_ThisActor(this).f_Weak()](ENetTCPState _StateAdded)
					{
						if (!(_StateAdded & (ENetTCPState_Read | ENetTCPState_Closed)))
							return;

						auto This = WeakThis.f_Lock();
						if (!This)
							return;

						DMibLogWarningOrDiscardResult(This.f_Bind<&CInterfaceAddressChangesActor::fp_Read>(), "Mib/Network", "Failed to read the changes of the interface addresses");
					}
				)
			;
		}

		co_return {};
	}

	// Reports the messages that are waiting with one call of the subscriber, which the coalesced functor merges with a call that is still queued.
	// A read that stops at its limit continues in a later call, since the socket only reports readiness again once a read finds it empty
	void CInterfaceAddressChangesActor::fp_Read()
	{
		if (mp_bFailed || !mp_Socket.f_IsValid())
			return;

		bool bChanged = false;
		bool bDrained = false;
		try
		{
			for (umint iMessage = 0; iMessage < mcp_nMessagesPerRead; ++iMessage)
			{
				CDatagramReceiveResult Received = mp_Socket.f_ReceiveDatagram(mp_MessageBuffer.f_GetArray(), mp_MessageBuffer.f_GetLen());
				if (!Received.m_bReceived)
				{
					bDrained = true;
					break;
				}

				if (Received.m_bTruncated || NSys::NNetwork::fg_IsInterfaceAddressChange(mp_MessageBuffer.f_GetArray(), Received.m_nBytes))
					bChanged = true;
			}
		}
		catch (NException::CException const &_Exception)
		{
			// The socket reports nothing more, so the subscribers see later changes only through their periodic refreshes
			DMibLogWithCategory(Mib/Network, Error, "Stopped watching the interface addresses: {}", _Exception);
			mp_bFailed = true;
			bChanged = true;
		}

		if (bChanged)
			mp_fOnChange.f_CallDiscard();

		if (bDrained || mp_bFailed)
			return;

		DMibLogWarningOrDiscardResult
			(
				fg_ThisActor(this).f_Bind<&CInterfaceAddressChangesActor::fp_Read>()
				, "Mib/Network"
				, "Failed to continue reading the changes of the interface addresses"
			)
		;
	}

	NConcurrency::TCFuture<void> CInterfaceAddressChangesActor::fp_Destroy()
	{
		if (mp_Socket.f_IsValid())
		{
			NConcurrency::TCPromiseFuturePair<void> Closed;
			mp_Socket.f_CloseAsync
				(
					[Promise = fg_Move(Closed.m_Promise)]() mutable
					{
						Promise.f_SetResult();
					}
				)
			;

			co_await fg_Move(Closed.m_Future);
		}

		co_await fg_Move(mp_fOnChange).f_Destroy().f_Wrap() > NConcurrency::fg_LogError("Mib/Network", "Failed to destroy the subscriber of the interface address changes");

		co_return {};
	}
}

namespace NMib::NNetwork
{
	// Lists the IPv4 addresses of the interfaces of the host, with their masks and the peers of point-to-point interfaces. Throws CExceptionNet when
	// they can't be listed, and on platforms other than macOS, which don't support it yet
	NContainer::TCVector<CNetInterfaceAddressIPv4> fg_GetInterfaceAddressesIPv4()
	{
		return NSys::NNetwork::fg_GetInterfaceAddressesIPv4();
	}

	// Calls _fOnChange after IPv4 addresses of the host interfaces are added or removed, once for each burst of changes. Changes from when the
	// subscription resolves on are reported, so a subscriber that lists the addresses after subscribing misses none of the reports. The kernel drops
	// reports when they come faster than they are read, so a subscriber that must not miss a change also lists the addresses periodically.
	// Destroying the subscription stops the calls. Fails on platforms other than macOS, which don't support it yet
	auto fg_SubscribeInterfaceAddressChangesIPv4(NConcurrency::CActorFunctorCoalesced _fOnChange) -> NConcurrency::TCFuture<NConcurrency::CActorSubscription>
	{
		using namespace NPrivate;

		auto &Manager = NConcurrency::fg_ConcurrencyManager();
		NConcurrency::CIoLoopBinding Binding = Manager.f_PickIoLoopBinding(CInterfaceAddressChangesActor::mc_Priority);

		NConcurrency::TCActor<CInterfaceAddressChangesActor> Actor = Manager.f_ConstructActor(fg_Construct<CInterfaceAddressChangesActor>(fg_Move(_fOnChange)));
		if (Binding)
			Actor->f_SetInitialQueue(Binding.m_iQueue);

		auto StartResult = co_await Actor(&CInterfaceAddressChangesActor::f_Start, Binding).f_Wrap();
		if (!StartResult)
		{
			co_await fg_Move(Actor).f_Destroy().f_Wrap() > NConcurrency::fg_LogError("Mib/Network", "Failed to destroy the watch of the interface addresses");
			co_return StartResult.f_GetException();
		}

		co_return NConcurrency::g_ActorSubscription / [Actor = fg_Move(Actor)]() mutable -> NConcurrency::TCFuture<void>
			{
				co_await fg_Move(Actor).f_Destroy();
				co_return {};
			}
		;
	}
}
