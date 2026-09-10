// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Core/Core>
#include <Mib/Test/Test>
#include <Mib/Network/ResolveActor>

using namespace NMib;
using namespace NMib::NNetwork;
using namespace NMib::NConcurrency;
using namespace NMib::NStorage;

namespace
{
	struct CResolveActor_Tests : NTest::CTest
	{
		void f_DoTests()
		{
			DMibTestSuite("Addresses") -> TCFuture<void>
			{
				auto Resolver = fg_ConstructActor<CResolveActor>();

				for (auto PreferType : {ENetAddressType_TCPv4, ENetAddressType_TCPv6})
				{
					DMibTestPath(PreferType == ENetAddressType_TCPv4 ? "IPv4" : "IPv6");
					auto Lookup = co_await Resolver.f_Bind<&CResolveActor::f_ResolveHost>(NStr::CStr("localhost"), PreferType);
					auto Addresses = co_await fg_Move(Lookup.m_Result);

					DMibExpectFalse(Addresses.f_IsEmpty());
					DMibExpect(Addresses[0].f_GetType(), ==, PreferType);
				}

				auto Lookup = co_await Resolver.f_Bind<&CResolveActor::f_ResolveHost>(NStr::CStr("localhost"), ENetAddressType_None);
				auto Addresses = co_await fg_Move(Lookup.m_Result);
				bool bIPv4 = false;
				bool bIPv6 = false;
				for (auto const &Address : Addresses)
				{
					bIPv4 |= Address.f_GetType() == ENetAddressType_TCPv4;
					bIPv6 |= Address.f_GetType() == ENetAddressType_TCPv6;
				}

				DMibExpectTrue(bIPv4);
				DMibExpectTrue(bIPv6);

				auto BlockingActorCheckout = fg_BlockingActor();
				auto Scoped = co_await
					(
						g_Dispatch(BlockingActorCheckout) / []
						{
							return CSocket::fs_ResolveHost("fe80::1%1", ENetAddressType_TCPv6);
						}
					)
				;

				DMibAssertFalse(Scoped.f_IsEmpty());
				DMibExpect(Scoped[0].f_GetScopeID(), ==, 1u);
				DMibExpect(Scoped[0].f_GetType(), ==, ENetAddressType_TCPv6);

				auto ScopedLookup = co_await Resolver.f_Bind<&CResolveActor::f_ResolveHost>(NStr::CStr("fe80::1%1"), ENetAddressType_TCPv6);
				auto ScopedResults = co_await fg_Move(ScopedLookup.m_Result);

				DMibAssertFalse(ScopedResults.f_IsEmpty());
				DMibExpect(ScopedResults[0].f_GetScopeID(), ==, 1u);

				CNetAddress ScopedCopy = Scoped[0];
				Scoped.f_Clear();

				DMibExpect(ScopedCopy.f_GetScopeID(), ==, 1u);
				DMibExpect(ScopedCopy.f_GetType(), ==, ENetAddressType_TCPv6);
				DMibExpect(CNetAddress{}.f_GetScopeID(), ==, 0u);

				CNetAddressTCPv6 IPv6;
				DMibExpectTrue(ScopedCopy.f_Get(IPv6));
				DMibExpect(IPv6.m_IP[0], ==, 0xfe);
				DMibExpect(IPv6.m_IP[15], ==, 1);

				auto AddressLookup = co_await Resolver.f_Bind<&CResolveActor::f_Resolve>(NStr::CStr("127.0.0.1:1234"), ENetAddressType_TCPv4);
				auto AddressResults = co_await fg_Move(AddressLookup.m_Result);

				DMibAssertFalse(AddressResults.f_IsEmpty());
				auto &Address = AddressResults[0];

				DMibExpect(Address.f_GetPort(), ==, 1234);
				DMibExpect(Address.f_GetScopeID(), ==, 0u);

				co_await fg_Move(Resolver).f_Destroy();

				co_return {};
			};

			DMibTestSuite("EndpointCompatibility") -> TCFuture<void>
			{
				auto Resolver = fg_ConstructActor<CResolveActor>();
				auto BlockingActorCheckout = fg_BlockingActor();

				for
				(
					auto const *pAddress :
					{
						"127.0.0.1:1234"
						, "IPv4:127.0.0.1:http"
						, "IPv6:[::1]:1234"
						, "IPv6:[fe80::1%1]:1234"
						, "UNIX:resolver-vector.socket"
						, "UNIX(0700):resolver-vector-mode.socket"
						, "127.0.0.1:not-a-service"
						, "UNIX("
					}
				)
				{
					DMibTestPath(pAddress);

					auto Previous = co_await
						(
							g_Dispatch(BlockingActorCheckout) / [Text = NStr::CStr(pAddress)]
							{
								return CSocket::fs_ResolveAddress(Text, ENetAddressType_None);
							}
						)
						.f_Wrap()
					;

					auto Lookup = co_await Resolver.f_Bind<&CResolveActor::f_Resolve>(NStr::CStr(pAddress), ENetAddressType_None);
					auto Result = co_await fg_Move(Lookup.m_Result).f_Wrap();

					DMibExpect(bool(Result), ==, bool(Previous));
					if (Result && Previous)
					{
						DMibAssertFalse(Result->f_IsEmpty());
						DMibExpect((*Result)[0], ==, *Previous);
						DMibExpect((*Result)[0].f_GetScopeID(), ==, Previous->f_GetScopeID());

						bool bPortsMatch = true;
						for (auto const &Address : *Result)
							bPortsMatch &= Address.f_GetPort() == Previous->f_GetPort();

						DMibExpectTrue(bPortsMatch);
					}
				}

				co_await fg_Move(Resolver).f_Destroy();

				co_return {};
			};

			DMibTestSuite("BlockingLimit") -> TCFuture<void>
			{
				struct CState
				{
					NThread::CEvent Release;
					TCPromise<void> Saturated;
					NAtomic::TCAtomic<uint32> Started{0};
					NAtomic::TCAtomic<uint32> CancelledStarted{0};
				};

				TCSharedPointer<CState> pState = fg_Construct();
				pState->Release.f_ResetSignaled();
				auto Cleanup = g_OnScopeExit / [pState]
					{
						pState->Release.f_SetSignaled();
					}
				;

				CResolveActor::FHostResolver fResolve = [pState](NStr::CStr const &_Host, ENetAddressType)
					{
						if (_Host == "cancelled.test")
							pState->CancelledStarted.f_FetchAdd(1);
						if (pState->Started.f_FetchAdd(1) == 1)
							pState->Saturated.f_SetResult();

						(void)pState->Release.f_WaitTimeout(5.0);

						return CResolveActor::CAddresses{CNetAddress(CNetAddressTCPv4(CNetAddressIPv4(127, 0, 0, 1), 0))};
					}
				;

				auto Resolver = fg_ConstructActor<CResolveActor>(fResolve, 2);
				auto First = co_await Resolver.f_Bind<&CResolveActor::f_ResolveHost>(NStr::CStr("first.test"), ENetAddressType_None);
				auto Second = co_await Resolver.f_Bind<&CResolveActor::f_ResolveHost>(NStr::CStr("second.test"), ENetAddressType_None);
				co_await pState->Saturated.f_Future().f_Timeout(5.0, "Resolver did not fill its slots");

				auto Cancelled = co_await Resolver.f_Bind<&CResolveActor::f_ResolveHost>(NStr::CStr("cancelled.test"), ENetAddressType_None);
				auto Queued = co_await Resolver.f_Bind<&CResolveActor::f_ResolveHost>(NStr::CStr("queued.test"), ENetAddressType_None);
				auto AddressLookup = co_await Resolver.f_Bind<&CResolveActor::f_Resolve>(NStr::CStr("127.0.0.1:1234"), ENetAddressType_TCPv4);
				co_await AddressLookup.m_Cancel->f_Destroy();
				auto AddressResult = co_await fg_Move(AddressLookup.m_Result).f_Wrap();

				DMibExpectFalse(bool(AddressResult));

				auto EmptyLookup = co_await Resolver.f_Bind<&CResolveActor::f_Resolve>(NStr::CStr{}, ENetAddressType_None);
				auto EmptyAddresses = co_await fg_Move(EmptyLookup.m_Result).f_Timeout(5.0, "Empty address waited for the sequencer");

				DMibAssert(EmptyAddresses.f_GetLen(), ==, 1u);
				DMibExpectTrue(EmptyAddresses[0].f_IsEmpty());
				DMibExpectFalse(bool(EmptyLookup.m_Cancel));

				co_await Cancelled.m_Cancel->f_Destroy();
				co_await First.m_Cancel->f_Destroy();

				auto CancelledResult = co_await fg_Move(Cancelled.m_Result).f_Wrap();
				auto FirstResult = co_await fg_Move(First.m_Result).f_Wrap();
				co_await fg_Timeout(0.05);

				DMibExpectFalse(bool(CancelledResult));
				DMibExpectFalse(bool(FirstResult));
				DMibExpect(pState->Started.f_Load(), ==, 2u);

				pState->Release.f_SetSignaled();
				co_await fg_Move(Second.m_Result);
				co_await fg_Move(Queued.m_Result);

				DMibExpect(pState->Started.f_Load(), ==, 3u);
				DMibExpect(pState->CancelledStarted.f_Load(), ==, 0u);

				co_await fg_Move(Resolver).f_Destroy();

				co_return {};
			};

			DMibTestSuite("CancelPending") -> TCFuture<void>
			{
				for (bool bDestroyActor : {false, true})
				{
					DMibTestPath(bDestroyActor ? "Destroy" : "Cancel");

					struct CState
					{
						NThread::CEvent Release;
						TCPromise<void> Started;
						TCPromise<void> Finished;
					};

					TCSharedPointer<CState> pState = fg_Construct();
					pState->Release.f_ResetSignaled();
					auto Cleanup = g_OnScopeExit / [pState]
						{
							pState->Release.f_SetSignaled();
						}
					;

					CResolveActor::FHostResolver fResolve = [pState](NStr::CStr const &, ENetAddressType)
						{
							pState->Started.f_SetResult();
							pState->Release.f_Wait();
							pState->Finished.f_SetResult();

							return CResolveActor::CAddresses{CNetAddress(CNetAddressTCPv4(CNetAddressIPv4(127, 0, 0, 1), 0))};
						}
					;

					auto Resolver = fg_ConstructActor<CResolveActor>(fResolve);
					auto Lookup = co_await Resolver.f_Bind<&CResolveActor::f_ResolveHost>(NStr::CStr("pending.test"), ENetAddressType_None);
					co_await pState->Started.f_Future();

					// A timeout releases the backend even if cancellation accidentally waits for it.
					auto Watchdog = co_await fg_OneshotTimerAbortable
						(
							5.0
							, [pState]() -> TCFuture<void>
							{
								pState->Release.f_SetSignaled();

								co_return {};
							}
						)
					;

					if (bDestroyActor)
						co_await fg_Move(Resolver).f_Destroy();
					else
						co_await Lookup.m_Cancel->f_Destroy();

					auto Result = co_await fg_Move(Lookup.m_Result).f_Wrap();

					DMibExpectFalse(bool(Result));
					DMibExpectFalse(pState->Finished.f_IsSet());

					pState->Release.f_SetSignaled();
					co_await pState->Finished.f_Future();
					co_await Watchdog->f_Destroy();

					if (Resolver)
						co_await fg_Move(Resolver).f_Destroy();
				}

				co_return {};
			};
		}
	};

	DMibTestRegister(CResolveActor_Tests, Malterlib::Network);
}
