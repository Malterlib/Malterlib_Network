// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Core/Core>
#include <Mib/Test/Test>
#include <Mib/Network/Socket>
#include <Mib/Concurrency/ConcurrencyManager>

using namespace NMib;
using namespace NMib::NNetwork;
using namespace NMib::NConcurrency;
using namespace NMib::NStorage;

namespace
{
	struct CAsyncResolver_Tests : NTest::CTest
	{
		void f_DoTests()
		{
			DMibTestSuite("CloseAsync") -> TCFuture<void>
			{
				struct CState
				{
					NThread::CEvent Release;
					TCPromise<void> Started;
					TCPromise<void> Finished;
					TCPromise<void> Closed;
					NAtomic::TCAtomic<uint32> PendingCallbacks{0};
					NAtomic::TCAtomic<uint32> CloseCallbacks{0};
				};

				TCSharedPointer<CState> pState = fg_Construct();
				pState->Release.f_ResetSignaled();
				auto Cleanup = g_OnScopeExit / [pState]
					{
						pState->Release.f_SetSignaled();
					}
				;

				CAsyncResolver Resolver;
				Resolver.f_Open
					(
						"127.0.0.1:1234"
						, ENetAddressType_TCPv4
						, [pState]
						{
							pState->Started.f_SetResult();
							(void)pState->Release.f_WaitTimeout(5.0);
							pState->Finished.f_SetResult();
						}
					)
				;

				co_await pState->Started.f_Future().f_Timeout(5.0, "Resolver did not start");

				// The worker is inside the first callback, so these requests stay queued.
				CAsyncResolver Pending;
				Pending.f_Open
					(
						"127.0.0.1"
						, ENetAddressType_TCPv4
						, [pState]
						{
							pState->PendingCallbacks.f_FetchAdd(1);
						}
					)
				;

				Pending.f_CloseAsync
					(
						[pState]
						{
							pState->CloseCallbacks.f_FetchAdd(1);
						}
					)
				;

				DMibExpect(pState->CloseCallbacks.f_Load(), ==, 1u);
				DMibExpect(pState->PendingCallbacks.f_Load(), ==, 0u);

				// A repeated close consumes no second request and still acknowledges once.
				Pending.f_CloseAsync
					(
						[pState]
						{
							pState->CloseCallbacks.f_FetchAdd(1);
						}
					)
				;

				DMibExpect(pState->CloseCallbacks.f_Load(), ==, 2u);

				CNetAddress Address;
				NStr::CStr Error;
				DMibExpectTrue(Resolver.f_GetResult(Address, Error));
				DMibExpect(Address.f_GetPort(), ==, 1234);

				Resolver.f_CloseAsync
					(
						[pState]
						{
							pState->Closed.f_SetResult();
						}
					)
				;

				DMibExpectFalse(pState->Finished.f_IsSet());
				DMibExpectFalse(pState->Closed.f_IsSet());

				pState->Release.f_SetSignaled();
				co_await pState->Closed.f_Future().f_Timeout(5.0, "Resolver close did not complete");

				DMibTestPath("AfterClose");
				DMibExpectTrue(pState->Finished.f_IsSet());
				DMibExpect(pState->PendingCallbacks.f_Load(), ==, 0u);

				co_return {};
			};

			DMibTestSuite("ReleaseWhileActive") -> TCFuture<void>
			{
				for (bool bReopen : {false, true})
				{
					DMibTestPath(bReopen ? "Reopen" : "Destroy");

					struct CState
					{
						NThread::CEvent Release;
						TCPromise<void> Started;
						TCPromise<void> Finished;
						TCPromise<void> NextFinished;
						TCPromise<void> Closed;
					};

					TCSharedPointer<CState> pState = fg_Construct();
					pState->Release.f_ResetSignaled();
					auto Cleanup = g_OnScopeExit / [pState]
						{
							pState->Release.f_SetSignaled();
						}
					;

					TCUniquePointer<CAsyncResolver> pResolver = fg_Construct();
					pResolver->f_Open
						(
							"127.0.0.1"
							, ENetAddressType_TCPv4
							, [pState]
							{
								pState->Started.f_SetResult();
								(void)pState->Release.f_WaitTimeout(5.0);
								pState->Finished.f_SetResult();
							}
						)
					;

					co_await pState->Started.f_Future().f_Timeout(5.0, "Resolver did not start");

					if (!bReopen)
					{
						pResolver.f_Clear();
						pResolver = fg_Construct();
					}

					pResolver->f_Open
						(
							"127.0.0.1"
							, ENetAddressType_TCPv4
							, [pState]
							{
								pState->NextFinished.f_SetResult();
							}
						)
					;

					DMibExpectFalse(pState->Finished.f_IsSet());

					pState->Release.f_SetSignaled();
					co_await pState->NextFinished.f_Future().f_Timeout(5.0, "Next lookup did not finish");

					DMibExpectTrue(pState->Finished.f_IsSet());

					pResolver->f_CloseAsync
						(
							[pState]
							{
								pState->Closed.f_SetResult();
							}
						)
					;

					co_await pState->Closed.f_Future();
				}

				co_return {};
			};

			DMibTestSuite("CloseFromCallback") -> TCFuture<void>
			{
				struct CState
				{
					CAsyncResolver Resolver;
					NThread::CEvent Opened;
					TCPromise<void> Finished;
					TCPromise<void> Closed;
				};

				TCSharedPointer<CState> pState = fg_Construct();
				pState->Opened.f_ResetSignaled();
				pState->Resolver.f_Open
					(
						"127.0.0.1"
						, ENetAddressType_TCPv4
						, [pState]
						{
							pState->Opened.f_Wait();
							pState->Resolver.f_CloseAsync
								(
									[pState]
									{
										pState->Closed.f_SetResult();
									}
								)
							;

							pState->Finished.f_SetResult();
						}
					)
				;

				pState->Opened.f_SetSignaled();
				co_await pState->Closed.f_Future().f_Timeout(5.0, "Close from callback did not complete");

				DMibExpectTrue(pState->Finished.f_IsSet());

				co_return {};
			};
		}
	};

	DMibTestRegister(CAsyncResolver_Tests, Malterlib::Network);
}
