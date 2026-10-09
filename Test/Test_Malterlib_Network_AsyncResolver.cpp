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
	// The worker destroys a close callback only after calling it, which can be after the test has ended and the concurrency manager is
	// gone. Close callbacks therefore signal an event, as a promise they kept alive would be reported as a leaked future
	TCFuture<void> fg_WaitForClosed(TCSharedPointer<NThread::CEvent> _pClosed, NStr::CStr _Error)
	{
		auto BlockingActorCheckout = fg_BlockingActor();
		bool bTimedOut = co_await
			(
				g_Dispatch(BlockingActorCheckout) / [_pClosed]
				{
					return _pClosed->f_WaitTimeout(5.0);
				}
			)
		;

		if (bTimedOut)
			co_return DMibErrorInstance(_Error);

		co_return {};
	}

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
					NAtomic::TCAtomic<uint32> PendingCallbacks{0};
					NAtomic::TCAtomic<uint32> CloseCallbacks{0};
				};

				TCSharedPointer<CState> pState = fg_Construct();
				TCSharedPointer<NThread::CEvent> pClosed = fg_Construct();
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
						[pClosed]
						{
							pClosed->f_SetSignaled();
						}
					)
				;

				DMibExpectFalse(pState->Finished.f_IsSet());
				DMibExpectFalse(pClosed->f_TryWait());

				pState->Release.f_SetSignaled();
				co_await fg_WaitForClosed(pClosed, "Resolver close did not complete");

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
					};

					TCSharedPointer<CState> pState = fg_Construct();
					TCSharedPointer<NThread::CEvent> pClosed = fg_Construct();
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
							[pClosed]
							{
								pClosed->f_SetSignaled();
							}
						)
					;

					co_await fg_WaitForClosed(pClosed, "Resolver close did not complete");
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
				};

				TCSharedPointer<CState> pState = fg_Construct();
				TCSharedPointer<NThread::CEvent> pClosed = fg_Construct();
				pState->Opened.f_ResetSignaled();
				pState->Resolver.f_Open
					(
						"127.0.0.1"
						, ENetAddressType_TCPv4
						, [pState, pClosed]
						{
							pState->Opened.f_Wait();
							pState->Resolver.f_CloseAsync
								(
									[pClosed]
									{
										pClosed->f_SetSignaled();
									}
								)
							;

							pState->Finished.f_SetResult();
						}
					)
				;

				pState->Opened.f_SetSignaled();
				co_await fg_WaitForClosed(pClosed, "Close from callback did not complete");

				DMibExpectTrue(pState->Finished.f_IsSet());

				co_return {};
			};
		}
	};

	DMibTestRegister(CAsyncResolver_Tests, Malterlib::Network);
}
