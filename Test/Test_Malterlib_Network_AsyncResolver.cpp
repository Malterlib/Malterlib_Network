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
		void f_DoTests();
	};

	void CAsyncResolver_Tests::f_DoTests()
	{
		DMibTestSuite("CloseAsync") -> TCFuture<void>
		{
			struct CState
			{
				NThread::CEvent m_Release;
				TCPromise<void> m_Started;
				TCPromise<void> m_Finished;
				NAtomic::TCAtomic<uint32> m_PendingCallbacks{0};
				NAtomic::TCAtomic<uint32> m_CloseCallbacks{0};
			};

			TCSharedPointer<CState> pState = fg_Construct();
			TCSharedPointer<NThread::CEvent> pClosed = fg_Construct();
			pState->m_Release.f_ResetSignaled();
			auto Cleanup = g_OnScopeExit / [pState]
				{
					pState->m_Release.f_SetSignaled();
				}
			;

			CAsyncResolver Resolver;
			Resolver.f_Open
				(
					"127.0.0.1:1234"
					, ENetAddressType_TCPv4
					, [pState]
					{
						pState->m_Started.f_SetResult();
						(void)pState->m_Release.f_WaitTimeout(5.0);
						pState->m_Finished.f_SetResult();
					}
				)
			;

			co_await pState->m_Started.f_Future().f_Timeout(5.0, "Resolver did not start");

			// The worker is inside the first callback, so these requests stay queued.
			CAsyncResolver Pending;
			Pending.f_Open
				(
					"127.0.0.1"
					, ENetAddressType_TCPv4
					, [pState]
					{
						pState->m_PendingCallbacks.f_FetchAdd(1);
					}
				)
			;

			Pending.f_CloseAsync
				(
					[pState]
					{
						pState->m_CloseCallbacks.f_FetchAdd(1);
					}
				)
			;

			DMibExpect(pState->m_CloseCallbacks.f_Load(), ==, 1u);
			DMibExpect(pState->m_PendingCallbacks.f_Load(), ==, 0u);

			Pending.f_CloseAsync
				(
					[pState]
					{
						pState->m_CloseCallbacks.f_FetchAdd(1);
					}
				)
			;

			DMibExpect(pState->m_CloseCallbacks.f_Load(), ==, 2u);

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

			DMibExpectFalse(pState->m_Finished.f_IsSet());
			DMibExpectFalse(pClosed->f_TryWait());

			pState->m_Release.f_SetSignaled();
			co_await fg_WaitForClosed(pClosed, "Resolver close did not complete");

			DMibTestPath("AfterClose");
			DMibExpectTrue(pState->m_Finished.f_IsSet());
			DMibExpect(pState->m_PendingCallbacks.f_Load(), ==, 0u);

			co_return {};
		};

		DMibTestSuite("ReleaseWhileActive") -> TCFuture<void>
		{
			for (bool bReopen : {false, true})
			{
				DMibTestPath(bReopen ? "Reopen" : "Destroy");

				struct CState
				{
					NThread::CEvent m_Release;
					TCPromise<void> m_Started;
					TCPromise<void> m_Finished;
					TCPromise<void> m_NextFinished;
				};

				TCSharedPointer<CState> pState = fg_Construct();
				TCSharedPointer<NThread::CEvent> pClosed = fg_Construct();
				pState->m_Release.f_ResetSignaled();
				auto Cleanup = g_OnScopeExit / [pState]
					{
						pState->m_Release.f_SetSignaled();
					}
				;

				TCUniquePointer<CAsyncResolver> pResolver = fg_Construct();
				pResolver->f_Open
					(
						"127.0.0.1"
						, ENetAddressType_TCPv4
						, [pState]
						{
							pState->m_Started.f_SetResult();
							(void)pState->m_Release.f_WaitTimeout(5.0);
							pState->m_Finished.f_SetResult();
						}
					)
				;

				co_await pState->m_Started.f_Future().f_Timeout(5.0, "Resolver did not start");

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
							pState->m_NextFinished.f_SetResult();
						}
					)
				;

				DMibExpectFalse(pState->m_Finished.f_IsSet());

				pState->m_Release.f_SetSignaled();
				co_await pState->m_NextFinished.f_Future().f_Timeout(5.0, "Next lookup did not finish");

				DMibExpectTrue(pState->m_Finished.f_IsSet());

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
				CAsyncResolver m_Resolver;
				NThread::CEvent m_Opened;
				TCPromise<void> m_Finished;
			};

			TCSharedPointer<CState> pState = fg_Construct();
			TCSharedPointer<NThread::CEvent> pClosed = fg_Construct();
			pState->m_Opened.f_ResetSignaled();
			pState->m_Resolver.f_Open
				(
					"127.0.0.1"
					, ENetAddressType_TCPv4
					, [pState, pClosed]
					{
						pState->m_Opened.f_Wait();
						pState->m_Resolver.f_CloseAsync
							(
								[pClosed]
								{
									pClosed->f_SetSignaled();
								}
							)
						;

						pState->m_Finished.f_SetResult();
					}
				)
			;

			pState->m_Opened.f_SetSignaled();
			co_await fg_WaitForClosed(pClosed, "Close from callback did not complete");

			DMibExpectTrue(pState->m_Finished.f_IsSet());

			co_return {};
		};
	}

	DMibTestRegister(CAsyncResolver_Tests, Malterlib::Network);
}
