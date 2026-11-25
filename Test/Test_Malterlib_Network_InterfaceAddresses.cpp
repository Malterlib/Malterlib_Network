// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Core/Core>
#include <Mib/Test/Test>
#include <Mib/Network/InterfaceAddresses>
#include <Mib/Concurrency/Actor/Timer>

using namespace NMib;
using namespace NMib::NConcurrency;
using namespace NMib::NContainer;
using namespace NMib::NNetwork;
using namespace NMib::NStorage;
using namespace NMib::NStr;

struct CInterfaceAddresses_Tests : public NMib::NTest::CTest
{
	void f_DoTests();
};

void CInterfaceAddresses_Tests::f_DoTests()
{
	DMibTestSuite("List")
	{
#ifdef DPlatformFamily_macOS
		TCVector<CNetInterfaceAddressIPv4> Addresses = fg_GetInterfaceAddressesIPv4();

		CNetInterfaceAddressIPv4 const *pLoopback = nullptr;
		for (auto &Address : Addresses)
		{
			if (Address.m_Address.m_IP[0] == 127 && Address.m_Address.m_IP[1] == 0 && Address.m_Address.m_IP[2] == 0 && Address.m_Address.m_IP[3] == 1)
				pLoopback = &Address;
		}

		DMibAssertTrue(pLoopback != nullptr);
		DMibExpect(pLoopback->m_InterfaceName, ==, "lo0");
		DMibExpect(CStr("{}.{}.{}.{}"_f << pLoopback->m_Mask.m_IP[0] << pLoopback->m_Mask.m_IP[1] << pLoopback->m_Mask.m_IP[2] << pLoopback->m_Mask.m_IP[3]), ==, "255.0.0.0");
		DMibExpectFalse(pLoopback->m_bPointToPoint);
#else
		bool bRefused = false;
		try
		{
			fg_GetInterfaceAddressesIPv4();
		}
		catch (CExceptionNet const &)
		{
			bRefused = true;
		}

		DMibExpectTrue(bRefused);
#endif
	};

	DMibTestSuite("Subscribe Changes") -> TCFuture<void>
	{
		// A real change of the host addresses needs root, so this checks that a subscription starts, reports nothing while the addresses stay the
		// same, and releases the subscriber when it is destroyed
		TCActor<CActor> Subscriber = fg_Construct();
		TCSharedPointer<NAtomic::TCAtomic<umint>> pChanges = fg_Construct(umint(0));
		TCSharedPointer<int32> pCaptured = fg_Construct(0);
		umint nOwnReferences = pCaptured.f_GetRefCount();

		CActorFunctorCoalesced fOnChange = g_ActorFunctorCoalesced(Subscriber) / [pChanges, pCaptured]() -> TCFuture<void>
			{
				pChanges->f_FetchAdd(1);
				co_return {};
			}
		;

		auto SubscribeResult = co_await fg_SubscribeInterfaceAddressChangesIPv4(fg_Move(fOnChange)).f_Wrap();

#ifdef DPlatformFamily_macOS
		DMibAssert(SubscribeResult ? CStr() : SubscribeResult.f_GetExceptionStr(), ==, "");

		co_await fg_Timeout(0.5);
		umint nChangesWhileSubscribed = pChanges->f_Load();
		DMibExpect(nChangesWhileSubscribed, ==, 0);

		co_await (*SubscribeResult)->f_Destroy();

		umint nReferencesAfterDestroy = pCaptured.f_GetRefCount();
		DMibExpect(nReferencesAfterDestroy, ==, nOwnReferences);
#else
		DMibExpectFalse(bool(SubscribeResult));

		umint nReferencesAfterFailure = pCaptured.f_GetRefCount();
		DMibExpect(nReferencesAfterFailure, ==, nOwnReferences);
#endif

		co_await fg_Move(Subscriber).f_Destroy();

		co_return {};
	};
}

DMibTestRegister(CInterfaceAddresses_Tests, Malterlib::Network);
