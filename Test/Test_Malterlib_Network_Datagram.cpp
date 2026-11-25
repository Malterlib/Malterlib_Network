// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Core/Core>
#include <Mib/Test/Test>

#ifndef DPlatformFamily_Windows
#	include <netinet/in.h>
#	include <sys/socket.h>
#	include <unistd.h>
#endif

using namespace NMib;
using namespace NMib::NContainer;
using namespace NMib::NNetwork;
using namespace NMib::NStorage;
using namespace NMib::NStr;

namespace
{
	fp64 g_Timeout = 30.0 * NMib::NTest::gc_TimeoutMultiplier;
}

struct CDatagram_Tests : public NMib::NTest::CTest
{
	void f_DoTests();
};

void CDatagram_Tests::f_DoTests()
{
#ifndef DPlatformFamily_Windows
	DMibTestSuite("Connected Socket Pair")
	{
		int Files[2] = {-1, -1};
		DMibAssert(socketpair(AF_UNIX, SOCK_DGRAM, 0, Files), ==, 0);

		TCSharedPointer<NThread::CEvent> pReadable = fg_Construct();

		CSocket Sender;
		Sender.f_InheritDatagramHandle
			(
				(void *)umint(Files[0])
				, [](ENetTCPState _StateAdded)
				{
				}
			)
		;

		CSocket Receiver;
		Receiver.f_InheritDatagramHandle
			(
				(void *)umint(Files[1])
				, [pReadable](ENetTCPState _StateAdded)
				{
					if (_StateAdded & ENetTCPState_Read)
						pReadable->f_SetSignaled();
				}
			)
		;

		uint8 Buffer[256];

		{
			DMibTestPath("Readiness");

			// The socket reports itself readable once it starts, and again for a datagram that arrives after a receive found none
			bool bStartTimedOut = pReadable->f_WaitTimeout(g_Timeout);
			DMibAssertFalse(bStartTimedOut);
			pReadable->f_ResetSignaled();

			CDatagramReceiveResult Empty = Receiver.f_ReceiveDatagram(Buffer, sizeof(Buffer));
			DMibExpectFalse(Empty.m_bReceived);

			DMibAssertTrue(Sender.f_SendDatagram("Hello", 5));

			bool bReadableTimedOut = pReadable->f_WaitTimeout(g_Timeout);
			DMibAssertFalse(bReadableTimedOut);

			CDatagramReceiveResult Received = Receiver.f_ReceiveDatagram(Buffer, sizeof(Buffer));
			DMibAssertTrue(Received.m_bReceived);
			DMibExpect(Received.m_nBytes, ==, 5);
			DMibExpectFalse(Received.m_bTruncated);
			DMibExpect(CStr((ch8 const *)Buffer, Received.m_nBytes), ==, "Hello");
		}

		{
			DMibTestPath("Empty Datagram");

			DMibAssertTrue(Sender.f_SendDatagram(Buffer, 0));

			CDatagramReceiveResult Received = Receiver.f_ReceiveDatagram(Buffer, sizeof(Buffer));
			DMibExpectTrue(Received.m_bReceived);
			DMibExpect(Received.m_nBytes, ==, 0);
			DMibExpectFalse(Received.m_bTruncated);
		}

		{
			DMibTestPath("Truncated");

			uint8 Long[100];
			for (umint iByte = 0; iByte < sizeof(Long); ++iByte)
				Long[iByte] = uint8(iByte);

			DMibAssertTrue(Sender.f_SendDatagram(Long, sizeof(Long)));
			DMibAssertTrue(Sender.f_SendDatagram("After", 5));

			CDatagramReceiveResult Received = Receiver.f_ReceiveDatagram(Buffer, 10);
			DMibAssertTrue(Received.m_bReceived);
			DMibExpectTrue(Received.m_bTruncated);
			DMibExpect(Received.m_nBytes, ==, 10);
			DMibExpect(NMemory::fg_MemCmp(Buffer, Long, 10), ==, 0);

			// The rest of the truncated datagram is gone, so the next receive gets the next datagram
			CDatagramReceiveResult Next = Receiver.f_ReceiveDatagram(Buffer, sizeof(Buffer));
			DMibAssertTrue(Next.m_bReceived);
			DMibExpectFalse(Next.m_bTruncated);
			DMibExpect(CStr((ch8 const *)Buffer, Next.m_nBytes), ==, "After");

			CDatagramReceiveResult Empty = Receiver.f_ReceiveDatagram(Buffer, sizeof(Buffer));
			DMibExpectFalse(Empty.m_bReceived);
		}

		{
			DMibTestPath("Full Peer");

			// A send that the full receive buffer of the peer can't take is refused without an error, and sends succeed again once the peer reads
			uint8 Datagram[1000] = {};
			umint nSent = 0;
			bool bRefused = false;
			for (umint iSend = 0; iSend < 100000; ++iSend)
			{
				if (!Sender.f_SendDatagram(Datagram, sizeof(Datagram)))
				{
					bRefused = true;
					break;
				}

				++nSent;
			}

			DMibExpectTrue(bRefused);
			DMibExpect(nSent, >, 0);

			uint8 ReceiveBuffer[1000];
			CDatagramReceiveResult Received = Receiver.f_ReceiveDatagram(ReceiveBuffer, sizeof(ReceiveBuffer));
			DMibExpectTrue(Received.m_bReceived);
			DMibExpect(Received.m_nBytes, ==, sizeof(Datagram));

			DMibExpectTrue(Sender.f_SendDatagram(Datagram, sizeof(Datagram)));
		}

		Sender.f_Close();
		Receiver.f_Close();
	};

	DMibTestSuite("Inherited Bound Socket Sender")
	{
		auto fBindLoopback = [](int _File, ch8 const *_pName) -> uint16
			{
				DMibTestPath(_pName);

				sockaddr_in Address = {};
				Address.sin_family = AF_INET;
				Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
				DMibAssert(::bind(_File, (sockaddr const *)&Address, sizeof(Address)), ==, 0);

				socklen_t nAddress = sizeof(Address);
				DMibAssert(::getsockname(_File, (sockaddr *)&Address, &nAddress), ==, 0);

				return ntohs(Address.sin_port);
			}
		;

		int SenderFile = ::socket(AF_INET, SOCK_DGRAM, 0);
		DMibAssert(SenderFile, >=, 0);
		auto CloseSender = g_OnScopeExit / [&]
			{
				::close(SenderFile);
			}
		;
		uint16 SenderPort = fBindLoopback(SenderFile, "Sender");

		int ReceiverFile = ::socket(AF_INET, SOCK_DGRAM, 0);
		DMibAssert(ReceiverFile, >=, 0);
		uint16 ReceiverPort = fBindLoopback(ReceiverFile, "Receiver");

		sockaddr_in ReceiverAddress = {};
		ReceiverAddress.sin_family = AF_INET;
		ReceiverAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		ReceiverAddress.sin_port = htons(ReceiverPort);
		DMibAssert(::sendto(SenderFile, "Hello", 5, 0, (sockaddr const *)&ReceiverAddress, sizeof(ReceiverAddress)), ==, 5);

		TCSharedPointer<NThread::CEvent> pReadable = fg_Construct();

		CSocket Receiver;
		Receiver.f_InheritDatagramHandle
			(
				(void *)umint(ReceiverFile)
				, [pReadable](ENetTCPState _StateAdded)
				{
					if (_StateAdded & ENetTCPState_Read)
						pReadable->f_SetSignaled();
				}
			)
		;

		uint8 Buffer[256];
		CNetAddress Address = CNetAddressTCPv4{};
		umint nReceived = 0;
		bool bTimedOut = false;
		while (nReceived == 0 && !bTimedOut)
		{
			bTimedOut = pReadable->f_WaitTimeout(g_Timeout);
			pReadable->f_ResetSignaled();

			nReceived = Receiver.f_ReceiveDatagram(Address, Buffer, sizeof(Buffer));
		}

		DMibExpect(nReceived, ==, 5);
		DMibAssert(Address.f_GetType(), ==, ENetAddressType_TCPv4);
		DMibExpect(Address.f_GetPort(), ==, SenderPort);

		Receiver.f_Close();
	};
#endif
}

DMibTestRegister(CDatagram_Tests, Malterlib::Network);
