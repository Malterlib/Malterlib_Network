// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Core/Core>
#include <Mib/Time/Timeout>
#include <Mib/Test/Test>
#include <Mib/Network/Socket>
#include <Mib/Network/Sockets/TCP>
#include <Mib/Cryptography/RandomID>
#include <Mib/File/File>

using namespace NMib;
using namespace NMib::NNetwork;
using namespace NMib::NStr;
using namespace NMib::NStorage;
using namespace NMib::NContainer;
using namespace NMib::NTime;

namespace
{
	fp32 const gc_Timeout = 30.0f;

	// Minimal ICSocket that only implements sending, used to verify the default vectored
	// fallback semantics: span order, zero length skipping and stop on short write
	struct CSendRecordingSocket : public ICSocket
	{
		struct CSendCall
		{
			void const *m_pData;
			umint m_nBytes;
		};

		umint m_MaxBytesPerSend = TCLimitsInt<umint>::mc_Max;
		TCVector<CSendCall> m_Calls;

		virtual CSocketOperationResult f_Send(const void *_pData, umint _DataLen) override
		{
			umint nAccepted = fg_Min(_DataLen, m_MaxBytesPerSend);
			m_Calls.f_InsertLast(CSendCall{_pData, nAccepted});

			CSocketOperationResult Result;
			Result.m_nBytes = nAccepted;
			if (nAccepted)
				Result.m_bSentNetwork = true;

			return Result;
		}

		virtual bool f_IsValid() const override
		{
			return true;
		}

		virtual bool f_HandshakeDone() const override
		{
			return true;
		}

		virtual void f_Close() override
		{
		}

		virtual void f_Shutdown() override
		{
		}

		virtual void f_Connect(CNetAddress const &, NFunction::TCFunctionMovable<void (ENetTCPState)> &&, CNetAddress const &) override
		{
		}

		virtual void f_AsyncConnect(CNetAddress const &, NFunction::TCFunctionMovable<void (ENetTCPState)> &&, CNetAddress const &) override
		{
		}

		virtual void f_Listen(CNetAddress const &, NFunction::TCFunctionMovable<void (ENetTCPState)> &&, ENetFlag) override
		{
		}

		virtual void f_ListenDatagram(CNetAddress const &, NFunction::TCFunctionMovable<void (ENetTCPState)> &&, ENetFlag) override
		{
		}

		virtual TCUniquePointer<ICSocket> f_Accept(NFunction::TCFunctionMovable<void (ENetTCPState)> &&) override
		{
			return nullptr;
		}

		virtual void f_InheritHandle(void *, NFunction::TCFunctionMovable<void (ENetTCPState)> &&) override
		{
		}

		virtual void *f_GiveUpForInherit() override
		{
			return nullptr;
		}

		virtual void *f_GetOSSocket() override
		{
			return nullptr;
		}

		virtual void f_SetOnStateChange(NFunction::TCFunctionMovable<void (ENetTCPState)> &&) override
		{
		}

		virtual ENetTCPState f_GetState() override
		{
			return ENetTCPState_None;
		}

		virtual NStr::CStr f_GetCloseReason() override
		{
			return {};
		}

		virtual CSocketOperationResult f_Receive(void *, umint) override
		{
			return {};
		}

		virtual umint f_SendDatagram(CNetAddress const &, const void *, umint) override
		{
			return 0;
		}

		virtual umint f_ReceiveDatagram(CNetAddress &, void *, umint) override
		{
			return 0;
		}

		virtual CNetAddress f_GetPeerAddress() const override
		{
			return {};
		}

		virtual uint32 f_GetListenPort() const override
		{
			return 0;
		}

		virtual TCUniquePointer<ICSocketConnectionInfo> f_GetConnectionInfo() const override
		{
			return nullptr;
		}
	};

	struct CVectoredSend_Tests : public NMib::NTest::CTest
	{
		void f_DoTests()
		{
			DMibTestSuite("FallbackSemantics")
			{
				uint8 Data0[100];
				uint8 Data1[200];
				uint8 Data2[50];

				{
					DMibTestPath("AllSpansInOrder");
					CSendRecordingSocket Socket;

					NSys::CIoSpan Spans[4] = {{Data0, 100}, {nullptr, 0}, {Data1, 200}, {Data2, 50}};
					CSocketOperationResult Result = Socket.f_SendVectored(Spans, 4);

					DMibExpect(Result.m_nBytes, ==, umint(350));
					DMibExpectTrue(Result.m_bSentNetwork);
					DMibAssert(Socket.m_Calls.f_GetLen(), ==, umint(3));
					DMibExpectTrue(Socket.m_Calls[0].m_pData == Data0);
					DMibExpectTrue(Socket.m_Calls[1].m_pData == Data1);
					DMibExpectTrue(Socket.m_Calls[2].m_pData == Data2);
				}

				{
					DMibTestPath("StopsOnShortWrite");
					CSendRecordingSocket Socket;
					Socket.m_MaxBytesPerSend = 150;

					NSys::CIoSpan Spans[3] = {{Data0, 100}, {Data1, 200}, {Data2, 50}};
					CSocketOperationResult Result = Socket.f_SendVectored(Spans, 3);

					// The first span fits, the second is cut short, the third must not be attempted
					DMibExpect(Result.m_nBytes, ==, umint(250));
					DMibAssert(Socket.m_Calls.f_GetLen(), ==, umint(2));
					DMibExpect(Socket.m_Calls[1].m_nBytes, ==, umint(150));
				}

				{
					DMibTestPath("EmptySpanList");
					CSendRecordingSocket Socket;

					CSocketOperationResult Result = Socket.f_SendVectored(nullptr, 0);
					DMibExpect(Result.m_nBytes, ==, umint(0));
					DMibExpectFalse(Result.m_bSentNetwork);
				}
			};

#if defined(DPlatformFamily_macOS) || defined(DPlatformFamily_Linux)
			DMibTestSuite("UnixLoopback")
			{
				CStr Path = NNetwork::fg_GetSafeUnixSocketPath
					(
						"{}/VS_{}.socket"_f << NFile::CFile::fs_GetProgramDirectory() << NCryptography::fg_RandomID().f_Left(8)
					)
				;
				CNetAddress Address = CSocket::fs_ResolveAddress("UNIX:" + Path);

				auto pListen = CSocket_TCP::fs_GetFactory()("");
				pListen->f_Listen(Address, [](ENetTCPState){}, ENetFlag_None);

				auto pClient = CSocket_TCP::fs_GetFactory()("");
				pClient->f_Connect(Address, [](ENetTCPState){}, CNetAddress());

				TCUniquePointer<ICSocket> pServer;
				{
					CTimeout Timeout(gc_Timeout);
					while (!Timeout.f_TimedOut())
					{
						pServer = pListen->f_Accept([](ENetTCPState){});
						if (pServer && pServer->f_IsValid())
							break;

						NSys::fg_Thread_Sleep(0.005f);
					}
				}
				DMibAssertTrue(pServer && pServer->f_IsValid());

				// Three data spans with a zero length span in the middle; the expected wire
				// content is their concatenation in order
				CByteVector Expected;
				CByteVector Part0;
				Part0.f_SetLen(1000);
				CByteVector Part1;
				Part1.f_SetLen(2000);
				CByteVector Part2;
				Part2.f_SetLen(500);
				for (umint i = 0; i < 1000; ++i)
					Part0[i] = uint8(i);
				for (umint i = 0; i < 2000; ++i)
					Part1[i] = uint8(i * 3);
				for (umint i = 0; i < 500; ++i)
					Part2[i] = uint8(i * 7);
				Expected.f_Insert(Part0.f_GetArray(), 1000);
				Expected.f_Insert(Part1.f_GetArray(), 2000);
				Expected.f_Insert(Part2.f_GetArray(), 500);

				NSys::CIoSpan Spans[4] =
					{
						{Part0.f_GetArray(), 1000}
						, {nullptr, 0}
						, {Part1.f_GetArray(), 2000}
						, {Part2.f_GetArray(), 500}
					}
				;

				// Send with span cursor advance across partial progress, the same consumption
				// pattern the websocket drain loop uses
				umint iSpan = 0;
				umint SpanOffset = 0;
				{
					CTimeout Timeout(gc_Timeout);
					while (iSpan < 4 && !Timeout.f_TimedOut())
					{
						NSys::CIoSpan Remaining[4];
						umint nRemaining = 0;
						for (umint i = iSpan; i < 4; ++i)
						{
							umint Offset = i == iSpan ? SpanOffset : 0;
							// The span set deliberately includes a null zero length span; offsetting
							// a null pointer is undefined even by zero
							Remaining[nRemaining].m_pData = Offset ? (uint8 const *)Spans[i].m_pData + Offset : Spans[i].m_pData;
							Remaining[nRemaining].m_nBytes = Spans[i].m_nBytes - Offset;
							++nRemaining;
						}

						CSocketOperationResult Result = pClient->f_SendVectored(Remaining, nRemaining);

						umint nConsumed = Result.m_nBytes;
						while (nConsumed && iSpan < 4)
						{
							umint nSpanRemaining = Spans[iSpan].m_nBytes - SpanOffset;
							if (nConsumed >= nSpanRemaining)
							{
								nConsumed -= nSpanRemaining;
								++iSpan;
								SpanOffset = 0;
							}
							else
							{
								SpanOffset += nConsumed;
								nConsumed = 0;
							}
						}

						if (!Result.m_nBytes)
							NSys::fg_Thread_Sleep(0.005f);
					}
				}
				DMibExpect(iSpan, ==, umint(4));

				CByteVector Received;
				Received.f_SetLen(3500);
				umint nReceived = 0;
				{
					CTimeout Timeout(gc_Timeout);
					while (nReceived < 3500 && !Timeout.f_TimedOut())
					{
						CSocketOperationResult Result = pServer->f_Receive(Received.f_GetArray() + nReceived, 3500 - nReceived);
						nReceived += Result.m_nBytes;
						if (!Result.m_nBytes)
							NSys::fg_Thread_Sleep(0.005f);
					}
				}

				DMibAssert(nReceived, ==, umint(3500));
				DMibExpectTrue(Received == Expected);

				pClient->f_Close();
				pServer->f_Close();
				pListen->f_Close();
			};
#endif
		}
	};

	DMibTestRegister(CVectoredSend_Tests, Malterlib::Network);
}
