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
	constexpr fp32 gc_Timeout = 30.0f;

	struct CSendRecordingSocket : public ICSocket
	{
		struct CSendCall
		{
			void const *m_pData;
			umint m_nBytes;
		};

		virtual CSocketOperationResult f_Send(void const *_pData, umint _DataLen) override;
		virtual bool f_IsValid() const override;
		virtual bool f_HandshakeDone() const override;
		virtual void f_Close() override;
		virtual void f_Shutdown() override;
		virtual void f_SetAbortOnClose() override;
		virtual void f_Connect(CNetAddress const &_Address, NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange, CNetAddress const &_BindAddress) override;
		virtual void f_AsyncConnect(CNetAddress const &_Address, NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange, CNetAddress const &_BindAddress) override;
		virtual void f_Listen(CNetAddress const &_Address, NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange, ENetFlag _Flags) override;
		virtual void f_ListenDatagram(CNetAddress const &_Address, NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange, ENetFlag _Flags) override;
		virtual TCUniquePointer<ICSocket> f_Accept(NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange) override;
		virtual void f_InheritHandle(void *_pSocketHandle, NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange) override;
		virtual void *f_GiveUpForInherit() override;
		virtual void *f_GetOSSocket() override;
		virtual void f_SetOnStateChange(NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange) override;
		virtual ENetTCPState f_GetState() override;
		virtual NStr::CStr f_GetCloseReason() override;
		virtual CSocketOperationResult f_Receive(void *_pData, umint _DataLen) override;
		virtual umint f_SendDatagram(CNetAddress const &_Address, void const *_pData, umint _DataLen) override;
		virtual umint f_ReceiveDatagram(CNetAddress &_Address, void *_pData, umint _DataLen) override;
		virtual CNetAddress f_GetPeerAddress() const override;
		virtual uint32 f_GetListenPort() const override;
		virtual TCUniquePointer<ICSocketConnectionInfo> f_GetConnectionInfo() const override;

		umint m_MaxBytesPerSend = TCLimitsInt<umint>::mc_Max;
		TCVector<CSendCall> m_Calls;
	};

	CSocketOperationResult CSendRecordingSocket::f_Send(void const *_pData, umint _DataLen)
	{
		umint nAccepted = fg_Min(_DataLen, m_MaxBytesPerSend);
		m_Calls.f_InsertLast(CSendCall{_pData, nAccepted});

		CSocketOperationResult Result;
		Result.m_nBytes = nAccepted;
		if (nAccepted)
			Result.m_bSentNetwork = true;

		return Result;
	}

	bool CSendRecordingSocket::f_IsValid() const
	{
		return true;
	}

	bool CSendRecordingSocket::f_HandshakeDone() const
	{
		return true;
	}

	void CSendRecordingSocket::f_Close()
	{
	}

	void CSendRecordingSocket::f_Shutdown()
	{
	}

	void CSendRecordingSocket::f_SetAbortOnClose()
	{
	}

	void CSendRecordingSocket::f_Connect(CNetAddress const &_Address, NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange, CNetAddress const &_BindAddress)
	{
	}

	void CSendRecordingSocket::f_AsyncConnect(CNetAddress const &_Address, NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange, CNetAddress const &_BindAddress)
	{
	}

	void CSendRecordingSocket::f_Listen(CNetAddress const &_Address, NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange, ENetFlag _Flags)
	{
	}

	void CSendRecordingSocket::f_ListenDatagram(CNetAddress const &_Address, NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange, ENetFlag _Flags)
	{
	}

	TCUniquePointer<ICSocket> CSendRecordingSocket::f_Accept(NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		return nullptr;
	}

	void CSendRecordingSocket::f_InheritHandle(void *_pSocketHandle, NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
	}

	void *CSendRecordingSocket::f_GiveUpForInherit()
	{
		return nullptr;
	}

	void *CSendRecordingSocket::f_GetOSSocket()
	{
		return nullptr;
	}

	void CSendRecordingSocket::f_SetOnStateChange(NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
	}

	ENetTCPState CSendRecordingSocket::f_GetState()
	{
		return ENetTCPState_None;
	}

	NStr::CStr CSendRecordingSocket::f_GetCloseReason()
	{
		return {};
	}

	CSocketOperationResult CSendRecordingSocket::f_Receive(void *_pData, umint _DataLen)
	{
		return {};
	}

	umint CSendRecordingSocket::f_SendDatagram(CNetAddress const &_Address, void const *_pData, umint _DataLen)
	{
		return 0;
	}

	umint CSendRecordingSocket::f_ReceiveDatagram(CNetAddress &_Address, void *_pData, umint _DataLen)
	{
		return 0;
	}

	CNetAddress CSendRecordingSocket::f_GetPeerAddress() const
	{
		return {};
	}

	uint32 CSendRecordingSocket::f_GetListenPort() const
	{
		return 0;
	}

	TCUniquePointer<ICSocketConnectionInfo> CSendRecordingSocket::f_GetConnectionInfo() const
	{
		return nullptr;
	}

	struct CVectoredSend_Tests : public NMib::NTest::CTest
	{
		void f_DoTests();
	};

	void CVectoredSend_Tests::f_DoTests()
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
			CStr Path = NNetwork::fg_GetSafeUnixSocketPath("{}/VS_{}.socket"_f << NFile::CFile::fs_GetProgramDirectory() << NCryptography::fg_RandomID().f_Left(8));
			CNetAddress Address = CSocket::fs_ResolveAddress("UNIX:" + Path);

			auto pListen = CSocket_TCP::fs_GetFactory()("");
			pListen->f_Listen
				(
					Address
					, [](ENetTCPState _StateAdded)
					{
					}
					, ENetFlag_None
				)
			;

			auto pClient = CSocket_TCP::fs_GetFactory()("");
			pClient->f_Connect
				(
					Address
					, [](ENetTCPState _StateAdded)
					{
					}
					, CNetAddress()
				)
			;

			TCUniquePointer<ICSocket> pServer;
			{
				CTimeout Timeout(gc_Timeout);
				while (!Timeout.f_TimedOut())
				{
					pServer = pListen->f_Accept
						(
							[](ENetTCPState _StateAdded)
							{
							}
						)
					;
					if (pServer && pServer->f_IsValid())
						break;

					NSys::fg_Thread_Sleep(0.005f);
				}
			}
			DMibAssertTrue(pServer && pServer->f_IsValid());

			CByteVector Expected;
			CByteVector Part0;
			Part0.f_SetLen(1000);
			CByteVector Part1;
			Part1.f_SetLen(2000);
			CByteVector Part2;
			Part2.f_SetLen(500);
			for (umint iByte = 0; iByte < 1000; ++iByte)
				Part0[iByte] = uint8(iByte);
			for (umint iByte = 0; iByte < 2000; ++iByte)
				Part1[iByte] = uint8(iByte * 3);
			for (umint iByte = 0; iByte < 500; ++iByte)
				Part2[iByte] = uint8(iByte * 7);
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

			umint iSpan = 0;
			umint SpanOffset = 0;
			{
				CTimeout Timeout(gc_Timeout);
				while (iSpan < 4 && !Timeout.f_TimedOut())
				{
					NSys::CIoSpan Remaining[4];
					umint nRemaining = 0;
					for (umint iRemainingSpan = iSpan; iRemainingSpan < 4; ++iRemainingSpan)
					{
						umint Offset = iRemainingSpan == iSpan ? SpanOffset : 0;
						// The span set deliberately includes a null zero length span; offsetting
						// a null pointer is undefined even by zero
						Remaining[nRemaining].m_pData = Offset ? (uint8 const *)Spans[iRemainingSpan].m_pData + Offset : Spans[iRemainingSpan].m_pData;
						Remaining[nRemaining].m_nBytes = Spans[iRemainingSpan].m_nBytes - Offset;
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

	DMibTestRegister(CVectoredSend_Tests, Malterlib::Network);
}
