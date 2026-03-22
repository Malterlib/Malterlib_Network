// Copyright © 2015 Hansoft AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

/*
	Author:			Michael Wynne

	Contents:		NSys level network tests

	Comments:		For these tests to work you need a remote machine setup as follows:

					*	Connections on ports 20677 should have their contents echoed.
						Line by line echoing is fine. You can use socat as below for this:
							socat TCP-LISTEN:20677,reuseaddr,fork exec:'cat',pty,raw,echo=0

					*	Connections on port 20678 should be redirected to port 20680 on the
						calling machine. You can use socat as below for this:
							echo 'socat - TCP:$SOCAT_PEERADDR:20680' > RouteBack.sh
							chmod +x RouteBack.sh
							socat TCP-LISTEN:20678,fork,pktinfo,reuseaddr EXEC:'./RouteBack.sh'

					*	Connections on ports 20679 should receive anything sent to them
						but not send anything back. You can use socat as below for this:
							socat -u TCP-LISTEN:20679,reuseaddr,fork exec:'cat',pty,raw,echo=0

					The environment variable "MalterlibTestLoopbackMachine" specifies the host
					name of the remote machine. If it is unset the value in
					localhost is used and a loopback server is started.

					A good way of running the above three socat instances in a way that you can
					monitor is to use GNU screen. screen allows you to create multiple shells
					in your terminal window (with Ctrl-A C) and switch between them with
					Ctrl-A <0-9>.

					Alternatively you could use tmux so you can see each socat instance at the
					same time.

*/

#include <Mib/Core/Core>
#include <Mib/Time/Timeout>
#include <Mib/Test/Exception>

#include "Test_Malterlib_Network.h"

using namespace NMib;
using namespace NMib::NNetwork;
using namespace NMib::NStorage;
using namespace NMib::NStr;
using namespace NMib::NThread;
using namespace NMib::NMemory;
using namespace NMib::NTime;

static fp32 const gc_Timeout = 60.0f;

class CSysNet_Tests : public NMib::NTest::CTest
{
public:

	template <typename t_CNetAddress, typename t_CNotNetAddress>
	void f_TestAddress(t_CNetAddress const &_Localhost, t_CNotNetAddress const &_Other)
	{
		CNetAddress Localhost(_Localhost);
		DMibExpectFalse(Localhost.f_IsEmpty());
		DMibExpect(Localhost.f_GetType(), ==, t_CNetAddress::mc_Type);

		t_CNetAddress Return;
		DMibExpectTrue(Localhost.f_Get(Return));
		DMibExpect(fg_MemCmp((uint8 const *)&Return, (uint8 const *)&_Localhost, sizeof(Return)), ==, 0);

		t_CNotNetAddress NotReturn;
		DMibExpectTrue(Localhost.f_Get(NotReturn));

		CNetAddress Other(_Other);
		DMibExpectFalse(Other.f_IsEmpty());

		t_CNetAddress Return2;
		DMibExpectTrue(Other.f_Get(Return2));
		DMibExpect(fg_MemCmp((uint8 const *)&Return2, (uint8 const *)&_Other, sizeof(Return2)), ==, 0);

		DMibExpect(Localhost, ==, Localhost);
		DMibExpect(Localhost, <, Other);
	}

	template <typename t_CNetAddress>
	void f_TestResolve(CStr const &_Address, t_CNetAddress const &_Result)
	{
		CNetAddress Resolved = CSocket::fs_ResolveAddress("localhost", t_CNetAddress::mc_Type);
		DMibExpectFalse(Resolved.f_IsEmpty());

		t_CNetAddress Return;
		DMibExpectTrue(Resolved.f_Get(Return));
		DMibExpect(fg_MemCmp((uint8 const*)&Return.f_GetIP(), (uint8 const*)&_Result.f_GetIP(), sizeof(Return.f_GetIP())), ==, 0);
	}

	template <typename t_CNetAddress>
	void f_TestAsyncResolve(CStr const &_Address, t_CNetAddress const& _Result)
	{
		NStorage::TCSharedPointer<CEventAutoReset> pResolveEvent = fg_Construct();

		CAsyncResolver Resolver;
		Resolver.f_Open
			(
				_Address
				, t_CNetAddress::mc_Type
				, [pResolveEvent]
				{
					pResolveEvent->f_Signal();
				}
			)
		;

		if (pResolveEvent->f_WaitTimeout(gc_Timeout))
			DMibTest(!DMibExpr("Timed out async resolving address"))(ETest_FailAndStop);

		CNetAddress Resolved;
		CStr ErrorString;

		DMibExpectTrue(Resolver.f_GetResult(Resolved, ErrorString));
		DMibExpectFalse(Resolved.f_IsEmpty());

		if (!Resolved.f_IsEmpty())
		{
			t_CNetAddress Return;
			DMibExpectTrue(Resolved.f_Get(Return));
			DMibExpect(fg_MemCmp((uint8 const*)&Return.f_GetIP(), (uint8 const*)&_Result.f_GetIP(), sizeof(Return.f_GetIP())), ==, 0);
		}
	}

	template <typename t_CNetAddress, ENetAddressType t_Type>
	void f_TestConnectRefused(uint16 _Port)
	{
		CNetAddress Address = CSocket::fs_ResolveAddress("localhost", t_Type);
		DMibExpectFalse(Address.f_IsEmpty());

		if (Address.f_IsEmpty())
			return;

		{
			t_CNetAddress Return;
			DMibExpectTrue(Address.f_Get(Return));
			Return.m_Port = _Port;
			Address.f_Set(Return);
		}

		CSocket Socket;
		DMibExpectException
			(
				Socket.f_Connect(Address)
#if defined(DPlatformFamily_Linux)
				, DMibImpExceptionInstance(CExceptionNet, "Connection refused (111)")
#elif defined(DPlatformFamily_macOS)
				, DMibImpExceptionInstance(CExceptionNet, "Connection refused (61)")
#elif defined(DPlatformFamily_Windows)
				, DMibImpExceptionInstance(CExceptionNet, "10061 No connection could be made because the target machine actively refused it.")
#else
				, DMibImpExceptionInstance(CExceptionNet, "Implement this")
#endif
			)
		;
		DMibExpectFalse(Socket.f_IsValid());
	}

	template <typename t_CNetAddress, ENetAddressType _Type>
	void f_TestConnect(CStr _Address, uint16 _Port)
	{
		CNetAddress Address = CSocket::fs_ResolveAddress(_Address, _Type);
		DMibExpectFalse(Address.f_IsEmpty());
		{
			DMibTestPath("SetPort");
			t_CNetAddress Return;
			DMibExpectTrue(Address.f_Get(Return));

			Return.m_Port = _Port;
			Address.f_Set(Return);

			DMibExpectFalse(Address.f_IsEmpty());

			if (Address.f_IsEmpty())
				return;
		}

		CSocket Socket;
		Socket.f_Connect(Address);

		if (Socket.f_IsValid())
		{
			CNetAddress PeerAddress = Socket.f_GetPeerAddress();

			DMibExpectFalse(PeerAddress.f_IsEmpty());
			DMibExpect(PeerAddress, ==, Address);
		}

		DMibExpectTrue(Socket.f_IsValid());
		if (!Socket.f_IsValid())
			return;

		static uint8 const Message[] = { 'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!', '\n' };
		static umint const nMessageBytes = sizeof(Message);

		{
			umint nSent = Socket.f_Send(Message, nMessageBytes);
			DMibExpect(nSent, ==, nMessageBytes);
		}

		{
			umint nReceived = 0;
			umint nBytes = -1;
			uint8 Incoming[nMessageBytes];
			fg_MemClear(Incoming, nMessageBytes);
			CTimeout Timeout(gc_Timeout);
			while (nReceived < nMessageBytes && !Timeout.f_TimedOut())
			{
				nBytes = Socket.f_Receive(Incoming + nReceived, nMessageBytes - nReceived);

				if (nBytes == -1)
					break;

				nReceived += nBytes;
			}

			DMibExpect(nBytes, !=, -1);
			DMibExpect(nReceived, ==, nMessageBytes);
			DMibExpect(fg_MemCmp(Incoming, Message, nMessageBytes), ==, 0);
		}
	}

	template <typename t_CNetAddress, ENetAddressType t_Type>
	void f_TestConnectListen(CStr _Address, uint16 _Port, uint16 _ListenPort)
	{
		CNetAddress Address = CSocket::fs_ResolveAddress(_Address, t_Type);
		DMibExpectFalse(Address.f_IsEmpty());
		{
			DMibTestPath("SetPort");
			t_CNetAddress Return;
			DMibExpectTrue(Address.f_Get(Return));

			Return.m_Port = _Port;
			Address.f_Set(Return);

			DMibExpectFalse(Address.f_IsEmpty());

			if (Address.f_IsEmpty())
				return;
		}

		static uint8 const Message[] = { 'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!', '\n' };
		static umint const nMessageBytes = sizeof(Message);

		CEventAutoReset ServerReady;

		auto ServerThread = CThreadObject::fs_StartThread
			(
				[&](CThreadObject *_pThread) -> aint
				{
					DMibTestPath("Server");
					try
					{
						t_CNetAddress AnyAddr;
						AnyAddr.f_SetLocalhost();
						AnyAddr.m_Port = _ListenPort;

						CNetAddress BindAddress(AnyAddr);
						DMibExpectFalse(BindAddress.f_IsEmpty());

						CSocket Server;
						Server.f_Listen(BindAddress, nullptr, ENetFlag_None);

						DMibExpectTrue(Server.f_IsValid());

						if (!Server.f_IsValid())
							return -1;

						ServerReady.f_Signal();

						CSocket Client;

						CTimeout Timeout(gc_Timeout);

						while (!Client.f_IsValid() && !Timeout.f_TimedOut())
						{
							Client.f_Accept(&Server, nullptr);
							if (!Client.f_IsValid())
								NSys::fg_Thread_Yield();
						}

						DMibExpectTrue(Client.f_IsValid());

						if (!Client.f_IsValid())
							return -1;

						umint nSent = Client.f_Send(Message, nMessageBytes);
						DMibTest(DMibExpr(nSent) == DMibExpr(nMessageBytes));
					}
					catch (CExceptionNet const& _Exception)
					{
						(void)_Exception;
						DMibTest(DMibExpr(_Exception.f_GetErrorStr()) && DMibExpr(false));
					}

					return 0;
				},
				"TestConnectListen_Server"
			)
		;

		if (ServerReady.f_WaitTimeout(gc_Timeout))
			DMibTest(!DMibExpr("Timed out waiting for server ready"))(ETest_FailAndStop);

		NMib::NSys::fg_Thread_Sleep(1.0f);

		auto ClientThread = CThreadObject::fs_StartThread
			(
				[&](CThreadObject *_pThread) -> aint
				{
					DMibTestPath("Client");
					try
					{
						CSocket Client;
						Client.f_Connect(Address);

						DMibExpectTrue(Client.f_IsValid());
						if (!Client.f_IsValid())
							return -1;

						umint nReceived = 0, nBytes;
						uint8 Incoming[nMessageBytes];
						fg_MemClear(Incoming, nMessageBytes);
						CTimeout Timeout(gc_Timeout);

						while (nReceived < nMessageBytes && !Timeout.f_TimedOut())
						{
							nBytes = Client.f_Receive(&Incoming[nReceived], nMessageBytes - nReceived);

							if (nBytes == -1)
								break;

							nReceived += nBytes;
						}

						DMibExpect(nBytes, !=, -1);
						DMibExpect(nReceived, ==, nMessageBytes);
						DMibExpect(fg_MemCmp(Incoming, Message, nMessageBytes), ==, 0);
					}
					catch (CExceptionNet const& _Exception)
					{
						(void)_Exception;
						DMibTest(DMibExpr(_Exception.f_GetErrorStr()) && DMibExpr(false));
					}

					return 0;
				}
				, "TestConnectListen_Client"
			)
		;

		ClientThread->f_Stop();
		ServerThread->f_Stop();
	}

	template <typename t_CNetAddress, ENetAddressType t_Type>
	void f_TestConnectReportTo(CStr _Address, uint16 _Port)
	{
		CNetAddress Address = CSocket::fs_ResolveAddress(_Address, t_Type);
		DMibExpectFalse(Address.f_IsEmpty());
		{
			DMibTestPath("SetPort");
			t_CNetAddress Return;
			DMibExpectTrue(Address.f_Get(Return));

			Return.m_Port = _Port;
			Address.f_Set(Return);

			DMibExpectFalse(Address.f_IsEmpty());

			if (Address.f_IsEmpty())
				return;
		}

		CEventAutoReset SocketEvent;

		CSocket Socket;
		Socket.f_Connect
			(
				Address
				, [&SocketEvent](ENetTCPState _StateAdded)
				{
					SocketEvent.f_Signal();
				}
			)
		;

		DMibExpectTrue(Socket.f_IsValid());
		if (!Socket.f_IsValid())
			return;

		static umint const nBufferBytes = 1024*1024*16;
		NContainer::CByteVector Buffer;
		Buffer.f_SetLen(nBufferBytes);
		fg_MemClear(Buffer.f_GetArray(), Buffer.f_GetLen());

		{
			umint nTotalSent = 0;
			umint nSent = -1;

			while(nTotalSent < nBufferBytes)
			{
				nSent = Socket.f_Send(Buffer.f_GetArray() + nTotalSent, nBufferBytes - nTotalSent);
				if (nSent == -1)
					break;

				bool bStuffed = nSent < (nBufferBytes - nTotalSent);

				nTotalSent += nSent;

				if (bStuffed)
				{
					do
					{
						CStopwatch WaitTime;
						WaitTime.f_Start();
						if (SocketEvent.f_WaitTimeout(gc_Timeout))
						{
							DMibTest(DMibExpr(WaitTime.f_GetTime()) > DMibExpr(gc_Timeout));
							DMibTest(!DMibExpr("Timed out sending data"))(ETest_FailAndStop);
						}
					}
					while (!(Socket.f_GetState() & ENetTCPState_Write))
						;
				}
			}

			DMibTest(DMibExpr(nSent) != DMibExpr(-1)); // Error
			DMibTest(DMibExpr(nTotalSent) == DMibExpr(nBufferBytes));
		}
	}


	template<typename t_CNetAddress, ENetAddressType t_Type>
	void f_TestConnectListenReportTo(CStr _Address, uint16 _Port, uint16 _ListenPort)
	{
		CNetAddress Address = CSocket::fs_ResolveAddress(_Address, t_Type);
		DMibExpectFalse(Address.f_IsEmpty());
		{
			DMibTestPath("SetPort");
			t_CNetAddress Return;
			DMibExpectTrue(Address.f_Get(Return));

			Return.m_Port = _Port;
			Address.f_Set(Return);

			DMibExpectFalse(Address.f_IsEmpty());

			if (Address.f_IsEmpty())
				return;
		}

		static uint8 const Message[] = { 'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!', '\n' };
		static umint const nMessageBytes = sizeof(Message);

		CEventAutoReset ServerReady;

		auto ServerThread = CThreadObject::fs_StartThread
			(
				[&](CThreadObject *_pThread) -> aint
				{
					DMibTestPath("Server");
					try
					{
						t_CNetAddress AnyAddr; // = _Localhost;
						AnyAddr.f_SetLocalhost();
						AnyAddr.m_Port = _ListenPort;

						CNetAddress BindAddress(AnyAddr);
						DMibExpectFalse(BindAddress.f_IsEmpty());

						TCSharedPointer<CEventAutoReset> pListenEvent = fg_Construct();

						CSocket Server;
						Server.f_Listen
							(
								BindAddress
								, [pListenEvent](ENetTCPState _StateAdded)
								{
									if (_StateAdded & ENetTCPState_Connection)
										pListenEvent->f_Signal();
								}
								, ENetFlag_None
							)
						;

						DMibExpectTrue(Server.f_IsValid());

						if (!Server.f_IsValid())
							return -1;

						ServerReady.f_Signal();

						bool bTimedOut = pListenEvent->f_WaitTimeout(gc_Timeout);
						DMibExpectFalse(bTimedOut);

						if (bTimedOut)
							return -1;

						DMibExpect(Server.f_GetState(), &, ENetTCPState_Connection);

						CSocket Client;
						Client.f_Accept(&Server, nullptr);

						DMibExpectTrue(Client.f_IsValid());

						if (!Client.f_IsValid())
							return -1;

						umint nSent = Client.f_Send(Message, nMessageBytes);
						DMibTest(DMibExpr(nSent) == DMibExpr(nMessageBytes));
					}
					catch (CExceptionNet const& _Exception)
					{
						(void)_Exception;
						DMibTest(DMibExpr(_Exception.f_GetErrorStr()) && DMibExpr(false));
					}

					return 0;
				}
				, "TestConnectListen_Server"
			)
		;

		if (ServerReady.f_WaitTimeout(gc_Timeout))
			DMibTest(!DMibExpr("Timed out waiting for server ready"))(ETest_FailAndStop);
		NSys::fg_Thread_Sleep(1.0f);

		auto ClientThread = CThreadObject::fs_StartThread
			(
				[&](CThreadObject *_pThread) -> aint
				{
					DMibTestPath("Client");
					try
					{
						CSocket Client;
						Client.f_Connect(Address);

						DMibExpectTrue(Client.f_IsValid());
						if (!Client.f_IsValid())
							return -1;

						{
							umint nReceived = 0, nBytes;
							uint8 Incoming[nMessageBytes];
							fg_MemClear(Incoming, nMessageBytes);
							CTimeout Timeout(gc_Timeout);

							while (nReceived < nMessageBytes && !Timeout.f_TimedOut())
							{
								nBytes = Client.f_Receive(&Incoming[nReceived], nMessageBytes - nReceived);

								if (nBytes == -1)
									break;

								nReceived += nBytes;
							}

							DMibExpect(nBytes, !=, -1);
							DMibExpect(nReceived, ==, nMessageBytes);
							DMibExpect(fg_MemCmp(Incoming, Message, nMessageBytes), ==, 0);
						}
					}
					catch (CExceptionNet const& _Exception)
					{
						(void)_Exception;
						DMibTest(DMibExpr(_Exception.f_GetErrorStr()) && DMibExpr(false));
					}

					return 0;
				}
				, "TestConnectListen_Client"
			)
		;

		ClientThread->f_Stop();
		ServerThread->f_Stop();
	}


	template<typename t_CNetAddress, ENetAddressType t_Type>
	void f_TestInherit(CStr _Address, uint16 _Port)
	{
		CNetAddress Address = CSocket::fs_ResolveAddress(_Address, t_Type);
		DMibExpectFalse(Address.f_IsEmpty());
		{
			DMibTestPath("SetPort");
			t_CNetAddress Return;
			DMibExpectTrue(Address.f_Get(Return));

			Return.m_Port = _Port;
			Address.f_Set(Return);

			DMibExpectFalse(Address.f_IsEmpty());

			if (Address.f_IsEmpty())
				return;
		}

		CEventAutoReset SocketEvent;

		CSocket Socket;
		Socket.f_Connect(Address);

		DMibExpectTrue(Socket.f_IsValid());
		if (!Socket.f_IsValid())
			return;

		{
			CSocket OldSocket = fg_Move(Socket);

			void *pOSSocket = OldSocket.f_GiveUpForInherit();
			OldSocket.f_Close();

			DMibMovedFromValid(Socket);
			Socket.f_InheritHandle2
				(
					pOSSocket
					, [&SocketEvent](ENetTCPState _StateAdded)
					{
						SocketEvent.f_Signal();
					}
				)
			;
		}

		static umint const nBufferBytes = 1024*1024*4;
		NContainer::CByteVector Buffer;
		Buffer.f_SetLen(nBufferBytes);
		fg_MemClear(Buffer.f_GetArray(), Buffer.f_GetLen());

		{
			umint nTotalSent = 0;
			umint nSent = -1;

			while(nTotalSent < nBufferBytes)
			{
				nSent = Socket.f_Send(Buffer.f_GetArray() + nTotalSent, nBufferBytes - nTotalSent);
				if (nSent == -1)
					break;

				bool bStuffed = nSent < (nBufferBytes - nTotalSent);

				nTotalSent += nSent;

				if (bStuffed)
				{
					do
					{
						if (SocketEvent.f_WaitTimeout(gc_Timeout))
							DMibTest(!DMibExpr("Timed out sending data"))(ETest_FailAndStop);
					}
					while (!(Socket.f_GetState() & ENetTCPState_Write))
						;
				}
			}

			DMibTest(DMibExpr(nSent) != DMibExpr(-1)); // Error
			DMibTest(DMibExpr(nTotalSent) == DMibExpr(nBufferBytes));
		}
	}

	template<typename t_CNetAddress, ENetAddressType t_Type>
	void f_TestAsyncConnectReportTo(CStr _Address, uint16 _Port)
	{
		CNetAddress Address = CSocket::fs_ResolveAddress(_Address, t_Type);
		DMibExpectFalse(Address.f_IsEmpty());
		{
			DMibTestPath("SetPort");
			t_CNetAddress Return;
			DMibExpectTrue(Address.f_Get(Return));

			Return.m_Port = _Port;
			Address.f_Set(Return);

			DMibExpectFalse(Address.f_IsEmpty());

			if (Address.f_IsEmpty())
				return;
		}

		TCSharedPointer<CEventAutoReset> pSocketEvent = fg_Construct();

		CSocket Socket;

		Socket.f_AsyncConnect
			(
				Address
				, [pSocketEvent](ENetTCPState _StateAdded)
				{
					pSocketEvent->f_Signal();
				}
			)
		;

		DMibExpectTrue(Socket.f_IsValid());
		if (!Socket.f_IsValid())
			return;

		CTimeout Timeout(gc_Timeout);

		while (!(Socket.f_GetState() & ENetTCPState_Connected) && !Timeout.f_TimedOut())
			pSocketEvent->f_WaitTimeout(gc_Timeout);

		DMibExpectFalse(Timeout.f_TimedOut())(ETest_FailAndStop);

		static umint const nBufferBytes = 1024*1024*4;
		NContainer::CByteVector Buffer;
		Buffer.f_SetLen(nBufferBytes);
		fg_MemClear(Buffer.f_GetArray(), Buffer.f_GetLen());

		{
			umint nTotalSent = 0;
			umint nSent = -1;

			while (nTotalSent < nBufferBytes)
			{
				nSent = Socket.f_Send(Buffer.f_GetArray() + nTotalSent, nBufferBytes - nTotalSent);
				if (nSent == -1)
					break;

				bool bStuffed = nSent < (nBufferBytes - nTotalSent);

				nTotalSent += nSent;

				if (bStuffed)
				{
					do
					{
						if (pSocketEvent->f_WaitTimeout(gc_Timeout))
							DMibTest(!DMibExpr("Timed out sending data"))(ETest_FailAndStop);
					}
					while (!(Socket.f_GetState() & ENetTCPState_Write))
						;
				}
			}

			DMibTest(DMibExpr(nSent) != DMibExpr(-1)); // Error
			DMibTest(DMibExpr(nTotalSent) == DMibExpr(nBufferBytes));
		}
	}

	void f_DoTests()
	{
		static const uint16 Port = 20677;

		CNetAddressTCPv4 const Localhost_TCPv4( CNetAddressIPv4(127,0,0,1), Port);
		CNetAddressTCPv4 const Other_TCPv4( CNetAddressIPv4(127,0,0,2), Port);
		CNetAddressTCPv6 const Localhost_TCPv6( CNetAddressIPv6(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1), Port);
		CNetAddressTCPv6 const Other_TCPv6( CNetAddressIPv6(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2), Port);

		CStr RemoteMachine;
		auto fRemoteMachine = [&]() -> CStr const &
			{
				if (!RemoteMachine)
					RemoteMachine = fg_GetLoopbackMachine();

				return RemoteMachine;
			}
		;
		DMibTestSuite("Tests")
		{
			{
				DMibTestPath("Addresses_TCPv4");
				f_TestAddress(Localhost_TCPv4, Other_TCPv4);
			}
			{
				DMibTestPath("Addresses_TCPv6");
				f_TestAddress(Localhost_TCPv6, Other_TCPv6);
			}
			{
				DMibTestPath("Resolve_TCPv4");
				f_TestResolve("localhost", Localhost_TCPv4);
			}
			{
				DMibTestPath("Resolve_TCPv6");
				f_TestResolve("localhost", Localhost_TCPv6);
			}
			{
				DMibTestPath("AsyncResolve_TCPv4");
				f_TestAsyncResolve("localhost", Localhost_TCPv4);
			}
			{
				DMibTestPath("AsyncResolve_TCPv6");
				f_TestAsyncResolve("localhost", Localhost_TCPv6);
			}
			{
				DMibTestPath("ConnectRefused_TCPv4");
				f_TestConnectRefused<CNetAddressTCPv4, ENetAddressType_TCPv4>(20681);
			}
			{
				DMibTestPath("ConnectRefused_TCPv6");
				f_TestConnectRefused<CNetAddressTCPv6, ENetAddressType_TCPv6>(20681);
			}
			{
				DMibTestPath("Connect_TCPv4");
				f_TestConnect<CNetAddressTCPv4, ENetAddressType_TCPv4>(fRemoteMachine(), 20677);
			}
			{
				DMibTestPath("Connect_TCPv6");
				f_TestConnect<CNetAddressTCPv6, ENetAddressType_TCPv6>(fRemoteMachine(), 20677);
			}
			{
				DMibTestPath("ConnectListen_TCPv4");
				f_TestConnectListen<CNetAddressTCPv4, ENetAddressType_TCPv4>(fRemoteMachine(), 20678, 20680);
			}
			{
				DMibTestPath("ConnectListen_TCPv6");
				f_TestConnectListen<CNetAddressTCPv6, ENetAddressType_TCPv6>(fRemoteMachine(), 20678, 20680);
			}
			{
				DMibTestPath("ConnectReportTo_TCPv4");
				f_TestConnectReportTo<CNetAddressTCPv4, ENetAddressType_TCPv4>(fRemoteMachine(), 20679);
			}
			{
				DMibTestPath("ConnectReportTo_TCPv6");
				f_TestConnectReportTo<CNetAddressTCPv6, ENetAddressType_TCPv6>(fRemoteMachine(), 20679);
			}
			{
				DMibTestPath("ConnectListenReportTo_TCPv4");
				f_TestConnectListenReportTo<CNetAddressTCPv4, ENetAddressType_TCPv4>(fRemoteMachine(), 20678, 20680);
			}
			{
				DMibTestPath("ConnectListenReportTo_TCPv6");
				f_TestConnectListenReportTo<CNetAddressTCPv6, ENetAddressType_TCPv6>(fRemoteMachine(), 20678, 20680);
			}
			{
				DMibTestPath("Inherit");
				f_TestInherit<CNetAddressTCPv4, ENetAddressType_TCPv4>(fRemoteMachine(), 20679);
			}
			{
				DMibTestPath("AsyncConnectReportTo_TCPv4");
				f_TestAsyncConnectReportTo<CNetAddressTCPv4, ENetAddressType_TCPv4>(fRemoteMachine(), 20679);
			}
			{
				DMibTestPath("AsyncConnectReportTo_TCPv6");
				f_TestAsyncConnectReportTo<CNetAddressTCPv6, ENetAddressType_TCPv6>(fRemoteMachine(), 20679);
			}
		};
	}
};

DMibTestRegister(CSysNet_Tests, Malterlib::Network);
