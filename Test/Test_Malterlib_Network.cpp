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

#include "Test_Malterlib_Network.h"

using namespace NMib;
using namespace NMib::NSys::NNet;
using namespace NMib::NNet;

static fp32 const gc_Timeout = 60.0f;

class CSysNet_Tests : public NMib::NTest::CTest
{
public:

	template<typename t_CNetAddress, ENetAddressType _Type, typename t_CNotNetAddress, ENetAddressType _NotType>
	void f_TestAddress(t_CNetAddress const& _Localhost, t_CNetAddress const& _Other)
	{
		CAddress Localhost = fg_CreateAddress(_Type, &_Localhost, sizeof(t_CNetAddress));
		DMibTest(DMibExpr(Localhost) != DMibExpr(nullptr));

		DMibTest(DMibExpr(fg_GetAddressType(Localhost)) == DMibExpr(_Type));
		
		t_CNetAddress Return;
		DMibTest(DMibExpr(fg_GetAddressRaw(Localhost, _Type, &Return, sizeof(Return))) == DMibExpr((bint)true));

		t_CNotNetAddress NotReturn;
		DMibTest(DMibExpr(fg_GetAddressRaw(Localhost, _NotType, &NotReturn, sizeof(NotReturn))) == DMibExpr((bint)false));

		DMibTest(DMibExpr(NMem::fg_MemCmp((uint8 const*)&_Localhost, (uint8 const*)&Return, sizeof(t_CNetAddress))) == DMibExpr(0));

		CAddress Other = fg_CreateAddress(_Type, &_Other, sizeof(_Other));
		DMibTest(DMibExpr(Other) != DMibExpr(nullptr));

		t_CNetAddress Return2;
		DMibTest(DMibExpr(fg_GetAddressRaw(Other, _Type, &Return2, sizeof(Return2))) == DMibExpr((bint)true));

		DMibTest(DMibExpr(NMem::fg_MemCmp((uint8 const*)&_Other, (uint8 const*)&Return2, sizeof(t_CNetAddress))) == DMibExpr(0));

		DMibTest(DMibExpr(fg_CompareAddresses(Localhost, Localhost)) == DMibExpr(0));
		DMibTest(DMibExpr(fg_CompareAddresses(Localhost, Other)) < DMibExpr(0));

		fg_FreeAddress(Localhost);
		fg_FreeAddress(Other);
	}

	template<typename t_CNetAddress, ENetAddressType _Type>
	void f_TestResolve(NMib::NStr::CStr const& _Address, t_CNetAddress const& _Result)
	{
		CAddress Resolved = fg_ResolveAddress("localhost", _Type);
		DMibTest(DMibExpr(Resolved) != DMibExpr(nullptr));

		t_CNetAddress Return;
		DMibTest(DMibExpr(fg_GetAddressRaw(Resolved, _Type, &Return, sizeof(Return))) == DMibExpr((bint)true));

		DMibTest(DMibExpr(NMem::fg_MemCmp((uint8 const*)&Return.f_GetIP(), (uint8 const*)&_Result.f_GetIP(), sizeof(Return.f_GetIP()))) == DMibExpr(0));

		fg_FreeAddress(Resolved);
	}

	template<typename t_CNetAddress, ENetAddressType _Type>
	void f_TestAsyncResolve(NMib::NStr::CStr const& _Address, t_CNetAddress const& _Result)
	{

		NMib::NThread::CEventAutoResetReportable ResolveEvent;

		void* pResolver = fg_AsyncResolveAddress_Open(_Address, _Type, [&]{ResolveEvent.f_Signal();});

		if (ResolveEvent.f_WaitTimeout(gc_Timeout))
			DMibTest(!DMibExpr("Timed out async resolving address"))(ETest_FailAndStop);

		CAddress Resolved = nullptr;
		NStr::CStr ErrorString;

		bint bRet = fg_AsyncResolveAddress_GetResult(pResolver, Resolved, ErrorString);

		DMibTest(DMibExpr(bRet) == DMibExpr((bint)true));

		fg_AsyncResolveAddress_Close(pResolver);

		DMibTest(DMibExpr(Resolved) != DMibExpr(nullptr));

		if (Resolved != nullptr)
		{
			t_CNetAddress Return;
			DMibTest(DMibExpr(fg_GetAddressRaw(Resolved, _Type, &Return, sizeof(Return))) == DMibExpr((bint)true));

			DMibTest(DMibExpr(NMem::fg_MemCmp((uint8 const*)&Return.f_GetIP(), (uint8 const*)&_Result.f_GetIP(), sizeof(Return.f_GetIP()))) == DMibExpr(0));

			fg_FreeAddress(Resolved);
		}
	}

	template<typename t_CNetAddress, ENetAddressType _Type>
	void f_TestConnect(NMib::NStr::CStr _Address, uint16 _Port)
	{
//		CAddress Address = fg_CreateAddress(_Type, &_Address, sizeof(t_CNetAddress));
		CAddress Address = fg_ResolveAddress(_Address, _Type);
		auto CleanupAddress
			= g_OnScopeExit > [&]()
			{
				if (Address)
					fg_FreeAddress(Address);
				Address = nullptr;
			}
		;
		DMibTest(DMibExpr(Address) != DMibExpr(nullptr));

		{
			t_CNetAddress Return;
			DMibTest(DMibExpr(fg_GetAddressRaw(Address, _Type, &Return, sizeof(Return))) == DMibExpr((bint)true));
			Return.m_Port = _Port;

			CAddress TmpAddress = fg_SetAddressRaw(Address, _Type, &Return, sizeof(Return));
			DMibTest(DMibExpr(TmpAddress) != DMibExpr(nullptr));
			Address = TmpAddress;

			if (!Address)
				return;
		}

		void* pSocket = fg_Connect(Address, nullptr, nullptr);

		
		if (pSocket != nullptr)
		{
			CAddress PeerAddress = nullptr;

			PeerAddress = fg_GetPeerAddress(pSocket);

			DMibTest(DMibExpr(PeerAddress) != DMibExpr(nullptr));

			DMibTest( DMibExpr(fg_CompareAddresses(PeerAddress, Address)) == DMibExpr(0));

			fg_FreeAddress(PeerAddress);
		}

		auto Cleanup
			= fg_OnScopeExit
			(
				[&]()
				{
					if (pSocket)
						fg_Close(pSocket);
				}
			)
		;
		
		DMibTest(DMibExpr(pSocket) != DMibExpr(nullptr));
		if (pSocket == nullptr)
			return;

		static uint8 const Message[] = { 'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!', '\n' };
		static mint const nMessageBytes = sizeof(Message);

		{
			mint nSent = fg_Send(pSocket, Message, nMessageBytes);
			DMibTest(DMibExpr(nSent) == DMibExpr(nMessageBytes));
		}

		{
			mint nReceived = 0;
			mint nBytes = -1;
			uint8 Incoming[nMessageBytes];
			NMem::fg_MemClear(Incoming, nMessageBytes);
			NTime::CTimeout Timeout(gc_Timeout);
			while (nReceived < nMessageBytes && !Timeout.f_TimedOut())
			{
				nBytes = fg_Receive(pSocket, &Incoming[nReceived], nMessageBytes - nReceived);

				if (nBytes == -1)
					break;

				nReceived += nBytes;
			}

			DMibExpect(nBytes, !=, -1);
			DMibExpect(nReceived, ==, nMessageBytes);
			DMibExpect(NMem::fg_MemCmp(Incoming, Message, nMessageBytes), ==, 0);
		}
	}


	template<typename t_CNetAddress, ENetAddressType _Type>
	void f_TestConnectListen(NMib::NStr::CStr _Address, uint16 _Port, uint16 _ListenPort)
	{
//		CAddress Address = fg_CreateAddress(_Type, &_Address, sizeof(t_CNetAddress));
		CAddress Address = fg_ResolveAddress(_Address, _Type);
		auto CleanupAddress
			= g_OnScopeExit > [&]()
			{
				if (Address)
					fg_FreeAddress(Address);
				Address = nullptr;
			}
		;
		DMibTest(DMibExpr(Address) != DMibExpr(nullptr));

		{
			t_CNetAddress Return;
			DMibTest(DMibExpr(fg_GetAddressRaw(Address, _Type, &Return, sizeof(Return))) == DMibExpr((bint)true));
			Return.m_Port = _Port;

			CAddress TmpAddress = fg_SetAddressRaw(Address, _Type, &Return, sizeof(Return));
			DMibTest(DMibExpr(TmpAddress) != DMibExpr(nullptr));
			Address = TmpAddress;

			if (!Address)
				return;
		}

		static uint8 const Message[] = { 'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!', '\n' };
		static mint const nMessageBytes = sizeof(Message);

		NMib::NThread::CEventAutoResetReportable ServerReady;

		auto ServerThread = NThread::CThreadObject::fs_StartThread
			(
				[&](NThread::CThreadObject* _pThread) -> aint
				{
					try
					{
	//					DMibTraceRaw("ConnectListen Server Thread\n");
	//					return f_InternalConnectListen_Server<t_CNetAddress, _Type>(_Port, ServerReady);
						t_CNetAddress AnyAddr; // = _Localhost;
						AnyAddr.f_SetLocalhost();
						AnyAddr.m_Port = _ListenPort;

						CAddress BindAddress = fg_CreateAddress(_Type, &AnyAddr, sizeof(AnyAddr));
						DMibTest(DMibExpr(BindAddress) != DMibExpr(nullptr));

						void* pServer = fg_Listen(BindAddress, nullptr, NMib::NNet::ENetFlag_None);
						auto CleanupServer
							= fg_OnScopeExit
							(
								[&]()
								{
									fg_Close(pServer);
								}
							)
						;

						fg_FreeAddress(BindAddress);
						BindAddress = nullptr;

						DMibTest(DMibExpr(pServer) != DMibExpr(nullptr));

						if (pServer == nullptr)
							return -1;

						ServerReady.f_Signal();

						void *pConn = nullptr;

						NTime::CTimeout Timeout(gc_Timeout);

						while(pConn == nullptr && !Timeout.f_TimedOut())
						{
							pConn = fg_Accept(pServer, nullptr);
							if (pConn == nullptr)
								NSys::fg_Thread_Yield();
						}

						auto CleanupClient
							= fg_OnScopeExit
							(
								[&]()
								{
									if (pConn)
										fg_Close(pConn);
								}
							)
						;

						DMibTest(DMibExpr(pConn) != DMibExpr(nullptr));
						
						if (pConn == nullptr)
							return -1;

						mint nSent = fg_Send(pConn, Message, nMessageBytes);
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

		auto ClientThread = NThread::CThreadObject::fs_StartThread(
			[&](NThread::CThreadObject* _pThread) -> aint
			{
				//return f_InternalConnectListen_Client<t_CNetAddress, _Type>(Address, _Port);
//				DMibTraceRaw("ConnectListen Client Thread\n");
				try
				{
					void* pClient = fg_Connect(Address, nullptr, nullptr);
					auto Cleanup
						= fg_OnScopeExit
						(
							[&]()
							{
								fg_Close(pClient);								
							}
						)
					;

					DMibTest(DMibExpr(pClient) != DMibExpr(nullptr));
					if (pClient == nullptr)
						return -1;

					{
						mint nReceived = 0, nBytes;
						uint8 Incoming[nMessageBytes];
						NMem::fg_MemClear(Incoming, nMessageBytes);
						NTime::CTimeout Timeout(gc_Timeout);

						while (nReceived < nMessageBytes && !Timeout.f_TimedOut())
						{
							nBytes = fg_Receive(pClient, &Incoming[nReceived], nMessageBytes - nReceived);

							if (nBytes == -1)
								break;

							nReceived += nBytes;
						}

						DMibExpect(nBytes, !=, -1);
						DMibExpect(nReceived, ==, nMessageBytes);
						DMibExpect(NMem::fg_MemCmp(Incoming, Message, nMessageBytes), ==, 0);
					}
				}
				catch (CExceptionNet const& _Exception)
				{
					(void)_Exception;
					DMibTest(DMibExpr(_Exception.f_GetErrorStr()) && DMibExpr(false));
				}

				return 0;
			},
			"TestConnectListen_Client"
		);

		ClientThread->f_Stop();
		ServerThread->f_Stop();

	}

	template<typename t_CNetAddress, ENetAddressType _Type>
	void f_TestConnectReportTo(NMib::NStr::CStr _Address, uint16 _Port)
	{
//		CAddress Address = fg_CreateAddress(_Type, &_Address, sizeof(t_CNetAddress));
		CAddress Address = fg_ResolveAddress(_Address, _Type);
		auto CleanupAddress
			= g_OnScopeExit > [&]()
			{
				if (Address)
					fg_FreeAddress(Address);
				Address = nullptr;
			}
		;
		DMibTest(DMibExpr(Address) != DMibExpr(nullptr));

		{
			t_CNetAddress Return;
			DMibTest(DMibExpr(fg_GetAddressRaw(Address, _Type, &Return, sizeof(Return))) == DMibExpr((bint)true));
			Return.m_Port = _Port;

			CAddress TmpAddress = fg_SetAddressRaw(Address, _Type, &Return, sizeof(Return));
			DMibTest(DMibExpr(TmpAddress) != DMibExpr(nullptr));
			Address = TmpAddress;

			if (!Address)
				return;
		}


		NMib::NThread::CEventAutoResetReportable SocketEvent;

		void* pSocket = fg_Connect
			(
				Address
				, [&SocketEvent](::NMib::NNet::ENetTCPState _StateAdded)
				{
					SocketEvent.f_Signal();
				}
				, nullptr
			)
		;
		
		auto Cleanup
			= fg_OnScopeExit
			(
				[&]()
				{
					if (pSocket)
						fg_Close(pSocket);
				}
			)
		;
		

		DMibTest(DMibExpr(pSocket) != DMibExpr(nullptr));
		if (pSocket == nullptr)
			return;

		static mint const nBufferBytes = 1024*1024*16;
		NContainer::TCVector<uint8> lBuffer;
		lBuffer.f_SetLen(nBufferBytes);
		NMem::fg_MemClear(lBuffer.f_GetArray(), lBuffer.f_GetLen());

		{
			mint nTotalSent = 0;
			mint nSent = -1;

//			DMibTraceRaw("Entering send loop\n");
			while(nTotalSent < nBufferBytes)
			{
				nSent = fg_Send(pSocket, lBuffer.f_GetArray() + nTotalSent, nBufferBytes - nTotalSent);			
//				DMibTrace("Sent: {}\n", nSent);
				if (nSent == -1)
					break;

				// OSX note:
				// Occasionally you will receive two kqueue WRITE notifications after a single stuffing send.
				// When this occurs it is possible that the report event will be signaled when a fg_Send will return 0.
				// So we don't do this test:
//				if (nSent == 0)
//					break;
				// A possible fix is to only signal the report event when State does NOT have the write flag,
				// But this may break windows. Investigate when we refactor the windows net code.

				bint bStuffed = nSent < (nBufferBytes - nTotalSent);

				nTotalSent += nSent;

				if (bStuffed)
				{
//					DMibTrace("Waiting after sending {} bytes\n", nTotalSent);
					do
					{
						NMib::NTime::CClock WaitTime;
						WaitTime.f_Start();
						if (SocketEvent.f_WaitTimeout(gc_Timeout))
						{
							DMibTest(DMibExpr(WaitTime.f_GetTime()) > DMibExpr(gc_Timeout));
							DMibTest(!DMibExpr("Timed out sending data"))(ETest_FailAndStop);
						}
					} while ( !(fg_GetState(pSocket) & ENetTCPState_Write) );
				}
			}

			DMibTest(DMibExpr(nSent) != DMibExpr(-1)); // Error

//			DMibTest(DMibExpr(nSent) > DMibExpr(0)); // Socket event was useless.

			DMibTest(DMibExpr(nTotalSent) == DMibExpr(nBufferBytes));

		}

	}


	template<typename t_CNetAddress, ENetAddressType _Type>
	void f_TestConnectListenReportTo(NMib::NStr::CStr _Address, uint16 _Port, uint16 _ListenPort)
	{
//		CAddress Address = fg_CreateAddress(_Type, &_Address, sizeof(t_CNetAddress));
		CAddress Address = fg_ResolveAddress(_Address, _Type);
		auto CleanupAddress
			= g_OnScopeExit > [&]()
			{
				if (Address)
					fg_FreeAddress(Address);
				Address = nullptr;
			}
		;
		DMibTest(DMibExpr(Address) != DMibExpr(nullptr));

		{
			t_CNetAddress Return;
			DMibTest(DMibExpr(fg_GetAddressRaw(Address, _Type, &Return, sizeof(Return))) == DMibExpr((bint)true));
			Return.m_Port = _Port;

			CAddress TmpAddress = fg_SetAddressRaw(Address, _Type, &Return, sizeof(Return));
			DMibTest(DMibExpr(TmpAddress) != DMibExpr(nullptr));
			Address = TmpAddress;

			if (!Address)
				return;
		}

		static uint8 const Message[] = { 'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!', '\n' };
		static mint const nMessageBytes = sizeof(Message);

		NMib::NThread::CEventAutoResetReportable ServerReady;

		auto ServerThread = NThread::CThreadObject::fs_StartThread(
				[&](NThread::CThreadObject* _pThread) -> aint
				{
//					return f_InternalConnectListen_Server<t_CNetAddress, _Type>(_Port, ServerReady);
					try
					{
						t_CNetAddress AnyAddr; // = _Localhost;
						AnyAddr.f_SetLocalhost();
						AnyAddr.m_Port = _ListenPort;

						CAddress BindAddress = fg_CreateAddress(_Type, &AnyAddr, sizeof(AnyAddr));
						DMibTest(DMibExpr(BindAddress) != DMibExpr(nullptr));

						NMib::NThread::CEventAutoResetReportable ListenEvent;

						void* pServer = fg_Listen
							(
								BindAddress
								, [&ListenEvent](::NMib::NNet::ENetTCPState _StateAdded)
								{
									ListenEvent.f_Signal();
								}
								, NMib::NNet::ENetFlag_None
							)
						;

						auto Cleanup
							= fg_OnScopeExit
							(
								[&]()
								{
									if (pServer)
										fg_Close(pServer);
								}
							)
						;
						
						fg_FreeAddress(BindAddress);
						BindAddress = nullptr;

						DMibTest(DMibExpr(pServer) != DMibExpr(nullptr));

						if (pServer == nullptr)
							return -1;

						ServerReady.f_Signal();

						void *pConn = nullptr;

						bool bTimedOut = ListenEvent.f_WaitTimeout(gc_Timeout);
						
						DMibTest(!DMibExpr(bTimedOut));
						
						if (bTimedOut)
							return -1;

						DMibTest( DMibExpr(fg_GetState(pServer)) & DMibExpr(ENetTCPState_Connection) );

						pConn = fg_Accept(pServer, nullptr);

						DMibTest(DMibExpr(pConn) != DMibExpr(nullptr));
						
						if (pConn == nullptr)
							return -1;
						
						auto CleanupConn
							= fg_OnScopeExit
							(
								[&]()
								{
									if (pConn)
										fg_Close(pConn);
								}
							)
						;
						

						mint nSent = fg_Send(pConn, Message, nMessageBytes);
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
			);

		if (ServerReady.f_WaitTimeout(gc_Timeout))
			DMibTest(!DMibExpr("Timed out waiting for server ready"))(ETest_FailAndStop);
		NMib::NSys::fg_Thread_Sleep(1.0f);

		auto ClientThread = NThread::CThreadObject::fs_StartThread(
			[&](NThread::CThreadObject* _pThread) -> aint
			{
				try
				{
					//return f_InternalConnectListen_Client<t_CNetAddress, _Type>(Address, _Port);
					void* pClient = fg_Connect(Address, nullptr, nullptr);


					DMibTest(DMibExpr(pClient) != DMibExpr(nullptr));
					if (pClient == nullptr)
						return -1;

					auto CleanupClient
						= fg_OnScopeExit
						(
							[&]()
							{
								if (pClient)
									fg_Close(pClient);
							}
						)
					;
					
					{
						mint nReceived = 0, nBytes;
						uint8 Incoming[nMessageBytes];
						NMem::fg_MemClear(Incoming, nMessageBytes);
						NTime::CTimeout Timeout(gc_Timeout);

						while (nReceived < nMessageBytes && !Timeout.f_TimedOut())
						{
							nBytes = fg_Receive(pClient, &Incoming[nReceived], nMessageBytes - nReceived);

							if (nBytes == -1)
								break;

							nReceived += nBytes;
						}

						DMibExpect(nBytes, !=, -1);
						DMibExpect(nReceived, ==, nMessageBytes);
						DMibExpect(NMem::fg_MemCmp(Incoming, Message, nMessageBytes), ==, 0);
					}
				}
				catch (CExceptionNet const& _Exception)
				{
					(void)_Exception;
					DMibTest(DMibExpr(_Exception.f_GetErrorStr()) && DMibExpr(false));
				}

				return 0;
			},
			"TestConnectListen_Client"
		);

		ClientThread->f_Stop();
		ServerThread->f_Stop();

	}


	template<typename t_CNetAddress, ENetAddressType _Type>
	void f_TestInherit(NMib::NStr::CStr _Address, uint16 _Port)
	{
//		CAddress Address = fg_CreateAddress(_Type, &_Address, sizeof(t_CNetAddress));
		CAddress Address = fg_ResolveAddress(_Address, _Type);
		auto CleanupAddress
			= g_OnScopeExit > [&]()
			{
				if (Address)
					fg_FreeAddress(Address);
				Address = nullptr;
			}
		;
		DMibTest(DMibExpr(Address) != DMibExpr(nullptr));

		{
			t_CNetAddress Return;
			DMibTest(DMibExpr(fg_GetAddressRaw(Address, _Type, &Return, sizeof(Return))) == DMibExpr((bint)true));
			Return.m_Port = _Port;

			CAddress TmpAddress = fg_SetAddressRaw(Address, _Type, &Return, sizeof(Return));
			DMibTest(DMibExpr(TmpAddress) != DMibExpr(nullptr));
			Address = TmpAddress;

			if (!Address)
				return;
		}


		NMib::NThread::CEventAutoResetReportable SocketEvent;

		void* pSocket = fg_Connect(Address, nullptr, nullptr);

		auto Cleanup
			= fg_OnScopeExit
			(
				[&]()
				{
					if (pSocket)
						fg_Close(pSocket);
				}
			)
		;
		
		

		DMibTest(DMibExpr(pSocket) != DMibExpr(nullptr));
		if (pSocket == nullptr)
			return;

		{
			void* pOldSocket = pSocket;
			pSocket = nullptr;
			void* pOSSocket = fg_GiveUpForInherit(pOldSocket);

			fg_Close(pOldSocket);

			pSocket = fg_InheritHandle2
				(
					pOSSocket
					, [&SocketEvent](::NMib::NNet::ENetTCPState _StateAdded)
					{
						SocketEvent.f_Signal();
					}
				)
			;
		}

		static mint const nBufferBytes = 1024*1024*4;
		NContainer::TCVector<uint8> lBuffer;
		lBuffer.f_SetLen(nBufferBytes);
		NMem::fg_MemClear(lBuffer.f_GetArray(), lBuffer.f_GetLen());

		{
			mint nTotalSent = 0;
			mint nSent = -1;

//			DMibTraceRaw("Entering send loop\n");
			while(nTotalSent < nBufferBytes)
			{
				nSent = fg_Send(pSocket, lBuffer.f_GetArray() + nTotalSent, nBufferBytes - nTotalSent);			
//				DMibTrace("Sent: {}\n", nSent);
				if (nSent == -1)
					break;

				bint bStuffed = nSent < (nBufferBytes - nTotalSent);

				nTotalSent += nSent;

				if (bStuffed)
				{
//					DMibTrace("Waiting after sending {} bytes\n", nTotalSent);
					do
					{
//						DMibTraceRaw("...Wait\n");
						if (SocketEvent.f_WaitTimeout(gc_Timeout))
							DMibTest(!DMibExpr("Timed out sending data"))(ETest_FailAndStop);
					} while ( !(fg_GetState(pSocket) & ENetTCPState_Write) );
				}
			}
			
			DMibTest(DMibExpr(nSent) != DMibExpr(-1)); // Error

			DMibTest(DMibExpr(nTotalSent) == DMibExpr(nBufferBytes));

		}
	}


	template<typename t_CNetAddress, ENetAddressType _Type>
	void f_TestAsyncConnectReportTo(NMib::NStr::CStr _Address, uint16 _Port)
	{
//		CAddress Address = fg_CreateAddress(_Type, &_Address, sizeof(t_CNetAddress));
		CAddress Address = fg_ResolveAddress(_Address, _Type);
		auto CleanupAddress
			= g_OnScopeExit > [&]()
			{
				if (Address)
					fg_FreeAddress(Address);
				Address = nullptr;
			}
		;
		DMibTest(DMibExpr(Address) != DMibExpr(nullptr));

		{
			t_CNetAddress Return;
			DMibTest(DMibExpr(fg_GetAddressRaw(Address, _Type, &Return, sizeof(Return))) == DMibExpr((bint)true));
			Return.m_Port = _Port;

			CAddress TmpAddress = fg_SetAddressRaw(Address, _Type, &Return, sizeof(Return));
			DMibTest(DMibExpr(TmpAddress) != DMibExpr(nullptr));
			Address = TmpAddress;

			if (!Address)
				return;
		}


		NMib::NThread::CEventAutoResetReportable SocketEvent;

		void* pSocket = fg_AsyncConnect
			(
				Address
				, [&SocketEvent](::NMib::NNet::ENetTCPState _StateAdded)
				{
					SocketEvent.f_Signal();
				}
				, nullptr
			)
		;

		auto Cleanup
			= fg_OnScopeExit
			(
				[&]()
				{
					if (pSocket)
						fg_Close(pSocket);
				}
			)
		;
		
		DMibTest(DMibExpr(pSocket) != DMibExpr(nullptr));
		if (pSocket == nullptr)
			return;

		NTime::CTimeout Timeout(gc_Timeout);

		while( !(fg_GetState(pSocket) & ENetTCPState_Connected) && !Timeout.f_TimedOut())
		{
			SocketEvent.f_WaitTimeout(gc_Timeout);
		};
		
		DMibTest(!DMibExpr(Timeout.f_TimedOut()))(ETest_FailAndStop);

		static mint const nBufferBytes = 1024*1024*4;
		NContainer::TCVector<uint8> lBuffer;
		lBuffer.f_SetLen(nBufferBytes);
		NMem::fg_MemClear(lBuffer.f_GetArray(), lBuffer.f_GetLen());

		{
			mint nTotalSent = 0;
			mint nSent = -1;

//			DMibTraceRaw("Entering send loop\n");
			while(nTotalSent < nBufferBytes)
			{
				nSent = fg_Send(pSocket, lBuffer.f_GetArray() + nTotalSent, nBufferBytes - nTotalSent);			
//				DMibTrace("Sent: {}\n", nSent);
				if (nSent == -1)
					break;

				bint bStuffed = nSent < (nBufferBytes - nTotalSent);

				nTotalSent += nSent;

				if (bStuffed)
				{
//					DMibTrace("Waiting after sending {} bytes\n", nTotalSent);
					do
					{
//						DMibTraceRaw("...Wait\n");
						if (SocketEvent.f_WaitTimeout(gc_Timeout))
							DMibTest(!DMibExpr("Timed out sending data"))(ETest_FailAndStop);
					} while ( !(fg_GetState(pSocket) & ENetTCPState_Write) );
				}
			}

			DMibTest(DMibExpr(nSent) != DMibExpr(-1)); // Error

//			DMibTest(DMibExpr(nSent) > DMibExpr(0)); // Socket event was useless.

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

		NStr::CStr RemoteMachine = fg_GetLoopbackMachine();

		//DMibTestCategory(CTestCategory("Manual tests") << CTestGroup("Manual"))
		{
			DMibTestSuite("Addresses_TCPv4")
			{			
				f_TestAddress<CNetAddressTCPv4, ENetAddressType_TCPv4, CNetAddressTCPv6, ENetAddressType_TCPv6>(Localhost_TCPv4, Other_TCPv4);
			};

			DMibTestSuite("Addresses_TCPv6")
			{				
				f_TestAddress<CNetAddressTCPv6, ENetAddressType_TCPv6, CNetAddressTCPv4, ENetAddressType_TCPv4>(Localhost_TCPv6, Other_TCPv6);
			};

			DMibTestSuite("Resolve_TCPv4")
			{
				f_TestResolve<CNetAddressTCPv4, ENetAddressType_TCPv4>("localhost", Localhost_TCPv4);
			};

			DMibTestSuite("Resolve_TCPv6")
			{
				f_TestResolve<CNetAddressTCPv6, ENetAddressType_TCPv6>("localhost", Localhost_TCPv6);
			};

			DMibTestSuite("AsyncResolve_TCPv4")
			{
				f_TestAsyncResolve<CNetAddressTCPv4, ENetAddressType_TCPv4>("localhost", Localhost_TCPv4);
			};

			DMibTestSuite("AsyncResolve_TCPv6")
			{
				f_TestAsyncResolve<CNetAddressTCPv6, ENetAddressType_TCPv6>("localhost", Localhost_TCPv6);
			};

			DMibTestSuite("Connect_TCPv4")
			{
				f_TestConnect<CNetAddressTCPv4, ENetAddressType_TCPv4>(RemoteMachine, 20677);
			};

			DMibTestSuite("Connect_TCPv6")
			{
				f_TestConnect<CNetAddressTCPv6, ENetAddressType_TCPv6>(RemoteMachine, 20677);
			};

			DMibTestSuite("ConnectListen_TCPv4")
			{
				f_TestConnectListen<CNetAddressTCPv4, ENetAddressType_TCPv4>(RemoteMachine, 20678, 20680);
			};

			DMibTestSuite("ConnectListen_TCPv6")
			{
				f_TestConnectListen<CNetAddressTCPv6, ENetAddressType_TCPv6>(RemoteMachine, 20678, 20680);
			};

			DMibTestSuite("ConnectReportTo_TCPv4")
			{
				f_TestConnectReportTo<CNetAddressTCPv4, ENetAddressType_TCPv4>(RemoteMachine, 20679);
			};

			DMibTestSuite("ConnectReportTo_TCPv6")
			{
				f_TestConnectReportTo<CNetAddressTCPv6, ENetAddressType_TCPv6>(RemoteMachine, 20679);
			};

			DMibTestSuite("ConnectListenReportTo_TCPv4")
			{
				f_TestConnectListenReportTo<CNetAddressTCPv4, ENetAddressType_TCPv4>(RemoteMachine, 20678, 20680);
			};

			DMibTestSuite("ConnectListenReportTo_TCPv6")
			{
				f_TestConnectListenReportTo<CNetAddressTCPv6, ENetAddressType_TCPv6>(RemoteMachine, 20678, 20680);
			};

			DMibTestSuite("Inherit")
			{
				f_TestInherit<CNetAddressTCPv4, ENetAddressType_TCPv4>(RemoteMachine, 20679);
			};

			DMibTestSuite("AsyncConnectReportTo_TCPv4")
			{
				f_TestAsyncConnectReportTo<CNetAddressTCPv4, ENetAddressType_TCPv4>(RemoteMachine, 20679);
			};

			DMibTestSuite("AsyncConnectReportTo_TCPv6")
			{
				f_TestAsyncConnectReportTo<CNetAddressTCPv6, ENetAddressType_TCPv6>(RemoteMachine, 20679);
			};

		};
	}
};

DMibTestRegister(CSysNet_Tests, Malterlib::Network);

