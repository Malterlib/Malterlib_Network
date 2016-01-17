// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Core/Core>
#include <Mib/Concurrency/ThreadSafeQueue>

using namespace NMib;
using namespace NMib::NSys::NNet;
using namespace NMib::NNet;

namespace
{
	struct CLoopbackServer
	{
		NNet::CSocket m_ListenSocketV4;
		NNet::CSocket m_ListenSocketV6;
		NNet::CSocket m_EchoListenSocketV4;
		NNet::CSocket m_EchoListenSocketV6;
		NNet::CSocket m_MirrorListenSocketV4;
		NNet::CSocket m_MirrorListenSocketV6;
		
		NPtr::TCUniquePointer<NThread::CThreadObject> m_pThread;
		
		NContainer::TCThreadSafeQueue<NFunction::TCFunction<void ()>> m_DispatchQueue;
		NContainer::TCLinkedList<NPtr::TCSharedPointer<NPtr::TCSharedPointer<CSocket>>> m_ConnectedSockets;
		
		void f_Dispatch(NFunction::TCFunction<void ()> const &_fDispatch)
		{
			m_DispatchQueue.f_Push(_fDispatch);
			m_pThread->m_EventWantQuit.f_Signal();
		}
		
		enum ELoopbackType
		{
			ELoopbackType_Normal
			, ELoopbackType_Echo
			, ELoopbackType_Mirror
		};
		
		CLoopbackServer()
		{
			m_pThread = NThread::CThreadObject::fs_StartThread
				(
					[this](NThread::CThreadObject *_pThread)
					{
						while (_pThread->f_GetState() != NThread::EThreadState_EventWantQuit)
						{
							while (auto Entry = m_DispatchQueue.f_Pop())
								(*Entry)();
							_pThread->m_EventWantQuit.f_WaitTimeout(0.001);
						}
						return 0;
					}
					, "LoopbackServerThread"
				)
			;

			auto fHandlerFactory
				= [=](CSocket *_pListenSocket, ELoopbackType _LoopbackType)
				{
					return [=](NNet::ENetTCPState _StateAdded)
						{
							f_Dispatch
								(
									[=]()
									{
										if (_StateAdded & NNet::ENetTCPState_Connection)
										{
											while (true)
											{
												auto pSocket = &m_ConnectedSockets.f_Insert();
												*pSocket = fg_Construct(fg_Construct());
												auto pSocketShared = *pSocket;
												NPtr::TCSharedPointer<NContainer::TCVector<uint8>> pSendBuffer = fg_Construct();
												
												try
												{
													(**pSocket)->f_Accept
														(
															_pListenSocket
															, [=](NNet::ENetTCPState _StateAdded)
															{
																f_Dispatch
																	(
																		[=]()
																		{
																			if (!(*pSocketShared))
																			{
																				return;
																			}
																			if (_StateAdded & NNet::ENetTCPState_Read)
																			{
																				try
																				{
																					uint8 Buffer[4096];
																					while (mint nBytes = (*pSocketShared)->f_Receive(Buffer, 4096))
																					{
																						if (_LoopbackType == ELoopbackType_Echo)
																						{
																							pSendBuffer->f_Insert(Buffer, nBytes);
																						}
																					}
																					while (!pSendBuffer->f_IsEmpty())
																					{
																						mint nSent = (*pSocketShared)->f_Send(pSendBuffer->f_GetArray(), pSendBuffer->f_GetLen());
																						if (!nSent)
																							break;
																						pSendBuffer->f_Remove(0, nSent);
																					}
																				}
																				catch (CExceptionNet const &)
																				{
																					m_ConnectedSockets.f_Remove(*pSocket);
																					(*pSocketShared)->f_Close();
																					(*pSocketShared).f_Clear();
																				}
																			}
																			if (_StateAdded & NNet::ENetTCPState_Closed)
																			{
																				m_ConnectedSockets.f_Remove(*pSocket);
																				(*pSocketShared)->f_Close();
																				(*pSocketShared).f_Clear();
																			}
																		}
																	)
																;
															}
														)
													;
													if (!(**pSocket)->f_IsValid())
													{
														m_ConnectedSockets.f_Remove(*pSocket);
														break;
													}
													if (_LoopbackType == ELoopbackType_Mirror)
													{
														auto pSocketMirror = &m_ConnectedSockets.f_Insert();
														*pSocketMirror = fg_Construct(fg_Construct());
														auto pSocketSharedMirror = *pSocketMirror;
														NPtr::TCSharedPointer<NContainer::TCVector<uint8>> pSendBufferMirror = fg_Construct();
														
														auto Peer = (*pSocketShared)->f_GetPeerAddress();
														
														Peer.f_SetPort(20680);
														
														(*pSocketSharedMirror)->f_AsyncConnect
															(
																Peer
																, [=](NNet::ENetTCPState _StateAdded)
																{
																	f_Dispatch
																		(
																			[=]()
																			{
																				if (!(*pSocketSharedMirror))
																					return;
																				if (_StateAdded & NNet::ENetTCPState_Read)
																				{
																					try
																					{
																						uint8 Buffer[4096];
																						while (mint nBytes = (*pSocketSharedMirror)->f_Receive(Buffer, 4096))
																							pSendBufferMirror->f_Insert(Buffer, nBytes);
																						if (*pSocketShared)
																						{
																							while (!pSendBufferMirror->f_IsEmpty())
																							{
																								mint nSent = (*pSocketShared)->f_Send(pSendBufferMirror->f_GetArray(), pSendBufferMirror->f_GetLen());
																								if (!nSent)
																									break;
																								pSendBufferMirror->f_Remove(0, nSent);
																							}
																						}
																					}
																					catch (CExceptionNet const &_Exception)
																					{
																						(void)_Exception;
																						DMibTrace("Error: {}\n", _Exception.f_GetErrorStr());
																						m_ConnectedSockets.f_Remove(*pSocketMirror);
																						(*pSocketSharedMirror)->f_Close();
																						(*pSocketSharedMirror).f_Clear();
																					}
																				}
																				if (_StateAdded & NNet::ENetTCPState_Closed)
																				{
																					m_ConnectedSockets.f_Remove(*pSocketMirror);
																					(*pSocketSharedMirror)->f_Close();
																					(*pSocketSharedMirror).f_Clear();
																				}
																			}
																		)
																	;
																}
															)
														;
														
													}										
												}
												catch (CExceptionNet const &)
												{
													(*pSocketShared)->f_Close();
													m_ConnectedSockets.f_Remove(*pSocket);
													break;
												}
											}
										}
									}
								)
							;
						}
					;
				}
			;
			
			{
				CNetAddressTCPv4 ListenV4;
				ListenV4.m_Port = 20679;

				CNetAddressTCPv6 ListenV6;
				ListenV6.m_Port = 20679;
				
				m_ListenSocketV4.f_Listen
					(
						CNetAddress(ListenV4)
						, fHandlerFactory(&m_ListenSocketV4, ELoopbackType_Normal)
					)
				;
				m_ListenSocketV6.f_Listen
					(
						CNetAddress(ListenV6)
						, fHandlerFactory(&m_ListenSocketV6, ELoopbackType_Normal)
					)
				;
			}

			{
				CNetAddressTCPv4 ListenV4;
				ListenV4.m_Port = 20677;

				CNetAddressTCPv6 ListenV6;
				ListenV6.m_Port = 20677;
				
				m_EchoListenSocketV4.f_Listen
					(
						CNetAddress(ListenV4)
						, fHandlerFactory(&m_EchoListenSocketV4, ELoopbackType_Echo)
					)
				;
				m_EchoListenSocketV6.f_Listen
					(
						CNetAddress(ListenV6)
						, fHandlerFactory(&m_EchoListenSocketV6, ELoopbackType_Echo)
					)
				;
			}

			{
				CNetAddressTCPv4 ListenV4;
				ListenV4.m_Port = 20678;

				CNetAddressTCPv6 ListenV6;
				ListenV6.m_Port = 20678;
				
				m_MirrorListenSocketV4.f_Listen
					(
						CNetAddress(ListenV4)
						, fHandlerFactory(&m_MirrorListenSocketV4, ELoopbackType_Mirror)
					)
				;
				m_MirrorListenSocketV6.f_Listen
					(
						CNetAddress(ListenV6)
						, fHandlerFactory(&m_MirrorListenSocketV6, ELoopbackType_Mirror)
					)
				;
			}
		}
		
		~CLoopbackServer()
		{
			m_pThread->f_Stop();
			for (auto &Socket : m_ConnectedSockets)
				(*Socket)->f_Close();
			m_ConnectedSockets.f_Clear();
			m_pThread = nullptr;
			m_DispatchQueue.f_Clear();
			for (auto &Socket : m_ConnectedSockets)
				(*Socket)->f_Close();
			m_ConnectedSockets.f_Clear();
		}
	};
	
	NPtr::TCUniquePointer<CLoopbackServer> g_pLoopbackServer;
}

namespace NMib
{
	namespace NNet
	{

		NStr::CStr fg_GetLoopbackMachine()
		{
			NStr::CStr Machine = NSys::fg_Process_GetEnvironmentVariable(NStr::CStr("MalterlibTestLoopbackMachine"));
			if (!Machine.f_IsEmpty())
				return Machine;
			else
			{
				if (!g_pLoopbackServer)
					g_pLoopbackServer = fg_Construct();
				return "localhost";
			}

		}
	}
}
