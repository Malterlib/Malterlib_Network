// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#pragma once

/*---------------------------------------------------------------------------------------------*\
	Author:			Erik Olofsson, Michael Wynne
	
	Contents:		NMib::NNet:
						CNetAddressIPv4
						CNetAddressIPv6
						CNetAddressTCPv4
						CNetAddressTCPv6
						ENetTCPState
						CNetAddress
						CSocket

					System Specifics in NMib::NSys::NNet:
						typedef void* CAddress;
				
						CAddress fg_CreateAddress(::NMib::NNet::ENetAddressType _Type, void const* _pData, mint _nDataBytes);

						::NMib::NNet::ENetAddressType fg_GetAddressType(CAddress _Address);
						bint fg_GetAddressRaw(CAddress _Address, ::NMib::NNet::ENetAddressType _ExpectedType, void* _opRawData, mint _nDataBytes);
						CAddress fg_SetAddressRaw(CAddress _Address, ::NMib::NNet::ENetAddressType _Type, void const* _pRawData, mint _nDataBytes);

						CAddress fg_ResolveAddress(const NMib::NStr::CStr &_Address, ::NMib::NNet::ENetAddressType _PreferType = ::NMib::NNet::ENetAddressType_None);

						void *fg_AsyncResolveAddress_Open(const NMib::NStr::CStr &_Address, ::NMib::NNet::ENetAddressType _PreferType, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo);
						bint fg_AsyncResolveAddress_GetResult(void *_pResolver, CAddress& _opAddress, NMib::NStr::CStr &_Error);
						void fg_AsyncResolveAddress_Close(void *_pResolver);

						int fg_CompareAddresses(CAddress _pFirst, CAddress _pSecond);

						void fg_FreeAddress(CAddress _Address); // It is OK to free a nullptr address.

						NMib::NStr::CStr fg_GetAddressString(CAddress _Address, bint _bIncludeType);

					// Connection Operations
						void *fg_Connect(CAddress _pAddr, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo); // Report to the supplied event when new data is received or when we are ready to send new data

						void *fg_AsyncConnect(CAddress _pAddr, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo); // Report to the supplied event when new data is received or when we are ready to send new data and when the connection is connected

						void *fg_Listen(CAddress _pAddr, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo); // Report to the supplied event when a new connection has arrived
						void *fg_Accept(void *_pSocket, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo); // Report to the supplied event when new data is received or when we are ready to send new data

						void fg_Close(void *_pSocket); // Closes the socket and connection

						mint fg_Receive(void *_pSocket, void *_pData, mint _DataLen); // Returns bytes received
						mint fg_Send(void *_pSocket, const void *_pData, mint _DataLen); // Returns bytes sent

					// Socket Properties & State

						void fg_SetReportTo(void *_pSocket, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo); // Report to the supplied event when new data is received or when we are ready to send new data				

						NMib::NNet::ENetTCPState fg_GetState(void *_pSocket); // Get the state of data available
						NMib::NStr::CStr fg_GetCloseReason(void *_pSocket);
				
						void *fg_InheritHandle2(void *_pSocket, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo);
						void *fg_GiveUpForInherit(void *_pSocket);
						void *fg_GetOSSocket(void *_pSocket);
						
						CAddress fg_GetPeerAddress(void *_pSocket);

	Comments:			Non-Blocking Operation:

						All reportable events are edge triggered. That is, they are signalled when
						the sockets state changes.

						When a reportable event is signalled you call fg_GetState(pSocket) to 
						get the current state of the socket. The returned state bitfield represents
						state changes since the last time fg_GetState was called on that socket,
						NOT the current state of the socket.

						In some circumstances a reportable event will be signalled erroneously.
						This means that you should ALWAYS check the socket state after the event
						is signalled.

						TODO: 
							Typedef for sockets in NSys::NNet
								typedef void* CSocket;
	
\*_____________________________________________________________________________________________*/
#ifndef DMibSafety_IncMalterlib_H
#	error "You have to include this file through <Mib/Core/Core>"
#endif


#include <Mib/Core/Platform>
#include "Malterlib_Network_Exception.h"

namespace NMib
{
	namespace NNet
	{

		class CNetAddressIPv4
		{
		public:
			uint8 m_IP[4];

			CNetAddressIPv4()
			{
				NMem::fg_MemClear(*this);
			}

			CNetAddressIPv4(uint8 _0, uint8 _1, uint8 _2, uint8 _3)
			{
				m_IP[0] = _0;
				m_IP[1] = _1;
				m_IP[2] = _2;
				m_IP[3] = _3;
			}

			CNetAddressIPv4(const CNetAddressIPv4 &_Src)
			{
				NMem::fg_MemCopy(this, &_Src, sizeof(*this));
			}

			CNetAddressIPv4 &operator = (const CNetAddressIPv4 &_Src)
			{
				NMem::fg_MemCopy(this, &_Src, sizeof(*this));

				return *this;
			}
		};

		class CNetAddressIPv6
		{
		public:
			uint8 m_IP[16];

			CNetAddressIPv6()
			{
				NMem::fg_MemClear(*this);
			}

			CNetAddressIPv6(	uint8 _0, uint8 _1, uint8 _2, uint8 _3
							,	uint8 _4, uint8 _5, uint8 _6, uint8 _7
							,	uint8 _8, uint8 _9, uint8 _10, uint8 _11
							,	uint8 _12, uint8 _13, uint8 _14, uint8 _15)
			{
				m_IP[0] = _0; m_IP[1] = _1;
				m_IP[2] = _2; m_IP[3] = _3;
				m_IP[4] = _4; m_IP[5] = _5;
				m_IP[6] = _6; m_IP[7] = _7;
				m_IP[8] = _8; m_IP[9] = _9;
				m_IP[10] = _10; m_IP[11] = _11;
				m_IP[12] = _12; m_IP[13] = _13;
				m_IP[14] = _14; m_IP[15] = _15;
			}

			CNetAddressIPv6(const CNetAddressIPv6 &_Src)
			{
				NMem::fg_MemCopy(this, &_Src, sizeof(*this));
			}

			CNetAddressIPv6 &operator = (const CNetAddressIPv6 &_Src)
			{
				NMem::fg_MemCopy(this, &_Src, sizeof(*this));

				return *this;
			}
		};

		// This is not an enum as each platform can add it's own address types.
		typedef uint32 ENetAddressType;
		static const uint32 ENetAddressType_None = 0;
		static const uint32 ENetAddressType_TCPv4 = 1;
		static const uint32 ENetAddressType_TCPv6 = 2;		

		template<typename t_CIPAddress, ENetAddressType t_Type>
		class TNetAddressTCP : public t_CIPAddress
		{
		public:
			uint16 m_Port;			

			TNetAddressTCP()
				: m_Port(0)
			{
			}

			TNetAddressTCP(const TNetAddressTCP &_Src)
			{
				NMem::fg_MemCopy(this, &_Src, sizeof(*this));
			}

			TNetAddressTCP(const t_CIPAddress &_Src, uint16 _Port)
				: t_CIPAddress(_Src)
				, m_Port(_Port)
			{
			}

			TNetAddressTCP &operator = (const TNetAddressTCP &_Src)
			{
				NMem::fg_MemCopy(this, &_Src, sizeof(*this));

				return *this;
			}

			TNetAddressTCP &operator = (const t_CIPAddress &_Src)
			{
				(*this) = _Src;

				return *this;
			}

			t_CIPAddress const& f_GetIP() const { return *this; }

			static ENetAddressType fs_GetType() 
			{
				return t_Type;
			}
		};

		typedef TNetAddressTCP<CNetAddressIPv4, ENetAddressType_TCPv4> CNetAddressTCPv4;
		typedef TNetAddressTCP<CNetAddressIPv6, ENetAddressType_TCPv6> CNetAddressTCPv6;		
		
		enum ENetTCPState
		{
			ENetTCPState_None			= 0
			, ENetTCPState_Read			= DMibBit(0) // Data is awailable for reading
			, ENetTCPState_Write		= DMibBit(1) // More data can now be sent
			, ENetTCPState_Connection	= DMibBit(2) // A new connection is available for accept
			, ENetTCPState_Connected	= DMibBit(3) // A async connection has completed
			, ENetTCPState_Closed		= DMibBit(4) // The connection has been lost
		};

		class CNetAddress;
	}
	namespace NStream
	{
		template <typename t_CStream>
		class TCBinaryStreamTypeReference<t_CStream, NNet::CNetAddressTCPv4 >
		{
		public:
			static void fs_Feed(t_CStream &_Stream, NNet::CNetAddressTCPv4 const &_Data)
			{
				_Stream.f_FeedBytes(_Data.m_IP, sizeof(_Data.m_IP));
				_Stream << _Data.m_Port;
			}
	
			static void fs_Consume(t_CStream &_Stream, NNet::CNetAddressTCPv4 &_Data)
			{
				_Stream.f_ConsumeBytes(_Data.m_IP, sizeof(_Data.m_IP));
				_Stream >> _Data.m_Port;
			}
		};

		template <typename t_CStream>
		class TCBinaryStreamTypeReference<t_CStream, NNet::CNetAddressIPv4 >
		{
		public:
			static void fs_Feed(t_CStream &_Stream, NNet::CNetAddressIPv4 const &_Data)
			{
				_Stream.f_FeedBytes(_Data.m_IP, sizeof(_Data.m_IP));
			}
	
			static void fs_Consume(t_CStream &_Stream, NNet::CNetAddressIPv4 &_Data)
			{
				_Stream.f_ConsumeBytes(_Data.m_IP, sizeof(_Data.m_IP));
			}
		};

		template <typename t_CStream>
		class TCBinaryStreamTypeReference<t_CStream, NNet::CNetAddressTCPv6 >
		{
		public:
			static void fs_Feed(t_CStream &_Stream, NNet::CNetAddressTCPv6 const &_Data)
			{
				_Stream.f_FeedBytes(_Data.m_IP, sizeof(_Data.m_IP));
				_Stream << _Data.m_Port;
			}
	
			static void fs_Consume(t_CStream &_Stream, NNet::CNetAddressTCPv6 &_Data)
			{
				_Stream.f_ConsumeBytes(_Data.m_IP, sizeof(_Data.m_IP));
				_Stream >> _Data.m_Port;
			}
		};

		template <typename t_CStream>
		class TCBinaryStreamTypeReference<t_CStream, NNet::CNetAddressIPv6 >
		{
		public:
			static void fs_Feed(t_CStream &_Stream, NNet::CNetAddressIPv6 const &_Data)
			{
				_Stream.f_FeedBytes(_Data.m_IP, sizeof(_Data.m_IP));
			}
	
			static void fs_Consume(t_CStream &_Stream, NNet::CNetAddressIPv6 &_Data)
			{
				_Stream.f_ConsumeBytes(_Data.m_IP, sizeof(_Data.m_IP));
			}
		};


	}
	namespace NSys
	{
		namespace NNet
		{
			// Addresses

				typedef void* CAddress;
		
				CAddress fg_CreateAddress(::NMib::NNet::ENetAddressType _Type, void const* _pData, mint _nDataBytes);
				CAddress fg_DuplicateAddress(CAddress _Address);

				::NMib::NNet::ENetAddressType fg_GetAddressType(CAddress _Address);
				bint fg_GetAddressRaw(CAddress _Address, ::NMib::NNet::ENetAddressType _ExpectedType, void* _opRawData, mint _nDataBytes);
				CAddress fg_SetAddressRaw(CAddress _Address, ::NMib::NNet::ENetAddressType _Type, void const* _pRawData, mint _nDataBytes);

				CAddress fg_ResolveAddress(const NMib::NStr::CStr &_Address, ::NMib::NNet::ENetAddressType _PreferType = ::NMib::NNet::ENetAddressType_None);

				void *fg_AsyncResolveAddress_Open(const NMib::NStr::CStr &_Address, ::NMib::NNet::ENetAddressType _PreferType, NMib::NFunction::TCFunction<void ()>&& _fOnFinish);
				bint fg_AsyncResolveAddress_GetResult(void *_pResolver, CAddress& _opAddress, NMib::NStr::CStr &_Error);
				void fg_AsyncResolveAddress_Close(void *_pResolver);

				int fg_CompareAddresses(CAddress _pFirst, CAddress _pSecond);

				void fg_FreeAddress(CAddress _Address); // It is OK to free a nullptr address.

				NMib::NStr::CStr fg_GetAddressString(CAddress _Address, bint _bIncludeType);

			// Connection Operations
				void *fg_Connect(CAddress _pAddr, NMib::NFunction::TCFunction<void (::NMib::NNet::ENetTCPState _StateAdded)>&& _OnStateChange, CAddress _pBindAddr); // Report to the supplied event when new data is received or when we are ready to send new data

				void *fg_AsyncConnect(CAddress _pAddr, NMib::NFunction::TCFunction<void (::NMib::NNet::ENetTCPState _StateAdded)>&& _OnStateChange, CAddress _pBindAddr); // Report to the supplied event when new data is received or when we are ready to send new data and when the connection is connected

				void *fg_Listen(CAddress _pAddr, NMib::NFunction::TCFunction<void (::NMib::NNet::ENetTCPState _StateAdded)>&& _OnStateChange); // Report to the supplied event when a new connection has arrived
				void *fg_ListenDatagram(CAddress _pAddr, NMib::NFunction::TCFunction<void (::NMib::NNet::ENetTCPState _StateAdded)>&& _OnStateChange); // Report to the supplied event when new data is received or when we are ready to send new data
				void *fg_Accept(void *_pSocket, NMib::NFunction::TCFunction<void (::NMib::NNet::ENetTCPState _StateAdded)>&& _OnStateChange); // Report to the supplied event when new data is received or when we are ready to send new data

				void fg_Close(void *_pSocket); // Closes the socket and connection

				mint fg_Receive(void *_pSocket, void *_pData, mint _DataLen); // Returns bytes received
				mint fg_Send(void *_pSocket, const void *_pData, mint _DataLen); // Returns bytes sent
				mint fg_SendDatagram(void *_pSocket, NSys::NNet::CAddress _Address, const void *_pData, mint _DataLen); // Returns bytes sent
				mint fg_ReceiveDatagram(void *_pSocket, NSys::NNet::CAddress _Address, void *_pData, mint _DataLen); // Returns bytes received

			// Socket Properties & State

				void fg_SetOnStateChange(void *_pSocket, NMib::NFunction::TCFunction<void (::NMib::NNet::ENetTCPState _StateAdded)>&& _OnStateChange); // Report to the supplied event when new data is received or when we are ready to send new data				

				NMib::NNet::ENetTCPState fg_GetState(void *_pSocket); // Get the state of data available
				NMib::NStr::CStr fg_GetCloseReason(void *_pSocket);
		
				void *fg_InheritHandle2(void *_pSocket, NMib::NFunction::TCFunction<void (::NMib::NNet::ENetTCPState _StateAdded)>&& _OnStateChange);
				void *fg_GiveUpForInherit(void *_pSocket);
				void *fg_GetOSSocket(void *_pSocket);
				
				CAddress fg_GetPeerAddress(void *_pSocket);
				uint32 fg_GetListenPort(void *_pSocket);
		}
	}

	namespace NNet
	{


		class CNetAddress
		{			
			protected:
				NMib::NSys::NNet::CAddress mp_Address;

			public:
				CNetAddress()
					: mp_Address(nullptr)
				{}

				explicit CNetAddress(NMib::NSys::NNet::CAddress _Address)
					: mp_Address(_Address)
				{
					// DMibLogCat(NNet);
					// DMibLog(Debug, "CNetAddress::CNetAddress(CAddress)");
				}

				CNetAddress(CNetAddress&& _ToMove)
					: mp_Address(_ToMove.mp_Address)
				{
					_ToMove.mp_Address = nullptr;
					// DMibLogCat(NNet);
					// DMibLog(Debug, "CNetAddress::CNetAddress(CNetAddress&&)");
				}

				CNetAddress(CNetAddress const& _ToCopy)
					: mp_Address(nullptr)
				{
					mp_Address = NMib::NSys::NNet::fg_DuplicateAddress(_ToCopy.mp_Address);
					// DMibLogCat(NNet);
					// DMibLog(Debug, "CNetAddress::CNetAddress(CNetAddress const&)");
				}

				template<typename t_CAddress>
				CNetAddress(t_CAddress const& _Address)
					: mp_Address(NMib::NSys::NNet::fg_CreateAddress(t_CAddress::fs_GetType(), &_Address, sizeof(t_CAddress)))
				{
				}

				template<typename t_CAddress>
				CNetAddress& operator= (t_CAddress const& _Address)
				{
					f_Clear();

					mp_Address = NMib::NSys::NNet::fg_CreateAddress(t_CAddress::fs_GetType(), &_Address, sizeof(t_CAddress));

					return *this;
				}
			
				CNetAddress& operator= (CNetAddress&& _ToMove)
				{
					f_Clear();

					mp_Address = _ToMove.mp_Address;
					_ToMove.mp_Address = nullptr;

					// DMibLogCat(NNet);
					// DMibLog(Debug, "CNetAddress::operator =(CNetAddress &&)");

					return *this;
				}

				CNetAddress& operator= (CNetAddress const& _ToCopy)
				{
					f_Clear();

					mp_Address = NMib::NSys::NNet::fg_DuplicateAddress(_ToCopy.mp_Address);

					// DMibLogCat(NNet);
					// DMibLog(Debug, "CNetAddress::operator =(CNetAddress const&)");

					return *this;
				}

				~CNetAddress()
				{
					f_Clear();
				}

				void f_Clear()
				{
					if (mp_Address)
					{
						NMib::NSys::NNet::fg_FreeAddress(mp_Address);
						mp_Address = nullptr;
					}
				}

				void *f_Detach()
				{
					void *pRet = mp_Address;
					mp_Address = nullptr;
					return pRet;
				}

				bint f_IsEmpty() const
				{
					return mp_Address == nullptr;
				}

				NStr::CStr f_GetString(bint _bIncludeType = false) const { return NMib::NSys::NNet::fg_GetAddressString(mp_Address, _bIncludeType); }

				ENetAddressType f_GetType() const
				{
					return mp_Address ? NMib::NSys::NNet::fg_GetAddressType(mp_Address) : ENetAddressType_None;
				}

				template<typename t_CAddress>
				bint f_Get(t_CAddress& _oAddress) const
				{
					return NMib::NSys::NNet::fg_GetAddressRaw(mp_Address, t_CAddress::fs_GetType(), &_oAddress, sizeof(t_CAddress));
				}

				bint f_Set(CNetAddress const& _Address)
				{
					mp_Address = NMib::NSys::NNet::fg_DuplicateAddress(_Address.mp_Address);

					return mp_Address != nullptr;
				}

				template<typename t_CAddress>
				bint f_Set(t_CAddress const& _Address)
				{
					if (mp_Address)
						mp_Address = NMib::NSys::NNet::fg_SetAddressRaw(mp_Address, t_CAddress::fs_GetType(), &_Address, sizeof(t_CAddress));
					else
						mp_Address = NMib::NSys::NNet::fg_CreateAddress(t_CAddress::fs_GetType(), &_Address, sizeof(t_CAddress));

					return mp_Address != nullptr;
				}

				bint f_SetPort(uint16 _Port)
				{
					if (!mp_Address)
						return false;

					switch(NMib::NSys::NNet::fg_GetAddressType(mp_Address))
					{
						case ENetAddressType_TCPv4:
							{
								CNetAddressTCPv4 TCPv4;
								if (!f_Get(TCPv4))
									return false;

								TCPv4.m_Port = _Port;

								return f_Set(TCPv4);
							}

						case ENetAddressType_TCPv6:
							{
								CNetAddressTCPv6 TCPv6;
								if (!f_Get(TCPv6))
									return false;

								TCPv6.m_Port = _Port;

								return f_Set(TCPv6);
							}
						default:
							return false;
					}
				}

				uint16 f_GetPort() const
				{
					if (!mp_Address)
						return 0;

					switch(NMib::NSys::NNet::fg_GetAddressType(mp_Address))
					{
						case ENetAddressType_TCPv4:
							{
								CNetAddressTCPv4 TCPv4;
								if (!f_Get(TCPv4))
									return 0;

								return TCPv4.m_Port;
							}

						case ENetAddressType_TCPv6:
							{
								CNetAddressTCPv6 TCPv6;
								if (!f_Get(TCPv6))
									return 0;

								return TCPv6.m_Port;
							}
						default:
							return 0;
					}
				}

				operator NMib::NSys::NNet::CAddress() const
				{
					return mp_Address;
				}

				bint operator==(CNetAddress const& _Other)
				{
					return NMib::NSys::NNet::fg_CompareAddresses(mp_Address, _Other.mp_Address) == 0;
				}

				bint operator<(CNetAddress const& _Other)
				{
					return NMib::NSys::NNet::fg_CompareAddresses(mp_Address, _Other.mp_Address) < 0;
				}


		};

		class CAsyncResolver
		{
			void *mp_pResolver;
			void fp_CheckValid() const
			{
				if (!mp_pResolver)
					DMibErrorNet("Resolver is not valid");
			}
		public:

			CAsyncResolver()
			{
				mp_pResolver = nullptr;
			}

			~CAsyncResolver()
			{
				f_Close();
			}

			void f_Close()
			{
				if (mp_pResolver)
					NMib::NSys::NNet::fg_AsyncResolveAddress_Close(mp_pResolver);
				mp_pResolver = nullptr;
			}
			
			void f_Open(const NMib::NStr::CStr &_Address, ::NMib::NNet::ENetAddressType _PreferType, NMib::NFunction::TCFunction<void ()>&& _fOnFinish)
			{
				f_Close();
				mp_pResolver = NMib::NSys::NNet::fg_AsyncResolveAddress_Open(_Address, _PreferType, fg_Move(_fOnFinish));
			}
			
			void f_Open(const NMib::NStr::CStr &_Address, ::NMib::NNet::ENetAddressType _PreferType, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo)
			{
				f_Close();
				mp_pResolver = NMib::NSys::NNet::fg_AsyncResolveAddress_Open
					(
						_Address
						, _PreferType
						, [_pReportTo]()
						{
							_pReportTo->f_Signal();
						}
					)
				;
			}

			bint f_GetResult(NMib::NNet::CNetAddress &_Address, NStr::CStr &_Error)
			{
				fp_CheckValid();
				NMib::NSys::NNet::CAddress Address;
				if (NMib::NSys::NNet::fg_AsyncResolveAddress_GetResult(mp_pResolver, Address, _Error))
				{
					_Address = NMib::NNet::CNetAddress(Address);
					return true;
				}
				else
					return false;
			}
		};

		class CSocket
		{
			void *mp_pSocket;

			void fp_CheckSocket() const
			{
				if (!mp_pSocket)
					DMibErrorNet("Socket is not valid");
			}
			
			static NFunction::TCFunction<void (::NMib::NNet::ENetTCPState _StateAdded)> fsp_GetChangeReportTo(NMib::NThread::CSemaphoreReportableAggregate *_pReportTo)
			{
				if (_pReportTo)
				{
					return [_pReportTo](::NMib::NNet::ENetTCPState _StateAdded)
						{
							_pReportTo->f_Signal();
						}
					;
				}
				return NFunction::TCFunction<void (::NMib::NNet::ENetTCPState _StateAdded)>();
			}
			CSocket(CSocket const& _Other);
			CSocket & operator =(CSocket const& _Other);
		public:
			CSocket()
			{
				mp_pSocket = nullptr;
			}

			~CSocket()
			{
				f_Close();
			}

			CSocket(CSocket &&_Other)
			{
				mp_pSocket = _Other.mp_pSocket;
				_Other.mp_pSocket = nullptr;
			}

			CSocket & operator =(CSocket &&_Other)
			{
				mp_pSocket = _Other.mp_pSocket;
				_Other.mp_pSocket = nullptr;
				return *this;
			}

			bint f_IsValid() const
			{
				return mp_pSocket != nullptr;
			}

			void f_Close()
			{
				if (mp_pSocket)
					NMib::NSys::NNet::fg_Close(mp_pSocket);
				mp_pSocket = nullptr;
			}

			void f_Connect(NMib::NNet::CNetAddress const& _Address, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo = nullptr)
			{
				f_Close();

				mp_pSocket = NMib::NSys::NNet::fg_Connect(_Address, fsp_GetChangeReportTo(_pReportTo), CNetAddress());
			}

			void f_Connect(NMib::NNet::CNetAddress const& _Address, NMib::NFunction::TCFunction<void (::NMib::NNet::ENetTCPState _StateAdded)>&& _OnStateChange, NMib::NNet::CNetAddress const &_BindAddress = NMib::NNet::CNetAddress())
			{
				f_Close();

				mp_pSocket = NMib::NSys::NNet::fg_Connect(_Address, fg_Move(_OnStateChange), _BindAddress);
			}

			void f_AsyncConnect(NMib::NNet::CNetAddress const& _Address, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo = nullptr)
			{
				f_Close();

				mp_pSocket = NMib::NSys::NNet::fg_AsyncConnect(_Address, fsp_GetChangeReportTo(_pReportTo), CNetAddress());
			}
			
			void f_AsyncConnect(NMib::NNet::CNetAddress const& _Address, NMib::NFunction::TCFunction<void (::NMib::NNet::ENetTCPState _StateAdded)>&& _OnStateChange, NMib::NNet::CNetAddress const &_BindAddress = NMib::NNet::CNetAddress())
			{
				f_Close();

				mp_pSocket = NMib::NSys::NNet::fg_AsyncConnect(_Address, fg_Move(_OnStateChange), _BindAddress);
			}
			
			void f_Listen(NMib::NNet::CNetAddress const& _Address, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo)
			{
				f_Close();

				mp_pSocket = NMib::NSys::NNet::fg_Listen(_Address, fsp_GetChangeReportTo(_pReportTo));
			}
			
			void f_Listen(NMib::NNet::CNetAddress const& _Address, NMib::NFunction::TCFunction<void (::NMib::NNet::ENetTCPState _StateAdded)>&& _OnStateChange)
			{
				f_Close();

				mp_pSocket = NMib::NSys::NNet::fg_Listen(_Address, fg_Move(_OnStateChange));
			}
			
			void f_ListenDatagram(NMib::NNet::CNetAddress const& _Address, NMib::NFunction::TCFunction<void (::NMib::NNet::ENetTCPState _StateAdded)>&& _OnStateChange)
			{
				f_Close();

				mp_pSocket = NMib::NSys::NNet::fg_ListenDatagram(_Address, fg_Move(_OnStateChange));
			}
			
			void f_Accept(CSocket *_pAcceptFrom, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo)
			{
				f_Close();

				mp_pSocket = NMib::NSys::NNet::fg_Accept(_pAcceptFrom->mp_pSocket, fsp_GetChangeReportTo(_pReportTo));
			}

			void f_Accept(CSocket *_pAcceptFrom, NMib::NFunction::TCFunction<void (::NMib::NNet::ENetTCPState _StateAdded)>&& _OnStateChange)
			{
				f_Close();

				mp_pSocket = NMib::NSys::NNet::fg_Accept(_pAcceptFrom->mp_pSocket, fg_Move(_OnStateChange));
			}

			void f_InheritHandle2(void *_pSocketHandle, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo)
			{
				mp_pSocket = NMib::NSys::NNet::fg_InheritHandle2(_pSocketHandle, fsp_GetChangeReportTo(_pReportTo));
			}

			void f_InheritHandle2(void *_pSocketHandle, NMib::NFunction::TCFunction<void (::NMib::NNet::ENetTCPState _StateAdded)>&& _OnStateChange)
			{
				mp_pSocket = NMib::NSys::NNet::fg_InheritHandle2(_pSocketHandle, fg_Move(_OnStateChange));
			}

			void *f_GiveUpForInherit()
			{
				return NMib::NSys::NNet::fg_GiveUpForInherit(mp_pSocket);
			}

			void *f_GetOSSocket()
			{
				return NMib::NSys::NNet::fg_GetOSSocket(mp_pSocket);
			}
			
			void f_SetReportTo(NMib::NThread::CSemaphoreReportableAggregate *_pReportTo)
			{
				NMib::NSys::NNet::fg_SetOnStateChange(mp_pSocket, fsp_GetChangeReportTo(_pReportTo));
			}

			void f_SetOnStateChange(NMib::NFunction::TCFunction<void (::NMib::NNet::ENetTCPState _StateAdded)>&& _OnStateChange)
			{
				NMib::NSys::NNet::fg_SetOnStateChange(mp_pSocket, fg_Move(_OnStateChange));
			}

			ENetTCPState f_GetState()
			{
				fp_CheckSocket();

				return NMib::NSys::NNet::fg_GetState(mp_pSocket);
			}

			NStr::CStr f_GetCloseReason()
			{
				fp_CheckSocket();

				return NMib::NSys::NNet::fg_GetCloseReason(mp_pSocket);
			}

			mint f_Receive(void *_pData, mint _DataLen)
			{
				fp_CheckSocket();

				return NMib::NSys::NNet::fg_Receive(mp_pSocket, _pData, _DataLen);
			}

			mint f_Send(const void *_pData, mint _DataLen)
			{
				fp_CheckSocket();

				return NMib::NSys::NNet::fg_Send(mp_pSocket, _pData, _DataLen);
			}

			mint f_SendDatagram(NMib::NNet::CNetAddress const &_Address, const void *_pData, mint _DataLen)
			{
				fp_CheckSocket();

				return NMib::NSys::NNet::fg_SendDatagram(mp_pSocket, _Address, _pData, _DataLen);
			}

			mint f_ReceiveDatagram(NMib::NNet::CNetAddress &_Address, void *_pData, mint _DataLen)
			{
				fp_CheckSocket();

				return NMib::NSys::NNet::fg_ReceiveDatagram(mp_pSocket, _Address, _pData, _DataLen);
			}

			NMib::NNet::CNetAddress f_GetPeerAddress() const
			{
				fp_CheckSocket();
				return CNetAddress(NMib::NSys::NNet::fg_GetPeerAddress(mp_pSocket));
			}

			uint32 f_GetListenPort() const
			{
				fp_CheckSocket();
				return NMib::NSys::NNet::fg_GetListenPort(mp_pSocket);
			}

			static NMib::NNet::CNetAddress fs_ResolveAddress(const NMib::NStr::CStr &_Address, ::NMib::NNet::ENetAddressType _PreferType = ::NMib::NNet::ENetAddressType_None)
			{
				return fg_Move(CNetAddress(NMib::NSys::NNet::fg_ResolveAddress(_Address, _PreferType)));
			}

		};

	}
}


#ifndef DMibPNoShortCuts
	using namespace NMib::NNet;
#endif
