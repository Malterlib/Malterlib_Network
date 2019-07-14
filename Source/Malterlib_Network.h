// Copyright © 2015 Hansoft AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#pragma once

/*---------------------------------------------------------------------------------------------*\
	Author:			Erik Olofsson, Michael Wynne

	Contents:		NMib::NNetwork:
						CNetAddressIPv4
						CNetAddressIPv6
						CNetAddressTCPv4
						CNetAddressTCPv6
						ENetTCPState
						CNetAddress
						CSocket

					System Specifics in NMib::NSys::NNetwork:
						typedef void* CAddress;

						CAddress fg_CreateAddress(::NMib::NNetwork::ENetAddressType _Type, void const* _pData, mint _nDataBytes);

						::NMib::NNetwork::ENetAddressType fg_GetAddressType(CAddress _Address);
						bool fg_GetAddressRaw(CAddress _Address, ::NMib::NNetwork::ENetAddressType _ExpectedType, void* _opRawData, mint _nDataBytes);
						CAddress fg_SetAddressRaw(CAddress _Address, ::NMib::NNetwork::ENetAddressType _Type, void const* _pRawData, mint _nDataBytes);

						CAddress fg_ResolveAddress(const NMib::NStr::CStr &_Address, ::NMib::NNetwork::ENetAddressType _PreferType = ::NMib::NNetwork::ENetAddressType_None);

						void *fg_AsyncResolveAddress_Open(const NMib::NStr::CStr &_Address, ::NMib::NNetwork::ENetAddressType _PreferType, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo);
						bool fg_AsyncResolveAddress_GetResult(void *_pResolver, CAddress& _opAddress, NMib::NStr::CStr &_Error);
						void fg_AsyncResolveAddress_Close(void *_pResolver);

						int fg_CompareAddresses(CAddress _pFirst, CAddress _pSecond);

						void fg_FreeAddress(CAddress _Address); // It is OK to free a nullptr address.

						NMib::NStr::CStr fg_GetAddressString(CAddress _Address, bool _bIncludeType);

					// Connection Operations
						void *fg_AsyncConnect(CAddress _pAddr, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo); // Report to the supplied event when new data is received or when we are ready to send new data and when the connection is connected

						void *fg_Listen(CAddress _pAddr, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo, NMib::NNetwork::ENetFlag _Flags); // Report to the supplied event when a new connection has arrived
						void *fg_Accept(void *_pSocket, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo, NMib::NNetwork::ENetFlag _Flags); // Report to the supplied event when new data is received or when we are ready to send new data

						void fg_Close(void *_pSocket); // Closes the socket and connection

						mint fg_Receive(void *_pSocket, void *_pData, mint _DataLen); // Returns bytes received
						mint fg_Send(void *_pSocket, const void *_pData, mint _DataLen); // Returns bytes sent

					// Socket Properties & State

						void fg_SetReportTo(void *_pSocket, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo); // Report to the supplied event when new data is received or when we are ready to send new data

						NMib::NNetwork::ENetTCPState fg_GetState(void *_pSocket); // Get the state of data available
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
							Typedef for sockets in NSys::NNetwork
								typedef void* CSocket;

\*_____________________________________________________________________________________________*/
#ifndef DMibSafety_IncMalterlib_H
#	error "You have to include this file through <Mib/Core/Core>"
#endif

#include <Mib/Core/Platform>
#include "Malterlib_Network_Exception.h"

namespace NMib::NNetwork
{
	class CNetAddressIPv4
	{
	public:
		uint8 m_IP[4];

		CNetAddressIPv4()
		{
			NMemory::fg_MemClear(*this);
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
			NMemory::fg_MemCopy(this, &_Src, sizeof(*this));
		}

		CNetAddressIPv4 &operator = (const CNetAddressIPv4 &_Src)
		{
			NMemory::fg_MemCopy(this, &_Src, sizeof(*this));

			return *this;
		}

		void f_SetLocalhost()
		{
			*this = {127, 0, 0, 1};
		}
	};

	class CNetAddressIPv6
	{
	public:
		uint8 m_IP[16];

		CNetAddressIPv6()
		{
			NMemory::fg_MemClear(*this);
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
			NMemory::fg_MemCopy(this, &_Src, sizeof(*this));
		}

		CNetAddressIPv6 &operator = (const CNetAddressIPv6 &_Src)
		{
			NMemory::fg_MemCopy(this, &_Src, sizeof(*this));

			return *this;
		}

		void f_SetLocalhost()
		{
			*this = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
		}
	};

	enum ENetAddressType : uint32
	{
		ENetAddressType_None = 0
		, ENetAddressType_TCPv4 = 1
		, ENetAddressType_TCPv6 = 2
		, ENetAddressType_Unix = 3
	};

	template<typename t_CIPAddress, ENetAddressType t_Type>
	class TCNetAddressTCP : public t_CIPAddress
	{
	public:
		uint16 m_Port;

		static constexpr ENetAddressType mc_Type = t_Type;

		TCNetAddressTCP()
			: m_Port(0)
		{
		}

		TCNetAddressTCP(const TCNetAddressTCP &_Src)
		{
			NMemory::fg_MemCopy(this, &_Src, sizeof(*this));
		}

		TCNetAddressTCP(const t_CIPAddress &_Src, uint16 _Port)
			: t_CIPAddress(_Src)
			, m_Port(_Port)
		{
		}

		TCNetAddressTCP &operator = (const TCNetAddressTCP &_Src)
		{
			NMemory::fg_MemCopy(this, &_Src, sizeof(*this));

			return *this;
		}

		TCNetAddressTCP &operator = (const t_CIPAddress &_Src)
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

	typedef TCNetAddressTCP<CNetAddressIPv4, ENetAddressType_TCPv4> CNetAddressTCPv4;
	typedef TCNetAddressTCP<CNetAddressIPv6, ENetAddressType_TCPv6> CNetAddressTCPv6;

	enum ENetTCPState
	{
		ENetTCPState_None			= 0
		, ENetTCPState_Read			= DMibBit(0) // Data is awailable for reading
		, ENetTCPState_Write		= DMibBit(1) // More data can now be sent
		, ENetTCPState_Connection	= DMibBit(2) // A new connection is available for accept
		, ENetTCPState_Connected	= DMibBit(3) // A async connection has completed
		, ENetTCPState_Closed		= DMibBit(4) // The connection has been lost
		, ENetTCPState_RemoteClosed	= DMibBit(5) // A connection closure was initiated by remote call f_Shutdown
	};

	enum ENetFlag
	{
		ENetFlag_None = 0
		, ENetFlag_ReusePort = DMibBit(0) // Reuse port, allowing several sockets to bind to the same port
	};

	class CNetAddress;

	NStr::CStr fg_GetSafeUnixSocketPath(NStr::CStr const &_WantedPath);
}

namespace NMib::NStream
{
	template <typename t_CStream>
	class TCBinaryStreamTypeReference<t_CStream, NNetwork::CNetAddressTCPv4 >
	{
	public:
		static void fs_Feed(t_CStream &_Stream, NNetwork::CNetAddressTCPv4 const &_Data)
		{
			_Stream.f_FeedBytes(_Data.m_IP, sizeof(_Data.m_IP));
			_Stream << _Data.m_Port;
		}

		static void fs_Consume(t_CStream &_Stream, NNetwork::CNetAddressTCPv4 &_Data)
		{
			_Stream.f_ConsumeBytes(_Data.m_IP, sizeof(_Data.m_IP));
			_Stream >> _Data.m_Port;
		}
	};

	template <typename t_CStream>
	class TCBinaryStreamTypeReference<t_CStream, NNetwork::CNetAddressIPv4 >
	{
	public:
		static void fs_Feed(t_CStream &_Stream, NNetwork::CNetAddressIPv4 const &_Data)
		{
			_Stream.f_FeedBytes(_Data.m_IP, sizeof(_Data.m_IP));
		}

		static void fs_Consume(t_CStream &_Stream, NNetwork::CNetAddressIPv4 &_Data)
		{
			_Stream.f_ConsumeBytes(_Data.m_IP, sizeof(_Data.m_IP));
		}
	};

	template <typename t_CStream>
	class TCBinaryStreamTypeReference<t_CStream, NNetwork::CNetAddressTCPv6 >
	{
	public:
		static void fs_Feed(t_CStream &_Stream, NNetwork::CNetAddressTCPv6 const &_Data)
		{
			_Stream.f_FeedBytes(_Data.m_IP, sizeof(_Data.m_IP));
			_Stream << _Data.m_Port;
		}

		static void fs_Consume(t_CStream &_Stream, NNetwork::CNetAddressTCPv6 &_Data)
		{
			_Stream.f_ConsumeBytes(_Data.m_IP, sizeof(_Data.m_IP));
			_Stream >> _Data.m_Port;
		}
	};

	template <typename t_CStream>
	class TCBinaryStreamTypeReference<t_CStream, NNetwork::CNetAddressIPv6 >
	{
	public:
		static void fs_Feed(t_CStream &_Stream, NNetwork::CNetAddressIPv6 const &_Data)
		{
			_Stream.f_FeedBytes(_Data.m_IP, sizeof(_Data.m_IP));
		}

		static void fs_Consume(t_CStream &_Stream, NNetwork::CNetAddressIPv6 &_Data)
		{
			_Stream.f_ConsumeBytes(_Data.m_IP, sizeof(_Data.m_IP));
		}
	};
}

namespace NMib::NSys::NNetwork
{
// Addresses

	typedef void* CAddress;

	CAddress fg_CreateAddress(::NMib::NNetwork::ENetAddressType _Type, void const* _pData, mint _nDataBytes);
	CAddress fg_DuplicateAddress(CAddress _Address);

	::NMib::NNetwork::ENetAddressType fg_GetAddressType(CAddress _Address);
	bool fg_GetAddressRaw(CAddress _Address, ::NMib::NNetwork::ENetAddressType _ExpectedType, void* _opRawData, mint _nDataBytes);
	CAddress fg_SetAddressRaw(CAddress _Address, ::NMib::NNetwork::ENetAddressType _Type, void const* _pRawData, mint _nDataBytes);

	CAddress fg_ResolveAddress(const NMib::NStr::CStr &_Address, ::NMib::NNetwork::ENetAddressType _PreferType = ::NMib::NNetwork::ENetAddressType_None);

	mint fg_GetMaxUnixSocketNameLength();

	void *fg_AsyncResolveAddress_Open(const NMib::NStr::CStr &_Address, ::NMib::NNetwork::ENetAddressType _PreferType, NMib::NFunction::TCFunction<void ()> &&_fOnFinish);
	bool fg_AsyncResolveAddress_GetResult(void *_pResolver, CAddress& _opAddress, NMib::NStr::CStr &_Error);
	void fg_AsyncResolveAddress_Close(void *_pResolver);

	int fg_CompareAddresses(CAddress _pFirst, CAddress _pSecond);

	void fg_FreeAddress(CAddress _Address); // It is OK to free a nullptr address.

	NMib::NStr::CStr fg_GetAddressString(CAddress _Address, bool _bIncludeType);

// Connection Operations

	// Report to the supplied event when new data is received or when we are ready to send new data and when the connection is connected
	void *fg_AsyncConnect(CAddress _pAddr, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange, CAddress _pBindAddr);
	void fg_StartSocket(void *_pSocket); // Starts the event loop

	// Report to the supplied event when a new connection has arrived
	void *fg_Listen(CAddress _pAddr, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange, NMib::NNetwork::ENetFlag _Flags);
	// Report to the supplied event when new data is received or when we are ready to send new data
	void *fg_ListenDatagram(CAddress _pAddr, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange, NMib::NNetwork::ENetFlag _Flags);
	// Report to the supplied event when new data is received or when we are ready to send new data
	void *fg_Accept(void *_pSocket, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange);

	void fg_Shutdown(void *_pSocket); // Closes the socket and connection

	void fg_Close(void *_pSocket); // Closes the socket and connection

	mint fg_Receive(void *_pSocket, void *_pData, mint _DataLen); // Returns bytes received
	mint fg_Send(void *_pSocket, const void *_pData, mint _DataLen); // Returns bytes sent
	mint fg_SendDatagram(void *_pSocket, NSys::NNetwork::CAddress _Address, const void *_pData, mint _DataLen); // Returns bytes sent
	mint fg_ReceiveDatagram(void *_pSocket, NSys::NNetwork::CAddress _Address, void *_pData, mint _DataLen); // Returns bytes received

// Socket Properties & State

	// Report to the supplied event when new data is received or when we are ready to send new data
	void fg_SetOnStateChange(void *_pSocket, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange);

	NMib::NNetwork::ENetTCPState fg_GetState(void *_pSocket); // Get the state of data available
	NMib::NStr::CStr fg_GetCloseReason(void *_pSocket);

	void *fg_InheritHandle2(void *_pSocket, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange);
	void *fg_GiveUpForInherit(void *_pSocket);
	void *fg_GetOSSocket(void *_pSocket);

	CAddress fg_GetPeerAddress(void *_pSocket);
	uint32 fg_GetListenPort(void *_pSocket);
}

namespace NMib::NNetwork
{
	class CNetAddress
	{
	protected:
		NMib::NSys::NNetwork::CAddress mp_Address;

	public:
		CNetAddress()
			: mp_Address(nullptr)
		{}

		explicit CNetAddress(NMib::NSys::NNetwork::CAddress _Address)
			: mp_Address(_Address)
		{
		}

		CNetAddress(CNetAddress&& _ToMove)
			: mp_Address(_ToMove.mp_Address)
		{
			_ToMove.mp_Address = nullptr;
		}

		CNetAddress(CNetAddress const& _ToCopy)
			: mp_Address(nullptr)
		{
			if (_ToCopy.mp_Address)
				mp_Address = NMib::NSys::NNetwork::fg_DuplicateAddress(_ToCopy.mp_Address);
		}

		template<typename t_CAddress>
		CNetAddress(t_CAddress const &_Address)
			: mp_Address(NMib::NSys::NNetwork::fg_CreateAddress(t_CAddress::fs_GetType(), &_Address, sizeof(t_CAddress)))
		{
		}

		template<typename t_CAddress>
		CNetAddress& operator= (t_CAddress const &_Address)
		{
			f_Clear();

			mp_Address = NMib::NSys::NNetwork::fg_CreateAddress(t_CAddress::fs_GetType(), &_Address, sizeof(t_CAddress));

			return *this;
		}

		CNetAddress& operator= (CNetAddress&& _ToMove)
		{
			f_Clear();

			mp_Address = _ToMove.mp_Address;
			_ToMove.mp_Address = nullptr;

			return *this;
		}

		CNetAddress& operator= (CNetAddress const& _ToCopy)
		{
			f_Clear();

			if (_ToCopy.mp_Address)
				mp_Address = NMib::NSys::NNetwork::fg_DuplicateAddress(_ToCopy.mp_Address);

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
				NMib::NSys::NNetwork::fg_FreeAddress(mp_Address);
				mp_Address = nullptr;
			}
		}

		void *f_Detach()
		{
			void *pRet = mp_Address;
			mp_Address = nullptr;
			return pRet;
		}

		void *f_AccessRaw() const
		{
			return mp_Address;
		}

		bool f_IsEmpty() const
		{
			return mp_Address == nullptr;
		}

		NStr::CStr f_GetString(bool _bIncludeType = false) const
		{
			if (mp_Address == nullptr)
				return "";
			return NMib::NSys::NNetwork::fg_GetAddressString(mp_Address, _bIncludeType);
		}

		ENetAddressType f_GetType() const
		{
			return mp_Address ? NMib::NSys::NNetwork::fg_GetAddressType(mp_Address) : ENetAddressType_None;
		}

		template<typename t_CAddress>
		bool f_Get(t_CAddress& _oAddress) const
		{
			return NMib::NSys::NNetwork::fg_GetAddressRaw(mp_Address, t_CAddress::fs_GetType(), &_oAddress, sizeof(t_CAddress));
		}

		bool f_Set(CNetAddress const &_Address)
		{
			f_Clear();
			if (_Address.mp_Address)
				mp_Address = NMib::NSys::NNetwork::fg_DuplicateAddress(_Address.mp_Address);

			return mp_Address != nullptr;
		}

		template<typename t_CAddress>
		bool f_Set(t_CAddress const &_Address)
		{
			f_Clear();

			if (mp_Address)
				mp_Address = NMib::NSys::NNetwork::fg_SetAddressRaw(mp_Address, t_CAddress::fs_GetType(), &_Address, sizeof(t_CAddress));
			else
				mp_Address = NMib::NSys::NNetwork::fg_CreateAddress(t_CAddress::fs_GetType(), &_Address, sizeof(t_CAddress));

			return mp_Address != nullptr;
		}

		bool f_SetPort(uint16 _Port)
		{
			if (!mp_Address)
				return false;

			switch(NMib::NSys::NNetwork::fg_GetAddressType(mp_Address))
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

			switch(NMib::NSys::NNetwork::fg_GetAddressType(mp_Address))
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

		operator NMib::NSys::NNetwork::CAddress() const
		{
			return mp_Address;
		}

		bool operator==(CNetAddress const& _Other)
		{
			return NMib::NSys::NNetwork::fg_CompareAddresses(mp_Address, _Other.mp_Address) == 0;
		}

		bool operator<(CNetAddress const& _Other)
		{
			return NMib::NSys::NNetwork::fg_CompareAddresses(mp_Address, _Other.mp_Address) < 0;
		}

		template <typename tf_CStr>
		void f_Format(tf_CStr &o_Str) const
		{
			o_Str += f_GetString();
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

		CAsyncResolver(CAsyncResolver const &) = delete;
		CAsyncResolver &operator = (CAsyncResolver const &) = delete;

		CAsyncResolver(CAsyncResolver &&_Other)
			: mp_pResolver(_Other.mp_pResolver)
		{
			_Other.mp_pResolver = nullptr;
		}

		CAsyncResolver &operator = (CAsyncResolver &&_Other)
		{
			f_Close();
			mp_pResolver = _Other.mp_pResolver;
			_Other.mp_pResolver = nullptr;

			return *this;
		}

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
				NMib::NSys::NNetwork::fg_AsyncResolveAddress_Close(mp_pResolver);
			mp_pResolver = nullptr;
		}

		void f_Open(const NMib::NStr::CStr &_Address, ::NMib::NNetwork::ENetAddressType _PreferType, NMib::NFunction::TCFunction<void ()> &&_fOnFinish)
		{
			f_Close();
			mp_pResolver = NMib::NSys::NNetwork::fg_AsyncResolveAddress_Open(_Address, _PreferType, fg_Move(_fOnFinish));
		}

		void f_Open(const NMib::NStr::CStr &_Address, ::NMib::NNetwork::ENetAddressType _PreferType, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo)
		{
			f_Close();
			mp_pResolver = NMib::NSys::NNetwork::fg_AsyncResolveAddress_Open
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

		bool f_GetResult(NMib::NNetwork::CNetAddress &_Address, NStr::CStr &_Error)
		{
			fp_CheckValid();
			NMib::NSys::NNetwork::CAddress Address;
			if (NMib::NSys::NNetwork::fg_AsyncResolveAddress_GetResult(mp_pResolver, Address, _Error))
			{
				_Address = NMib::NNetwork::CNetAddress(Address);
				return true;
			}
			else
				return false;
		}
	};

	struct CSocketOperationResult
	{
		mint m_nBytes = 0;
		bool m_bSentNetwork = false;
		bool m_bReceivedNetwork = false;

		CSocketOperationResult &operator += (CSocketOperationResult const &_Other);
	};

	class CSocket
	{
		void *mp_pSocket;

		void fp_CheckSocket() const
		{
			if (!mp_pSocket)
				DMibErrorNet("Socket is not valid");
		}

		static NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> fsp_GetChangeReportTo(NMib::NThread::CSemaphoreReportableAggregate *_pReportTo)
		{
			if (_pReportTo)
			{
				return [_pReportTo](::NMib::NNetwork::ENetTCPState _StateAdded)
					{
						_pReportTo->f_Signal();
					}
				;
			}
			return NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)>();
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

		bool f_IsValid() const
		{
			return mp_pSocket != nullptr;
		}

		void f_Close()
		{
			if (mp_pSocket)
				NMib::NSys::NNetwork::fg_Close(mp_pSocket);
			mp_pSocket = nullptr;
		}

		void f_Connect(NMib::NNetwork::CNetAddress const &_Address, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo = nullptr, fp64 _Timeout = 15.0)
		{
			f_Connect(_Address, fsp_GetChangeReportTo(_pReportTo), CNetAddress(), _Timeout);
		}

		void f_Connect
			(
			 	NMib::NNetwork::CNetAddress const &_Address
			 	, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange
			 	, NMib::NNetwork::CNetAddress const &_BindAddress = NMib::NNetwork::CNetAddress()
			 	, fp64 _Timeout = 15.0
			)
		;

		void f_AsyncConnect(NMib::NNetwork::CNetAddress const &_Address, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo = nullptr)
		{
			f_Close();

			mp_pSocket = NMib::NSys::NNetwork::fg_AsyncConnect(_Address, fsp_GetChangeReportTo(_pReportTo), CNetAddress());
			NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
		}

		void f_AsyncConnect
			(
			 	NMib::NNetwork::CNetAddress const &_Address
			 	, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange
			 	, NMib::NNetwork::CNetAddress const &_BindAddress = NMib::NNetwork::CNetAddress()
			)
		{
			f_Close();

			mp_pSocket = NMib::NSys::NNetwork::fg_AsyncConnect(_Address, fg_Move(_fOnStateChange), _BindAddress);
			NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
		}

		void f_Listen(NMib::NNetwork::CNetAddress const &_Address, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo, ENetFlag _Flags)
		{
			f_Close();

			mp_pSocket = NMib::NSys::NNetwork::fg_Listen(_Address, fsp_GetChangeReportTo(_pReportTo), _Flags);
			NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
		}

		void f_Listen(NMib::NNetwork::CNetAddress const &_Address, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange, ENetFlag _Flags)
		{
			f_Close();

			mp_pSocket = NMib::NSys::NNetwork::fg_Listen(_Address, fg_Move(_fOnStateChange), _Flags);
			NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
		}

		void f_ListenDatagram
			(
			 	NMib::NNetwork::CNetAddress const &_Address
			 	, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange
			 	, ENetFlag _Flags
			)
		{
			f_Close();

			mp_pSocket = NMib::NSys::NNetwork::fg_ListenDatagram(_Address, fg_Move(_fOnStateChange), _Flags);
			NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
		}

		void f_Accept(CSocket *_pAcceptFrom, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo)
		{
			f_Close();

			mp_pSocket = NMib::NSys::NNetwork::fg_Accept(_pAcceptFrom->mp_pSocket, fsp_GetChangeReportTo(_pReportTo));
			if (mp_pSocket)
				NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
		}

		void f_Accept(CSocket *_pAcceptFrom, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange)
		{
			f_Close();

			mp_pSocket = NMib::NSys::NNetwork::fg_Accept(_pAcceptFrom->mp_pSocket, fg_Move(_fOnStateChange));
			if (mp_pSocket)
				NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
		}

		void f_InheritHandle2(void *_pSocketHandle, NMib::NThread::CSemaphoreReportableAggregate *_pReportTo)
		{
			mp_pSocket = NMib::NSys::NNetwork::fg_InheritHandle2(_pSocketHandle, fsp_GetChangeReportTo(_pReportTo));
			NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
		}

		void f_InheritHandle2(void *_pSocketHandle, NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange)
		{
			mp_pSocket = NMib::NSys::NNetwork::fg_InheritHandle2(_pSocketHandle, fg_Move(_fOnStateChange));
			NMib::NSys::NNetwork::fg_StartSocket(mp_pSocket);
		}

		void *f_GiveUpForInherit()
		{
			return NMib::NSys::NNetwork::fg_GiveUpForInherit(mp_pSocket);
		}

		void *f_GetOSSocket()
		{
			return NMib::NSys::NNetwork::fg_GetOSSocket(mp_pSocket);
		}

		void f_SetReportTo(NMib::NThread::CSemaphoreReportableAggregate *_pReportTo)
		{
			NMib::NSys::NNetwork::fg_SetOnStateChange(mp_pSocket, fsp_GetChangeReportTo(_pReportTo));
		}

		void f_SetOnStateChange(NMib::NFunction::TCFunctionMovable<void (::NMib::NNetwork::ENetTCPState _StateAdded)> &&_fOnStateChange)
		{
			NMib::NSys::NNetwork::fg_SetOnStateChange(mp_pSocket, fg_Move(_fOnStateChange));
		}

		void f_Shutdown()
		{
			fp_CheckSocket();

			return NMib::NSys::NNetwork::fg_Shutdown(mp_pSocket);
		}

		ENetTCPState f_GetState()
		{
			fp_CheckSocket();

			return NMib::NSys::NNetwork::fg_GetState(mp_pSocket);
		}

		NStr::CStr f_GetCloseReason()
		{
			fp_CheckSocket();

			return NMib::NSys::NNetwork::fg_GetCloseReason(mp_pSocket);
		}

		mint f_Receive(void *_pData, mint _DataLen)
		{
			fp_CheckSocket();

			return NMib::NSys::NNetwork::fg_Receive(mp_pSocket, _pData, _DataLen);
		}

		mint f_Send(const void *_pData, mint _DataLen)
		{
			fp_CheckSocket();

			return NMib::NSys::NNetwork::fg_Send(mp_pSocket, _pData, _DataLen);
		}

		mint f_SendDatagram(NMib::NNetwork::CNetAddress const &_Address, const void *_pData, mint _DataLen)
		{
			fp_CheckSocket();

			return NMib::NSys::NNetwork::fg_SendDatagram(mp_pSocket, _Address, _pData, _DataLen);
		}

		mint f_ReceiveDatagram(NMib::NNetwork::CNetAddress &_Address, void *_pData, mint _DataLen)
		{
			fp_CheckSocket();

			return NMib::NSys::NNetwork::fg_ReceiveDatagram(mp_pSocket, _Address, _pData, _DataLen);
		}

		NMib::NNetwork::CNetAddress f_GetPeerAddress() const
		{
			fp_CheckSocket();
			return CNetAddress(NMib::NSys::NNetwork::fg_GetPeerAddress(mp_pSocket));
		}

		uint32 f_GetListenPort() const
		{
			fp_CheckSocket();
			return NMib::NSys::NNetwork::fg_GetListenPort(mp_pSocket);
		}

		static NMib::NNetwork::CNetAddress fs_ResolveAddress(const NMib::NStr::CStr &_Address, ::NMib::NNetwork::ENetAddressType _PreferType = ::NMib::NNetwork::ENetAddressType_None)
		{
			return fg_Move(CNetAddress(NMib::NSys::NNetwork::fg_ResolveAddress(_Address, _PreferType)));
		}

	};

	bool fg_IsValidHostname(NStr::CStr const &_String, ch8 const *_pSeparatorChars = "");
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
