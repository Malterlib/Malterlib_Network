// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

namespace NMib::NNetwork
{
	inline CNetAddressIPv4::CNetAddressIPv4(uint8 _Octet0, uint8 _Octet1, uint8 _Octet2, uint8 _Octet3)
	{
		m_IP[0] = _Octet0;
		m_IP[1] = _Octet1;
		m_IP[2] = _Octet2;
		m_IP[3] = _Octet3;
	}

	inline CNetAddressIPv4::CNetAddressIPv4(CNetAddressIPv4 const &_Src)
	{
		NMemory::fg_MemCopy(m_IP, _Src.m_IP, sizeof(m_IP));
	}

	template <typename tf_CStream>
	void CNetAddressIPv4::f_Stream(tf_CStream &_Stream)
	{
		for (auto &Ip : m_IP)
			_Stream % Ip;
	}

	template <typename tf_CStr>
	void CNetAddressIPv4::f_Format(tf_CStr &o_String) const
	{
		o_String += typename tf_CStr::CFormat("{}.{}.{}.{}") << m_IP[0] << m_IP[1] << m_IP[2] << m_IP[3];
	}

	template <typename tf_CStream>
	void CNetAddressIPv6::f_Stream(tf_CStream &_Stream)
	{
		for (auto &Ip : m_IP)
			_Stream % Ip;
	}

	template <typename t_CIPAddress, ENetAddressType t_Type>
	TCNetAddressTCP<t_CIPAddress, t_Type>::TCNetAddressTCP()
		: m_Port(0)
	{
	}

	template <typename t_CIPAddress, ENetAddressType t_Type>
	TCNetAddressTCP<t_CIPAddress, t_Type>::TCNetAddressTCP(TCNetAddressTCP const &_Src)
	{
		NMemory::fg_MemCopy(this, &_Src, sizeof(*this));
	}

	template <typename t_CIPAddress, ENetAddressType t_Type>
	TCNetAddressTCP<t_CIPAddress, t_Type>::TCNetAddressTCP(t_CIPAddress const &_Src, uint16 _Port)
		: t_CIPAddress(_Src)
		, m_Port(_Port)
	{
	}

	template <typename t_CIPAddress, ENetAddressType t_Type>
	auto TCNetAddressTCP<t_CIPAddress, t_Type>::operator = (TCNetAddressTCP const &_Src) -> TCNetAddressTCP &
	{
		NMemory::fg_MemCopy(this, &_Src, sizeof(*this));

		return *this;
	}

	template <typename t_CIPAddress, ENetAddressType t_Type>
	auto TCNetAddressTCP<t_CIPAddress, t_Type>::operator = (t_CIPAddress const &_Src) -> TCNetAddressTCP &
	{
		(*this) = _Src;

		return *this;
	}

	template <typename t_CIPAddress, ENetAddressType t_Type>
	t_CIPAddress const &TCNetAddressTCP<t_CIPAddress, t_Type>::f_GetIP() const
	{
		return *this;
	}

	template <typename t_CIPAddress, ENetAddressType t_Type>
	ENetAddressType TCNetAddressTCP<t_CIPAddress, t_Type>::fs_GetType()
	{
		return t_Type;
	}
}

namespace NMib::NStream
{
	template <typename t_CStream>
	constexpr void TCBinaryStreamTypeReference<t_CStream, NNetwork::CNetAddressTCPv4>::fs_Feed(t_CStream &_Stream, NNetwork::CNetAddressTCPv4 const &_Data)
	{
		_Stream.f_FeedBytes(_Data.m_IP, sizeof(_Data.m_IP));
		_Stream << _Data.m_Port;
	}

	template <typename t_CStream>
	constexpr void TCBinaryStreamTypeReference<t_CStream, NNetwork::CNetAddressTCPv4>::fs_Consume(t_CStream &_Stream, NNetwork::CNetAddressTCPv4 &_Data)
	{
		_Stream.f_ConsumeBytes(_Data.m_IP, sizeof(_Data.m_IP));
		_Stream >> _Data.m_Port;
	}

	template <typename t_CStream>
	constexpr void TCBinaryStreamTypeReference<t_CStream, NNetwork::CNetAddressIPv4>::fs_Feed(t_CStream &_Stream, NNetwork::CNetAddressIPv4 const &_Data)
	{
		_Stream.f_FeedBytes(_Data.m_IP, sizeof(_Data.m_IP));
	}

	template <typename t_CStream>
	constexpr void TCBinaryStreamTypeReference<t_CStream, NNetwork::CNetAddressIPv4>::fs_Consume(t_CStream &_Stream, NNetwork::CNetAddressIPv4 &_Data)
	{
		_Stream.f_ConsumeBytes(_Data.m_IP, sizeof(_Data.m_IP));
	}

	template <typename t_CStream>
	constexpr void TCBinaryStreamTypeReference<t_CStream, NNetwork::CNetAddressTCPv6>::fs_Feed(t_CStream &_Stream, NNetwork::CNetAddressTCPv6 const &_Data)
	{
		_Stream.f_FeedBytes(_Data.m_IP, sizeof(_Data.m_IP));
		_Stream << _Data.m_Port;
	}

	template <typename t_CStream>
	constexpr void TCBinaryStreamTypeReference<t_CStream, NNetwork::CNetAddressTCPv6>::fs_Consume(t_CStream &_Stream, NNetwork::CNetAddressTCPv6 &_Data)
	{
		_Stream.f_ConsumeBytes(_Data.m_IP, sizeof(_Data.m_IP));
		_Stream >> _Data.m_Port;
	}

	template <typename t_CStream>
	constexpr void TCBinaryStreamTypeReference<t_CStream, NNetwork::CNetAddressIPv6>::fs_Feed(t_CStream &_Stream, NNetwork::CNetAddressIPv6 const &_Data)
	{
		_Stream.f_FeedBytes(_Data.m_IP, sizeof(_Data.m_IP));
	}

	template <typename t_CStream>
	constexpr void TCBinaryStreamTypeReference<t_CStream, NNetwork::CNetAddressIPv6>::fs_Consume(t_CStream &_Stream, NNetwork::CNetAddressIPv6 &_Data)
	{
		_Stream.f_ConsumeBytes(_Data.m_IP, sizeof(_Data.m_IP));
	}
}

namespace NMib::NNetwork
{
	inline CNetAddress::CNetAddress(NMib::NSys::NNetwork::CAddress _pAddress)
		: mp_pAddress(_pAddress)
	{
	}

	template <typename tf_CAddress>
	CNetAddress::CNetAddress(tf_CAddress const &_Address)
		: mp_pAddress(NMib::NSys::NNetwork::fg_CreateAddress(tf_CAddress::fs_GetType(), &_Address, sizeof(tf_CAddress)))
	{
	}

	template <typename tf_CAddress>
	CNetAddress &CNetAddress::operator = (tf_CAddress const &_Address)
	{
		f_Clear();

		mp_pAddress = NMib::NSys::NNetwork::fg_CreateAddress(tf_CAddress::fs_GetType(), &_Address, sizeof(tf_CAddress));

		return *this;
	}

	inline CNetAddress::~CNetAddress()
	{
		f_Clear();
	}

	inline void CNetAddress::f_Clear()
	{
		if (mp_pAddress)
		{
			NMib::NSys::NNetwork::fg_FreeAddress(mp_pAddress);
			mp_pAddress = nullptr;
		}
	}

	inline void *CNetAddress::f_Detach()
	{
		void *pRet = mp_pAddress;
		mp_pAddress = nullptr;
		return pRet;
	}

	inline void *CNetAddress::f_AccessRaw() const
	{
		return mp_pAddress;
	}

	template <typename tf_CAddress>
	bool CNetAddress::f_Get(tf_CAddress &o_Address) const
	{
		return NMib::NSys::NNetwork::fg_GetAddressRaw(mp_pAddress, tf_CAddress::fs_GetType(), &o_Address, sizeof(tf_CAddress));
	}

	template <typename tf_CAddress>
	bool CNetAddress::f_Set(tf_CAddress const &_Address)
	{
		f_Clear();

		if (mp_pAddress)
			mp_pAddress = NMib::NSys::NNetwork::fg_SetAddressRaw(mp_pAddress, tf_CAddress::fs_GetType(), &_Address, sizeof(tf_CAddress));
		else
			mp_pAddress = NMib::NSys::NNetwork::fg_CreateAddress(tf_CAddress::fs_GetType(), &_Address, sizeof(tf_CAddress));

		return mp_pAddress != nullptr;
	}

	inline uint16 CNetAddress::f_GetPort() const
	{
		if (!mp_pAddress)
			return 0;

		switch (NMib::NSys::NNetwork::fg_GetAddressType(mp_pAddress))
		{
		case ENetAddressType_TCPv4:
			{
				CNetAddressTCPv4 AddressTCPv4;
				if (!f_Get(AddressTCPv4))
					return 0;

				return AddressTCPv4.m_Port;
			}

		case ENetAddressType_TCPv6:
			{
				CNetAddressTCPv6 AddressTCPv6;
				if (!f_Get(AddressTCPv6))
					return 0;

				return AddressTCPv6.m_Port;
			}
		default: return 0;
		}
	}

	template <typename tf_CStr>
	void CNetAddress::f_Format(tf_CStr &o_Str) const
	{
		auto Type = f_GetType();

		ENetAddressStringFlag Flags = ENetAddressStringFlag_IncludePort;
		if (Type == ENetAddressType_Unix)
			Flags |= ENetAddressStringFlag_IncludeType;

		o_Str += f_GetString(Flags);
	}
}
