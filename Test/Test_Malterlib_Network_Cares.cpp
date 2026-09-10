// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Core/Core>
#include <Mib/Test/Test>
#include <Mib/Network/ResolveActor>
#include <Mib/Concurrency/WeakActor>
#include <Mib/Concurrency/AsyncDestroy>

using namespace NMib;
using namespace NMib::NNetwork;
using namespace NMib::NConcurrency;
using namespace NMib::NStorage;
using namespace NMib::NContainer;

namespace
{
	struct CNameServer : CActor
	{
		enum class EMode : uint8
		{
			mc_Reply
			, mc_DropFirst
			, mc_DropAll
			, mc_Truncate
			, mc_NotFound
			, mc_IPv6Only
			, mc_Multiple
		};

		CNameServer(EMode _Mode, TCPromise<void> const &_Started)
			: m_Started(_Started)
			, m_Mode(_Mode)
		{
		}

		CNetAddress f_Address() const
		{
			return CNetAddressTCPv4(CNetAddressIPv4(127, 0, 0, 1), uint16(m_UDP.f_GetListenPort()));
		}

		umint f_TCPRequests() const
		{
			return m_TCPRequests;
		}

		umint f_UDPRequests() const
		{
			return m_UDPRequests;
		}

		void f_SetMode(EMode _Mode)
		{
			m_Mode = _Mode;
		}

		TCFuture<void> f_SecondRequest()
		{
			co_return co_await m_SecondStarted.f_Future();
		}

		NFunction::TCFunctionMovable<void (ENetTCPState)> f_Callback()
		{
			auto Weak = fg_ThisActor(this).f_Weak();

			return [Weak](ENetTCPState)
				{
					if (auto Actor = Weak.f_Lock())
						Actor.f_Bind<&CNameServer::f_Poll>().f_DiscardResult();
				}
			;
		}

		void fp_Construct() override
		{
			m_Listen.f_Listen(CNetAddressTCPv4(CNetAddressIPv4(127, 0, 0, 1), 0), f_Callback(), ENetFlag_None);
			m_UDP.f_ListenDatagram
				(
					CNetAddressTCPv4(CNetAddressIPv4(127, 0, 0, 1), uint16(m_Listen.f_GetListenPort()))
					, f_Callback()
					, ENetFlag_None
				)
			;
		}

		CByteVector f_Response(uint8 const *_pQuery, umint _Size, bool _bTCP)
		{
			if (_Size < 12)
				return {};

			umint End = 12;
			while (End < _Size && _pQuery[End])
			{
				if (_pQuery[End] > 63 || End + _pQuery[End] + 1 >= _Size)
					return {};
				End += _pQuery[End] + 1;
			}

			if (End + 5 > _Size)
				return {};

			uint16 Type = uint16(uint16(_pQuery[End + 1]) << 8) | _pQuery[End + 2];
			End += 5;

			if (_bTCP)
				++m_TCPRequests;
			else
				++m_UDPRequests;

			if (m_UDPRequests >= 2 && !m_SecondStarted.f_IsSet())
				m_SecondStarted.f_SetResult();

			if (!m_Started.f_IsSet())
				m_Started.f_SetResult();

			if (m_Mode == EMode::mc_DropAll || (m_Mode == EMode::mc_DropFirst && m_UDPRequests == 1 && !_bTCP))
				return {};

			CByteVector Reply;
			Reply.f_Insert(_pQuery, End);
			Reply[2] = 0x81;
			Reply[3] = m_Mode == EMode::mc_NotFound ? 0x83 : 0x80;
			for (umint i = 6; i < 12; ++i)
				Reply[i] = 0;

			if (m_Mode == EMode::mc_Truncate && !_bTCP)
			{
				Reply[2] |= 2;

				return Reply;
			}
			if (m_Mode == EMode::mc_NotFound || (m_Mode == EMode::mc_IPv6Only && Type == 1) || (Type != 1 && Type != 28))
				return Reply;

			Reply[7] = 1;
			uint8 Answer[] = {0xc0, 0x0c, 0, uint8(Type), 0, 1, 0, 0, 0, 30, 0, uint8(Type == 1 ? 4 : 16)};
			Reply.f_Insert(Answer, sizeof(Answer));
			if (Type == 1)
			{
				uint8 Address[] = {127, 0, 0, 42};
				Reply.f_Insert(Address, sizeof(Address));
				if (m_Mode == EMode::mc_Multiple)
				{
					Reply[7] = 2;
					Address[3] = 43;
					Reply.f_Insert(Answer, sizeof(Answer));
					Reply.f_Insert(Address, sizeof(Address));
				}
			}
			else
			{
				uint8 Address[] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42};
				Reply.f_Insert(Address, sizeof(Address));
			}

			return Reply;
		}

		void f_Poll()
		{
			if (f_IsDestroyed())
				return;

			uint8 Buffer[4096];
			CNetAddress From = CNetAddressTCPv4{};
			while (auto Size = m_UDP.f_ReceiveDatagram(From, Buffer, sizeof(Buffer)))
			{
				auto Reply = f_Response(Buffer, Size, false);
				if (!Reply.f_IsEmpty())
					m_UDP.f_SendDatagram(From, Reply.f_GetArray(), Reply.f_GetLen());
			}

			if (!m_Client.f_IsValid() && (m_Listen.f_GetState() & ENetTCPState_Connection) != 0)
				m_Client.f_Accept(&m_Listen, f_Callback());

			if (!m_Client.f_IsValid())
				return;

			bool bEnd = false;
			while (auto Size = m_Client.f_Receive(Buffer, sizeof(Buffer), bEnd))
				m_Input.f_Insert(Buffer, Size);

			if (m_Input.f_GetLen() >= 2 && m_Output.f_IsEmpty())
			{
				umint Size = (umint(m_Input[0]) << 8) | m_Input[1];
				if (m_Input.f_GetLen() >= Size + 2)
				{
					auto Reply = f_Response(m_Input.f_GetArray() + 2, Size, true);
					uint8 Length[] = {uint8(Reply.f_GetLen() >> 8), uint8(Reply.f_GetLen())};
					m_Output.f_Insert(Length, 2);
					m_Output.f_Insert(Reply.f_GetArray(), Reply.f_GetLen());
				}
			}

			while (m_Sent < m_Output.f_GetLen())
			{
				auto Sent = m_Client.f_Send(m_Output.f_GetArray() + m_Sent, m_Output.f_GetLen() - m_Sent);
				if (!Sent)
					break;

				m_Sent += Sent;
			}

			if (bEnd)
			{
				m_Client.f_CloseAsync({});
				m_Input.f_Clear();
				m_Output.f_Clear();
				m_Sent = 0;
			}
		}

		TCFuture<void> fp_Destroy() override
		{
			for (auto *pSocket : {&m_Client, &m_UDP, &m_Listen})
			{
				TCPromise<void> Closed;
				pSocket->f_CloseAsync
					(
						[Closed]() mutable
						{
							Closed.f_SetResult();
						}
					)
				;

				co_await Closed.f_Future();
			}

			co_return {};
		}

		CSocket m_UDP;
		CSocket m_Listen;
		CSocket m_Client;
		TCPromise<void> m_Started;
		TCPromise<void> m_SecondStarted;
		CByteVector m_Input;
		CByteVector m_Output;
		umint m_Sent = 0;
		umint m_UDPRequests = 0;
		umint m_TCPRequests = 0;
		EMode m_Mode;
	};

	struct CCares_Tests : NTest::CTest
	{
		void f_DoTests()
		{
			DMibTestSuite("Replies") -> TCFuture<void>
			{
				for (auto Mode : {CNameServer::EMode::mc_Reply, CNameServer::EMode::mc_DropFirst, CNameServer::EMode::mc_Truncate, CNameServer::EMode::mc_NotFound})
				{
					auto *pName = Mode == CNameServer::EMode::mc_Reply ? "UDP"
						: Mode == CNameServer::EMode::mc_DropFirst ? "Retry"
						: Mode == CNameServer::EMode::mc_Truncate ? "TCP" : "NXDOMAIN"
					;
					DMibTestPath(pName);
					TCPromise<void> Started;
					auto Server = fg_ConstructActor<CNameServer>(Mode, Started);
					auto DestroyServer = co_await fg_AsyncDestroy(Server);
					auto Address = co_await Server.f_Bind<&CNameServer::f_Address>();
					auto Resolver = fg_ConstructActor<CResolveActor>(CResolveActor::FHostResolver{}, 4, Address);
					auto DestroyResolver = co_await fg_AsyncDestroy(Resolver);

					auto Lookup = co_await Resolver.f_Bind<&CResolveActor::f_ResolveHost>(NStr::CStr("resolver.test."), ENetAddressType_TCPv4);
					auto Result = co_await fg_Move(Lookup.m_Result).f_Timeout(15.0, "DNS lookup timed out").f_Wrap();

					DMibExpect(bool(Result), ==, Mode != CNameServer::EMode::mc_NotFound);
					if (Result)
					{
						DMibAssertFalse(Result->f_IsEmpty());
						CNetAddressTCPv4 IP;
						DMibExpectTrue((*Result)[0].f_Get(IP));
						DMibExpect(IP.m_IP[3], ==, 42);
					}

					if (Mode == CNameServer::EMode::mc_Truncate)
						DMibExpect(co_await Server.f_Bind<&CNameServer::f_TCPRequests>(), ==, 1u);
					if (Mode == CNameServer::EMode::mc_DropFirst)
						DMibExpect(co_await Server.f_Bind<&CNameServer::f_UDPRequests>(), >=, 2u);

					if (Mode == CNameServer::EMode::mc_Reply)
					{
						auto IPv6Lookup = co_await Resolver.f_Bind<&CResolveActor::f_ResolveHost>(NStr::CStr("resolver.test."), ENetAddressType_TCPv6);
						auto IPv6Result = co_await fg_Move(IPv6Lookup.m_Result);
						CNetAddressTCPv6 IP;

						DMibAssertFalse(IPv6Result.f_IsEmpty());
						DMibExpectTrue(IPv6Result[0].f_Get(IP));
						DMibExpect(IP.m_IP[15], ==, 42);
					}
				}

				co_return {};
			};

			DMibTestSuite("FullAddresses") -> TCFuture<void>
			{
				for (auto Mode : {CNameServer::EMode::mc_Reply, CNameServer::EMode::mc_IPv6Only, CNameServer::EMode::mc_Multiple})
				{
					DMibTestPath(Mode == CNameServer::EMode::mc_Reply ? "IPv4First" : Mode == CNameServer::EMode::mc_IPv6Only ? "IPv6Fallback" : "Multiple");
					TCPromise<void> Started;
					auto Server = fg_ConstructActor<CNameServer>(Mode, Started);
					auto DestroyServer = co_await fg_AsyncDestroy(Server);
					auto Address = co_await Server.f_Bind<&CNameServer::f_Address>();
					auto Resolver = fg_ConstructActor<CResolveActor>(CResolveActor::FHostResolver{}, 4, Address);
					auto DestroyResolver = co_await fg_AsyncDestroy(Resolver);

					for (bool bServiceName : {false, true})
					{
						DMibTestPath(bServiceName ? "ServiceName" : "Port");
						auto Text = NStr::CStr(bServiceName ? "resolver.test.:http" : "resolver.test.:1234");
						auto Lookup = co_await Resolver.f_Bind<&CResolveActor::f_Resolve>(Text, ENetAddressType_None);
						auto Result = co_await fg_Move(Lookup.m_Result).f_Timeout(5.0, "Endpoint lookup did not use the configured name server");

						DMibAssert(Result.f_GetLen(), ==, Mode == CNameServer::EMode::mc_Multiple ? 2u : 1u);
						bool bPortsMatch = true;
						for (auto const &Resolved : Result)
							bPortsMatch &= Resolved.f_GetPort() == (bServiceName ? 80 : 1234);

						DMibExpectTrue(bPortsMatch);
						DMibExpect(Result[0].f_GetType(), ==, Mode == CNameServer::EMode::mc_IPv6Only ? ENetAddressType_TCPv6 : ENetAddressType_TCPv4);
					}

					auto IPv6 = co_await Resolver.f_Bind<&CResolveActor::f_Resolve>(NStr::CStr("IPv6:resolver.test.:4321"), ENetAddressType_TCPv4);
					auto IPv6Result = co_await fg_Move(IPv6.m_Result);

					DMibAssertFalse(IPv6Result.f_IsEmpty());
					DMibExpect(IPv6Result[0].f_GetType(), ==, ENetAddressType_TCPv6);
					DMibExpect(IPv6Result[0].f_GetPort(), ==, 4321);
				}

				co_return {};
			};

			DMibTestSuite("IndependentCancellation") -> TCFuture<void>
			{
				TCPromise<void> Started;
				auto Server = fg_ConstructActor<CNameServer>(CNameServer::EMode::mc_DropAll, Started);
				auto DestroyServer = co_await fg_AsyncDestroy(Server);
				auto Address = co_await Server.f_Bind<&CNameServer::f_Address>();
				auto Resolver = fg_ConstructActor<CResolveActor>(CResolveActor::FHostResolver{}, 4, Address);
				auto DestroyResolver = co_await fg_AsyncDestroy(Resolver);

				auto First = co_await Resolver.f_Bind<&CResolveActor::f_ResolveHost>(NStr::CStr("first.test."), ENetAddressType_TCPv4);
				auto Second = co_await Resolver.f_Bind<&CResolveActor::f_Resolve>(NStr::CStr("second.test.:4321"), ENetAddressType_TCPv4);
				co_await Server.f_Bind<&CNameServer::f_SecondRequest>().f_Timeout(5.0, "Queries did not reach the server");

				co_await First.m_Cancel->f_Destroy();
				co_await Server.f_Bind<&CNameServer::f_SetMode>(CNameServer::EMode::mc_Reply);
				auto Cancelled = co_await fg_Move(First.m_Result).f_Wrap();
				auto Result = co_await fg_Move(Second.m_Result).f_Timeout(15.0, "Other query was cancelled");

				DMibExpectFalse(bool(Cancelled));
				DMibAssertFalse(Result.f_IsEmpty());
				CNetAddressTCPv4 IP;
				DMibExpectTrue(Result[0].f_Get(IP));
				DMibExpect(IP.m_IP[3], ==, 42);

				co_return {};
			};

			DMibTestSuite("CancelAndDestroy") -> TCFuture<void>
			{
				for (bool bCancel : {false, true})
				{
					DMibTestPath(bCancel ? "Cancel" : "Destroy");
					TCPromise<void> Started;
					auto Server = fg_ConstructActor<CNameServer>(CNameServer::EMode::mc_DropAll, Started);
					auto DestroyServer = co_await fg_AsyncDestroy(Server);
					auto Address = co_await Server.f_Bind<&CNameServer::f_Address>();
					auto Resolver = fg_ConstructActor<CResolveActor>(CResolveActor::FHostResolver{}, 4, Address);
					auto DestroyResolver = co_await fg_AsyncDestroy(Resolver);

					auto Lookup = co_await Resolver.f_Bind<&CResolveActor::f_Resolve>(NStr::CStr("pending.test.:1234"), ENetAddressType_None);
					co_await Started.f_Future().f_Timeout(5.0, "DNS query did not reach the server");
					if (bCancel)
						co_await Lookup.m_Cancel->f_Destroy();

					co_await fg_Move(Resolver).f_Destroy().f_Timeout(5.0, "Resolver waited for an unanswered DNS query");
					auto Result = co_await fg_Move(Lookup.m_Result).f_Wrap();

					DMibExpectFalse(bool(Result));
				}

				co_return {};
			};

		}
	};

	DMibTestRegister(CCares_Tests, Malterlib::Network);
}
