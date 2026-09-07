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

	// Exercise data arrival between a would-block readiness request and kernel arming; level-at-arm must report it.
	struct CReadinessRace_Tests : public NMib::NTest::CTest
	{
		void fp_Test(CNetAddress const &_ListenAddress, bool _bTcp)
		{
			auto pListen = CSocket_TCP::fs_GetFactory()("");
			pListen->f_Listen(_ListenAddress, [](ENetTCPState){}, ENetFlag_None);

			CNetAddress ConnectAddress = _ListenAddress;
			if (_bTcp)
			{
				CNetAddressTCPv4 Address;
				Address.f_SetLocalhost();
				Address.m_Port = uint16(pListen->f_GetListenPort());
				ConnectAddress = Address;
			}

			auto pClient = CSocket_TCP::fs_GetFactory()("");
			pClient->f_Connect(ConnectAddress, [](ENetTCPState){}, CNetAddress());

			NAtomic::TCAtomic<umint> nReadReports = 0;
			TCUniquePointer<ICSocket> pServer;
			{
				CTimeout Timeout(gc_Timeout);
				while (!Timeout.f_TimedOut())
				{
					pServer = pListen->f_Accept
						(
							[&nReadReports](ENetTCPState _State)
							{
								if (_State & ENetTCPState_Read)
									nReadReports.f_FetchAdd(1);
							}
						)
					;
					if (pServer && pServer->f_IsValid())
						break;

					NSys::fg_Thread_Sleep(0.005f);
				}
			}
			DMibAssertTrue(pServer && pServer->f_IsValid());

			constexpr umint c_nRounds = 300;
			umint nMisses = 0;
			umint nMissesWithByteReadable = 0;
			umint nShortSends = 0;
			umint nRoundsRun = 0;
			for (umint iRound = 0; iRound < c_nRounds && nMisses < 5; ++iRound)
			{
				++nRoundsRun;

				uint8 Buffer[256];
				while (pServer->f_Receive(Buffer, sizeof(Buffer)).m_nBytes)
					;
				pServer->f_GetState();
				umint nReportsBefore = nReadReports.f_Load();

				uint8 Byte = uint8(iRound);
				if (pClient->f_Send(&Byte, 1).m_nBytes != 1)
					++nShortSends;

				CTimeout Timeout(1.0);
				while (nReadReports.f_Load() == nReportsBefore && !Timeout.f_TimedOut())
					NSys::fg_Thread_Sleep(0.001f);

				if (nReadReports.f_Load() == nReportsBefore)
				{
					++nMisses;

					// The byte is there for the taking, only the report never came
					if (pServer->f_Receive(Buffer, sizeof(Buffer)).m_nBytes == 1)
						++nMissesWithByteReadable;
				}
			}

			DMibLog(Info, "{} rounds, {} missed readiness reports ({} with the byte readable), {} short sends", nRoundsRun, nMisses, nMissesWithByteReadable, nShortSends);
			DMibExpect(nShortSends, ==, 0);
			DMibExpect(nMisses, ==, 0);
			DMibExpect(nMissesWithByteReadable, ==, nMisses);

			pClient->f_Close();
			pServer->f_Close();
			pListen->f_Close();
		}

		void f_DoTests()
		{
			DMibTestSuite("ReadinessRace Tcp")
			{
				CNetAddressTCPv4 Address;
				Address.f_SetLocalhost();
				Address.m_Port = 0;
				fp_Test(Address, true);
			};

			DMibTestSuite("ReadinessRace Unix")
			{
				CStr Path = NNetwork::fg_GetSafeUnixSocketPath
					(
						"{}/RR_{}.socket"_f << NFile::CFile::fs_GetProgramDirectory() << NCryptography::fg_RandomID().f_Left(8)
					)
				;
				fp_Test(CSocket::fs_ResolveAddress("UNIX:" + Path), false);
			};
		}
	};

	DMibTestRegister(CReadinessRace_Tests, Malterlib::Network);
}
