// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Core/Core>
#include <Mib/Time/Timeout>
#include <Mib/Test/Exception>
#include <Mib/Test/Recursive>
#include <Mib/Network/Sockets/AuthenticatedUnix>
#include <Mib/Network/Sockets/TCP>
#include <Mib/Cryptography/Certificate>
#include <Mib/Cryptography/RandomID>
#include <Mib/Process/ProcessLaunch>
#include <Mib/File/File>

using namespace NMib;
using namespace NMib::NNetwork;
using namespace NMib::NStr;
using namespace NMib::NStorage;
using namespace NMib::NContainer;
using namespace NMib::NCryptography;
using namespace NMib::NTime;

namespace
{
	fp32 const gc_Timeout = 30.0f;

	void fg_MakeSelfSigned(CByteVector &o_Certificate, CSecureByteVector &o_PrivateKey)
	{
		CCertificateOptions Options;
		Options.m_CommonName = "Malterlib AuthenticatedUnix Test";
		Options.m_Hostnames = fg_CreateVector<CStr>("localhost");
		Options.m_KeySetting = CPublicKeySettings_EC_secp256r1{};

		CCertificate::fs_GenerateSelfSignedCertAndKey(Options, o_Certificate, o_PrivateKey);
	}

	CStr fg_UniqueUnixPath(CStr const &_Name)
	{
		return NNetwork::fg_GetSafeUnixSocketPath("{}/PA_{}_{}.socket"_f << NFile::CFile::fs_GetProgramDirectory() << _Name << NCryptography::fg_RandomID().f_Left(8));
	}

	// Server context that presents a self-signed certificate and accepts an anonymous client. The
	// process id binding is exercised independently of the certificate exchange.
	TCSharedPointer<CAuthenticatedUnixContext> fg_MakeServerContext(bool _bIgnoreVerification = false)
	{
		CSSLSettings Settings;
		fg_MakeSelfSigned(Settings.m_PublicCertificateData, Settings.m_PrivateKeyData);
		Settings.m_CACertificateData = Settings.m_PublicCertificateData;
		Settings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_AllowMissingPeerCertificate;
		if (_bIgnoreVerification)
			Settings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_IgnoreVerificationFailures;

		return fg_Construct(CAuthenticatedUnixContext::EType::mc_Server, Settings);
	}

	TCSharedPointer<CAuthenticatedUnixContext> fg_MakeClientContext(CByteVector const &_ServerCertificate, bool _bIgnoreVerification = false)
	{
		CSSLSettings Settings;
		Settings.m_CACertificateData = _ServerCertificate;
		if (_bIgnoreVerification)
			Settings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_IgnoreVerificationFailures;

		return fg_Construct(CAuthenticatedUnixContext::EType::mc_Client, Settings);
	}

	struct CHandshakeOutcome
	{
		bool m_bClientDone = false;
		bool m_bServerDone = false;
		CStr m_ClientCloseReason;
		CStr m_ServerCloseReason;
	};

	bool fg_HandshakeFailed(ICSocket *_pSocket, CStr &o_Reason)
	{
		if (_pSocket->f_HandshakeDone())
			return false;

		// A pending handshake is not a failure: an open POSIX socket reports a default non-empty
		// close reason (end of file), so the reason is only read once the socket state shows the
		// connection actually ended. Consuming pending state bits through f_GetState is fine here
		// because the pump loop is the only state consumer for these sockets
		ENetTCPState State = _pSocket->f_GetState();
		if (!(State & (ENetTCPState_Closed | ENetTCPState_RemoteClosed)))
			return false;

		CStr Reason = _pSocket->f_GetCloseReason();
		if (Reason.f_IsEmpty())
			return false;

		o_Reason = Reason;

		return true;
	}

	// Pumps both endpoints of a directly connected authenticated unix pair until both complete their
	// handshake, one of them fails, or the timeout elapses. During the handshake f_Receive drives
	// the state machine and flushes queued frames.
	void fg_PumpHandshake(ICSocket *_pClient, ICSocket *_pServer, CHandshakeOutcome &o_Outcome)
	{
		CTimeout Timeout(gc_Timeout);
		uint8 Buffer[512];

		while (!Timeout.f_TimedOut())
		{
			bool bClientPending = !o_Outcome.m_bClientDone && o_Outcome.m_ClientCloseReason.f_IsEmpty();
			bool bServerPending = !o_Outcome.m_bServerDone && o_Outcome.m_ServerCloseReason.f_IsEmpty();

			if (bClientPending)
			{
				_pClient->f_Receive(Buffer, sizeof(Buffer));
				if (_pClient->f_HandshakeDone())
					o_Outcome.m_bClientDone = true;
				else
					fg_HandshakeFailed(_pClient, o_Outcome.m_ClientCloseReason);
			}

			if (bServerPending)
			{
				_pServer->f_Receive(Buffer, sizeof(Buffer));
				if (_pServer->f_HandshakeDone())
					o_Outcome.m_bServerDone = true;
				else
					fg_HandshakeFailed(_pServer, o_Outcome.m_ServerCloseReason);
			}

			bool bClientSettled = o_Outcome.m_bClientDone || !o_Outcome.m_ClientCloseReason.f_IsEmpty();
			bool bServerSettled = o_Outcome.m_bServerDone || !o_Outcome.m_ServerCloseReason.f_IsEmpty();

			if (bClientSettled && bServerSettled)
				return;

			NSys::fg_Thread_Sleep(0.005f);
		}
	}

	TCUniquePointer<ICSocket> fg_AcceptWithTimeout(ICSocket *_pListen)
	{
		CTimeout Timeout(gc_Timeout);

		while (!Timeout.f_TimedOut())
		{
			auto pAccepted = _pListen->f_Accept([](ENetTCPState){});
			if (pAccepted && pAccepted->f_IsValid())
				return pAccepted;

			NSys::fg_Thread_Sleep(0.005f);
		}

		return nullptr;
	}

	// Raw byte relay run inside a separate recursive invocation of the test binary (no fork, so
	// it works on every platform with unix sockets). It binds _ClientPath (where the
	// authenticated unix client connects) and connects _ServerPath (the authenticated unix
	// server), then forwards bytes between the two so both endpoints see the relay process as
	// their immediate peer
	void fg_RunRelay(CStr const &_ClientPath, CStr const &_ServerPath)
	{
		CTimeout Timeout(gc_Timeout);

		CSocket Listen;
		Listen.f_Listen(CSocket::fs_ResolveAddress("UNIX:" + _ClientPath), nullptr, ENetFlag_None);

		// The authenticated server is listening before the relay launches, so its path exists
		CSocket Server;
		Server.f_Connect(CSocket::fs_ResolveAddress("UNIX:" + _ServerPath));

		CSocket Client;
		while (!Client.f_IsValid() && !Timeout.f_TimedOut())
		{
			Client.f_Accept(&Listen, (NMib::NThread::CSemaphoreAggregate *)nullptr);
			if (!Client.f_IsValid())
				NSys::fg_Thread_Sleep(0.005f);
		}

		if (!Client.f_IsValid())
			return;

		auto fForward = [&](CSocket &_From, CSocket &_To) -> bool
			{
				uint8 Buffer[4096];
				umint nRead = _From.f_Receive(Buffer, sizeof(Buffer));
				umint nWritten = 0;
				while (nWritten < nRead && !Timeout.f_TimedOut())
				{
					umint nThis = _To.f_Send(Buffer + nWritten, nRead - nWritten);
					nWritten += nThis;
					if (!nThis)
						NSys::fg_Thread_Sleep(0.002f);
				}

				return nRead != 0;
			}
		;

		while (!Timeout.f_TimedOut())
		{
			bool bActivity = fForward(Client, Server);
			bActivity |= fForward(Server, Client);

			if ((Client.f_GetState() | Server.f_GetState()) & (ENetTCPState_Closed | ENetTCPState_RemoteClosed))
				break;

			if (!bActivity)
				NSys::fg_Thread_Sleep(0.002f);
		}
	}
}

struct CAuthenticatedUnix_Tests : public NMib::NTest::CTest
{
	void f_DoTests()
	{
		DMibTestSuite("Support")
		{
			bool const bSupported = NNetwork::fg_IsAuthenticatedUnixSupported();

#if defined(DPlatformFamily_macOS) || defined(DPlatformFamily_Linux)
			DMibExpectTrue(bSupported);
#elif !defined(DPlatformFamily_Windows)
			// Windows is a runtime property (SIO_AF_UNIX_GETPEERPID needs the 1809 kernel);
			// every other platform must report unsupported
			DMibExpectFalse(bSupported);
#endif

			if (!bSupported)
			{
				DMibTestPath("Context rejected on unsupported platform");

				CSSLSettings Settings;
				fg_MakeSelfSigned(Settings.m_PublicCertificateData, Settings.m_PrivateKeyData);
				Settings.m_CACertificateData = Settings.m_PublicCertificateData;

				bool bThrew = false;
				try
				{
					// The explicit pointer type forces the construction; auto would only capture the
					// lazy fg_Construct proxy and the constructor would never run
					TCSharedPointer<CAuthenticatedUnixContext> pContext = fg_Construct(CAuthenticatedUnixContext::EType::mc_Server, Settings);
					(void)pContext;
				}
				catch (NException::CException const &)
				{
					bThrew = true;
				}

				DMibExpectTrue(bThrew);
			}
		};

		DMibTestSuite("Process identity API")
		{
			if (!NNetwork::fg_IsAuthenticatedUnixSupported())
				return;

			{
				DMibTestPath("Connected unix socket reports both pids");

				CStr Path = fg_UniqueUnixPath("Identity");
				CNetAddress ListenAddress = CSocket::fs_ResolveAddress("UNIX:" + Path);

				CSocket Listen;
				Listen.f_Listen(ListenAddress, nullptr, ENetFlag_None);

				CSocket Client;
				Client.f_Connect(ListenAddress);

				CSocket Accepted;
				CTimeout Timeout(gc_Timeout);
				while (!Accepted.f_IsValid() && !Timeout.f_TimedOut())
				{
					Accepted.f_Accept(&Listen, (NMib::NThread::CSemaphoreAggregate *)nullptr);
					if (!Accepted.f_IsValid())
						NSys::fg_Thread_Sleep(0.005f);
				}

				DMibExpectTrue(Accepted.f_IsValid());
				if (Accepted.f_IsValid())
				{
					NSys::NNetwork::CProcessIdentity LocalIdentity;
					NSys::NNetwork::CProcessIdentity PeerIdentity;
					DMibExpectTrue(Accepted.f_GetProcessIdentity(LocalIdentity, PeerIdentity));
					// Both endpoints live in this process, so the kernel reports the same pid for the
					// local process and the peer
					DMibExpect(LocalIdentity.m_ProcessID, !=, uint64(0));
					DMibExpect(PeerIdentity.m_ProcessID, ==, LocalIdentity.m_ProcessID);
				}
			}

			{
				DMibTestPath("Non-unix socket fails closed");

				CSocket Socket;
				DMibExpectFalse(Socket.f_IsValid());
			}
		};

		DMibTestSuite("Handshake")
		{
			if (!NNetwork::fg_IsAuthenticatedUnixSupported())
				return;

			CByteVector ServerCertificate;
			{
				auto pServerContext = fg_MakeServerContext();
				ServerCertificate = pServerContext->m_Settings.m_PublicCertificateData;
			}

			{
				DMibTestPath("Mismatched certificate and key rejected");

				// A key that does not pair with the certificate could never complete a handshake, so
				// the context must reject the combination at construction as a configuration error
				CSSLSettings Settings;
				fg_MakeSelfSigned(Settings.m_PublicCertificateData, Settings.m_PrivateKeyData);

				CByteVector OtherCertificate;
				CSecureByteVector OtherKey;
				fg_MakeSelfSigned(OtherCertificate, OtherKey);
				Settings.m_PrivateKeyData = OtherKey;

				// The two generated keypairs must differ or the mismatch below would not exist
				DMibExpectTrue(CCertificate::fs_GetCertificatePublicKey(Settings.m_PublicCertificateData) != CCertificate::fs_GetCertificatePublicKey(OtherCertificate));

				bool bThrew = false;
				try
				{
					// The explicit pointer type forces the construction; auto would only capture the
					// lazy fg_Construct proxy and the constructor would never run
					TCSharedPointer<CAuthenticatedUnixContext> pContext = fg_Construct(CAuthenticatedUnixContext::EType::mc_Server, Settings);
					(void)pContext;
				}
				catch (NException::CException const &)
				{
					bThrew = true;
				}

				DMibExpectTrue(bThrew);
			}

			{
				DMibTestPath("Direct unix connection succeeds");

				auto pServerContext = fg_MakeServerContext();
				auto pClientContext = fg_MakeClientContext(pServerContext->m_Settings.m_PublicCertificateData);

				CStr Path = fg_UniqueUnixPath("Direct");
				CNetAddress Address = CSocket::fs_ResolveAddress("UNIX:" + Path);

				auto pListen = CSocket_AuthenticatedUnix::fs_GetFactory(pServerContext)("");
				pListen->f_Listen(Address, [](ENetTCPState){}, ENetFlag_None);

				auto pClient = CSocket_AuthenticatedUnix::fs_GetFactory(pClientContext)("");
				pClient->f_Connect(Address, [](ENetTCPState){}, CNetAddress());

				auto pServer = fg_AcceptWithTimeout(pListen.f_Get());
				DMibAssertTrue(pServer && pServer->f_IsValid());

				CHandshakeOutcome Outcome;
				fg_PumpHandshake(pClient.f_Get(), pServer.f_Get(), Outcome);

				DMibExpectTrue(Outcome.m_bClientDone);
				DMibExpectTrue(Outcome.m_bServerDone);
				DMibExpect(Outcome.m_ClientCloseReason, ==, CStr());
				DMibExpect(Outcome.m_ServerCloseReason, ==, CStr());
			}

			{
				DMibTestPath("Half close drains in flight data");

				auto pServerContext = fg_MakeServerContext();
				auto pClientContext = fg_MakeClientContext(pServerContext->m_Settings.m_PublicCertificateData);

				CStr Path = fg_UniqueUnixPath("HalfClose");
				CNetAddress Address = CSocket::fs_ResolveAddress("UNIX:" + Path);

				auto pListen = CSocket_AuthenticatedUnix::fs_GetFactory(pServerContext)("");
				pListen->f_Listen(Address, [](ENetTCPState){}, ENetFlag_None);

				auto pClient = CSocket_AuthenticatedUnix::fs_GetFactory(pClientContext)("");
				pClient->f_Connect(Address, [](ENetTCPState){}, CNetAddress());

				auto pServer = fg_AcceptWithTimeout(pListen.f_Get());
				DMibAssertTrue(pServer && pServer->f_IsValid());

				CHandshakeOutcome Outcome;
				fg_PumpHandshake(pClient.f_Get(), pServer.f_Get(), Outcome);
				DMibAssertTrue(Outcome.m_bClientDone && Outcome.m_bServerDone);

				// Data sent before the shutdown must stay readable after it: on an established
				// connection shutdown only closes the write side, so the receiver drains what the
				// peer already sent
				uint8 const Payload[] = {'d', 'r', 'a', 'i', 'n', 'e', 'd'};
				DMibExpect(pServer->f_Send(Payload, sizeof(Payload)).m_nBytes, ==, umint(sizeof(Payload)));
				pServer->f_Shutdown();

				uint8 Buffer[64];
				umint nRead = 0;
				CTimeout Timeout(gc_Timeout);
				while (nRead < sizeof(Payload) && !Timeout.f_TimedOut())
				{
					auto Result = pClient->f_Receive(Buffer + nRead, sizeof(Buffer) - nRead);
					nRead += Result.m_nBytes;
					if (!Result.m_nBytes)
						NSys::fg_Thread_Sleep(0.005f);
				}

				DMibExpect(nRead, ==, umint(sizeof(Payload)));

				// The shut down side no longer sends
				DMibExpect(pServer->f_Send(Payload, sizeof(Payload)).m_nBytes, ==, umint(0));
			}

			{
				DMibTestPath("TCP connection fails closed");

				auto pServerContext = fg_MakeServerContext();
				auto pClientContext = fg_MakeClientContext(pServerContext->m_Settings.m_PublicCertificateData);

				CNetAddressTCPv4 Loopback;
				Loopback.f_SetLocalhost();
				Loopback.m_Port = 0;
				CNetAddress ListenAddress;
				ListenAddress.f_Set(Loopback);

				auto pListen = CSocket_AuthenticatedUnix::fs_GetFactory(pServerContext)("");
				pListen->f_Listen(ListenAddress, [](ENetTCPState){}, ENetFlag_None);
				uint32 Port = pListen->f_GetListenPort();
				DMibAssert(Port, !=, 0u);

				CNetAddressTCPv4 ConnectTo;
				ConnectTo.f_SetLocalhost();
				ConnectTo.m_Port = uint16(Port);
				CNetAddress ConnectAddress;
				ConnectAddress.f_Set(ConnectTo);

				auto pClient = CSocket_AuthenticatedUnix::fs_GetFactory(pClientContext)("");
				pClient->f_Connect(ConnectAddress, [](ENetTCPState){}, CNetAddress());

				auto pServer = fg_AcceptWithTimeout(pListen.f_Get());
				DMibAssertTrue(pServer && pServer->f_IsValid());

				CHandshakeOutcome Outcome;
				fg_PumpHandshake(pClient.f_Get(), pServer.f_Get(), Outcome);

				// Both sides refuse to run the certificate-only handshake without the kernel binding
				DMibExpectFalse(Outcome.m_bClientDone);
				DMibExpectFalse(Outcome.m_bServerDone);
				DMibExpectTrue(Outcome.m_ClientCloseReason.f_Find("kernel peer process identity") >= 0);
				DMibExpectTrue(Outcome.m_ServerCloseReason.f_Find("kernel peer process identity") >= 0);
			}

			{
				DMibTestPath("Verification-ignore flags do not bypass the binding");

				auto pServerContext = fg_MakeServerContext(true);
				auto pClientContext = fg_MakeClientContext(pServerContext->m_Settings.m_PublicCertificateData, true);

				CNetAddressTCPv4 Loopback;
				Loopback.f_SetLocalhost();
				Loopback.m_Port = 0;
				CNetAddress ListenAddress;
				ListenAddress.f_Set(Loopback);

				auto pListen = CSocket_AuthenticatedUnix::fs_GetFactory(pServerContext)("");
				pListen->f_Listen(ListenAddress, [](ENetTCPState){}, ENetFlag_None);
				uint32 Port = pListen->f_GetListenPort();

				CNetAddressTCPv4 ConnectTo;
				ConnectTo.f_SetLocalhost();
				ConnectTo.m_Port = uint16(Port);
				CNetAddress ConnectAddress;
				ConnectAddress.f_Set(ConnectTo);

				auto pClient = CSocket_AuthenticatedUnix::fs_GetFactory(pClientContext)("");
				pClient->f_Connect(ConnectAddress, [](ENetTCPState){}, CNetAddress());

				auto pServer = fg_AcceptWithTimeout(pListen.f_Get());
				DMibAssertTrue(pServer && pServer->f_IsValid());

				CHandshakeOutcome Outcome;
				fg_PumpHandshake(pClient.f_Get(), pServer.f_Get(), Outcome);

				DMibExpectFalse(Outcome.m_bClientDone);
				DMibExpectFalse(Outcome.m_bServerDone);
			}

		};

		DMibTestSuite("Relay")
		{
			if (!NNetwork::fg_IsAuthenticatedUnixSupported())
				return;

			// In the recursive invocation this process is the relay: it forwards raw bytes
			// between the two socket paths passed through the environment, then exits
			if (fg_TestReportFlags() & ETestReportFlag_ProcessRecursive)
			{
				fg_RunRelay
					(
						fg_GetSys()->f_GetEnvironmentVariable("MalterlibTest_RelayClientPath")
						, fg_GetSys()->f_GetEnvironmentVariable("MalterlibTest_RelayServerPath")
					)
				;
				return;
			}

			// Captured at suite level: the recursive child targets the suite so its run reaches
			// the relay branch above
			CStr RecursiveTestPath = fg_TestGetCurrentPath();

			DMibTestPath("Separate-process relay cannot complete");

			auto pServerContext = fg_MakeServerContext();
			auto pClientContext = fg_MakeClientContext(pServerContext->m_Settings.m_PublicCertificateData);

			CStr ServerPath = fg_UniqueUnixPath("RelayServer");
			CStr ClientPath = fg_UniqueUnixPath("RelayClient");

			CNetAddress ServerAddress = CSocket::fs_ResolveAddress("UNIX:" + ServerPath);

			auto pListen = CSocket_AuthenticatedUnix::fs_GetFactory(pServerContext)("");
			pListen->f_Listen(ServerAddress, [](ENetTCPState){}, ENetFlag_None);

			// The relay is a recursive invocation of this test binary targeting this suite; it
			// receives the socket paths through the environment. The destruct flags terminate it
			// if it has not exited by the end of the test
			NProcess::CProcessLaunchParams LaunchParams;
			LaunchParams.m_Target = NFile::CFile::fs_GetProgramPath();
			LaunchParams.m_Parameters = NProcess::CProcessLaunchParams::fs_GetParams
				(
					{"--test", RecursiveTestPath, "--logger", "Null", "--filter-results", "[\"All\"]", "--process-recursive"}
				)
			;
			LaunchParams.m_Environment["MalterlibTest_RelayClientPath"] = ClientPath;
			LaunchParams.m_Environment["MalterlibTest_RelayServerPath"] = ServerPath;

			NProcess::CProcessLaunch Relay(LaunchParams, NProcess::EProcessLaunchCloseFlag_TerminateProcess);

			CNetAddress ClientAddress = CSocket::fs_ResolveAddress("UNIX:" + ClientPath);

			// The relay binds its listen path asynchronously; retry until the client connects.
			// A missing socket path makes connect throw, so absorb that until the relay is ready.
			TCUniquePointer<ICSocket> pClient;
			{
				CTimeout Timeout(gc_Timeout);
				while (!Timeout.f_TimedOut())
				{
					auto pAttempt = CSocket_AuthenticatedUnix::fs_GetFactory(pClientContext)("");
					try
					{
						NException::CDisableExceptionTraceScope DisableTrace;
						pAttempt->f_Connect(ClientAddress, [](ENetTCPState){}, CNetAddress());
					}
					catch (NException::CException const &)
					{
						NSys::fg_Thread_Sleep(0.01f);
						continue;
					}

					if (pAttempt->f_IsValid())
					{
						pClient = fg_Move(pAttempt);
						break;
					}

					NSys::fg_Thread_Sleep(0.01f);
				}
			}

			DMibAssertTrue(pClient && pClient->f_IsValid());

			auto pServer = fg_AcceptWithTimeout(pListen.f_Get());
			DMibAssertTrue(pServer && pServer->f_IsValid());

			CHandshakeOutcome Outcome;
			fg_PumpHandshake(pClient.f_Get(), pServer.f_Get(), Outcome);

			// Each endpoint's kernel peer is the relay process, which differs from the process id
			// the other endpoint signed into its hello, so neither handshake can complete
			DMibExpectFalse(Outcome.m_bClientDone);
			DMibExpectFalse(Outcome.m_bServerDone);
		};
	}
};

DMibTestRegister(CAuthenticatedUnix_Tests, Malterlib::Network);
