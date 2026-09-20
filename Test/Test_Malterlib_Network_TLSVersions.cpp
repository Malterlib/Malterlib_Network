// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Network/AsyncSocket>
#include <Mib/Network/Sockets/SSL>
#include <Mib/Concurrency/AsyncDestroy>
#include <Mib/Concurrency/ConcurrencyManager>
#include <Mib/Cryptography/Certificate>
#include <Mib/Cryptography/BoringSSL>
#include <Mib/Test/Exception>

namespace
{
	using namespace NMib;
	using namespace NMib::NNetwork;
	using namespace NMib::NConcurrency;
	using namespace NMib::NStorage;
	using namespace NMib::NStr;
	using namespace NMib::NCryptography;

	struct CTLSVersions_Tests : NTest::CTest
	{
		static NContainer::CByteVector fs_ConfiguredClientHello(CSSLSettings const &_Settings)
		{
			CNetAddressTCPv4 Address;
			Address.f_SetLocalhost();
			Address.m_Port = 0;
			CSocket Listener;
			Listener.f_Listen(Address, nullptr, ENetFlag_None);
			Address.m_Port = Listener.f_GetListenPort();

			CSocket Socket;
			Socket.f_Connect(Address);

			TCSharedPointer<NThread::CEventAutoReset> Changed = fg_Construct();
			CSocket Peer;

			// Accepting only succeeds once the connection has arrived, and the listener reports no state,
			// so it is retried until it does
			for (NTime::CStopwatch AcceptTimeout(true); !Peer.f_IsValid(); )
			{
				Peer.f_Accept
					(
						&Listener, [Changed](ENetTCPState)
						{
							Changed->f_Signal();
						}
					)
				;

				if (Peer.f_IsValid())
					break;

				if (AcceptTimeout.f_GetTime() >= 10.0 * NTest::gc_TimeoutMultiplier)
					DMibError("Could not accept the connection for the configured ClientHello");

				NSys::fg_Thread_Sleep(0.005f);
			}

			TCSharedPointer<CSSLContext> Context = fg_Construct(CSSLContext::EType_Client, _Settings);
			CSSLConnection Connection(Context, {}, {}, "localhost");
			Connection.f_GiveSocket(&Socket);
			Connection.f_Connect();

			NContainer::CByteVector Hello;
			Hello.f_SetLen(CSSLConnection::mc_nMaxRecordSize);
			umint nReceived = 0;
			NTime::CStopwatch Timeout(true);

			for (;;)
			{
				Connection.f_FlushPending();

				bool bEndOfStream = false;
				nReceived += Peer.f_Receive(Hello.f_GetArray() + nReceived, Hello.f_GetLen() - nReceived, bEndOfStream);
				if (nReceived >= 5 && nReceived >= 5 + (umint(Hello[3]) << 8) + Hello[4])
					break;

				if (bEndOfStream || nReceived == Hello.f_GetLen() || Timeout.f_GetTime() >= 10.0 * NTest::gc_TimeoutMultiplier)
					DMibError("Could not receive configured ClientHello");

				Changed->f_WaitTimeout(0.1);
			}

			Hello.f_SetLen(nReceived);

			return Hello;
		}

		static NContainer::TCVector<uint16> fs_ClientHelloIDs(NContainer::CByteVector const &_Hello, uint16 _ExtensionType)
		{
			using namespace NCryptography::NBoringSSL;

			if (_Hello.f_GetLen() < 9 || _Hello[0] != 22 || _Hello[5] != 1)
				DMibError("Expected a ClientHello record");

			CBS Message, SessionID, Ciphers, Compression, Extensions;
			CBS_init(&Message, _Hello.f_GetArray() + 9, _Hello.f_GetLen() - 9);
			if
			(
				!CBS_skip(&Message, 34) || !CBS_get_u8_length_prefixed(&Message, &SessionID)
				|| !CBS_get_u16_length_prefixed(&Message, &Ciphers) || !CBS_get_u8_length_prefixed(&Message, &Compression)
				|| !CBS_get_u16_length_prefixed(&Message, &Extensions)
			)
			{
				DMibError("Invalid ClientHello fixture");
			}

			while (CBS_len(&Extensions))
			{
				uint16 Type;
				CBS Extension, Algorithms;
				if (!CBS_get_u16(&Extensions, &Type) || !CBS_get_u16_length_prefixed(&Extensions, &Extension))
					DMibError("Invalid ClientHello extension");

				if (Type != _ExtensionType)
					continue;

				if (!CBS_get_u16_length_prefixed(&Extension, &Algorithms) || CBS_len(&Extension))
					DMibError("Invalid TLS algorithms extension");

				NContainer::TCVector<uint16> Result;
				while (CBS_len(&Algorithms))
				{
					uint16 Algorithm;
					if (!CBS_get_u16(&Algorithms, &Algorithm))
						DMibError("Invalid TLS algorithm ID");

					Result.f_InsertLast(Algorithm);

					if (_ExtensionType == TLSEXT_TYPE_key_share)
					{
						CBS Share;
						if (!CBS_get_u16_length_prefixed(&Algorithms, &Share) || !CBS_len(&Share))
							DMibError("Invalid TLS key share");
					}
				}

				return Result;
			}

			DMibError("Missing TLS algorithms extension");
		}

		static NContainer::CByteVector fs_ClientHello(uint32 _MinimumBits, bool _bConfigurePolicy = true)
		{
			return NCryptography::NBoringSSL::fg_RunProtectRegisters
				(
					[&]
					{
						return fsp_ClientHello(_MinimumBits, _bConfigurePolicy);
					}
				)
			;
		}

		static NContainer::CByteVector fsp_ClientHello(uint32 _MinimumBits, bool _bConfigurePolicy)
		{
			using namespace NCryptography::NBoringSSL;

			bssl::UniquePtr<SSL_CTX> Context(SSL_CTX_new(TLS_client_method()));
			if
			(
				!Context
				|| !SSL_CTX_set_min_proto_version(Context.get(), TLS1_3_VERSION)
				|| !SSL_CTX_set_max_proto_version(Context.get(), TLS1_3_VERSION)
				|| (_bConfigurePolicy && !SSL_CTX_set_tls13_cipher_policy(Context.get(), _MinimumBits, 1))
			)
			{
				DMibErrorCryptography(fg_GetExceptionStr("Could not prepare TLS client fixture"));
			}

			bssl::SSL_CTX_set_aes_hw_override_for_testing(Context.get(), true);

			bssl::UniquePtr<SSL> Connection(SSL_new(Context.get()));
			bssl::UniquePtr<BIO> Read(BIO_new(BIO_s_mem()));
			bssl::UniquePtr<BIO> Write(BIO_new(BIO_s_mem()));
			if (!Connection || !Read || !Write)
				DMibErrorCryptography(fg_GetExceptionStr("Could not allocate TLS fixture"));

			auto *pWrite = Write.get();
			SSL_set_bio(Connection.get(), Read.release(), Write.release());
			SSL_set_connect_state(Connection.get());

			ERR_clear_error();
			auto Result = SSL_connect(Connection.get());
			if (Result >= 0 || SSL_get_error(Connection.get(), Result) != SSL_ERROR_WANT_READ)
				DMibErrorCryptography(fg_GetExceptionStr("Could not generate ClientHello fixture"));

			char *pData = nullptr;
			auto Length = BIO_get_mem_data(pWrite, &pData);
			if (Length < 5 || uint8(pData[0]) != 22)
				DMibError("Expected a TLS handshake record");

			umint RecordLength = (umint(uint8(pData[3])) << 8) + uint8(pData[4]) + 5;
			if (RecordLength > umint(Length))
				DMibError("Incomplete ClientHello fixture");

			NContainer::CByteVector Bytes;
			Bytes.f_SetLen(RecordLength);
			NMemory::fg_MemCopy(Bytes.f_GetArray(), pData, RecordLength);

			return Bytes;
		}

		static umint fs_CipherOffset(NContainer::CByteVector const &_Hello)
		{
			if (_Hello.f_GetLen() < 46 || _Hello[5] != 1)
				DMibError("Expected a ClientHello message");

			umint Offset = 44 + _Hello[43];
			if (Offset + 2 > _Hello.f_GetLen())
				DMibError("Incomplete ClientHello session ID");

			umint Length = (umint(_Hello[Offset]) << 8) + _Hello[Offset + 1];
			if (Length < 2 || (Length & 1) || Offset + 2 + Length > _Hello.f_GetLen())
				DMibError("Invalid ClientHello cipher list");

			return Offset;
		}

		static NContainer::CByteVector fs_AES128OnlyHello()
		{
			auto Hello = fs_ClientHello(0);
			auto Offset = fs_CipherOffset(Hello);
			umint CipherBytes = (umint(Hello[Offset]) << 8) + Hello[Offset + 1];

			NContainer::CByteVector Restricted;
			Restricted.f_SetLen(Hello.f_GetLen() - CipherBytes + 2);
			NMemory::fg_MemCopy(Restricted.f_GetArray(), Hello.f_GetArray(), Offset);
			Restricted[Offset] = 0;
			Restricted[Offset + 1] = 2;
			Restricted[Offset + 2] = 0x13;
			Restricted[Offset + 3] = 0x01; // TLS_AES_128_GCM_SHA256
			NMemory::fg_MemCopy
				(
					Restricted.f_GetArray() + Offset + 4
					, Hello.f_GetArray() + Offset + 2 + CipherBytes
					, Hello.f_GetLen() - Offset - 2 - CipherBytes
				)
			;

			auto RecordLength = Restricted.f_GetLen() - 5;
			auto HandshakeLength = Restricted.f_GetLen() - 9;
			Restricted[3] = uint8(RecordLength >> 8);
			Restricted[4] = uint8(RecordLength);
			Restricted[6] = uint8(HandshakeLength >> 16);
			Restricted[7] = uint8(HandshakeLength >> 8);
			Restricted[8] = uint8(HandshakeLength);

			return Restricted;
		}

		static void fs_CheckServerCipherFilter(CSSLSettings const &_Credentials, bool _bStrict)
		{
			NCryptography::NBoringSSL::fg_RunProtectRegisters
				(
					[&]
					{
						fsp_CheckServerCipherFilter(_Credentials, _bStrict);
					}
				)
			;
		}

		static void fsp_CheckServerCipherFilter(CSSLSettings const &_Credentials, bool _bStrict)
		{
			using namespace NCryptography::NBoringSSL;

			bssl::UniquePtr<SSL_CTX> Context(SSL_CTX_new(TLS_server_method()));
			if
			(
				!Context
				|| !SSL_CTX_set_min_proto_version(Context.get(), TLS1_3_VERSION)
				|| !SSL_CTX_set_max_proto_version(Context.get(), TLS1_3_VERSION)
				|| !SSL_CTX_set_tls13_cipher_policy(Context.get(), _bStrict ? 256 : 0, 1)
			)
			{
				DMibErrorCryptography(fg_GetExceptionStr("Could not prepare TLS server fixture"));
			}

			bssl::UniquePtr<X509> Certificate(fg_LoadCertificate(_Credentials.m_PublicCertificateData));
			bssl::UniquePtr<EVP_PKEY> Key(fg_LoadPrivateKey(_Credentials.m_PrivateKeyData));
			if (!SSL_CTX_use_certificate(Context.get(), Certificate.get()) || !SSL_CTX_use_PrivateKey(Context.get(), Key.get()))
				DMibErrorCryptography(fg_GetExceptionStr("Could not install TLS fixture credentials"));

			bssl::UniquePtr<SSL> Connection(SSL_new(Context.get()));
			bssl::UniquePtr<BIO> Read(BIO_new(BIO_s_mem()));
			bssl::UniquePtr<BIO> Write(BIO_new(BIO_s_mem()));
			if (!Connection || !Read || !Write)
				DMibErrorCryptography(fg_GetExceptionStr("Could not allocate TLS fixture"));

			auto Hello = fs_AES128OnlyHello();
			if (BIO_write(Read.get(), Hello.f_GetArray(), int(Hello.f_GetLen())) != int(Hello.f_GetLen()))
				DMibErrorCryptography(fg_GetExceptionStr("Could not feed ClientHello fixture"));

			SSL_set_bio(Connection.get(), Read.release(), Write.release());
			SSL_set_accept_state(Connection.get());

			ERR_clear_error();
			auto Result = SSL_accept(Connection.get());
			auto Error = SSL_get_error(Connection.get(), Result);
			auto Reason = ERR_GET_REASON(ERR_peek_last_error());
			auto Details = fg_GetErrors();

			if (_bStrict)
			{
				DMibExpect(Error, ==, SSL_ERROR_SSL)(Details);
				DMibExpect(Reason, ==, SSL_R_NO_SHARED_CIPHER)(Details);
			}
			else
			{
				DMibExpect(Error, ==, SSL_ERROR_WANT_READ)(Details);

				auto *pCipher = SSL_get_pending_cipher(Connection.get());
				DMibAssertTrue(pCipher != nullptr);
				DMibExpect(SSL_CIPHER_get_bits(pCipher, nullptr), ==, 128);
			}

			ERR_clear_error();
		}

		static void fs_CheckInitialKeyShare(CSSLSettings const &_Credentials, NContainer::CByteVector const &_Hello, uint16_t _Group)
		{
			NCryptography::NBoringSSL::fg_RunProtectRegisters
				(
					[&]
					{
						using namespace NCryptography::NBoringSSL;

						bssl::UniquePtr<SSL_CTX> Context(SSL_CTX_new(TLS_server_method()));
						uint16_t Group = _Group;
						uint16_t Signature = SSL_SIGN_ECDSA_SECP521R1_SHA512;
						if
						(
							!Context || !SSL_CTX_set_min_proto_version(Context.get(), TLS1_3_VERSION)
							|| !SSL_CTX_set1_group_ids(Context.get(), &Group, 1) || !SSL_CTX_set_signing_algorithm_prefs(Context.get(), &Signature, 1)
						)
						{
							DMibErrorCryptography(fg_GetExceptionStr("Could not prepare single-group server fixture"));
						}

						bssl::UniquePtr<X509> Certificate(fg_LoadCertificate(_Credentials.m_PublicCertificateData));
						bssl::UniquePtr<EVP_PKEY> Key(fg_LoadPrivateKey(_Credentials.m_PrivateKeyData));
						if (!SSL_CTX_use_certificate(Context.get(), Certificate.get()) || !SSL_CTX_use_PrivateKey(Context.get(), Key.get()))
							DMibErrorCryptography(fg_GetExceptionStr("Could not install single-group server credentials"));

						bssl::UniquePtr<SSL> Connection(SSL_new(Context.get()));
						bssl::UniquePtr<BIO> Read(BIO_new(BIO_s_mem()));
						bssl::UniquePtr<BIO> Write(BIO_new(BIO_s_mem()));
						if (!Connection || !Read || !Write || BIO_write(Read.get(), _Hello.f_GetArray(), int(_Hello.f_GetLen())) != int(_Hello.f_GetLen()))
							DMibErrorCryptography(fg_GetExceptionStr("Could not feed single-group handshake fixture"));

						SSL_set_bio(Connection.get(), Read.release(), Write.release());
						SSL_set_accept_state(Connection.get());

						ERR_clear_error();
						auto Result = SSL_accept(Connection.get());
						auto Error = SSL_get_error(Connection.get(), Result);

						DMibExpect(Error, ==, SSL_ERROR_WANT_READ)(fg_GetErrors());
						DMibExpectFalse(bool(SSL_used_hello_retry_request(Connection.get())));
						DMibExpect(SSL_get_group_id(Connection.get()), ==, Group);

						ERR_clear_error();
					}
				)
			;
		}

		static CSSLSettings fs_Settings(CStr const &_Name, bool _bStrong, bool _bCA = false, EDigestType _Digest = EDigestType_SHA512)
		{
			CSSLSettings Settings;
			Settings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_AllowMissingPeerCertificate;

			CCertificateOptions Options;
			Options.m_CommonName = _Name;
			Options.m_Hostnames = NContainer::fg_CreateVector<CStr>("localhost");
			if (_bStrong)
				Options.m_KeySetting = CPublicKeySettings_EC_secp521r1{};
			else
				Options.m_KeySetting = CPublicKeySettings_EC_secp256r1{};

			if (_bCA)
				Options.f_MakeCA();

			CCertificateSignOptions SignOptions;
			SignOptions.m_Digest = _Digest;

			CCertificate::fs_GenerateSelfSignedCertAndKey(Options, Settings.m_PublicCertificateData, Settings.m_PrivateKeyData, SignOptions);

			return Settings;
		}

		static NContainer::CByteVector fs_RSAChainCertificate(CSSLSettings const &_Signer, int _Bits)
		{
			return NCryptography::NBoringSSL::fg_RunProtectRegisters
				(
					[&]
					{
						using namespace NCryptography::NBoringSSL;

						bssl::UniquePtr<BIGNUM> Modulus(BN_new());
						bssl::UniquePtr<BIGNUM> Exponent(BN_new());
						if (!Modulus || !Exponent || !BN_set_bit(Modulus.get(), _Bits - 1) || !BN_set_bit(Modulus.get(), 0) || !BN_set_word(Exponent.get(), RSA_F4))
							DMibErrorCryptography(fg_GetExceptionStr("Could not prepare RSA modulus fixture"));

						// Only the public modulus length is exercised; no RSA private key or handshake is needed.
						bssl::UniquePtr<RSA> RSAKey(RSA_new_public_key(Modulus.get(), Exponent.get()));
						bssl::UniquePtr<EVP_PKEY> Key(EVP_PKEY_new());
						bssl::UniquePtr<X509> Certificate(fg_LoadCertificate(_Signer.m_PublicCertificateData));
						bssl::UniquePtr<EVP_PKEY> Signer(fg_LoadPrivateKey(_Signer.m_PrivateKeyData));
						if
						(
							!RSAKey || !Key || !EVP_PKEY_set1_RSA(Key.get(), RSAKey.get())
							|| !X509_set_pubkey(Certificate.get(), Key.get()) || !X509_sign(Certificate.get(), Signer.get(), EVP_sha512())
						)
						{
							DMibErrorCryptography(fg_GetExceptionStr("Could not prepare RSA certificate fixture"));
						}

						return fg_ConvertX509ToBinary(Certificate.get());
					}
				)
			;
		}

		static CSSLSettings fs_SignedSettings(CSSLSettings const &_Issuer, CStr const &_Name, bool _bStrong, bool _bCA, EDigestType _Digest = EDigestType_SHA512)
		{
			CSSLSettings Settings;
			Settings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_AllowMissingPeerCertificate;

			CCertificateOptions Options;
			Options.m_CommonName = _Name;
			Options.m_Hostnames = NContainer::fg_CreateVector<CStr>("localhost");
			if (_bStrong)
				Options.m_KeySetting = CPublicKeySettings_EC_secp521r1{};
			else
				Options.m_KeySetting = CPublicKeySettings_EC_secp256r1{};

			if (_bCA)
				Options.f_MakeCA();

			NContainer::CByteVector Request;
			CCertificate::fs_GenerateClientCertificateRequest(Options, Request, Settings.m_PrivateKeyData, EDigestType_SHA512);

			CCertificateSignOptions SignOptions;
			SignOptions.m_Digest = _Digest;
			SignOptions.m_LeafRole = _bCA ? ECertificateLeafRole_Unrestricted : ECertificateLeafRole_ServerAuth;

			CCertificate::fs_SignClientCertificate
				(
					_Issuer.m_PublicCertificateData, _Issuer.m_PrivateKeyData, Request, Settings.m_PublicCertificateData, SignOptions
				)
			;

			Settings.m_CACertificateData = _Issuer.m_PublicCertificateData;

			return Settings;
		}

		static auto fs_CheckConnection
			(
				CSSLSettings _ClientSettings
				, CSSLSettings _ServerSettings
				, CStr _ExpectedProtocol
				, uint16 _ExpectedKeyStrength
				, bool _bExpectedRetry
			)
			-> TCFuture<CStr>
		{
			TCSharedPointer<CSSLContext> pServerContext = fg_Construct(CSSLContext::EType_Server, _ServerSettings);
			TCSharedPointer<CSSLContext> pClientContext = fg_Construct(CSSLContext::EType_Client, _ClientSettings);

			auto Server = fg_ConstructActor<CAsyncSocketServerActor>();
			auto Client = fg_ConstructActor<CAsyncSocketClientActor>();
			auto DestroyServer = co_await fg_AsyncDestroy(Server);
			auto DestroyClient = co_await fg_AsyncDestroy(Client);

			TCPromise<CSocketConnectionInfo_SSL> ServerInfo;
			TCPromise<TCActorInterface<CAsyncSocketActor>> ServerAccepted;
			CAsyncSocketServerCallbacks Callbacks;
			Callbacks.m_fNewConnection = g_ActorFunctor / [ServerInfo, ServerAccepted](CAsyncSocketNewServerConnection Connection) -> TCFuture<void>
				{
					auto *pInfo = static_cast<CSocketConnectionInfo_SSL *>(Connection.m_Info.m_pSocketInfo.f_Get());
					DMibRequire(pInfo);

					ServerInfo.f_SetResult(CSocketConnectionInfo_SSL(*pInfo));
					ServerAccepted.f_SetResult(co_await Connection.f_Accept({}));

					co_return {};
				}
			;

			CNetAddressTCPv4 Address;
			Address.f_SetLocalhost();
			Address.m_Port = 0;

			auto Listen = co_await Server
				(
					&CAsyncSocketServerActor::f_StartListenAddress
					, NContainer::fg_CreateVector<CNetAddress>(Address), ENetFlag_None
					, fg_Move(Callbacks), CSocket_SSL::fs_GetFactory(pServerContext)
				)
			;

			auto Connection = co_await Client
				(
					&CAsyncSocketClientActor::f_Connect
					, CStr("localhost"), CStr{}, ENetAddressType_TCPv4, Listen.m_ListenPorts[0], CSocket_SSL::fs_GetFactory(pClientContext)
				)
			;

			auto *pInfo = static_cast<CSocketConnectionInfo_SSL *>(Connection.m_pSocketInfo.f_Get());
			DMibAssertTrue(pInfo != nullptr);

			DMibExpect(pInfo->m_ProtocolVersion, ==, _ExpectedProtocol);
			DMibExpect(pInfo->m_CipherStrength, ==, uint16(256));
			DMibExpect(pInfo->m_KeyExchangeStrength, ==, _ExpectedKeyStrength);
			DMibExpect(pInfo->m_bHelloRetryRequest, ==, _bExpectedRetry);

			auto ClientDigest = pInfo->m_SessionKeyDigest.f_GetString();

			auto ClientSocket = co_await Connection.f_Accept({});
			auto DestroyClientSocket = co_await fg_AsyncDestroy(ClientSocket);

			auto ServerSocket = co_await ServerAccepted.f_Future().f_Timeout(10.0 * NTest::gc_TimeoutMultiplier, "TLS server did not accept");
			auto DestroyServerSocket = co_await fg_AsyncDestroy(ServerSocket);

			auto Info = co_await ServerInfo.f_Future();

			DMibExpect(Info.m_ProtocolVersion, ==, _ExpectedProtocol);
			DMibExpect(Info.m_CipherStrength, ==, uint16(256));
			DMibExpect(Info.m_KeyExchangeStrength, ==, _ExpectedKeyStrength);
			DMibExpect(Info.m_bHelloRetryRequest, ==, _bExpectedRetry);
			DMibExpect(Info.m_SessionKeyDigest.f_GetString(), ==, ClientDigest);

			co_await Listen.m_Subscription->f_Destroy();

			co_return ClientDigest;
		}

		static TCFuture<void> fs_ExpectConnectionFailure(CSSLSettings _ClientSettings, FVirtualSocketFactory _ServerFactory)
		{
			TCSharedPointer<CSSLContext> pClientContext = fg_Construct(CSSLContext::EType_Client, _ClientSettings);

			auto Server = fg_ConstructActor<CAsyncSocketServerActor>();
			auto Client = fg_ConstructActor<CAsyncSocketClientActor>();
			auto DestroyServer = co_await fg_AsyncDestroy(Server);
			auto DestroyClient = co_await fg_AsyncDestroy(Client);

			CNetAddressTCPv4 Address;
			Address.f_SetLocalhost();
			Address.m_Port = 0;

			auto Listen = co_await Server
				(
					&CAsyncSocketServerActor::f_StartListenAddress
					, NContainer::fg_CreateVector<CNetAddress>(Address), ENetFlag_None
					, CAsyncSocketServerCallbacks{}, fg_Move(_ServerFactory)
				)
			;

			auto Result = co_await Client
				(
					&CAsyncSocketClientActor::f_Connect
					, CStr("localhost"), CStr{}, ENetAddressType_TCPv4, Listen.m_ListenPorts[0], CSocket_SSL::fs_GetFactory(pClientContext)
				)
				.f_Timeout(10.0 * NTest::gc_TimeoutMultiplier, "TLS rejection timed out").f_Wrap()
			;

			DMibExpectFalse(bool(Result));
			if (!Result)
			{
				DMibExpect(Result.f_GetExceptionStr().f_Find("TLS rejection timed out"), <, 0);

				if (uint16(_ClientSettings.m_MinimumCryptoStrength))
					DMibExpect(Result.f_GetExceptionStr().f_Find("Configured TLS minimum:"), >=, 0)(Result.f_GetExceptionStr());
			}

			co_await Listen.m_Subscription->f_Destroy();

			co_return {};
		}

		static TCFuture<void> fs_ExpectHandshakeFailure(CSSLSettings _ClientSettings, CSSLSettings _ServerSettings)
		{
			TCSharedPointer<CSSLContext> pServerContext = fg_Construct(CSSLContext::EType_Server, _ServerSettings);

			co_await fs_ExpectConnectionFailure(fg_Move(_ClientSettings), CSocket_SSL::fs_GetFactory(pServerContext));

			co_return {};
		}

		void f_DoTests()
		{
			DMibTestSuite("Negotiation") -> TCFuture<void>
			{
				auto CompatibleServer = fs_Settings("Compatible server", false);
				auto StrongServer = fs_Settings("Strong server", true);
				using CStrength = NCryptography::ECryptoStrength;

				struct CCase
				{
					ch8 const *m_Name;
					CSSLSettings::EProtocol m_Client;
					CSSLSettings::EProtocol m_Server;
					ch8 const *m_Expected;
					bool m_bStrict = false;
				};

				CCase Cases[] =
				{
					{"Default", CSSLSettings::EProtocol_TLS, CSSLSettings::EProtocol_TLS, "TLSv1.3"},
					{"TLS12Server", CSSLSettings::EProtocol_TLS, CSSLSettings::EProtocol_TLS_1_2, "TLSv1.2"},
					{"TLS12Client", CSSLSettings::EProtocol_TLS_1_2, CSSLSettings::EProtocol_TLS, "TLSv1.2"},
					{"TLS13Server", CSSLSettings::EProtocol_TLS, CSSLSettings::EProtocol_TLS_1_3, "TLSv1.3"},
					{"TLS13Client", CSSLSettings::EProtocol_TLS_1_3, CSSLSettings::EProtocol_TLS, "TLSv1.3"},
					{"StrictTLS12", CSSLSettings::EProtocol_TLS_1_2, CSSLSettings::EProtocol_TLS_1_2, "TLSv1.2", true},
					{"StrictTLS13", CSSLSettings::EProtocol_TLS_1_3, CSSLSettings::EProtocol_TLS_1_3, "TLSv1.3", true},
				};
				NContainer::TCMap<CStr, CStr> PreviousDigests;

				for (auto const &Case : Cases)
				{
					DMibTestPath(Case.m_Name);

					auto Server = Case.m_bStrict ? StrongServer : CompatibleServer;
					Server.m_Protocol = Case.m_Server;
					Server.m_MinimumCryptoStrength = Case.m_bStrict ? CStrength::mc_EquivalentSymmetric256bit : CStrength::mc_Compatible;

					CSSLSettings Client;
					Client.m_Protocol = Case.m_Client;
					Client.m_CACertificateData = Server.m_PublicCertificateData;
					Client.m_MinimumCryptoStrength = Server.m_MinimumCryptoStrength;

					bool bExpectedRetry = !Case.m_bStrict && CStr(Case.m_Expected) == "TLSv1.3";
					auto Digest = co_await fs_CheckConnection(fg_Move(Client), fg_Move(Server), Case.m_Expected, Case.m_bStrict ? 256 : 128, bExpectedRetry);
					auto &Previous = PreviousDigests[CStr(Case.m_Expected)];
					if (!Previous.f_IsEmpty())
						DMibExpect(Digest, !=, Previous);

					Previous = fg_Move(Digest);
				}

				DMibTestCategory("AlgorithmPreferences") -> TCFuture<void>
				{
					using namespace NCryptography::NBoringSSL;

					CSSLSettings Medium;
					CCertificateOptions Options;
					Options.m_CommonName = "P384 signature preference";
					Options.m_KeySetting = CPublicKeySettings_EC_secp384r1{};
					CCertificateSignOptions SignOptions;
					SignOptions.m_Digest = EDigestType_SHA512;

					CCertificate::fs_GenerateSelfSignedCertAndKey(Options, Medium.m_PublicCertificateData, Medium.m_PrivateKeyData, SignOptions);

					struct CPreferenceCase
					{
						ch8 const *m_Name;
						CSSLSettings m_Settings;
						CStrength m_Minimum;
						uint16 m_First;
						NContainer::TCVector<uint16> m_Groups;
						uint16 m_InitialShare;
					};

					CPreferenceCase PreferenceCases[] =
					{
						{
							"P256", CompatibleServer, CStrength::mc_Compatible, SSL_SIGN_ECDSA_SECP256R1_SHA256
							, {SSL_GROUP_X25519, SSL_GROUP_SECP256R1, SSL_GROUP_SECP384R1, SSL_GROUP_SECP521R1}, SSL_GROUP_SECP384R1
						},
						{
							"P384", Medium, CStrength::mc_Compatible, SSL_SIGN_ECDSA_SECP384R1_SHA384
							, {SSL_GROUP_SECP384R1, SSL_GROUP_SECP521R1, SSL_GROUP_X25519, SSL_GROUP_SECP256R1}, SSL_GROUP_SECP384R1
						},
						{
							"P521", StrongServer, CStrength::mc_Compatible, SSL_SIGN_ECDSA_SECP521R1_SHA512
							, {SSL_GROUP_SECP521R1, SSL_GROUP_SECP384R1, SSL_GROUP_X25519, SSL_GROUP_SECP256R1}, SSL_GROUP_SECP384R1
						},
						{
							"P256Minimum128", CompatibleServer, CStrength::mc_EquivalentSymmetric128bit, SSL_SIGN_ECDSA_SECP256R1_SHA256
							, {SSL_GROUP_X25519, SSL_GROUP_SECP256R1, SSL_GROUP_SECP384R1, SSL_GROUP_SECP521R1}, SSL_GROUP_X25519
						},
						{
							"P384Minimum128", Medium, CStrength::mc_EquivalentSymmetric128bit, SSL_SIGN_ECDSA_SECP384R1_SHA384
							, {SSL_GROUP_SECP384R1, SSL_GROUP_SECP521R1, SSL_GROUP_X25519, SSL_GROUP_SECP256R1}, SSL_GROUP_X25519
						},
						{
							"P521Minimum192", StrongServer, CStrength::mc_EquivalentSymmetric192bit, SSL_SIGN_ECDSA_SECP521R1_SHA512
							, {SSL_GROUP_SECP521R1, SSL_GROUP_SECP384R1}, SSL_GROUP_SECP384R1
						},
						{
							"P384Minimum192", Medium, CStrength::mc_EquivalentSymmetric192bit, SSL_SIGN_ECDSA_SECP384R1_SHA384
							, {SSL_GROUP_SECP384R1, SSL_GROUP_SECP521R1}, SSL_GROUP_SECP384R1
						},
						{
							"P521Minimum256", StrongServer, CStrength::mc_EquivalentSymmetric256bit, SSL_SIGN_ECDSA_SECP521R1_SHA512
							, {SSL_GROUP_SECP521R1}, SSL_GROUP_SECP521R1
						},
						{
							"NoLocalKey", {}, CStrength::mc_Compatible, SSL_SIGN_ECDSA_SECP521R1_SHA512
							, {SSL_GROUP_SECP521R1, SSL_GROUP_SECP384R1, SSL_GROUP_X25519, SSL_GROUP_SECP256R1}, SSL_GROUP_SECP384R1
						},
						{
							"NoLocalKeyMinimum128", {}, CStrength::mc_EquivalentSymmetric128bit, SSL_SIGN_ECDSA_SECP256R1_SHA256
							, {SSL_GROUP_X25519, SSL_GROUP_SECP256R1, SSL_GROUP_SECP384R1, SSL_GROUP_SECP521R1}, SSL_GROUP_X25519
						},
						{
							"NoLocalKeyMinimum192", {}, CStrength::mc_EquivalentSymmetric192bit, SSL_SIGN_ECDSA_SECP384R1_SHA384
							, {SSL_GROUP_SECP384R1, SSL_GROUP_SECP521R1}, SSL_GROUP_SECP384R1
						},
						{
							"NoLocalKeyMinimum256", {}, CStrength::mc_EquivalentSymmetric256bit, SSL_SIGN_ECDSA_SECP521R1_SHA512
							, {SSL_GROUP_SECP521R1}, SSL_GROUP_SECP521R1
						},
					};

					for (auto const &Case : PreferenceCases)
					{
						DMibTestPath(Case.m_Name);

						for (auto Protocol : {CSSLSettings::EProtocol_TLS_1_2, CSSLSettings::EProtocol_TLS_1_3})
						{
							DMibTestPath(Protocol == CSSLSettings::EProtocol_TLS_1_2 ? "TLS12" : "TLS13");

							auto Settings = Case.m_Settings;
							Settings.m_Protocol = Protocol;
							Settings.m_MinimumCryptoStrength = Case.m_Minimum;

							auto Blocking = fg_BlockingActor();
							auto Hello = co_await
								(
									g_Dispatch(Blocking) / [Settings = fg_Move(Settings)]
									{
										return fs_ConfiguredClientHello(Settings);
									}
								)
							;

							auto Groups = fs_ClientHelloIDs(Hello, TLSEXT_TYPE_supported_groups);

							DMibAssert(Groups.f_GetLen(), ==, Case.m_Groups.f_GetLen());
							for (umint i = 0; i < Groups.f_GetLen(); ++i)
							{
								DMibTestPath("Group {}"_f << i);

								DMibExpect(Groups[i], ==, Case.m_Groups[i]);
							}

							if (Protocol == CSSLSettings::EProtocol_TLS_1_3)
							{
								auto Shares = fs_ClientHelloIDs(Hello, TLSEXT_TYPE_key_share);

								DMibAssert(Shares.f_GetLen(), ==, umint(1));
								DMibExpect(Shares[0], ==, Case.m_InitialShare);
							}

							auto Algorithms = fs_ClientHelloIDs(Hello, TLSEXT_TYPE_signature_algorithms);

							DMibAssertFalse(Algorithms.f_IsEmpty());
							DMibExpect(Algorithms[0], ==, Case.m_First);
							for (auto Algorithm : Algorithms)
							{
								DMibTestPath("{}"_f << Algorithm);

								auto *pDigest = SSL_get_signature_algorithm_digest(Algorithm);
								DMibAssertTrue(pDigest != nullptr);
								DMibExpect(uint16(EVP_MD_size(pDigest) * 4), >=, uint16(Case.m_Minimum));
							}
						}
					}

					co_return {};
				};

				DMibTestCategory("CipherFiltering")
				{
					DMibExpectExceptionType(fs_ClientHello(257), CExceptionCryptography);

					struct COfferCase
					{
						ch8 const *m_Name;
						uint32 m_Minimum;
						bool m_bConfigurePolicy;
					};

					COfferCase Offers[] =
					{
						{"Default", 0, false},
						{"Compatible", 0, true},
						{"Minimum128", 128, true},
						{"Minimum192", 192, true},
						{"Minimum256", 256, true},
					};

					for (auto const &Offer : Offers)
					{
						DMibTestPath(Offer.m_Name);

						auto Hello = fs_ClientHello(Offer.m_Minimum, Offer.m_bConfigurePolicy);
						auto Offset = fs_CipherOffset(Hello);
						umint CipherBytes = (umint(Hello[Offset]) << 8) + Hello[Offset + 1];

						NContainer::TCVector<uint16> Offered;
						for (umint i = 0; i < CipherBytes; i += 2)
							Offered.f_InsertLast(uint16((uint16(Hello[Offset + 2 + i]) << 8) + Hello[Offset + 3 + i]));

						NContainer::TCVector<uint16> Expected = {0x1302, 0x1303};
						if (Offer.m_Minimum <= 128)
							Expected.f_InsertLast(0x1301);

						DMibAssert(Offered.f_GetLen(), ==, Expected.f_GetLen());
						for (umint i = 0; i < Expected.f_GetLen(); ++i)
						{
							DMibTestPath("Cipher {}"_f << i);
							DMibExpect(Offered[i], ==, Expected[i]);
						}
					}

					for (bool bStrict : {false, true})
					{
						DMibTestPath(bStrict ? "StrictServer" : "CompatibleServer");

						fs_CheckServerCipherFilter(CompatibleServer, bStrict);
					}
				};

				DMibTestCategory("InitialKeyShare") -> TCFuture<void>
				{
					using namespace NCryptography::NBoringSSL;

					CStrength Minimums[] =
						{
							CStrength::mc_Compatible, CStrength::mc_EquivalentSymmetric128bit
							, CStrength::mc_EquivalentSymmetric192bit, CStrength::mc_EquivalentSymmetric256bit
						}
					;
					uint16_t Groups[] = {SSL_GROUP_SECP384R1, SSL_GROUP_X25519, SSL_GROUP_SECP384R1, SSL_GROUP_SECP521R1};

					for (umint i = 0; i < fg_ArraySize(Minimums); ++i)
					{
						DMibTestPath("{}"_f << uint16(Minimums[i]));

						CSSLSettings Settings;
						Settings.m_Protocol = CSSLSettings::EProtocol_TLS_1_3;
						Settings.m_MinimumCryptoStrength = Minimums[i];

						auto Blocking = fg_BlockingActor();
						auto Hello = co_await
							(
								g_Dispatch(Blocking) / [Settings = fg_Move(Settings)]
								{
									return fs_ConfiguredClientHello(Settings);
								}
							)
						;

						fs_CheckInitialKeyShare(StrongServer, Hello, Groups[i]);
					}

					co_return {};
				};

				DMibTestCategory("ProtocolMismatch") -> TCFuture<void>
				{
					for (bool bClientTLS13 : {false, true})
					{
						DMibTestPath(bClientTLS13 ? "TLS13Client" : "TLS12Client");

						auto Server = CompatibleServer;
						Server.m_Protocol = bClientTLS13 ? CSSLSettings::EProtocol_TLS_1_2 : CSSLSettings::EProtocol_TLS_1_3;

						CSSLSettings Client;
						Client.m_Protocol = bClientTLS13 ? CSSLSettings::EProtocol_TLS_1_3 : CSSLSettings::EProtocol_TLS_1_2;
						Client.m_CACertificateData = Server.m_PublicCertificateData;

						co_await fs_ExpectHandshakeFailure(fg_Move(Client), fg_Move(Server));
					}

					co_return {};
				};

				DMibTestCategory("RSAChainStrength")
				{
					struct CRSAKeyCase
					{
						int m_Bits;
						CStrength m_Minimum;
						bool m_bAccepted;
					};

					CRSAKeyCase Keys[] =
					{
						{6789, CStrength::mc_EquivalentSymmetric128bit, false},
						{6790, CStrength::mc_EquivalentSymmetric128bit, true},
						{8192, CStrength::mc_EquivalentSymmetric192bit, false},
						{16384, CStrength::mc_EquivalentSymmetric256bit, false},
					};

					for (auto const &Key : Keys)
					{
						DMibTestPath("{}"_f << Key.m_Bits);

						auto Server = StrongServer;
						Server.m_CACertificateData = fs_RSAChainCertificate(StrongServer, Key.m_Bits);
						Server.m_MinimumCryptoStrength = Key.m_Minimum;

						if (Key.m_bAccepted)
							DMibExpectNoException(CSSLContext(CSSLContext::EType_Server, Server));
						else
							DMibExpectExceptionType(CSSLContext(CSSLContext::EType_Server, Server), CExceptionCryptography);
					}
				};

				DMibTestCategory("WeakLocalKey")
				{
					auto Server = CompatibleServer;
					Server.m_MinimumCryptoStrength = CStrength::mc_EquivalentSymmetric256bit;

					DMibExpectExceptionType(CSSLContext(CSSLContext::EType_Server, Server), CExceptionCryptography);
				};

				DMibTestCategory("UnsupportedKeyExchangeFlag")
				{
					auto Settings = CompatibleServer;
					Settings.m_VerificationFlags |= CSSLSettings::EVerificationFlag_DisallowEllipticCurveDHKeyExchange;

					DMibExpectExceptionType(CSSLContext(CSSLContext::EType_Server, Settings), CExceptionCryptography);
				};

				DMibTestCategory("RootSelfSignature") -> TCFuture<void>
				{
					auto Root = fs_Settings("Trusted root", true, true, EDigestType_SHA256);
					auto Credentials = fs_SignedSettings(Root, "Strong leaf", true, false);

					for (auto Protocol : {CSSLSettings::EProtocol_TLS_1_2, CSSLSettings::EProtocol_TLS_1_3})
					{
						DMibTestPath(Protocol == CSSLSettings::EProtocol_TLS_1_2 ? "TLS12" : "TLS13");

						auto Server = Credentials;
						Server.m_Protocol = Protocol;
						Server.m_MinimumCryptoStrength = CStrength::mc_EquivalentSymmetric256bit;

						CSSLSettings Client;
						Client.m_Protocol = Protocol;
						Client.m_MinimumCryptoStrength = Server.m_MinimumCryptoStrength;
						Client.m_CACertificateData = Root.m_PublicCertificateData;

						co_await fs_CheckConnection(fg_Move(Client), fg_Move(Server), Protocol == CSSLSettings::EProtocol_TLS_1_2 ? "TLSv1.2" : "TLSv1.3", 256, false);
					}

					CSSLSettings UntrustedClient;
					UntrustedClient.m_MinimumCryptoStrength = CStrength::mc_EquivalentSymmetric256bit;
					UntrustedClient.m_VerificationFlags = CSSLSettings::EVerificationFlag_IgnoreTrustFailures | CSSLSettings::EVerificationFlag_IgnoreVerificationFailures;

					co_await fs_ExpectHandshakeFailure(fg_Move(UntrustedClient), fs_Settings("Untrusted self-signed leaf", true, false, EDigestType_SHA256));

					co_return {};
				};

				DMibTestCategory("PeerClosesDuringHandshake") -> TCFuture<void>
				{
					CSSLSettings Client;
					Client.m_MinimumCryptoStrength = CStrength::mc_EquivalentSymmetric256bit;

					// A plain TCP listener without an accept callback closes before a TLS handshake can complete.
					co_await fs_ExpectConnectionFailure(fg_Move(Client), {});

					co_return {};
				};

				DMibTestCategory("PeerStrength") -> TCFuture<void>
				{
					auto Root = fs_Settings("Peer strength root", true, true);

					for (bool bWeakKey : {false, true})
					{
						DMibTestPath(bWeakKey ? "WeakKey" : "WeakSignatureHash");

						auto Server = fs_SignedSettings(Root, "Peer strength leaf", !bWeakKey, false, bWeakKey ? EDigestType_SHA512 : EDigestType_SHA256);

						CSSLSettings Client;
						Client.m_MinimumCryptoStrength = CStrength::mc_EquivalentSymmetric256bit;
						Client.m_CACertificateData = Root.m_PublicCertificateData;
						Client.m_VerificationFlags |= CSSLSettings::EVerificationFlag_IgnoreTrustFailures | CSSLSettings::EVerificationFlag_IgnoreVerificationFailures;

						co_await fs_ExpectHandshakeFailure(fg_Move(Client), fg_Move(Server));
					}

					co_return {};
				};

				DMibTestCategory("CertificateChain") -> TCFuture<void>
				{
					for (bool bWeakRoot : {false, true})
					{
						DMibTestPath(bWeakRoot ? "WeakRoot" : "WeakIntermediate");

						auto Root = fs_Settings("Root", !bWeakRoot, true);
						auto Intermediate = fs_SignedSettings(Root, "Intermediate", bWeakRoot, true);
						auto Server = fs_SignedSettings(Intermediate, "Server", true, false);

						CSSLSettings Client;
						Client.m_CACertificateData = Root.m_PublicCertificateData;
						Client.m_MinimumCryptoStrength = CStrength::mc_EquivalentSymmetric256bit;

						co_await fs_ExpectHandshakeFailure(fg_Move(Client), fg_Move(Server));
					}

					co_return {};
				};

				co_return {};
			};
		}
	};
}

DMibTestRegister(CTLSVersions_Tests, Malterlib::Network);
