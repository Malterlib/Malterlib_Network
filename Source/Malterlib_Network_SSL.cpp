// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Network_SSL.h"
#include "Malterlib_Network_SSLTransport.h"
#include "Malterlib_Network_Socket.h"

#include <Mib/Cryptography/BoringSSL>
#include <Mib/Encoding/Base64>

#include "Malterlib_Network_SSL_DHParams.hpp"

namespace NMib::NNetwork
{
	using namespace NCryptography::NBoringSSL;
	using namespace NCryptography;

	namespace
	{
		struct CSSLLowLevelDataIndex
		{
			CSSLLowLevelDataIndex()
			{
				m_ExDataIndex = SSL_get_ex_new_index(0, (void*)"CSSLConnection Index", nullptr, nullptr, nullptr);
			}
			int m_ExDataIndex = 0;
		};

		constinit NStorage::TCAggregate<CSSLLowLevelDataIndex> g_SSLLowLevelDataIndex = {DAggregateInit};

		// Decided once for the process: the compile time default, which a build carrying the io
		// debugging overrides lets the environment answer instead. Both shapes are correct, so this
		// is a measurement knob rather than a way out of anything. Without the overrides every
		// knob is its compile time answer as a constexpr constant, so the branches consulting it
		// fold away
#if DMibConfig_IoDebug_Enable
		bool fg_SendBatchingEnabled()
		{
			static bool s_bEnabled =
				(
					[]() -> bool
					{
						auto Setting = NSys::fg_Process_GetEnvironmentVariable_NonProtected(NStr::gc_Str<"MalterlibSSLSendBatching">.m_Str);
						if (Setting == "0")
							return false;
						if (Setting == "1")
							return true;

						return DMibConfig_SSLSendBatching != 0;
					}
					()
				)
			;

			return s_bEnabled;
		}

		// Same shape as the batching knob: a build carrying the io debugging overrides lets the
		// environment answer, so both paths can be measured against each other in one binary
		bool fg_ZeroCopyEnabled()
		{
			static bool s_bEnabled =
				(
					[]() -> bool
					{
						auto Setting = NSys::fg_Process_GetEnvironmentVariable_NonProtected(NStr::gc_Str<"MalterlibSSLZeroCopy">.m_Str);
						if (Setting == "0")
							return false;
						if (Setting == "1")
							return true;

						return DMibConfig_SSLZeroCopy != 0;
					}
					()
				)
			;

			return s_bEnabled;
		}

		// Each direction answers separately so one can be measured against the readiness path
		// while the other is held fixed. The direction specific name wins over the shared one,
		// which is there so a recipe that predates the split still sets both
		bool fg_CompletionIoDirectionEnabled(NStr::CStr const &_DirectionName, bool _bCompiledDefault)
		{
			auto Setting = NSys::fg_Process_GetEnvironmentVariable_NonProtected(_DirectionName);
			if (Setting.f_IsEmpty())
				Setting = NSys::fg_Process_GetEnvironmentVariable_NonProtected(NStr::gc_Str<"MalterlibSSLCompletionIo">.m_Str);

			if (Setting == "0")
				return false;
			if (Setting == "1")
				return true;

			return _bCompiledDefault;
		}

		bool fg_CompletionIoSendEnabled()
		{
			static bool s_bEnabled = fg_CompletionIoDirectionEnabled
				(
					NStr::gc_Str<"MalterlibSSLCompletionIoSend">.m_Str
					, DMibConfig_SSLCompletionIoSend != 0
				)
			;

			return s_bEnabled;
		}

		bool fg_CompletionIoReceiveEnabled()
		{
			static bool s_bEnabled = fg_CompletionIoDirectionEnabled
				(
					NStr::gc_Str<"MalterlibSSLCompletionIoReceive">.m_Str
					, DMibConfig_SSLCompletionIoReceive != 0
				)
			;

			return s_bEnabled;
		}
#else
		constexpr bool fg_SendBatchingEnabled()
		{
			return DMibConfig_SSLSendBatching != 0;
		}

		constexpr bool fg_ZeroCopyEnabled()
		{
			return DMibConfig_SSLZeroCopy != 0;
		}

		constexpr bool fg_CompletionIoSendEnabled()
		{
			return DMibConfig_SSLCompletionIoSend != 0;
		}

		constexpr bool fg_CompletionIoReceiveEnabled()
		{
			return DMibConfig_SSLCompletionIoReceive != 0;
		}
#endif

		SSL_CTX *fg_CreateSSLContext(SSL_METHOD const *_pMethod)
		{
			return SSL_CTX_new(_pMethod);
		}

		int fg_ExDataIndex()
		{
			return g_SSLLowLevelDataIndex->m_ExDataIndex;
		}


		int fg_SSLTransportBioRead(BIO *_pBio, char *_pData, int _nBytes)
		{
			BIO_clear_retry_flags(_pBio);

			auto *pTransport = (CSSLTransport *)BIO_get_data(_pBio);
			if (!pTransport || _nBytes <= 0)
				return 0;

			umint nRead = 0;
			switch (pTransport->f_Read(_pData, (umint)_nBytes, nRead))
			{
			case CSSLTransport::ETransferResult::mc_Data:
				return (int)nRead;
			case CSSLTransport::ETransferResult::mc_WouldBlock:
				BIO_set_retry_read(_pBio);
				return -1;
			case CSSLTransport::ETransferResult::mc_EndOfStream:
				return 0;
			case CSSLTransport::ETransferResult::mc_Failed:
				return -1;
			}

			DMibNeverGetHere;
			return -1;
		}

		int fg_SSLTransportBioWrite(BIO *_pBio, char const *_pData, int _nBytes)
		{
			BIO_clear_retry_flags(_pBio);

			auto *pTransport = (CSSLTransport *)BIO_get_data(_pBio);
			if (!pTransport || _nBytes <= 0)
				return 0;

			umint nWritten = 0;
			switch (pTransport->f_Write(_pData, (umint)_nBytes, nWritten))
			{
			case CSSLTransport::ETransferResult::mc_Data:
				return (int)nWritten;
			case CSSLTransport::ETransferResult::mc_WouldBlock:
				BIO_set_retry_write(_pBio);
				return -1;
			case CSSLTransport::ETransferResult::mc_EndOfStream:
			case CSSLTransport::ETransferResult::mc_Failed:
				return -1;
			}

			DMibNeverGetHere;
			return -1;
		}

		long fg_SSLTransportBioCtrl(BIO *_pBio, int _Command, long _Argument, void *_pParameter)
		{
			auto *pTransport = (CSSLTransport *)BIO_get_data(_pBio);
			if (!pTransport)
				return 0;

			switch (_Command)
			{
			case BIO_CTRL_FLUSH:
				{
					BIO_clear_retry_flags(_pBio);

					CSSLTransport::ETransferResult Result = pTransport->f_Flush();
					if (Result == CSSLTransport::ETransferResult::mc_WouldBlock)
						BIO_set_retry_write(_pBio);

					return Result == CSSLTransport::ETransferResult::mc_Data ? 1 : -1;
				}
			case BIO_CTRL_PENDING:
				return (long)pTransport->f_GetPendingRead();
			case BIO_CTRL_WPENDING:
				return (long)pTransport->f_GetPendingWrite();
			case BIO_CTRL_EOF:
				return pTransport->f_IsEndOfStream() ? 1 : 0;
			case BIO_CTRL_GET_CLOSE:
				return 0; // The transport is owned by the socket, never by the BIO
			case BIO_CTRL_SET_CLOSE:
				return 1;
			}

			return 0;
		}

		// One method for the process, allocated because the type is opaque outside the library.
		// Freeing it at aggregate teardown is safe because the BIOs pointing at it are reached
		// through actors, and the subsystems owning those are torn down before the aggregates
		struct CSSLTransportBioMethod
		{
			CSSLTransportBioMethod()
			{
				m_pMethod = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "Malterlib socket transport");
				if (!m_pMethod)
					DMibErrorCryptography("Could not create the TLS transport method");

				BIO_meth_set_read(m_pMethod, fg_SSLTransportBioRead);
				BIO_meth_set_write(m_pMethod, fg_SSLTransportBioWrite);
				BIO_meth_set_ctrl(m_pMethod, fg_SSLTransportBioCtrl);
			}

			~CSSLTransportBioMethod()
			{
				BIO_meth_free(m_pMethod);
			}

			BIO_METHOD *m_pMethod = nullptr;
		};

		constinit NStorage::TCAggregate<CSSLTransportBioMethod> g_SSLTransportBioMethod = {DAggregateInit};
	}

	// CSSLContext::CSession methods.
	class CSSLContext::CSession
	{
	public:
		CSession(SSL_CTX *_pContext)
			: mp_pSSL(nullptr)
			, mp_pContext(_pContext)
		{
			fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						mp_pSSL = SSL_new(_pContext);
					}
				)
			;
		}

		~CSession()
		{
			if (mp_pSSL)
			{
				fg_RunProtectRegisters
					(
						[&]() -> decltype(auto)
						{
							SSL_set_shutdown(mp_pSSL, SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);
							auto pSession = SSL_get_session(mp_pSSL);
							if (pSession)
								SSL_CTX_remove_session(mp_pContext, pSession);
							SSL_free(mp_pSSL);
						}
					)
				;
			}
		}

		SSL* f_GetSSL()
		{
			return mp_pSSL;
		}

	protected:

		SSL_CTX* mp_pContext;
		SSL* mp_pSSL;

	};

	// CSSLContext methods
	class CSSLContext::CInternal
	{
	public:

		CInternal(CSSLContext::EType _Type, CSSLSettings const &_Settings)
			: mp_pContext(nullptr)
			, mp_Type(_Type)
			, mp_State(CSSLContext::EState_None)
			, mp_Settings(_Settings)
		{
			fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						// Protect against destructor not being run in case of exception
						auto Cleanup = g_OnScopeExit / [&]
							{
								this->~CInternal();
							}
						;

						if (mp_Settings.m_Protocol == CSSLSettings::EProtocol_TLS)
						{
							if (f_IsClientContext())
								mp_pContext = fg_CreateSSLContext(TLSv1_2_client_method());
							else
								mp_pContext = fg_CreateSSLContext(TLSv1_2_server_method());
						}
						else
						{
							if (f_IsClientContext())
								mp_pContext = fg_CreateSSLContext(SSLv23_client_method());
							else
								mp_pContext = fg_CreateSSLContext(SSLv23_server_method());
						}

						SSL_CTX_set_default_passwd_cb_userdata(mp_pContext, nullptr);
						SSL_CTX_set_quiet_shutdown(mp_pContext, 1);
						if (!(mp_Settings.m_VerificationFlags & CSSLSettings::EVerificationFlag_AllowInsecureSSLVersions))
							SSL_CTX_set_options(mp_pContext, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1);
						SSL_CTX_set_options(mp_pContext, SSL_OP_CIPHER_SERVER_PREFERENCE);
						SSL_CTX_set_session_cache_mode(mp_pContext, SSL_SESS_CACHE_OFF);
						if (!(mp_Settings.m_VerificationFlags & CSSLSettings::EVerificationFlag_AllowInsecureCipherSuites))
							SSL_CTX_set_cipher_list(mp_pContext, "AES256+EECDH:AES256+EDH:!aNULL:!SHA:!SHA256:!SHA384:!DSS");

						fp_ProcessSettings();
						Cleanup.f_Clear();
					}
				)
			;
		}

		~CInternal()
		{
			fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						if (mp_pContext)
							SSL_CTX_free(mp_pContext);
					}
				)
			;
		}

		bool f_IsServerContext() const
		{
			return mp_Type == CSSLContext::EType_Server;
		}

		bool f_IsClientContext() const
		{
			return mp_Type == CSSLContext::EType_Client;
		}

		NStorage::TCUniquePointer<CSSLContext::CSession> fp_CreateSession()
		{
			return fg_Construct(mp_pContext);
		}

		CSSLContext::EState f_GetState() const
		{
			return mp_State;
		}

		void f_ReportInvalidContext(CSSLConnectionResult &_ConnectionResult) const
		{
			if (mp_State & CSSLContext::EState_InvalidCertificateAuthorityLocation)
				_ConnectionResult.f_LogMiscError(CSSLConnectionResult::EMiscError_InvalidCertificateAuthorityLocation);

			if (mp_State & CSSLContext::EState_InvalidPublicCertificate)
				_ConnectionResult.f_LogMiscError(CSSLConnectionResult::EMiscError_InvalidPublicCertificate);

			if (mp_State & CSSLContext::EState_InvalidPrivateKey)
				_ConnectionResult.f_LogMiscError(CSSLConnectionResult::EMiscError_InvalidPrivateKey);

			if (mp_State & CSSLContext::EState_CertificatePrivateKeyMisMatch)
				_ConnectionResult.f_LogMiscError(CSSLConnectionResult::EMiscError_CertificatePrivateKeyMisMatch);

			if (mp_State & CSSLContext::EState_InvalidCRLData)
				_ConnectionResult.f_LogMiscError(CSSLConnectionResult::EMiscError_InvalidCRLData);

			if (mp_State & CSSLContext::EState_InvalidCRLPath)
				_ConnectionResult.f_LogMiscError(CSSLConnectionResult::EMiscError_InvalidCRLPath);

			if (mp_State & CSSLContext::EState_InvalidCertificateAuthorityData)
				_ConnectionResult.f_LogMiscError(CSSLConnectionResult::EMiscError_InvalidCertificateAuthorityData);
		}

		CSSLSettings::EVerificationFlag f_GetVerificationFlags() const
		{
			return mp_Settings.m_VerificationFlags;
		}

		CSSLSettings const& f_GetSettings() const
		{
			return mp_Settings;
		}

		static bool fs_VerifyHostname(NStr::CStr const &_Hostname, X509 *_pCertificate)
		{
			NContainer::CByteVector CertData = fg_ConvertX509ToBinary(_pCertificate);

			NContainer::TCVector<NStr::CStr> lHostnames = CCertificate::fs_GetCertificateHostnames(CertData);
			for (auto const& CertHostName : lHostnames)
			{
				if (_Hostname.f_CmpNoCase(CertHostName) == 0)
					return true;

				// Alternatively, check for wildcard domain matching.
				if (CertHostName.f_StartsWith("*."))
				{
					aint iFirstPos = CertHostName.f_Find(".");
					aint iLastPos = CertHostName.f_FindReverse(".");
					if (iFirstPos == iLastPos)
						continue;

					aint iSubDomainPos = _Hostname.f_Find(".");
					if (iSubDomainPos == -1 ||
						iSubDomainPos == _Hostname.f_GetLen() - 1)
						continue;

					NStr::CStr NonWildCardPart = CertHostName.f_Extract(2);
					NStr::CStr HostnameAfterSubDomainLevel = _Hostname.f_Extract(iSubDomainPos + 1);

					if (NonWildCardPart.f_CmpNoCase(HostnameAfterSubDomainLevel) == 0)
						return true;
				}
			}

			return false;
		}

		static int fs_VerifyCallback(int _PreVerifyOK, X509_STORE_CTX *_pStoreContext)
		{
			int Error = X509_STORE_CTX_get_error(_pStoreContext);
			int Depth = X509_STORE_CTX_get_error_depth(_pStoreContext);

			SSL* pSSL = (SSL*)X509_STORE_CTX_get_ex_data(_pStoreContext, SSL_get_ex_data_X509_STORE_CTX_idx());
			if (!pSSL)
				return 0;

			CSSLConnection* pCSSL = (CSSLConnection*)SSL_get_ex_data(pSSL, fg_ExDataIndex());
			if (!pCSSL)
				return 0;

			// Check for renegotiation and return the original result as we do not support our verification methods
			// for renegotiations yet.
			if (pCSSL->f_Connected())
			{
				return _PreVerifyOK;
			}

			if (_PreVerifyOK == 0)
			{
				if
					(
						Error == X509_V_ERR_SUBJECT_ISSUER_MISMATCH
						|| Error == X509_V_ERR_AKID_SKID_MISMATCH
						|| Error == X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH
					)
				{
					// Don't log these. And I quote:
					// The presence of rejection messages does not itself imply that anything is wrong: during the normal verify process several rejections may take place.
					// We must handle these because of our use of X509_V_FLAG_CB_ISSUER_CHECK:
					// The X509_V_FLAG_CB_ISSUER_CHECK flag enables debugging of certificate issuer checks.
					// It is not needed unless you are logging certificate verification.
					// If this flag is set then additional status codes will be sent to the verification callback and it must be prepared to handle such cases without assuming they are hard errors.
					return 0;
				}
			}

			CSSLConnectionResult& Result = pCSSL->f_GetConnectionResult();

			// Update chain of certificates
			if (!Result.f_HasLoggedCertificateChain())
			{
				auto *pChain = X509_STORE_CTX_get0_chain(_pStoreContext);
				auto nCertsInChain = sk_X509_num(pChain);
				while (nCertsInChain)
				{
					X509* pCert = sk_X509_value(pChain, nCertsInChain - 1);
					NContainer::CByteVector CertData;
					try
					{
						CertData = fg_ConvertX509ToBinary(pCert);

						Result.f_LogCertificate(nCertsInChain - 1, CertData);
						--nCertsInChain;

						// Check the hostname on the peer certificate
						if (nCertsInChain == 0 && pCSSL->f_GetVerificationFlags() & CSSLSettings::EVerificationFlag_VerifyHostnameMatches)
						{
							if (!fs_VerifyHostname(pCSSL->f_GetHostname(), pCert))
							{
								Result.f_LogMiscError(CSSLConnectionResult::EMiscError_HostnameMisMatch);
							}
						}
					}
					catch (CExceptionCryptography const &_Exception)
					{
						Result.f_LogMiscError(CSSLConnectionResult::EMiscError_InternalError);
						Result.f_AddSSLError(_Exception.f_GetErrorStr());
					}
				}
			}

			if (_PreVerifyOK == 0)
				Result.f_LogError(Depth, Error);

			return 1;
		}

		static X509_CRL *fs_LoadCRL(NContainer::CByteVector const &_CRLData)
		{
			ERR_clear_error();
			BIO* pMemoryBio = BIO_new_mem_buf(const_cast<void*>(static_cast<void const*>(_CRLData.f_GetArray())), _CRLData.f_GetLen());
			if (!pMemoryBio)
				DMibErrorCryptography(fg_GetExceptionStr("Error creating BIO"));
			auto Cleanup = g_OnScopeExit / [&]
				{
					BIO_free(pMemoryBio);
				}
			;

			ERR_clear_error();
			X509_CRL *pCRL = PEM_read_bio_X509_CRL(pMemoryBio, nullptr, nullptr, nullptr);
			if (!pCRL)
				DMibErrorCryptography(fg_GetExceptionStr("Error reading x509 certificate revocation list from BIO"));

			return pCRL;
		}

	protected:

		void fp_ProcessSettings()
		{
			bool bVerifyIssuer = false;
			int VerifyFlags = SSL_VERIFY_PEER;

			if (fp_LoadCertificateAuthority())
			{
				SSL_CTX_set_verify_depth(mp_pContext, mp_Settings.m_VerificationDepth);

				if (f_IsServerContext())
				{
					if (!(mp_Settings.m_VerificationFlags & CSSLSettings::EVerificationFlag_AllowMissingPeerCertificate))
						VerifyFlags |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
				}
				else if (f_IsClientContext())
					bVerifyIssuer = true;
			}
			else if (f_IsClientContext() && mp_Settings.m_VerificationFlags & CSSLSettings::EVerificationFlag_UseOSStoreIfNoCASpecified)
			{
				fp_LoadTrustedStoreFromOS();
				bVerifyIssuer = true;
			}

			if (f_IsClientContext())
			{
				unsigned long ClientFlags = 0;
				if (bVerifyIssuer)
					ClientFlags |= X509_V_FLAG_CHECK_SS_SIGNATURE | X509_V_FLAG_CB_ISSUER_CHECK;
				X509_STORE_set_flags(SSL_CTX_get_cert_store(mp_pContext), ClientFlags);
			}

			SSL_CTX_set_verify(mp_pContext, VerifyFlags, fs_VerifyCallback);

			static const int s_SupportedCurves[] =
				{
					NID_secp521r1
					, NID_secp384r1
					, NID_X25519
					, NID_X9_62_prime256v1
				}
			;

			ERR_clear_error();
			if (!SSL_CTX_set1_curves(mp_pContext, s_SupportedCurves, fg_ArraySize(s_SupportedCurves)))
				DMibErrorCryptography(fg_GetExceptionStr("Failed to set supported curves on ssl context"));

			bool bVerifyCertAndKey = false;
			if (fp_LoadPublicCertificate())
				bVerifyCertAndKey = true;

			if (fp_LoadPrivateKey())
				bVerifyCertAndKey = true;

			if (bVerifyCertAndKey)
				fp_VerifyPublicCertAndPrivateKey();

			fp_LoadCRLs();
		}

		bool fp_LoadCertificateAuthority()
		{
			bool bUsingCertificateAuthority = false;

			if (!mp_Settings.m_CAStoreLocation.f_IsEmpty())
			{
				X509_STORE* pStore = SSL_CTX_get_cert_store(mp_pContext);

				if (!NFile::CFile::fs_FileExists(mp_Settings.m_CAStoreLocation, NFile::EFileAttrib_Directory))
					DMibErrorCryptography(fg_Format("Certificate store location '{}' does not exist", mp_Settings.m_CAStoreLocation));
				else
				{
					NContainer::TCVector<NStr::CStr> lCertificateFiles = NFile::CFile::fs_FindFiles(mp_Settings.m_CAStoreLocation + "/*", NFile::EFileAttrib_File, false);

					if (lCertificateFiles.f_IsEmpty())
						DMibErrorCryptography(fg_Format("No certificates found at location '{}'", mp_Settings.m_CAStoreLocation));

					for (auto Iter = lCertificateFiles.f_GetIterator(); Iter; ++Iter)
					{
						NContainer::CByteVector CertificateData = NFile::CFile::fs_ReadFile(*Iter);
						if (CertificateData.f_IsEmpty())
							continue;

						bUsingCertificateAuthority = true;

						X509 *pCertificate = fg_LoadCertificate(CertificateData);
						auto Cleanup0 = g_OnScopeExit / [&]
							{
								X509_free(pCertificate);
							}
						;

						ERR_clear_error();
						if (!X509_STORE_add_cert(pStore, pCertificate))
							DMibErrorCryptography(fg_GetExceptionStr(fg_Format("Failed to add certificate '{}' to store", *Iter)));
					}

					if (!bUsingCertificateAuthority)
						DMibErrorCryptography(fg_Format("No certificates found at location '{}'", mp_Settings.m_CAStoreLocation));
				}
			}

			if (!mp_Settings.m_CACertificateData.f_IsEmpty())
			{
				X509_STORE* pStore = SSL_CTX_get_cert_store(mp_pContext);
				X509 *pCertificate = fg_LoadCertificate(mp_Settings.m_CACertificateData);
				auto Cleanup0 = g_OnScopeExit / [&]
					{
						X509_free(pCertificate);
					}
				;

				ERR_clear_error();
				if (!X509_STORE_add_cert(pStore, pCertificate))
					DMibErrorCryptography(fg_GetExceptionStr("Failed to add certificate '{}' to store"));

				ERR_clear_error();
				if (!SSL_CTX_add1_chain_cert(mp_pContext, pCertificate))
					DMibErrorCryptography(fg_GetExceptionStr("Failed to add certificate '{}' to certificate chain"));

				bUsingCertificateAuthority = true;
			}

			return bUsingCertificateAuthority;
		}

		bool fp_LoadPublicCertificate()
		{
			if (mp_Settings.m_PublicCertificateData.f_IsEmpty())
				return false;

			X509 *pCertificate = fg_LoadCertificate(mp_Settings.m_PublicCertificateData);
			auto Cleanup0 = g_OnScopeExit / [&]
				{
					X509_free(pCertificate);
				}
			;

			ERR_clear_error();
			if (SSL_CTX_use_certificate(mp_pContext, pCertificate) <= 0)
				DMibErrorCryptography(fg_GetExceptionStr("Failed to add certificate '{}' to store"));

			return true;
		}

		void fp_LoadCRLs()
		{
			if (!mp_Settings.m_CRLData.f_IsEmpty())
			{
				ERR_clear_error();
				X509_STORE* pStore = SSL_CTX_get_cert_store(mp_pContext);
				if (!pStore)
					DMibErrorCryptography(fg_GetExceptionStr("Failed to get cert store"));

				X509_CRL* pCRL = fs_LoadCRL(mp_Settings.m_CRLData);

				auto Cleanup = g_OnScopeExit / [&]
					{
						X509_CRL_free(pCRL);
					}
				;

				ERR_clear_error();
				if (!X509_STORE_add_crl(pStore, pCRL))
					DMibErrorCryptography(fg_GetExceptionStr("Failed to add certificate revocation list to store"));

				ERR_clear_error();
				if (!X509_STORE_set_flags(pStore, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL))
					DMibErrorCryptography(fg_GetExceptionStr("Failed to set store flags"));
			}

			if (!mp_Settings.m_PathToCRLs.f_IsEmpty())
			{
				ERR_clear_error();
				X509_STORE* pStore = SSL_CTX_get_cert_store(mp_pContext);
				if (!pStore)
					DMibErrorCryptography(fg_GetExceptionStr("Failed to get cert store"));

				if (!NFile::CFile::fs_FileExists(mp_Settings.m_PathToCRLs, NFile::EFileAttrib_Directory))
					DMibErrorCryptography(fg_Format("CRL path '{}' does not exist", mp_Settings.m_PathToCRLs));

				NContainer::TCVector<NStr::CStr> lCRLFiles = NFile::CFile::fs_FindFiles(mp_Settings.m_PathToCRLs + "/*", NFile::EFileAttrib_File, false);

				bool bAdded = false;
				for (auto Iter = lCRLFiles.f_GetIterator(); Iter; ++Iter)
				{
					NContainer::CByteVector CRLData = NFile::CFile::fs_ReadFile(*Iter);
					if (CRLData.f_IsEmpty())
						continue;

					X509_CRL* pCRL = fs_LoadCRL(CRLData);
					auto Cleanup = g_OnScopeExit / [&]
						{
							X509_CRL_free(pCRL);
						}
					;

					ERR_clear_error();
					if (!X509_STORE_add_crl(pStore, pCRL))
						DMibErrorCryptography(fg_GetExceptionStr("Failed to add certificate revocation list to store"));
					bAdded = true;
				}

				if (bAdded)
					X509_STORE_set_flags(pStore, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
			}
		}

		void fp_DeduceSigningAlgorithms(int _CurveName)
		{
			static const uint16_t s_DefaultAlgos[] =
				{
					SSL_SIGN_ECDSA_SECP521R1_SHA512
					, SSL_SIGN_RSA_PSS_SHA512
					, SSL_SIGN_RSA_PKCS1_SHA512
					, SSL_SIGN_ECDSA_SECP384R1_SHA384
					, SSL_SIGN_RSA_PSS_SHA384
					, SSL_SIGN_RSA_PKCS1_SHA384
					, SSL_SIGN_ECDSA_SECP256R1_SHA256
					, SSL_SIGN_RSA_PSS_SHA256
					, SSL_SIGN_RSA_PKCS1_SHA256
				}
			;
			umint nAlgos = fg_ArraySize(s_DefaultAlgos);
			const uint16_t *pAlgos = s_DefaultAlgos;

			switch (_CurveName)
			{
			case NID_secp521r1: break;
			case NID_secp384r1:
				{
					static const uint16_t s_CustomAlgos[] =
						{
							SSL_SIGN_ECDSA_SECP384R1_SHA384
							, SSL_SIGN_RSA_PSS_SHA384
							, SSL_SIGN_RSA_PKCS1_SHA384
							, SSL_SIGN_ECDSA_SECP521R1_SHA512
							, SSL_SIGN_RSA_PSS_SHA512
							, SSL_SIGN_RSA_PKCS1_SHA512
							, SSL_SIGN_ECDSA_SECP256R1_SHA256
							, SSL_SIGN_RSA_PSS_SHA256
							, SSL_SIGN_RSA_PKCS1_SHA256
						}
					;
					nAlgos = fg_ArraySize(s_CustomAlgos);
					pAlgos = s_CustomAlgos;
				}
				break;
			case NID_X9_62_prime256v1:
			case NID_X25519:
				{
					static const uint16_t s_CustomAlgos[] =
						{
							SSL_SIGN_ECDSA_SECP256R1_SHA256
							, SSL_SIGN_RSA_PSS_SHA256
							, SSL_SIGN_RSA_PKCS1_SHA256
							, SSL_SIGN_ECDSA_SECP384R1_SHA384
							, SSL_SIGN_RSA_PSS_SHA384
							, SSL_SIGN_RSA_PKCS1_SHA384
							, SSL_SIGN_ECDSA_SECP521R1_SHA512
							, SSL_SIGN_RSA_PSS_SHA512
							, SSL_SIGN_RSA_PKCS1_SHA512
						}
					;
					nAlgos = fg_ArraySize(s_CustomAlgos);
					pAlgos = s_CustomAlgos;
				}
				break;
			}

			ERR_clear_error();
			if (!SSL_CTX_set_signing_algorithm_prefs(mp_pContext, pAlgos, nAlgos))
				DMibErrorCryptography(fg_GetExceptionStr("Failed to set preferred signing algorithms on ssl context"));
			if (!SSL_CTX_set_verify_algorithm_prefs(mp_pContext, pAlgos, nAlgos))
				DMibErrorCryptography(fg_GetExceptionStr("Failed to set preferred verify algorithms on ssl context"));
		}

		bool fp_LoadPrivateKey()
		{
			if (mp_Settings.m_PrivateKeyData.f_IsEmpty())
			{
				fp_DeduceSigningAlgorithms(0);
				return false;
			}

			EVP_PKEY* pKey = fg_LoadPrivateKey(mp_Settings.m_PrivateKeyData);
			auto Cleanup = g_OnScopeExit / [&]
				{
					EVP_PKEY_free(pKey);
				}
			;

			{
				int CurveName = 0;
				if (auto pRSA = EVP_PKEY_get1_RSA(pKey))
				{
					auto RSASize = RSA_size(pRSA) * 8;
					RSA_free(pRSA);

					DH *pDHParam;
					if (RSASize >= 8192)
						pDHParam = fg_Get_dh8192();
					else if (RSASize >= 4096)
						pDHParam = fg_Get_dh4096();
					else if (RSASize >= 2048)
						pDHParam = fg_Get_dh2048();
					else
						pDHParam = fg_Get_dh1024();

					if (!(mp_Settings.m_VerificationFlags & CSSLSettings::EVerificationFlag_DisallowEllipticCurveDHKeyExchange))
					{
						if (RSASize >= 12288)
							CurveName = NID_secp521r1;
						else if (RSASize >= 4096)
							CurveName = NID_secp384r1;
						else
							CurveName = NID_X25519;
					}

					if (SSL_CTX_set_tmp_dh(mp_pContext, pDHParam) != 1)
						DMibErrorCryptography(fg_GetExceptionStr("Failed to set tmp dh param in SSL context"));
					DH_free(pDHParam);
				}
				else if (auto pECKey = EVP_PKEY_get1_EC_KEY(pKey))
				{
					CurveName = EC_GROUP_get_curve_name(EC_KEY_get0_group(pECKey));
					if (!CurveName)
						CurveName = NID_secp521r1;
					EC_KEY_free(pECKey);
				}

				fp_DeduceSigningAlgorithms(CurveName);

				if (f_IsServerContext() && CurveName)
				{
					EC_KEY *pECDH = EC_KEY_new_by_curve_name(CurveName);
					if (pECDH)
					{
						auto Cleanup = g_OnScopeExit / [&]
							{
								EC_KEY_free(pECDH);
							}
						;
						SSL_CTX_set_options(mp_pContext, SSL_OP_SINGLE_ECDH_USE);
						if (SSL_CTX_set_tmp_ecdh(mp_pContext, pECDH) != 1)
							DMibErrorCryptography(fg_GetExceptionStr("Failed to set ecdh in SSL context"));
					}
				}
			}

			ERR_clear_error();
			if (SSL_CTX_use_PrivateKey(mp_pContext, pKey) <= 0)
				DMibErrorCryptography(fg_GetExceptionStr("Failed to use private key in SSL context"));

			return true;
		}

		void fp_VerifyPublicCertAndPrivateKey()
		{
			ERR_clear_error();
			if (!SSL_CTX_check_private_key(mp_pContext))
				DMibErrorCryptography(fg_GetExceptionStr("Certificate private and public key verfication failed"));
		}

		void fp_LoadTrustedStoreFromOS()
		{
			CCertificate::fs_GetSystemCertificates(SSL_CTX_get_cert_store(mp_pContext));
		};

		SSL_CTX* mp_pContext;

		CSSLContext::EType mp_Type;
		CSSLContext::EState mp_State;

		CSSLSettings mp_Settings;
	};

	CSSLContext::CSSLContext(CSSLContext::EType _Type, CSSLSettings const &_Settings)
		: mp_pInternal(nullptr)
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					mp_pInternal = fg_Construct(_Type, _Settings);
				}
			)
		;
	}

	CSSLContext::~CSSLContext()
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					mp_pInternal = nullptr;
				}
			)
		;
	}

	NStorage::TCUniquePointer<CSSLContext::CSession> CSSLContext::fp_CreateSession()
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->fp_CreateSession();
				}
			)
		;
	}

	bool CSSLContext::f_IsValid() const
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return bool(mp_pInternal->f_GetState() == CSSLContext::EState_None);
				}
			)
		;
	}

	void CSSLContext::f_ReportInvalidContext(CSSLConnectionResult &_ConnectionResult) const
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					mp_pInternal->f_ReportInvalidContext(_ConnectionResult);
				}
			)
		;
	}

	bool CSSLContext::f_IsClientContext() const
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_IsClientContext();
				}
			)
		;
	}

	bool CSSLContext::f_IsServerContext() const
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_IsServerContext();
				}
			)
		;
	}

	CSSLSettings::EVerificationFlag CSSLContext::f_GetVerificationFlags() const
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_GetVerificationFlags();
				}
			)
		;
	}

	CSSLSettings const &CSSLContext::f_GetSettings() const
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_GetSettings();
				}
			)
		;
	}

	bool CSSLContext::f_CanAskUserToTrustServers() const
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return (f_GetVerificationFlags() & CSSLSettings::EVerificationFlag_UserCanAcceptUntrusted);
				}
			)
		;
	}


	// CSSLConnection methods.
	class CSSLConnection::CInternal
	{
	public:

		CInternal
			(
				CSSLConnection *_pSSL
				, NStorage::TCSharedPointer<CSSLContext> const &_pContext
				, FAuthenticationResultCallback &&_AuthenticationResultCallback
				, FUserTrustDecisionCallback &&_UserTrustCallback
				, NStr::CStr const &_Hostname
			)
			: mp_pSSL(_pSSL)
			, mp_pSession(mp_pContext->fp_CreateSession())
			, mp_pContext(_pContext)
			, mp_Hostname(_Hostname)
			, mp_State(EState_None)
			, mp_bConnected(false)
			, mp_AuthenticationResultCallback(fg_Move(_AuthenticationResultCallback))
			, mp_UserTrustCallback(fg_Move(_UserTrustCallback))
			, mp_bHandshakeInProgress(false)
			, mp_bUsingTrustDecision(false)
		{
			fp_AttachTransport();

			if (_Hostname)
			{
				ERR_clear_error();
				if (!SSL_set_tlsext_host_name(mp_pSession->f_GetSSL(), _Hostname.f_GetStr()))
					DMibErrorCryptography(fg_GetExceptionStr("Failed to set hostname in SSL"));
			}
		}

		~CInternal()
		{
			// The library's hold on the transport goes first: the BIO reaches into this object, and
			// freeing the session is what releases it
			mp_pSession.f_Clear();
		}

		SSL* f_GetSSL()
		{
			return mp_pSession->f_GetSSL();
		}

		EState f_GetState() const
		{
			return mp_State;
		}

		void f_SetState(EState _State)
		{
			mp_State = _State;
		}

		// Whether the peer's close_notify has been opened (or a mutual shutdown completed):
		// only then is an end of the TCP stream an authenticated end of the TLS stream
		bool f_ReceivedShutdown() const
		{
			return mp_State == EState_ConnectionShutdown;
		}

		bool f_Connected() const
		{
			return mp_bConnected;
		}

		void f_SetExpectedConnectionResult(CSSLConnectionResult const &_ExpectedResult)
		{
			mp_bUsingTrustDecision = true;
			mp_ExpectedResultCallback = _ExpectedResult;
		}

		void f_GiveSocket(CSocket *_pSocket)
		{
			mp_Transport.f_SetSocket(_pSocket);
		}

		bool f_HasSocket() const
		{
			return mp_Transport.f_HasSocket();
		}

		// Holds the records a run of sends produces in the transport so they leave as one write.
		// Only a send may be batched: the read path and the shutdown path both come to rest waiting
		// on the peer, and the library flushes for neither of them
		void f_SetSendBatching(bool _bBatching)
		{
			mp_Transport.f_SetDeferFlush(_bBatching && fg_SendBatchingEnabled());
		}

		bool f_IsSendBufferFull() const
		{
			return mp_Transport.f_IsFull();
		}

		// Hands the transport what it has not managed to write yet, for the write readiness the
		// socket layer reports when a send has stalled. Records the library has produced are the
		// transport's to deliver, and outside a transfer call nothing else would offer them again
		CSocketOperationResult f_FlushPending()
		{
			CSocketOperationResult Result;

			if (!mp_Transport.f_GetPendingWrite())
				return Result;

			umint nSentBefore = mp_Transport.f_GetBytesSent();
			mp_Transport.f_Flush();
			Result.m_bSentNetwork = mp_Transport.f_GetBytesSent() != nSentBefore;

			fp_CheckTransportError(EState_WriteFailed);

			return Result;
		}

		NCryptography::CHashDigest_SHA256 f_GetSessionKeyDigest()
		{
			DMibRequire(mp_bConnected);

			auto pSession = SSL_get_session(f_GetSSL());
			DMibRequire(pSession);

			auto KeyLength = SSL_SESSION_get_master_key(pSession, nullptr, 0);
			NContainer::CByteVector KeyData;
			KeyData.f_SetLen(KeyLength);
			SSL_SESSION_get_master_key(pSession, KeyData.f_GetArray(), KeyLength);
			return NCryptography::CHash_SHA256::fs_DigestFromData(KeyData.f_GetArray(), KeyLength);
		}

		bool f_Connect()
		{
			return fp_Process(false);
		}

		bool f_Accept()
		{
			return fp_Process(true);
		}

		bool f_Shutdown()
		{
			ERR_clear_error();
			auto Ret = SSL_shutdown(f_GetSSL());

			// A close_notify is a warning alert, and the library flushes the write side only for
			// fatal ones, so the record it has just produced is sitting in the transport and no
			// other call would offer it. Its second stage waits for the peer's close_notify through
			// the read path, which never flushes either, so a peer that has not been given ours
			// would be waiting for a shutdown that was produced and never written
			mp_Transport.f_Flush();

			if (Ret == 1)
				return true;
			else if (Ret == -1)
			{
				int Error = SSL_get_error(f_GetSSL(), Ret);
				if (Error == SSL_ERROR_ZERO_RETURN)
					f_SetState(EState_ConnectionShutdown);
				else if (Error == SSL_ERROR_SYSCALL)
				{
					if (fp_CheckTransportError(EState_ShutdownFailed))
						DMibErrorNet((NStr::CStr::CFormat("Could not shut down SSL: {}") << mp_LastError).f_GetStr());

					DMibErrorNet("SSL_shutdown: End of file encountered");
				}
				else if (Error != SSL_ERROR_WANT_READ && Error != SSL_ERROR_WANT_WRITE)
				{
					mp_LastError = fg_GetErrors();
					f_SetState(EState_ShutdownFailed);
				}
			}
			return false;
		}

		bool f_BeginSend(void const *&o_pData, umint &o_nBytes, umint &o_iBuffer)
		{
			return mp_Transport.f_BeginSend(o_pData, o_nBytes, o_iBuffer);
		}

		bool f_IsSendPinned() const
		{
			return mp_Transport.f_IsSendPinned();
		}

		bool f_CanBeginSend() const
		{
			return mp_Transport.f_CanBeginSend();
		}

		smint f_NextBeginSend() const
		{
			return mp_Transport.f_NextBeginSend();
		}

		umint f_GetPendingSend() const
		{
			return mp_Transport.f_GetPendingWrite();
		}

		umint f_GetPendingSendUnpinned() const
		{
			return mp_Transport.f_GetPendingWriteUnpinned();
		}

		// Sealed records that cannot be sent leave the connection with a gap in its record
		// numbering, which the peer cannot recover from, so it is failed rather than continued
		void f_FailSend(NStr::CStr _Error)
		{
			mp_LastError = fg_Move(_Error);
			f_SetState(EState_WriteFailed);
		}

		void f_FailReceive(NStr::CStr _Error)
		{
			mp_LastError = fg_Move(_Error);
			f_SetState(EState_ReadFailed);
		}

		umint f_GetSendDepth() const
		{
			return mp_Transport.f_GetSendDepth();
		}

		void f_SetSendDepth(umint _nDepth)
		{
			mp_Transport.f_SetSendDepth(_nDepth);
		}

		void f_SetSendWindow(umint _nBytes)
		{
			mp_Transport.f_SetSendWindow(_nBytes);
		}

		NStorage::TCSharedPointer<NContainer::CByteVector> f_GetPinnedKeepAlive(umint _iBuffer) const
		{
			return mp_Transport.f_GetPinnedKeepAlive(_iBuffer);
		}

		void f_SetCompletionSend(bool _bCompletionSend)
		{
			mp_Transport.f_SetCompletionSend(_bCompletionSend);
		}

		void f_SetCompletionReceive(bool _bCompletionReceive)
		{
			mp_Transport.f_SetCompletionReceive(_bCompletionReceive);
		}

		void f_AbortSend(umint _iBuffer)
		{
			mp_Transport.f_AbortSend(_iBuffer);
		}

		bool f_SendCompleted(umint _iBuffer, umint _nBytes)
		{
			return mp_Transport.f_SendCompleted(_iBuffer, _nBytes);
		}

		umint f_GetFillBuffer() const
		{
			return mp_Transport.f_GetFillBuffer();
		}

		void f_ReleaseSendBuffer(umint _iBuffer)
		{
			mp_Transport.f_ReleaseSendBuffer(_iBuffer);
		}

		void f_AppendCipherSegment(void const *_pData, umint _nBytes, NStorage::TCSharedPointer<CVirtualDestroyBase const> &&_pOwner)
		{
			mp_Transport.f_AppendCipherSegment(_pData, _nBytes, fg_Move(_pOwner));
		}

		void f_ClearCipherQueue()
		{
			mp_Transport.f_ClearCipherQueue();
		}

		void f_CompactCipherIfStalled()
		{
			mp_Transport.f_CompactCipherIfStalled();
		}

		umint f_GetInboundBufferSize() const
		{
			return fg_Max(mp_nTransferSizeHint, CSSLTransport::mc_nInboundBufferSize);
		}

		void f_SetTransferSizeHint(umint _nBytes)
		{
			mp_nTransferSizeHint = _nBytes;
			mp_Transport.f_SetOutboundCap(_nBytes);
			mp_Transport.f_SetInboundSize(_nBytes);
		}

		// Seals the caller's spans straight into the transport's outbound buffer: the plaintext is
		// encrypted once from where it lies, and the ciphertext is never copied again on its way to
		// the socket. Records are filled to the maximum and several of them share one buffer, so a
		// gather leaves as one write.
		//
		// Returns false when the library will not take this path, which is every state that is not
		// the post handshake steady state. The caller falls back rather than failing, because a
		// refusal is not an error on the connection
		bool f_TrySealVectored(NSys::CIoSpan const *_pSpans, umint _nSpans, CSocketOperationResult &o_Result)
		{
			DMibRequire(mp_bConnected);
			DMibRequire(!mp_bHandshakeInProgress);
			DMibRequire(mp_State == EState_None);

			if (!fg_ZeroCopyEnabled())
				return false;

			// The spans as fragments. Zero length ones are dropped so they cannot spend a record's
			// fragment budget
			CRYPTO_IVEC Fragments[NSys::gc_IoLoopMaxSubmitSpans];
			umint nFragments = 0;
			umint nPlaintext = 0;

			for (umint iSpan = 0; iSpan < _nSpans && nFragments < fg_ArraySize(Fragments); ++iSpan)
			{
				if (!_pSpans[iSpan].m_nBytes)
					continue;

				Fragments[nFragments].in = (uint8 const *)_pSpans[iSpan].m_pData;
				Fragments[nFragments].len = _pSpans[iSpan].m_nBytes;
				++nFragments;
				nPlaintext += _pSpans[iSpan].m_nBytes;
			}

			if (!nFragments)
				return true;

			ERR_clear_error();
			auto pSSL = f_GetSSL();

			// Room for the plaintext and one record's framing for each record it will take, plus a
			// record's worth of slack for post handshake output that goes out ahead of it
			umint nRecords = nPlaintext / SSL3_RT_MAX_PLAIN_LENGTH + 1;
			umint nWanted = nPlaintext + (nRecords + 1) * SSL_max_seal_overhead(pSSL) + SSL3_RT_MAX_PLAIN_LENGTH;

			umint nRoom = 0;
			uint8 *pOut = mp_Transport.f_BeginSeal(nWanted, nRoom);

			size_t nWritten = 0;
			size_t nConsumed = 0;
			auto Ret = SSL_seal_app_datav(pSSL, pOut, &nWritten, nRoom, Fragments, nFragments, &nConsumed);

			// A refusal leaves the connection as it was, so the caller takes the path that reports
			// its own errors. A failure does not: post handshake output may already have been
			// taken from the library and records already sealed, and neither can be produced a
			// second time, so what was produced is kept and the connection is failed over it
			if (Ret == ssl_seal_v_refused)
			{
				ERR_clear_error();
				return false;
			}

			mp_Transport.f_CommitSeal(nWritten);
			o_Result.m_nBytes += nConsumed;

			if (Ret == ssl_seal_v_error)
			{
				mp_LastError = fg_GetErrors();
				f_SetState(EState_WriteFailed);
			}

			return true;
		}

		CSocketOperationResult f_Send(const void *_pData, umint _nLen)
		{
			DMibRequire(_nLen > 0);
			DMibRequire(mp_bConnected);
			DMibRequire(!mp_bHandshakeInProgress);
			DMibRequire(mp_State == EState_None);

			CSocketOperationResult Result;
			ERR_clear_error();
			auto pSSL = f_GetSSL();
			umint nReceivedBefore = mp_Transport.f_GetBytesReceived();
			umint nSentBefore = mp_Transport.f_GetBytesSent();
			int Ret = SSL_write(pSSL, _pData, (int)_nLen);
			Result.m_bReceivedNetwork = mp_Transport.f_GetBytesReceived() != nReceivedBefore;
			Result.m_bSentNetwork = mp_Transport.f_GetBytesSent() != nSentBefore;
			if (Ret <= 0)
			{
				// Write did not succeed.
				int Error = SSL_get_error(pSSL, Ret);
				DMibLog(DebugVerbose3, " **** SSL error {}", Error);
				if (Error == SSL_ERROR_ZERO_RETURN)
				{
					f_SetState(EState_ConnectionShutdown);
				}
				else if (Error == SSL_ERROR_SYSCALL)
				{
					if (fp_CheckTransportError(EState_WriteFailed))
						DMibErrorNet((NStr::CStr::CFormat("Could not write to socket (SSL): {}") << mp_LastError).f_GetStr());

					DMibErrorNet("send (write to SSL socket): End of file encountered");
				}
				else if (Error != SSL_ERROR_WANT_READ && Error != SSL_ERROR_WANT_WRITE)
				{
					mp_LastError = fg_GetErrors();
					f_SetState(EState_WriteFailed);
				}
			}
			else
			{
				DMibLog(DebugVerbose3, " **** SSL wrote {}", Ret);
				// Write succeeded, return the number of bytes written.
				Result.m_nBytes = (umint)Ret;
			}

			return Result;
		}

		// Opens records straight into the caller's buffer: the ciphertext lands in memory this
		// connection owns and the plaintext lands where it is wanted, with nothing between them.
		//
		// Returns false when the library will not take this path, leaving the caller to fall back
		bool f_TryOpenInto(void *_pData, umint _nLen, CSocketOperationResult &o_Result)
		{
			DMibRequire(mp_bConnected);
			DMibRequire(!mp_bHandshakeInProgress);
			DMibRequire(mp_State == EState_None);

			if (!fg_ZeroCopyEnabled())
				return false;

			ERR_clear_error();
			auto pSSL = f_GetSSL();

			// Anything a previous call could not fit goes out first, in order
			if (mp_Transport.f_GetHeld())
			{
				o_Result.m_nBytes += mp_Transport.f_TakeHeld(_pData, _nLen);
				return true;
			}

			CRYPTO_IOVEC Destination{(uint8 *)_pData, nullptr, _nLen};

			for (;;)
			{
				CRYPTO_IVEC Fragments[CSSLTransport::mc_nMaxCipherFragments];
				umint nFragments = mp_Transport.f_GetCipherFragments(Fragments);

				if (nFragments)
				{
					size_t nProduced = 0;
					size_t nConsumed = 0;
					auto Ret = SSL_open_app_datav(pSSL, &Destination, 1, &nProduced, &nConsumed, Fragments, nFragments);

					mp_Transport.f_ConsumeCipher(nConsumed);

					if (Ret == ssl_open_v_refused)
					{
						// The state does not allow this path, and nothing was read, so the caller
						// falls back to the one that reports its own errors
						ERR_clear_error();
						return false;
					}

					if (Ret == ssl_open_v_error)
					{
						// Records opened before the failure have already moved the read sequence
						// and are counted above, so there is no going back to another path
						if (fp_CheckTransportError(EState_ReadFailed))
							DMibErrorNet((NStr::CStr::CFormat("Could not read from socket (SSL): {}") << mp_LastError).f_GetStr());

						mp_LastError = fg_GetErrors();
						f_SetState(EState_ReadFailed);

						return true;
					}

					if (nProduced)
					{
						o_Result.m_nBytes += nProduced;
						o_Result.m_bReceivedNetwork = true;

						return true;
					}

					if (Ret == ssl_open_v_close_notify)
					{
						f_SetState(EState_ConnectionShutdown);
						return true;
					}

					// Records went by without producing application data, so there is room to try
					// again from what is already held before asking the transport for more
					if (nConsumed)
						continue;

					// A complete record that the destination has no room for. Opening it into the
					// holdover keeps the connection moving: without this a destination sized to
					// exactly what it wants back would never fit the next record and would stop
					if (mp_Transport.f_GetCipherPending() > SSL3_RT_HEADER_LENGTH)
					{
						umint nRoom = 0;
						uint8 *pHold = mp_Transport.f_BeginHold(nRoom);

						CRYPTO_IOVEC Held{pHold, nullptr, nRoom};
						size_t nHeld = 0;
						size_t nHeldConsumed = 0;
						auto HeldRet = SSL_open_app_datav(pSSL, &Held, 1, &nHeld, &nHeldConsumed, Fragments, nFragments);

						mp_Transport.f_ConsumeCipher(nHeldConsumed);

						if (HeldRet != ssl_open_v_error && nHeld)
						{
							mp_Transport.f_CommitHold(nHeld);
							o_Result.m_nBytes += mp_Transport.f_TakeHeld(_pData, _nLen);
							o_Result.m_bReceivedNetwork = true;

							return true;
						}

						if (HeldRet == ssl_open_v_close_notify)
						{
							f_SetState(EState_ConnectionShutdown);
							return true;
						}

						if (nHeldConsumed)
							continue;
					}
				}

				// Nothing complete yet. One read, then the records it completed are opened. On a
				// completion-receive connection the fill refuses by itself — the standing kernel
				// receive is the only reader — and this falls out with whatever was produced
				auto Fill = mp_Transport.f_FillCipher();

				if (Fill == CSSLTransport::ETransferResult::mc_Data)
				{
					o_Result.m_bReceivedNetwork = true;
					continue;
				}

				if (Fill == CSSLTransport::ETransferResult::mc_EndOfStream)
				{
					f_SetState(EState_ConnectionShutdown);
					return true;
				}

				if (Fill == CSSLTransport::ETransferResult::mc_Failed)
				{
					if (fp_CheckTransportError(EState_ReadFailed))
						DMibErrorNet((NStr::CStr::CFormat("Could not read from socket (SSL): {}") << mp_LastError).f_GetStr());

					return true;
				}

				// Would block, which the transport has already asked to hear about again
				return true;
			}
		}

		CSocketOperationResult f_Receive(void *_pData, umint _nLen)
		{
			DMibRequire(_nLen > 0);
			DMibRequire(mp_bConnected);
			DMibRequire(!mp_bHandshakeInProgress);
			DMibRequire(mp_State == EState_None);

			CSocketOperationResult Result;
			ERR_clear_error();
			auto pSSL = f_GetSSL();
			umint nReceivedBefore = mp_Transport.f_GetBytesReceived();
			umint nSentBefore = mp_Transport.f_GetBytesSent();

			// The library's read path never flushes the write side, so this is where produced output
			// has to be offered: what follows comes to rest waiting on the peer, and a peer waiting
			// on records that are still here waits forever. It sits inside the counter snapshot
			// because bytes leaving here are progress, and a caller draining this connection has to
			// see that rather than read the drain as idle and stop
			mp_Transport.f_Flush();

			int Ret = SSL_read(pSSL, _pData, _nLen);
			Result.m_bReceivedNetwork = mp_Transport.f_GetBytesReceived() != nReceivedBefore;
			Result.m_bSentNetwork = mp_Transport.f_GetBytesSent() != nSentBefore;

			if (Ret <= 0)
			{
				// Read did not succeed.
				int Error = SSL_get_error(pSSL, Ret);
				if (Error == SSL_ERROR_ZERO_RETURN)
				{
					f_SetState(EState_ConnectionShutdown);
				}
				else if (Error == SSL_ERROR_SYSCALL)
				{
					if (fp_CheckTransportError(EState_ReadFailed))
						DMibErrorNet((NStr::CStr::CFormat("Could not read from socket (SSL): {}") << mp_LastError).f_GetStr());

					DMibErrorNet("recv (read from SSL socket): End of file encountered");
				}
				else if (Error != SSL_ERROR_WANT_READ && Error != SSL_ERROR_WANT_WRITE)
				{
					mp_LastError = fg_GetErrors();
					DMibLog(DebugVerbose3, " **** Read failed: {} {}", Error, mp_LastError);
					f_SetState(EState_ReadFailed);
				}
			}
			else
			{
				// Read succeeded, return the number of bytes read.
				Result.m_nBytes = (umint)Ret;
			}

			return Result;
		}

		bool f_GetHandshakeInProgress() const
		{
			return mp_bHandshakeInProgress;
		}

		void f_SetHostname(NStr::CStr const &_Hostname)
		{
			mp_Hostname = _Hostname;
		}

		NStr::CStr f_GetHostname() const
		{
			return mp_Hostname;
		}

		NStr::CStr f_GetLastError() const
		{
			return mp_LastError;
		}

		CSSLSettings::EVerificationFlag f_GetVerificationFlags() const
		{
			return mp_pContext->f_GetVerificationFlags();
		}

	protected:

		CSSLConnection* mp_pSSL;
		NStorage::TCSharedPointer<CSSLContext> mp_pContext;

		NStr::CStr mp_Hostname;
		NStr::CStr mp_LastError;
		EState mp_State;
		FAuthenticationResultCallback mp_AuthenticationResultCallback;
		FUserTrustDecisionCallback mp_UserTrustCallback;

		CSSLConnectionResult mp_ExpectedResultCallback;
		NStorage::TCUniquePointer<CSSLContext::CSession> mp_pSession;
		CSSLTransport mp_Transport;
		umint mp_nTransferSizeHint = 0;

		bool mp_bConnected;
		bool mp_bHandshakeInProgress;
		bool mp_bUsingTrustDecision;

		void fp_AttachTransport()
		{
			BIO *pBio = BIO_new(g_SSLTransportBioMethod->m_pMethod);
			if (!pBio)
				DMibErrorCryptography(fg_GetExceptionStr("Failed to create the TLS transport"));

			BIO_set_data(pBio, &mp_Transport);
			BIO_set_init(pBio, 1);

			// Both directions are the same transport, and each side takes a reference of its own
			BIO_up_ref(pBio);
			SSL_set0_rbio(f_GetSSL(), pBio);
			SSL_set0_wbio(f_GetSSL(), pBio);

			// A batch that stalls is retried against a freshly gathered buffer, so the retry may
			// carry the same bytes at a different address. Partial writes stay off: a write that
			// reports less than it was given reads as a stalled transport to the caller, which then
			// waits for the write readiness that a transport which never blocked will never report
			SSL_set_mode(f_GetSSL(), SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
		}

		// A transport failure cannot be thrown from inside the library's frames, so it is carried
		// out through the return values and reported here, once the call it interrupted has returned
		bool fp_CheckTransportError(EState _State)
		{
			if (!mp_Transport.f_GetTransportError())
				return false;

			mp_LastError = mp_Transport.f_GetTransportError();
			f_SetState(_State);

			return true;
		}

		bool fp_Process(bool _bAccept)
		{
			mp_bHandshakeInProgress = true;

			EAuthenticationResult ResultForCallback = EAuthenticationResult_SocketNotReady;

			if (!mp_pContext->f_IsValid())
			{
				ResultForCallback = EAuthenticationResult_Failure;
				mp_State = EState_InvalidContext;
				mp_pContext->f_ReportInvalidContext(mp_pSSL->f_GetConnectionResult());
			}
			else
			{
				SSL_set_ex_data(f_GetSSL(), fg_ExDataIndex(), mp_pSSL);

				ERR_clear_error();
				int Ret = _bAccept ? SSL_accept(f_GetSSL()) : SSL_connect(f_GetSSL());

				fp_ProcessConnection(Ret, !_bAccept, ResultForCallback);
			}

			if (mp_AuthenticationResultCallback)
				mp_AuthenticationResultCallback(ResultForCallback, mp_pSSL->f_GetConnectionResult());
			mp_bHandshakeInProgress = ResultForCallback == EAuthenticationResult_SocketNotReady;

#if 0
			if (ResultForCallback == EAuthenticationResult_Success)
			{
				auto pChipher = SSL_get_current_cipher(f_GetSSL());
				auto pVerson = SSL_get_version(f_GetSSL());
				DMibConOut("Negotiated: {}   {}\n", pVerson, SSL_CIPHER_get_name(pChipher));
			}
#endif
			return ResultForCallback == EAuthenticationResult_Success;
		}

		void fp_ProcessConnection(int _Ret, bool _bConnect, EAuthenticationResult &_ResultForCallback)
		{
			// OpenSSL has established a connection but we will fail it here if the CSSLConnectionResult does
			// not satisfy our demands
			if (_Ret == 1)
			{
				CSSLConnectionResult &Result = mp_pSSL->f_GetConnectionResult();
				_ResultForCallback = EAuthenticationResult_Failure;

				bool bCallTrustCallback = false;
				bool bCanManageTrust = mp_pContext->f_GetSettings().f_UserCanIgnoreTrustFailures();
				bool bCanManageVerification = mp_pContext->f_GetSettings().f_UserCanIgnoreVerificationFailures();

				bool bTrustErrors = Result.f_ContainsTrustErrors();
				bool bVerificationErrors = Result.f_ContainsVerificationErrors();

				if (bVerificationErrors && (f_GetVerificationFlags() & CSSLSettings::EVerificationFlag_IgnoreVerificationFailures))
					bVerificationErrors = false;
				if (bTrustErrors && (f_GetVerificationFlags() & CSSLSettings::EVerificationFlag_IgnoreTrustFailures))
					bTrustErrors = false;

				// We can only accept one specific peer certificate
				if (f_GetVerificationFlags() & CSSLSettings::EVerificationFlag_UseSpecificPeerCertificate)
				{
					if (!Result.f_ContainsVerificationErrors())
					{
						if (Result.f_PeerCertificatesMatchesSpecificCertificate(mp_pContext->f_GetSettings().m_CACertificateData))
							_ResultForCallback = EAuthenticationResult_Success;
						else
							Result.f_LogMiscError(CSSLConnectionResult::EMiscError_MismatchingSpecificCertificate);
					}
				}
				// This was a connection based on user trust/verification decision, ensure connection results match up.
				else if (mp_bUsingTrustDecision)
				{
					if (mp_ExpectedResultCallback == mp_pSSL->f_GetConnectionResult())
						_ResultForCallback = EAuthenticationResult_Success;
				}
				// The peer certificate matches a remembered certificate and does not contain any verification errors.
				else if (!bVerificationErrors && bTrustErrors &&
					Result.f_PeerCertificateMatchesRememberedCertificates(mp_pContext->f_GetSettings().m_LocalCertificateStore))
				{
					_ResultForCallback = EAuthenticationResult_Success;
				}
				// No errors were reported.
				else if (!bTrustErrors && !bVerificationErrors)
				{
					_ResultForCallback = EAuthenticationResult_Success;
				}
				// User can manage certificates but cannot ignore verification failures
				else if (bCanManageTrust && !bCanManageVerification)
				{
					if (bTrustErrors && !bVerificationErrors)
						bCallTrustCallback = true;
				}
				// User cannot manage both
				else if (bCanManageTrust && bCanManageVerification)
				{
					if (bTrustErrors || bVerificationErrors)
						bCallTrustCallback = true;
				}
				// User can only manage verification failures.
				else if (!bCanManageTrust && bCanManageVerification)
				{
					if (!bTrustErrors && bVerificationErrors)
						bCallTrustCallback = true;
				}

				if (_ResultForCallback == EAuthenticationResult_Success)
				{
					mp_bConnected = true;
				}
				else
				{
					f_SetState(EState_ConnectionFailed);
					if (bCallTrustCallback)
					{
						f_SetState(EState_RequiresUserDecisionOnTrust);
						if (mp_UserTrustCallback)
							mp_UserTrustCallback(mp_pSSL->f_GetConnectionResult());
					}
				}
			}
			else
			{
				NStr::CStr SystemErrors;
				bool bConnectionRefused = false;
				if (fp_GenerateSystemErrors(_Ret, _ResultForCallback, SystemErrors, bConnectionRefused))
				{
					CSSLConnectionResult& Result = mp_pSSL->f_GetConnectionResult();
					Result.f_AddSSLError(SystemErrors);
					if (bConnectionRefused)
						Result.f_SetConnectionRefused();
					f_SetState(EState_ConnectionFailed);
				}
			}
		}

		static NStr::CStr fsp_GetErrorString(uint32_t _Error)
		{
			const uint32_t Lib = ERR_GET_LIB(_Error);
			const uint32_t Reason = ERR_GET_REASON(_Error);

			if (Lib == ERR_LIB_SYS)
			{
				if (Reason < 127)
					return NStr::CStr::CFormat("{cc}") << NMib::NPlatform::fg_ErrnoString<NStr::CStr>(Reason);
			}

			return NStr::CStr::CFormat("{cc}") << ERR_reason_error_string(_Error);
		}

		bool fp_GenerateSystemErrors(int _Ret, EAuthenticationResult &_Result, NStr::CStr &_SystemErrors, bool &_bConnectionRefused)
		{
			uint32_t SysError;
			NStr::CStr AllErrors;

			if ((SysError=ERR_peek_error()) != 0)
			{
				const char *pFile;
				int Line;
				while( (SysError = ERR_get_error_line(&pFile, &Line)))
					NStr::fg_AddStrSep(AllErrors, fsp_GetErrorString(SysError), "\n");

				_Result = EAuthenticationResult_Failure;
				_SystemErrors = AllErrors;
				_bConnectionRefused = true;
				return true;
			}
			else
			{
				int Error = SSL_get_error(f_GetSSL(), _Ret);
				if (Error == SSL_ERROR_SYSCALL)
				{
					_Result = EAuthenticationResult_Failure;
					// The transport reports its own failure; a handshake that ends without one ended
					// because the peer stopped talking
					_SystemErrors = mp_Transport.f_GetTransportError();
					if (!_SystemErrors)
						_SystemErrors = "End of file encountered";

					return true;
				}
				else if (Error != SSL_ERROR_WANT_WRITE && Error != SSL_ERROR_WANT_READ)
				{
					_Result = EAuthenticationResult_Failure;
					_bConnectionRefused = true;
					_SystemErrors = fsp_GetErrorString(SysError);
					return true;
				}
			}

			return false;
		}

	};

	CSSLConnection::CSendBatch::CSendBatch(CSSLConnection &_Connection)
		: mp_Connection(_Connection)
	{
		mp_Connection.f_SetSendBatching(true);
	}

	CSSLConnection::CSendBatch::~CSendBatch()
	{
		mp_Connection.f_SetSendBatching(false);
	}

	CSSLConnection::CSSLConnection
		(
			NStorage::TCSharedPointer<CSSLContext> const &_pContext
			, FAuthenticationResultCallback &&_AuthenticationResultCallback
			, FUserTrustDecisionCallback &&_UserTrustDecisionCallback
			, NStr::CStr const &_Hostname
		)
		: mp_pInternal(nullptr)
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					mp_pInternal = fg_Construct(this, _pContext, fg_Move(_AuthenticationResultCallback), fg_Move(_UserTrustDecisionCallback), _Hostname);
				}
			)
		;
	}

	CSSLConnection::~CSSLConnection()
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					mp_pInternal.f_Clear();
				}
			)
		;
	}

	bool CSSLConnection::f_BrokenState() const
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					if (mp_pInternal->f_GetState() != EState_None)
					{
						DMibLog(DebugVerbose3, " **** SSL broken: {}", mp_pInternal->f_GetState());
						return true;
					}
					return false;
				}
			)
		;
	}

	bool CSSLConnection::f_ReceivedShutdown() const
	{
		return mp_pInternal->f_ReceivedShutdown();
	}

	NStr::CStr CSSLConnection::f_GetLastError() const
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_GetLastError();
				}
			)
		;
	}

	void CSSLConnection::f_SetExpectedConnectionResult(CSSLConnectionResult const &_ExpectedResult)
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					mp_pInternal->f_SetExpectedConnectionResult(_ExpectedResult);
				}
			)
		;
	}

	bool CSSLConnection::f_Connected() const
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_Connected();
				}
			)
		;
	}

	bool CSSLConnection::f_HandshakeInProgress() const
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_GetHandshakeInProgress();
				}
			)
		;
	}

	void CSSLConnection::f_GiveSocket(CSocket *_pSocket)
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					mp_pInternal->f_GiveSocket(_pSocket);
				}
			)
		;
	}

	void CSSLConnection::f_SetSendBatching(bool _bBatching)
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					mp_pInternal->f_SetSendBatching(_bBatching);
				}
			)
		;
	}

	void CSSLConnection::f_SetTransferSizeHint(umint _nBytes)
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					mp_pInternal->f_SetTransferSizeHint(_nBytes);
				}
			)
		;
	}

	bool CSSLConnection::f_TrySealVectored(NSys::CIoSpan const *_pSpans, umint _nSpans, CSocketOperationResult &o_Result)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_TrySealVectored(_pSpans, _nSpans, o_Result);
				}
			)
		;
	}

	bool CSSLConnection::f_TryOpenInto(void *_pData, umint _nLen, CSocketOperationResult &o_Result)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_TryOpenInto(_pData, _nLen, o_Result);
				}
			)
		;
	}

	bool CSSLConnection::f_SupportsZeroCopy() const
	{
		return fg_ZeroCopyEnabled();
	}

	umint CSSLConnection::f_GetSendDepth() const
	{
		return mp_pInternal->f_GetSendDepth();
	}

	void CSSLConnection::f_SetSendDepth(umint _nDepth)
	{
		mp_pInternal->f_SetSendDepth(_nDepth);
	}

	void CSSLConnection::f_SetSendWindow(umint _nBytes)
	{
		mp_pInternal->f_SetSendWindow(_nBytes);
	}

	bool CSSLConnection::f_SupportsCompletionIoSend() const
	{
		return fg_ZeroCopyEnabled() && fg_CompletionIoSendEnabled();
	}

	bool CSSLConnection::f_SupportsCompletionIoReceive() const
	{
		return fg_ZeroCopyEnabled() && fg_CompletionIoReceiveEnabled();
	}

	bool CSSLConnection::f_BeginSend(void const *&o_pData, umint &o_nBytes, umint &o_iBuffer)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_BeginSend(o_pData, o_nBytes, o_iBuffer);
				}
			)
		;
	}

	bool CSSLConnection::f_CanBeginSend() const
	{
		return mp_pInternal->f_CanBeginSend();
	}

	smint CSSLConnection::f_NextBeginSend() const
	{
		return mp_pInternal->f_NextBeginSend();
	}

	bool CSSLConnection::f_IsSendPinned() const
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_IsSendPinned();
				}
			)
		;
	}

	umint CSSLConnection::f_GetPendingSendUnpinned() const
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_GetPendingSendUnpinned();
				}
			)
		;
	}

	umint CSSLConnection::f_GetPendingSend() const
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_GetPendingSend();
				}
			)
		;
	}

	void CSSLConnection::f_AbortSend(umint _iBuffer)
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					mp_pInternal->f_AbortSend(_iBuffer);
				}
			)
		;
	}

	void CSSLConnection::f_ReleaseSendBuffer(umint _iBuffer)
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					mp_pInternal->f_ReleaseSendBuffer(_iBuffer);
				}
			)
		;
	}

	bool CSSLConnection::f_SendCompleted(umint _iBuffer, umint _nBytes)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_SendCompleted(_iBuffer, _nBytes);
				}
			)
		;
	}

	umint CSSLConnection::f_GetFillBuffer() const
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_GetFillBuffer();
				}
			)
		;
	}

	void CSSLConnection::f_AppendCipherSegment(void const *_pData, umint _nBytes, NStorage::TCSharedPointer<CVirtualDestroyBase const> &&_pOwner)
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					mp_pInternal->f_AppendCipherSegment(_pData, _nBytes, fg_Move(_pOwner));
				}
			)
		;
	}

	void CSSLConnection::f_ClearCipherQueue()
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					mp_pInternal->f_ClearCipherQueue();
				}
			)
		;
	}

	void CSSLConnection::f_CompactCipherIfStalled()
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					mp_pInternal->f_CompactCipherIfStalled();
				}
			)
		;
	}

	bool CSSLConnection::f_OpenHeld(void *_pData, umint _nLen, CSocketOperationResult &o_Result)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_TryOpenInto(_pData, _nLen, o_Result);
				}
			)
		;
	}

	NStorage::TCSharedPointer<NContainer::CByteVector> CSSLConnection::f_GetPinnedKeepAlive(umint _iBuffer) const
	{
		return mp_pInternal->f_GetPinnedKeepAlive(_iBuffer);
	}

	umint CSSLConnection::f_GetInboundBufferSize() const
	{
		return mp_pInternal->f_GetInboundBufferSize();
	}

	void CSSLConnection::f_SetCompletionSend(bool _bCompletionSend)
	{
		mp_pInternal->f_SetCompletionSend(_bCompletionSend);
	}

	void CSSLConnection::f_SetCompletionReceive(bool _bCompletionReceive)
	{
		mp_pInternal->f_SetCompletionReceive(_bCompletionReceive);
	}

	void CSSLConnection::f_FailReceive(NStr::CStr _Error)
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					mp_pInternal->f_FailReceive(fg_Move(_Error));
				}
			)
		;
	}

	void CSSLConnection::f_FailSend(NStr::CStr _Error)
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					mp_pInternal->f_FailSend(fg_Move(_Error));
				}
			)
		;
	}

	bool CSSLConnection::f_IsSendBufferFull() const
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_IsSendBufferFull();
				}
			)
		;
	}

	CSocketOperationResult CSSLConnection::f_FlushPending()
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_FlushPending();
				}
			)
		;
	}

	bool CSSLConnection::f_HasSocket() const
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_HasSocket();
				}
			)
		;
	}

	void CSSLConnection::f_SetHostname(NStr::CStr const &_Hostname)
	{
		fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					mp_pInternal->f_SetHostname(_Hostname);
				}
			)
		;
	}

	NStr::CStr CSSLConnection::f_GetHostname() const
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_GetHostname();
				}
			)
		;
	}

	CSSLSettings::EVerificationFlag CSSLConnection::f_GetVerificationFlags() const
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_GetVerificationFlags();
				}
			)
		;
	}

	bool CSSLConnection::f_Connect()
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_Connect();
				}
			)
		;
	}

	bool CSSLConnection::f_Accept()
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_Accept();
				}
			)
		;
	}

	bool CSSLConnection::f_Shutdown()
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_Shutdown();
				}
			)
		;
	}

	CSocketOperationResult CSSLConnection::f_Send(const void *_pData, umint _nLen)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_Send(_pData, _nLen);
				}
			)
		;
	}

	CSocketOperationResult CSSLConnection::f_Receive(void *_pData, umint _nLen)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_Receive(_pData, _nLen);
				}
			)
		;
	}

	NCryptography::CHashDigest_SHA256 CSSLConnection::f_GetSessionKeyDigest() const
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_GetSessionKeyDigest();
				}
			)
		;
	}

	// CSSLConnectionResult

	void CSSLConnectionResult::f_LogError(umint _Depth, int _Error)
	{
		auto MapResult = mp_Certificates(_Depth);
		CResultCertificate &Certificate = *MapResult;
		DMibSafeCheck(!MapResult.f_WasCreated(), "Cert chain should have been logged before error logging.");

		auto ErrorMapResult = Certificate.m_Errors(_Error);
		int &Error = *ErrorMapResult;
		if (ErrorMapResult.f_WasCreated())
			Error = 0;
		++Error;

		if (fsp_IsTrustError(_Error))
			mp_bTrustErrorsOccured = true;
		else
			mp_bVerificationErrorsOccured = true;

	}

	void CSSLConnectionResult::f_LogMiscError(EMiscError _Error)
	{
		auto MapResult = mp_MiscErrors(_Error);
		int &Error = *MapResult;
		if (MapResult.f_WasCreated())
			Error = 0;

		++Error;

		if (_Error == EMiscError_HostnameMisMatch)
			mp_bVerificationErrorsOccured = true;
	}

	void CSSLConnectionResult::f_LogCertificate(umint _Depth, NContainer::CByteVector const &_Certificate)
	{
		CResultCertificate &Certificate = mp_Certificates[_Depth];
		Certificate.m_Data = _Certificate;
	}

	bool CSSLConnectionResult::f_ContainsTrustErrors() const
	{
		return mp_bTrustErrorsOccured;
	}

	bool CSSLConnectionResult::f_ContainsVerificationErrors() const
	{
		return mp_bVerificationErrorsOccured;
	}

	bool CSSLConnectionResult::f_ConnectionRefused() const
	{
		return mp_bConnectionRefused;
	}

	void CSSLConnectionResult::f_SetConnectionRefused()
	{
		mp_bConnectionRefused = true;
	}

	bool CSSLConnectionResult::f_ContainsInvalidContextErrors() const
	{
		for (auto Iter = mp_MiscErrors.f_GetIterator(); Iter; ++Iter)
		{
			if
				(
					Iter.f_GetKey() == EMiscError_InvalidCertificateAuthorityLocation
					|| Iter.f_GetKey() == EMiscError_InvalidPublicCertificate
					|| Iter.f_GetKey() == EMiscError_InvalidPrivateKey
					|| Iter.f_GetKey() == EMiscError_CertificatePrivateKeyMisMatch
					|| Iter.f_GetKey() == EMiscError_InvalidCRLData
					|| Iter.f_GetKey() == EMiscError_InvalidCRLPath
					|| Iter.f_GetKey() == EMiscError_InvalidCertificateAuthorityData
					|| Iter.f_GetKey() == EMiscError_InternalError
					|| Iter.f_GetKey() == EMiscError_MismatchingSpecificCertificate
				)
			{
				return true;
			}
		}

		return false;
	}

	void CSSLConnectionResult::f_AddSSLError(NStr::CStr const &_SSLError)
	{
		mp_SSLErrors = _SSLError;
	}

	bool CSSLConnectionResult::f_PeerCertificateMatchesRememberedCertificates(NContainer::TCVector<NContainer::CByteVector> const &_LocalStore) const
	{
		if (mp_Certificates.f_IsEmpty())
			return false;

		auto fl_VerifyAgainstLocalTrust = [=, this] (NContainer::CByteVector const &_Certificate) -> bool
		{
			if (_Certificate.f_IsEmpty())
				return false;

			return (mp_Certificates[umint(0)].m_Data == _Certificate);
		};

		for (auto Iter = _LocalStore.f_GetIterator(); Iter; ++Iter)
		{
			if (fl_VerifyAgainstLocalTrust(*Iter))
				return true;
		}

		return false;
	}

	bool CSSLConnectionResult::f_PeerCertificatesMatchesSpecificCertificate(NContainer::CByteVector const &_SpecificCertificate) const
	{
		if (_SpecificCertificate.f_IsEmpty())
			return false;

		if (mp_Certificates.f_IsEmpty())
			return false;

		X509* pPeerCertificate = fg_LoadCertificate(_SpecificCertificate);
		auto Cleanup0 = g_OnScopeExit / [&]
			{
				X509_free(pPeerCertificate);
			}
		;

		NContainer::CByteVector ConvertedCert = fg_ConvertX509ToBinary(pPeerCertificate);

		bool bMatches = (mp_Certificates[umint(0)].m_Data == ConvertedCert);
		return bMatches;
	}

	NStr::CStr CSSLConnectionResult::f_GetErrorMessage(EFormat _Format) const
	{
		NStr::CStr ErrorMessage;

		auto fl_AppendError = [&] (NStr::CStr const &_Error)
		{
			if (_Format == ECommaSeperated)
			{
				if (!ErrorMessage.f_IsEmpty())
					ErrorMessage += NStr::CStr::CFormat(", {}") << _Error;
				else
					ErrorMessage = _Error;
			}
			else if (_Format == EHtml)
			{
				if (!ErrorMessage.f_IsEmpty())
					ErrorMessage += NStr::CStr::CFormat("<li>{}</li>") << _Error;
				else
					ErrorMessage = NStr::CStr::CFormat("<ul><li>{}</li>") << _Error;
			}
		};

		// Add errors generated for each level of certificate chain.
		for (auto Iter = mp_Certificates.f_GetIterator(); Iter; ++Iter)
		{
			CResultCertificate const& Certificate = (*Iter);
			for (auto EIter = Certificate.m_Errors.f_GetIterator(); EIter; ++EIter)
			{
				fl_AppendError(fp_StringForError(EIter.f_GetKey()));
			}
		}

		// Add misc errors.
		for (auto Iter = mp_MiscErrors.f_GetIterator(); Iter; ++Iter)
			fl_AppendError(fp_StringForError(Iter.f_GetKey()));

		// Add system errors.
		if (!mp_SSLErrors.f_IsEmpty())
			fl_AppendError(mp_SSLErrors);

		if (_Format == EHtml)
			ErrorMessage += "</ul>";

		return ErrorMessage;
	}

	NStr::CStr CSSLConnectionResult::f_GetPeerCertificateDescription() const
	{
		if (mp_Certificates.f_IsEmpty())
			return NStr::CStr();

		return CCertificate::fs_GetCertificateDescription(mp_Certificates[umint(0)].m_Data);
	}

	NStr::CStr CSSLConnectionResult::f_GetPeerCertificateInformation() const
	{
		if (mp_Certificates.f_IsEmpty())
			return NStr::CStr();

		return CCertificate::fs_GetCertificateInformation(mp_Certificates[umint(0)].m_Data);
	}

	NContainer::CByteVector CSSLConnectionResult::f_GetPeerCertificate() const
	{
		if (!mp_Certificates.f_IsEmpty())
			return mp_Certificates[umint(0)].m_Data;

		return NContainer::CByteVector();
	}

	NContainer::TCVector<NContainer::CByteVector> CSSLConnectionResult::f_GetCertificateChain() const
	{
		NContainer::TCVector<NContainer::CByteVector> CertificateChain;
		for (auto &Certificate : mp_Certificates)
			CertificateChain.f_Insert(Certificate.m_Data);

		return CertificateChain;
	}

	NStr::CStr CSSLConnectionResult::f_GetPeerCertificateName() const
	{
		if (mp_Certificates.f_IsEmpty())
			return NStr::CStr();

		return CCertificate::fs_GetCertificateName(mp_Certificates[umint(0)].m_Data);
	}

	NStr::CStr CSSLConnectionResult::f_GetPeerCertificateDistinguishedName_RFC2253() const
	{
		if (mp_Certificates.f_IsEmpty())
			return NStr::CStr();

		return CCertificate::fs_GetCertificateDistinguishedName_RFC2253(mp_Certificates[umint(0)].m_Data);
	}

	NStr::CStr CSSLConnectionResult::f_GetPeerCertificateFingerprint() const
	{
		if (mp_Certificates.f_IsEmpty())
			return NStr::CStr();

		return CCertificate::fs_GetCertificateFingerprint(mp_Certificates[umint(0)].m_Data);
	}

	NStr::CStr CSSLConnectionResult::fp_GetLibraryStringForError(int _Error) const
	{
		using namespace NStr;

		return fg_RunProtectRegisters
			(
				[&]() -> NStr::CStr
				{
					if (_Error == EMiscError_HostnameMisMatch)
						return "Hostname mismatch (valid hostnames in certificate: {})"_f << CCertificate::fs_GetCertificateHostnamesStr(f_GetPeerCertificate());
					else
						return NStr::CStr(X509_verify_cert_error_string(_Error));
				}
			)
		;
	}

	NStr::CStr CSSLConnectionResult::fp_StringForError(int _Error) const
	{
		switch (_Error)
		{
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
			return "Unable to get issuer certificate";
		case X509_V_ERR_UNABLE_TO_GET_CRL:
			return "Unable to get CRL";
		case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
			return "Unable to decrypt certificate signature";
		case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
			return "Unable to decrypt CRL signature";
		case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
			return "Unable to decode issuer public key";
		case X509_V_ERR_CERT_SIGNATURE_FAILURE:
			return "Certificate signature failure";
		case X509_V_ERR_CRL_SIGNATURE_FAILURE:
			return "CRL signature failure";
		case X509_V_ERR_CERT_NOT_YET_VALID:
			return "Certificate is not yet valid (notBefore date is after current time)";
		case X509_V_ERR_CERT_HAS_EXPIRED:
			return "Certificate has expired (notAfter date is before the current time)";
		case X509_V_ERR_CRL_NOT_YET_VALID:
			return "CRL not yet valid";
		case X509_V_ERR_CRL_HAS_EXPIRED:
			return "CRL has expired";
		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
			return "Format error in certificate notBefore field";
		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
			return "Format error in certificate notAfter field";
		case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
			return "Format error in CRL lastUpdate field";
		case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
			return "Format error in CRL nextUpdate field";
		case X509_V_ERR_OUT_OF_MEM:
			return "Out of memory";
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
			return "The certificate is self signed and cannot be found in the list of trusted certificates";
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			return "Self signed certificate in chain";
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
			return "Unable to get issuer certificate locally";
		case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
			return "Unable to verify leaf signature (the chain contains only one certificate and it is not self signed)";
		case X509_V_ERR_CERT_CHAIN_TOO_LONG:
			return "Certificate chain too long";
		case X509_V_ERR_CERT_REVOKED:
			return "Certificate is revoked";
		case X509_V_ERR_INVALID_CA:
			return "Invalid certificate authority";
		case X509_V_ERR_PATH_LENGTH_EXCEEDED:
			return "Path length exceeded";
		case X509_V_ERR_INVALID_PURPOSE:
			return "Unsupported certificate purpose";
		case X509_V_ERR_CERT_UNTRUSTED:
			return "Certificate untrusted (the root CA is not marked as trusted for the specified purpose)";
		case X509_V_ERR_CERT_REJECTED:
			return "Certificate rejected (the root CA is marked to reject the specified purpose)";
		case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
			return "Subject issuer mismatch";
		case X509_V_ERR_AKID_SKID_MISMATCH:
			return "Authority and subject key identifier mismatch";
		case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
			return "Authority and issuer serial number mismatch";
		case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
			return "Key usage does not include certificate signing";
		case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
			return "Key usage does not include certificate signing";
		case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
			return "Key usage does not include certificate signing";
		case X509_V_ERR_KEYUSAGE_NO_CRL_SIGN:
			return "No CRL signature";
		case X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION:
			return "Unhandled critical CRL extension";
		case X509_V_ERR_INVALID_NON_CA:
			return "Invalid non certificate authority";
		case X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED:
			return "Proxy path length exceeded";
		case X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE:
			return "Key usage - no digital signature";
		case X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED:
			return "Proxy certificate are not allowed";
		case X509_V_ERR_INVALID_EXTENSION:
			return "Invalid or inconsistent certificate extension";
		case X509_V_ERR_INVALID_POLICY_EXTENSION:
			return "Invalid or inconsistent certificate policy extension";
		case X509_V_ERR_NO_EXPLICIT_POLICY:
			return "The verification flags were set to require an explicit policy but none was present";
		case X509_V_ERR_DIFFERENT_CRL_SCOPE:
			return "Different CRL scope";
		case X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE:
			return "Unsupported extension feature";
		case X509_V_ERR_UNNESTED_RESOURCE:
			return "Unnested resource";
		case X509_V_ERR_PERMITTED_VIOLATION:
			return "Permitted subtree violation";
		case X509_V_ERR_EXCLUDED_VIOLATION:
			return "Excluded subtree violation";
		case X509_V_ERR_SUBTREE_MINMAX:
			return "Name constraints minimum and maximum not supported";
		case X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE:
			return "Unsupported or invalid name constraint type";
		case X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX:
			return "Unsupported or invalid name constraint type";
		case X509_V_ERR_UNSUPPORTED_NAME_SYNTAX:
			return "Unsupported or invalid name constraint type";
		case X509_V_ERR_CRL_PATH_VALIDATION_ERROR:
			return "CRL path validation error";
		case EMiscError_HostnameMisMatch:
			return NStr::CStr::CFormat("Hostname mismatch (valid hostnames in certificate: {0})") << CCertificate::fs_GetCertificateHostnamesStr(f_GetPeerCertificate());
		case EMiscError_InvalidCertificateAuthorityLocation:
			return "Invalid certificate authority certificate location";
		case EMiscError_InvalidPublicCertificate:
			return "Invalid public certificate"	;
		case EMiscError_InvalidPrivateKey:
			return "Invalid private key";
		case EMiscError_CertificatePrivateKeyMisMatch:
			return "Public & Private key mismatch error.";
		case EMiscError_InvalidCRLData:
			return "Invalid certificate revocation list";
		case EMiscError_InvalidCRLPath:
			return "Invalid certificate revocation list path";
		case EMiscError_InvalidCertificateAuthorityData:
			return "Invalid certificate authority certificate";
		case EMiscError_InternalError:
			return "Internal error";
		case EMiscError_MismatchingSpecificCertificate:
			return "Mismatching specific certificate";
		}

		return NStr::CStr::CFormat("Unknown error: {}") << _Error;
	}

	bool CSSLConnectionResult::fsp_IsTrustError(int _Error)
	{
		if (_Error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
			_Error == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE ||
			_Error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
			_Error == X509_V_ERR_CERT_UNTRUSTED ||
			_Error == X509_V_ERR_UNABLE_TO_GET_CRL)
		{
			return true;
		}

		return false;
	}
}
