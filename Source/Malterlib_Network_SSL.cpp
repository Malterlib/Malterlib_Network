
#include "Malterlib_Network_SSL.h"

#include <Mib/Cryptography/BoringSSL>
#include <Mib/Encoding/Base64>

#include "Malterlib_Network_SSL_DHParams.hpp"

#if defined(DPlatformFamily_Windows)
	#include <Mib/Core/PlatformSpecific/WindowsError>

	static NMib::NStr::CStr fg_GetLastSystemError()
	{
		return NMib::NPlatform::fg_Win32_GetLastErrorStr();
	}

#else
	// Unix
	#include <Mib/Core/PlatformSpecific/PosixErrNo>
	#include <errno.h>

	static NMib::NStr::CStr fg_GetLastSystemError()
	{
		int Error = errno;
		if (Error == 0)
			return "End of file encountered";
		else
			return NMib::NPlatform::fg_FormatErrno("", Error);
	}
#endif

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

		constinit NStorage::TCAggregate<CSSLLowLevelDataIndex, 129> g_SSLLowLevelDataIndex = {DAggregateInit};

		SSL_CTX *fg_CreateSSLContext(SSL_METHOD const *_pMethod)
		{
			return SSL_CTX_new(_pMethod);
		}

		int fg_ExDataIndex()
		{
			return g_SSLLowLevelDataIndex->m_ExDataIndex;
		}
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
						auto Cleanup = g_OnScopeExit > [&]
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
				auto nCertsInChain = sk_X509_num(_pStoreContext->chain);
				while (nCertsInChain)
				{
					X509* pCert = sk_X509_value(_pStoreContext->chain, nCertsInChain - 1);
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
			auto Cleanup = g_OnScopeExit > [&]
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
			if (!SSL_CTX_set1_curves(mp_pContext, s_SupportedCurves, sizeof(s_SupportedCurves) / sizeof(s_SupportedCurves[0])))
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
						auto Cleanup0 = g_OnScopeExit > [&]
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
				auto Cleanup0 = g_OnScopeExit > [&]
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
			auto Cleanup0 = g_OnScopeExit > [&]
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

				ERR_clear_error();
				X509_LOOKUP* pLookup = X509_STORE_add_lookup(pStore, X509_LOOKUP_file());
				if (!pLookup)
					DMibErrorCryptography(fg_GetExceptionStr("Failed to add lookup file to store"));

				X509_CRL* pCRL = fs_LoadCRL(mp_Settings.m_CRLData);

				auto Cleanup = g_OnScopeExit > [&]
					{
						X509_CRL_free(pCRL);
					}
				;

				ERR_clear_error();
				if (!X509_STORE_add_crl(pLookup->store_ctx, pCRL))
					DMibErrorCryptography(fg_GetExceptionStr("Failed to add certificate revocation list to store"));

				ERR_clear_error();
				if (!X509_STORE_set_flags(pStore, X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL))
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
					auto Cleanup = g_OnScopeExit > [&]
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
					X509_STORE_set_flags(pStore, X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);
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
			mint nAlgos = sizeof(s_DefaultAlgos) / sizeof(s_DefaultAlgos[0]);
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
					nAlgos = sizeof(s_CustomAlgos) / sizeof(s_CustomAlgos[0]);
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
					nAlgos = sizeof(s_CustomAlgos) / sizeof(s_CustomAlgos[0]);
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
			auto Cleanup = g_OnScopeExit > [&]
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
						auto Cleanup = g_OnScopeExit > [&]
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
			, mp_State(EState_None)
			, mp_bConnected(false)
			, mp_AuthenticationResultCallback(fg_Move(_AuthenticationResultCallback))
			, mp_UserTrustCallback(fg_Move(_UserTrustCallback))
			, mp_bHandshakeInProgress(false)
			, mp_bUsingTrustDecision(false)
		{
			if (_Hostname)
			{
				ERR_clear_error();
				if (!SSL_set_tlsext_host_name(mp_pSession->f_GetSSL(), _Hostname.f_GetStr()))
					DMibErrorCryptography(fg_GetExceptionStr("Failed to set hostname in SSL"));
			}
		}

		~CInternal()
		{
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

		bool f_Connected() const
		{
			return mp_bConnected;
		}

		void f_SetExpectedConnectionResult(CSSLConnectionResult const &_ExpectedResult)
		{
			mp_bUsingTrustDecision = true;
			mp_ExpectedResultCallback = _ExpectedResult;
		}

		bool f_GiveSocket(void *_pSocket)
		{
			if (!SSL_set_fd(f_GetSSL(), (int)(mint)_pSocket))
				return false;

			return true;
		}

		bool f_HasSocket() const
		{
			return SSL_get_fd(fg_RemoveQualifiers(*this).f_GetSSL()) >= 0;
		}

		void* f_GetSocket() const
		{
			return (void*)(mint)SSL_get_fd(fg_RemoveQualifiers(*this).f_GetSSL());
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
			if (Ret == 1)
				return true;
			else if (Ret == -1)
			{
				int Error = SSL_get_error(f_GetSSL(), Ret);
				if (Error == SSL_ERROR_ZERO_RETURN)
					f_SetState(EState_ConnectionShutdown);
				else if (Error == SSL_ERROR_SYSCALL)
				{
	#if defined(DPlatformFamily_Windows)
					int Error = WSAGetLastError();
					DMibErrorNet((NStr::CStr::CFormat("Could not shut down SSL, windows returned: {}") << NMib::NPlatform::fg_Win32_GetLastErrorStr(Error)).f_GetStr());
	#else
					// Unix
					int Error = errno;
					if (Error == 0)
						DMibErrorNet("SSL_shutdown: End of file encountered");
					else
						DMibErrorNet(NMib::NPlatform::fg_FormatErrno("SSL_shutdown", Error));
	#endif
				}
				else if (Error != SSL_ERROR_WANT_READ && Error != SSL_ERROR_WANT_WRITE)
				{
					mp_LastError = fg_GetErrors();
					f_SetState(EState_ShutdownFailed);
				}
			}
			return false;
		}

		CSocketOperationResult f_Send(const void *_pData, mint _nLen)
		{
			DMibRequire(_nLen > 0);
			DMibRequire(mp_bConnected);
			DMibRequire(!mp_bHandshakeInProgress);
			DMibRequire(mp_State == EState_None);

			CSocketOperationResult Result;
			ERR_clear_error();
			auto pSSL = f_GetSSL();
			auto pReadBio = SSL_get_rbio(pSSL);
			auto pWriteBio = SSL_get_wbio(pSSL);
			auto SocketNumRead = pReadBio->num_read;
			auto SocketNumWrite = pWriteBio->num_write;
			int Ret = SSL_write(pSSL, _pData, (int)_nLen);
			if (pReadBio->num_read != SocketNumRead)
				Result.m_bReceivedNetwork = true;
			if (pReadBio->num_write != SocketNumWrite)
				Result.m_bSentNetwork = true;
			if (Ret <= 0)
			{
				// Write did not succeed.
				int Error = SSL_get_error(pSSL, Ret);
				DMibLog(DebugVerbose2, " **** SSL error {}", Error);
				if (Error == SSL_ERROR_ZERO_RETURN)
				{
					f_SetState(EState_ConnectionShutdown);
				}
				else if (Error == SSL_ERROR_SYSCALL)
				{
	#if defined(DPlatformFamily_Windows)
					int Error = WSAGetLastError();
					DMibErrorNet((NStr::CStr::CFormat("Could not write to socket (SSL), windows returned: {}") << NMib::NPlatform::fg_Win32_GetLastErrorStr(Error)).f_GetStr());
	#else
					// Unix
					int Error = errno;
					if (Error == 0)
						DMibErrorNet("send (write to SSL socket): End of file encountered");
					else
						DMibErrorNet(NMib::NPlatform::fg_FormatErrno("send (write to SSL socket)", Error));
	#endif
				}
				else if (Error != SSL_ERROR_WANT_READ && Error != SSL_ERROR_WANT_WRITE)
				{
					mp_LastError = fg_GetErrors();
					f_SetState(EState_WriteFailed);
				}
			}
			else
			{
				DMibLog(DebugVerbose2, " **** SSL wrote {}", Ret);
				// Write succeeded, return the number of bytes written.
				Result.m_nBytes = (mint)Ret;
			}

			return Result;
		}

		CSocketOperationResult f_Receive(void *_pData, mint _nLen)
		{
			DMibRequire(_nLen > 0);
			DMibRequire(mp_bConnected);
			DMibRequire(!mp_bHandshakeInProgress);
			DMibRequire(mp_State == EState_None);

			CSocketOperationResult Result;
			ERR_clear_error();
			auto pSSL = f_GetSSL();
			auto pReadBio = SSL_get_rbio(pSSL);
			auto pWriteBio = SSL_get_wbio(pSSL);
			auto SocketNumRead = pReadBio->num_read;
			auto SocketNumWrite = pWriteBio->num_write;
			int Ret = SSL_read(pSSL, _pData, _nLen);
			if (pReadBio->num_read != SocketNumRead)
				Result.m_bReceivedNetwork = true;
			if (pReadBio->num_write != SocketNumWrite)
				Result.m_bSentNetwork = true;

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
	#if defined(DPlatformFamily_Windows)
					int Error = WSAGetLastError();
					DMibErrorNet((NStr::CStr::CFormat("Could not read from socket (SSL), windows returned: {}") << NMib::NPlatform::fg_Win32_GetLastErrorStr(Error)).f_GetStr());
	#else
					// Unix
					int Error = errno;
					if (Error == 0)
						DMibErrorNet("recv (read from SSL socket): End of file encountered");
					else
						DMibErrorNet(NMib::NPlatform::fg_FormatErrno("recv (read from SSL socket)", Error));
	#endif
				}
				else if (Error != SSL_ERROR_WANT_READ && Error != SSL_ERROR_WANT_WRITE)
				{
					mp_LastError = fg_GetErrors();
					DMibLog(DebugVerbose2, " **** Read failed: {} {}", Error, mp_LastError);
					f_SetState(EState_ReadFailed);
				}
			}
			else
			{
				// Read succeeded, return the number of bytes read.
				Result.m_nBytes = (mint)Ret;
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

		bool mp_bConnected;
		bool mp_bHandshakeInProgress;
		bool mp_bUsingTrustDecision;

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
				DMibConOut2("Negotiated: {}   {}\n", pVerson, SSL_CIPHER_get_name(pChipher));
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

		bool fp_GenerateSystemErrors(int _Ret, EAuthenticationResult &_Result, NStr::CStr &_SystemErrors, bool &_bConnectionRefused)
		{
			unsigned long SysError;
			NStr::CStr AllErrors;

			if ((SysError=ERR_peek_error()) != 0)
			{
				const char *pFile;
				int Line;
				while( (SysError = ERR_get_error_line(&pFile, &Line)))
					NStr::fg_AddStrSep(AllErrors, NStr::CStr::CFormat("{cc}") << ERR_reason_error_string(SysError), "\n");

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
					_SystemErrors = fg_GetLastSystemError();
					return true;
				}
				else if (Error != SSL_ERROR_WANT_WRITE && Error != SSL_ERROR_WANT_READ)
				{
					_Result = EAuthenticationResult_Failure;
					_bConnectionRefused = true;
					_SystemErrors = NStr::fg_Format("{cc}", ERR_reason_error_string(SysError));
					return true;
				}
			}

			return false;
		}

	};

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
						DMibLog(DebugVerbose2, " **** SSL broken: {}", mp_pInternal->f_GetState());
						return true;
					}
					return false;
				}
			)
		;
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

	bool CSSLConnection::f_GiveSocket(void *_pSocket)
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_GiveSocket(_pSocket);
				}
			)
		;
	}

	void* CSSLConnection::f_GetSocket() const
	{
		return fg_RunProtectRegisters
			(
				[&]() -> decltype(auto)
				{
					return mp_pInternal->f_GetSocket();
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

	CSocketOperationResult CSSLConnection::f_Send(const void *_pData, mint _nLen)
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

	CSocketOperationResult CSSLConnection::f_Receive(void *_pData, mint _nLen)
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

	void CSSLConnectionResult::f_LogError(mint _Depth, int _Error)
	{
		bool bCreated = false;
		CResultCertificate& Certificate = mp_Certificates.f_Map(_Depth, bCreated);
		DMibSafeCheck(!bCreated, "Cert chain should have been logged before error logging.");

		bCreated = false;
		int& Error = Certificate.m_Errors.f_Map(_Error, bCreated);
		if (bCreated)
			Error = 0;
		++Error;

		if (fsp_IsTrustError(_Error))
			mp_bTrustErrorsOccured = true;
		else
			mp_bVerificationErrorsOccured = true;

	}

	void CSSLConnectionResult::f_LogMiscError(EMiscError _Error)
	{
		bool bCreated = false;
		int& Error = mp_MiscErrors.f_Map(_Error, bCreated);
		if (bCreated)
			Error = 0;

		++Error;

		if (_Error == EMiscError_HostnameMisMatch)
			mp_bVerificationErrorsOccured = true;
	}

	void CSSLConnectionResult::f_LogCertificate(mint _Depth, NContainer::CByteVector const &_Certificate)
	{
		bool bCreated = false;
		CResultCertificate& Certificate = mp_Certificates.f_Map(_Depth, bCreated);
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

		auto fl_VerifyAgainstLocalTrust = [=] (NContainer::CByteVector const &_Certificate) -> bool
		{
			if (_Certificate.f_IsEmpty())
				return false;

			return (mp_Certificates[mint(0)].m_Data == _Certificate);
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
		auto Cleanup0 = g_OnScopeExit > [&]
			{
				X509_free(pPeerCertificate);
			}
		;

		NContainer::CByteVector ConvertedCert = fg_ConvertX509ToBinary(pPeerCertificate);

		bool bMatches = (mp_Certificates[mint(0)].m_Data == ConvertedCert);
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

		return CCertificate::fs_GetCertificateDescription(mp_Certificates[mint(0)].m_Data);
	}

	NStr::CStr CSSLConnectionResult::f_GetPeerCertificateInformation() const
	{
		if (mp_Certificates.f_IsEmpty())
			return NStr::CStr();

		return CCertificate::fs_GetCertificateInformation(mp_Certificates[mint(0)].m_Data);
	}

	NContainer::CByteVector CSSLConnectionResult::f_GetPeerCertificate() const
	{
		if (!mp_Certificates.f_IsEmpty())
			return mp_Certificates[mint(0)].m_Data;

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

		return CCertificate::fs_GetCertificateName(mp_Certificates[mint(0)].m_Data);
	}

	NStr::CStr CSSLConnectionResult::f_GetPeerCertificateDistinguishedName_RFC2253() const
	{
		if (mp_Certificates.f_IsEmpty())
			return NStr::CStr();

		return CCertificate::fs_GetCertificateDistinguishedName_RFC2253(mp_Certificates[mint(0)].m_Data);
	}

	NStr::CStr CSSLConnectionResult::f_GetPeerCertificateFingerprint() const
	{
		if (mp_Certificates.f_IsEmpty())
			return NStr::CStr();

		return CCertificate::fs_GetCertificateFingerprint(mp_Certificates[mint(0)].m_Data);
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
