
#include "Malterlib_Network_SSL.h"

#include <Mib/Cryptography/Hashes/SHA>
#include <Mib/Storage/LazyInit>
#include <Mib/Encoding/Base64>

extern "C"
{
#	ifdef final
#		undef final
#	endif
#	include <openssl/dh.h>
#	include <openssl/ssl.h>
#	include <openssl/evp.h>
#	include <openssl/aes.h>
#	include <openssl/err.h>
#	include <openssl/conf.h>
#	include <openssl/engine.h>
#	undef X509_NAME
#	include <openssl/x509v3.h>

#	ifndef final
#		define final
#	endif
	
#ifdef DPlatformFamily_OSX
	#include <Security/Security.h>
#endif

};

#include "Malterlib_Network_SSL_DHParams.hpp"

#if !defined(OPENSSL_THREADS)
	#error Must use multithreaded openssl library!
#endif

#if defined(DPlatformFamily_Windows)
#include <Mib/Core/PlatformSpecific/WindowsError>

	static NMib::NStr::CStr fg_GetLastSystemError()
	{
		return NMib::NPlatform::fg_Win32_GetLastErrorStr();
	}

#else
	// Unix
	#include <Mib/Core/PlatformSpecific/PosixErrNo>

	static NMib::NStr::CStr fg_GetLastSystemError()
	{
		return NMib::NPlatform::fg_FormatErrno("", errno);
	}
#endif

struct CRegisterState
{
	__m128 m_XMM6;
	__m128 m_XMM7;
	__m128 m_XMM8;
	__m128 m_XMM9;
	__m128 m_XMM10;
	__m128 m_XMM11;
	__m128 m_XMM12;
	__m128 m_XMM13;
	__m128 m_XMM14;
	__m128 m_XMM15;

	uint64 m_RDI;
	uint64 m_RSI;
	uint64 m_RBX;
	uint64 m_RBP;

	uint64 m_R12;
	uint64 m_R13;
	uint64 m_R14;
	uint64 m_R15;
};

#if defined(DPlatformFamily_Windows) && defined(DArchitecture_x64)
extern "C" void fg_Malterlib_Network_SSL_SaveRegisters_X86_64(CRegisterState *_pRegisters);
extern "C" void fg_Malterlib_Network_SSL_RestoreRegisters_X86_64(CRegisterState *_pRegisters);
#endif
	
namespace
{
#if defined(DPlatformFamily_Windows) && defined(DArchitecture_x64)
	struct COpenSSLBrokenRegistryHandlingScope
	{
		CRegisterState m_RegisterState;

		inline_always COpenSSLBrokenRegistryHandlingScope()
		{
			fg_Malterlib_Network_SSL_SaveRegisters_X86_64(&m_RegisterState);
		}
		inline_always ~COpenSSLBrokenRegistryHandlingScope()
		{
			fg_Malterlib_Network_SSL_RestoreRegisters_X86_64(&m_RegisterState);
		}
	};

	template <typename t_FToRun>
	struct TCRunProtectedRegistersHelper
	{
		TCRunProtectedRegistersHelper(t_FToRun &&_fToRun)
			: mp_fToRun(NMib::fg_Move(_fToRun))
		{

		}
		inline_never decltype(auto) f_Run()
		{
			COpenSSLBrokenRegistryHandlingScope ProtectionScope;
			return fp_Run();
		}
	private:

		inline_never decltype(auto) fp_Run()
		{
			return mp_fToRun();
		}

		t_FToRun &&mp_fToRun;
	};

	template <typename t_FToRun>
	decltype(auto) fg_RunProtectRegisters(t_FToRun &&_fToRun)
	{
		TCRunProtectedRegistersHelper<t_FToRun &&> RunHelper{NMib::fg_Move(_fToRun)};

		return RunHelper.f_Run();
	}
#else
	template <typename t_FToRun>
	inline_always decltype(auto) fg_RunProtectRegisters(t_FToRun &&_fToRun)
	{
		return _fToRun();
	}
#endif
}

namespace NMib
{
	namespace NNet
	{
		namespace
		{
			static void fg_SSLLockingCallback(int _Mode, int _Type, char const* _File, int _Line);

			struct CSSLLowLevel
			{

				CSSLLowLevel()
				{
					fg_RunProtectRegisters
						(
							[&]() -> decltype(auto)
							{
								m_pThreadLocal = fg_Construct();

								SSL_library_init();
								ENGINE_load_builtin_engines();
								ENGINE_register_all_complete();

								SSL_load_error_strings();

								f_UseInThread();

								mint nSSLLocks = CRYPTO_num_locks();
								m_Locks.f_SetLen(nSSLLocks);
								CRYPTO_set_locking_callback(&fg_SSLLockingCallback);
							}
						)
					;
				}

				~CSSLLowLevel()
				{
					fg_RunProtectRegisters
						(
							[&]() -> decltype(auto)
							{
								m_pThreadLocal.f_Clear();

								CONF_modules_finish();
								CONF_modules_free();
								CONF_modules_unload(1);

								ERR_free_strings();

								EVP_cleanup();

								OBJ_cleanup();

								CRYPTO_set_locking_callback(nullptr);

								CRYPTO_cleanup_all_ex_data();

								ENGINE_cleanup();
					
								m_Locks.f_Clear();
							}
						)
					;
				}

				NContainer::TCVector<NIndirection::TCIndirection<NMib::NThread::CMutualManyRead>> m_Locks;
				NMib::NThread::CMutual m_ContextCreationLock;
				
				struct CThreadLocal
				{
					CRYPTO_THREADID m_ThreadID;
					CThreadLocal()
					{
						fg_RunProtectRegisters
							(
								[&]() -> decltype(auto)
								{
								    CRYPTO_THREADID_current(&m_ThreadID);
								}
							)
						;
					}
					~CThreadLocal()
					{
						fg_RunProtectRegisters
							(
								[&]() -> decltype(auto)
								{
									ERR_remove_thread_state(&m_ThreadID);
								}
							)
						;
					}
				};
				NPtr::TCUniquePointer<NMib::NThread::TCThreadLocal<CThreadLocal>> m_pThreadLocal;
				
				void f_UseInThread()
				{
					auto &Test = **m_pThreadLocal; // Make sure cleanup is done at thread exit

					(void)Test;
				}
				
			};

			NAggregate::TCAggregate<CSSLLowLevel> g_SSLLowLevel = {DAggregateInit};

			struct CSSLLowLevelDataIndex
			{
				CSSLLowLevelDataIndex()
				{
					m_ExDataIndex = SSL_get_ex_new_index(0, (void*)"CSSLConnection Index", nullptr, nullptr, nullptr);
				}
				int m_ExDataIndex = 0;
			};
			
			NAggregate::TCAggregate<CSSLLowLevelDataIndex> g_SSLLowLevelDataIndex = {DAggregateInit};

			static void fg_SSLLockingCallback(int _Mode, int _Type, char const* _File, int _Line)
			{
				DMibCheck(g_SSLLowLevel->m_Locks.f_IsPosValid(_Type));
				auto &Lock = g_SSLLowLevel->m_Locks[_Type].f_Get();
				if (_Mode & CRYPTO_LOCK)
				{
					if (_Mode & CRYPTO_READ)
						Lock.f_LockRead();
					else
						Lock.f_Lock();
				}
				else
				{
					if (_Mode & CRYPTO_READ)
						Lock.f_UnlockRead();
					else
						Lock.f_Unlock();
				}
			}

			SSL_CTX* fg_CreateSSLContext(SSL_METHOD const *_pMethod)
			{
				DMibLock(g_SSLLowLevel->m_ContextCreationLock);
				return SSL_CTX_new(_pMethod);
			}
			
			int fg_ExDataIndex()
			{
				return g_SSLLowLevelDataIndex->m_ExDataIndex;
			}

			NStr::CStr fg_GetErrors()
			{
				NStr::CStr Errors;
				auto fAddError = [&](char const *_pError, size_t _StringLength)
					{
						NStr::fg_AddStrSep(Errors, NStr::CStr(_pError, _StringLength), DMibNewLine);
					}
				;
				using CAddErrorType = decltype(fAddError);

				ERR_print_errors_cb
					(
						[](char const *_pError, size_t _StringLength, void *_pContext) -> int
						{
							(*((CAddErrorType *)_pContext))(_pError, _StringLength);
							return 1;
						}
						, &fAddError 
					)
				;
				
				return Errors;
			}

			NStr::CStr fg_GetExceptionStr(NStr::CStr const &_Description)
			{
				NStr::CStr Errors = fg_GetErrors();
				
				if (Errors.f_IsEmpty())
					return _Description;
				
				return fg_Format("{}: {}", _Description, Errors);
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
							g_SSLLowLevel->f_UseInThread();
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
								g_SSLLowLevel->f_UseInThread();
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

							g_SSLLowLevel->f_UseInThread();
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
									mp_pContext = fg_CreateSSLContext(SSLv3_server_method());
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
							g_SSLLowLevel->f_UseInThread();
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

			NPtr::TCUniquePointer<CSSLContext::CSession> fp_CreateSession()
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
				NContainer::TCVector<uint8> CertData = fs_ConvertX509ToBinary(_pCertificate);

				NContainer::TCVector<NStr::CStr> lHostnames = fs_GetCertificateHostnames(CertData);
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
				g_SSLLowLevel->f_UseInThread();
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
					if (Error == X509_V_ERR_SUBJECT_ISSUER_MISMATCH)
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
					int nCertsInChain = sk_X509_num(_pStoreContext->chain);
					while (nCertsInChain)
					{
						X509* pCert = sk_X509_value(_pStoreContext->chain, nCertsInChain - 1);
						NContainer::TCVector<uint8> CertData;
						try
						{
							CertData = fs_ConvertX509ToBinary(pCert);

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
						catch (CExceptionNetSSL const &_Exception)
						{
							Result.f_LogMiscError(CSSLConnectionResult::EMiscError_InternalError);
							Result.f_AddSSLError(_Exception.f_GetErrorStr());
						}
					}
				}

				if (_PreVerifyOK == 0)
				{
					Result.f_LogError(Depth, Error);
				}

				return 1;
			}

			static NStr::CStr fs_GetCertificateDescription(NContainer::TCVector<uint8> const &_CertificateData)
			{
				g_SSLLowLevel->f_UseInThread();
				NStr::CStr CertificateDescription;
				X509 *pCertificate = fs_LoadCertificate(_CertificateData);
				auto Cleanup0 = g_OnScopeExit > [&]
					{
						X509_free(pCertificate);
					}
				;
					
				ERR_clear_error();
				BIO* pMemoryBio = BIO_new(BIO_s_mem());
				if (!pMemoryBio)
					DMibErrorNetSSL(fg_GetExceptionStr("Failed to create BIO"));
				auto Cleanup1 = g_OnScopeExit > [&]
					{
						BIO_free_all(pMemoryBio);
					}
				;

				BUF_MEM* pMemory = nullptr;

				unsigned long NameOptions = 0;
				unsigned long CertOptions = 0;

				ERR_clear_error();
				if (!X509_print_ex(pMemoryBio, pCertificate, NameOptions, CertOptions))
					DMibErrorNetSSL(fg_GetExceptionStr("Failed to print x509 description"));
					
				(void)BIO_flush(pMemoryBio);
				BIO_get_mem_ptr(pMemoryBio, &pMemory);

				NContainer::TCVector<uint8> RawData;
				RawData.f_SetLen(pMemory->length);
				NMem::fg_MemCopy(RawData.f_GetArray(), pMemory->data, pMemory->length - 1);

				RawData[RawData.f_GetLen() - 1] = '\0';
				return NStr::CStr((ch8 const *)RawData.f_GetArray());
			}

			static NStr::CStr fs_GetCertificateInformation(NContainer::TCVector<uint8> _CertificateData)
			{
				if (!_CertificateData.f_IsEmpty())
				{
					_CertificateData[_CertificateData.f_GetLen() - 1] = '\0';
					return NStr::CStr((ch8 const *)_CertificateData.f_GetArray());
				}

				return NStr::CStr();
			}

			static NStr::CStr fs_GetCertificateName(NContainer::TCVector<uint8> const &_CertificateData)
			{
				g_SSLLowLevel->f_UseInThread();
				X509 *pCertificate = fs_LoadCertificate(_CertificateData);
				auto Cleanup0 = g_OnScopeExit > [&]
					{
						X509_free(pCertificate);
					}
				;
				
				char Buffer[256];
				ERR_clear_error();
				int nChars = X509_NAME_get_text_by_NID(X509_get_subject_name(pCertificate), NID_commonName, Buffer, 256); 
				if (nChars < 0)
					DMibErrorNetSSL(fg_GetExceptionStr("Failed to read certificate name"));
				return NStr::CStr(Buffer, nChars);
			}

			static NStr::CStr fs_GetCertificateFingerprint(NContainer::TCVector<uint8> const &_CertificateData)
			{
				g_SSLLowLevel->f_UseInThread();
				X509 *pCertificate = fs_LoadCertificate(_CertificateData);
				auto Cleanup0 = g_OnScopeExit > [&]
					{
						X509_free(pCertificate);
					}
				;
				
				unsigned int DigestSize = 0;
				unsigned char Digest[EVP_MAX_MD_SIZE];
				if (!X509_digest(pCertificate, EVP_sha256(), Digest, &DigestSize))
					DMibErrorNetSSL(fg_GetExceptionStr("Failed to calculate certificate digest"));
				
				NStr::CStr Fingerprint;
				for (mint iByte = 0; iByte < DigestSize; ++iByte)
					Fingerprint += NStr::CStr::CFormat("{nh,sf0,sf2}") << Digest[iByte];
				
				return Fingerprint;
			}
			
			static NStr::CStr fs_GetIssuerName(NContainer::TCVector<uint8> const &_CertificateData)
			{
				g_SSLLowLevel->f_UseInThread();
				NStr::CStr CertificateName;
				X509 *pCertificate = fs_LoadCertificate(_CertificateData);
				auto Cleanup0 = g_OnScopeExit > [&]
					{
						X509_free(pCertificate);
					}
				;
				char Buffer[256];
				ERR_clear_error();
				int nChars = X509_NAME_get_text_by_NID(X509_get_issuer_name(pCertificate), NID_commonName, Buffer, 256);
				if (nChars < 0)
					DMibErrorNetSSL(fg_GetExceptionStr("Failed to read certificate issuen name"));
				return NStr::CStr(Buffer);
			}

			static NStr::CStr fs_GetCertificateHostnamesStr(NContainer::TCVector<uint8> const &_CertificateData)
			{
				NStr::CStr Hostnames;
				NContainer::TCVector<NStr::CStr> lHostNames = fs_GetCertificateHostnames(_CertificateData);
				for (auto Iter = lHostNames.f_GetIterator(); Iter; ++Iter)
				{
					if (Hostnames.f_IsEmpty())
						Hostnames = (*Iter);
					else
						Hostnames += ", " + (*Iter);
				}

				if (Hostnames.f_IsEmpty())
					Hostnames = "-";

				return Hostnames;
			}

			static NContainer::TCVector<NStr::CStr> fs_GetCertificateHostnames(NContainer::TCVector<uint8> const &_CertificateData, bool _bCheckCommonName = true)
			{
				g_SSLLowLevel->f_UseInThread();
				NContainer::TCVector<NStr::CStr> lHostnames;

				X509 *pCertificate = fs_LoadCertificate(_CertificateData);
				auto Cleanup0 = g_OnScopeExit > [&]
					{
						X509_free(pCertificate);
					}
				;

				// First look at "subjectAltNames"
				int Index = -1;
				while(true)
				{
					GENERAL_NAMES* pSubjectAltNames = (GENERAL_NAMES*)X509_get_ext_d2i(pCertificate, NID_subject_alt_name, nullptr, &Index);
					if (!pSubjectAltNames)
						break;
					auto Cleanup = g_OnScopeExit > [&]
						{
							GENERAL_NAMES_free(pSubjectAltNames);
						}
					;
					int nAltEntries = sk_GENERAL_NAME_num(pSubjectAltNames);

					for (int iEntry = 0; iEntry < nAltEntries; ++iEntry)
					{
						GENERAL_NAME const* pName = sk_GENERAL_NAME_value(pSubjectAltNames, iEntry);
						if (!pName)
							continue;

						unsigned char* pBuffer = nullptr;

						switch (pName->type)
						{
						case GEN_DNS:
						case GEN_URI:
						case GEN_EMAIL:
							ASN1_STRING_to_UTF8((unsigned char**)&pBuffer, pName->d.ia5);
							if (pBuffer)
							{
								auto Cleanup = g_OnScopeExit > [&]
									{
										OPENSSL_free(pBuffer);
									}
								;
								lHostnames.f_Insert(NStr::CStr(pBuffer));
							}
							break;
						case GEN_IPADD:
							{
								pBuffer = pName->d.ip->data;
								NStr::CStr IPAddress;

								if (pName->d.ip->length == 4)
									IPAddress = NStr::CStr::CFormat("{}.{}.{}.{}") << pBuffer[0] << pBuffer[1] << pBuffer[2] << pBuffer[3];
								else if (pName->d.ip->length == 16)
								{
									for (int i = 0; i < 8; ++i)
									{
										if (IPAddress.f_IsEmpty())
											IPAddress += NStr::CStr::CFormat("{nfh,sj8,sf0}") << (pBuffer[0] << 8 | pBuffer[1]);
										else
											IPAddress += NStr::CStr::CFormat(":{nfh,sj8,sf0}") << (pBuffer[0] << 8 | pBuffer[1]);

										pBuffer += 2;
									}
								}

								if (!IPAddress.f_IsEmpty())
									lHostnames.f_Insert(IPAddress);
							}
							break;
						}
					}
				}

				// Fallback on the common name of the certificate
				if (_bCheckCommonName)
				{
					X509_NAME* pSubject = X509_get_subject_name(pCertificate);
					if (pSubject)
					{
						char CommonName[256];
						int nChars = X509_NAME_get_text_by_NID(pSubject, NID_commonName, CommonName, sizeof(CommonName));
						if (nChars > 0)
							lHostnames.f_Insert(NStr::CStr(CommonName, nChars));
					}
				}

				return lHostnames;
			}

			static bool fs_DecodeExtension(X509_EXTENSION *_pExtension, NStr::CStr &o_Name, CCertificateExtension &o_Extension)
			{
				ASN1_OBJECT *pObject = X509_EXTENSION_get_object(_pExtension);
				ASN1_OCTET_STRING *pData = X509_EXTENSION_get_data(_pExtension);
				int Critical = X509_EXTENSION_get_critical(_pExtension);
				
				NStr::CStr Name;
				int nID = OBJ_obj2nid(pObject);
				if (nID != NID_undef) 
				{
					const char *pShortName = OBJ_nid2sn(nID);
					if (pShortName)
					{
						Name = pShortName; 
					}
				}
				if (Name.f_IsEmpty())
				{
					ch8 Data[1024];
					Data[0] = 0;
					OBJ_obj2txt(Data, 1024, pObject, 0);
					Data[1023] = 0;
					Name = Data;						
				}

				if (Name.f_IsEmpty())
					return false;
				
				NStr::CStr Value;
				switch (pData->type)
				{
				case V_ASN1_NUMERICSTRING:
				case V_ASN1_PRINTABLESTRING:
				case V_ASN1_UTF8STRING:
				case V_ASN1_T61STRING:
				case V_ASN1_VIDEOTEXSTRING:
				case V_ASN1_ISO64STRING:
				case V_ASN1_IA5STRING:
				case V_ASN1_OCTET_STRING:
					{
						Value = NStr::CStr((ch8 const *)pData->data, pData->length); 
					}
					break;
				default:
					return false;
				}

				o_Name = fg_Move(Name);
				o_Extension.m_Value = fg_Move(Value);
				o_Extension.m_bCritical = Critical != 0;
				
				return true;
			}
			
			static NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> fs_GetCertificateRequestExtensions(NContainer::TCVector<uint8> const &_CertificateRequestData)
			{
				g_SSLLowLevel->f_UseInThread();

				X509_REQ *pCertificateRequest = fs_LoadCertificateRequest(_CertificateRequestData);
				auto Cleanup0 = g_OnScopeExit > [&]
					{
						X509_REQ_free(pCertificateRequest);
					}
				;

				ERR_clear_error();
				
				auto pExtensions = X509_REQ_get_extensions(pCertificateRequest);
				auto Cleanup = g_OnScopeExit > [&]
					{
						if (pExtensions)
							sk_X509_EXTENSION_pop_free(pExtensions, X509_EXTENSION_free);
					}
				;
				
				if (!pExtensions)
					return fg_Default();
								
				ERR_clear_error();
				int nExtensions = X509v3_get_ext_count(pExtensions);
				if (nExtensions < 0)
					DMibErrorNetSSL(fg_GetExceptionStr("Failed to get extension count from certificate request"));
				
				NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> Return;
				
				for (int iExtension = 0; iExtension < nExtensions; ++iExtension)
				{
					auto *pExtension = X509v3_get_ext(pExtensions, iExtension);
					if (!pExtension)
						continue;
					
					NStr::CStr Name;
					CCertificateExtension Extension;
					if (!fs_DecodeExtension(pExtension, Name, Extension))
						continue;

					Return[Name].f_Insert(fg_Move(Extension)); 
				}
				
				return Return;
			}
			
			static NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> fs_GetCertificateExtensions(NContainer::TCVector<uint8> const &_CertificateData)
			{
				g_SSLLowLevel->f_UseInThread();

				X509 *pCertificate = fs_LoadCertificate(_CertificateData);
				auto Cleanup0 = g_OnScopeExit > [&]
					{
						X509_free(pCertificate);
					}
				;

				ERR_clear_error();
				int nExtensions = X509_get_ext_count(pCertificate);
				
				NContainer::TCMap<NStr::CStr, NContainer::TCVector<CCertificateExtension>> Return;
				
				for (int iExtension = 0; iExtension < nExtensions; ++iExtension)
				{
					auto *pExtension = X509_get_ext(pCertificate, iExtension);
					if (!pExtension)
						continue;
					
					NStr::CStr Name;
					CCertificateExtension Extension;
					if (!fs_DecodeExtension(pExtension, Name, Extension))
						continue;

					Return[Name].f_Insert(fg_Move(Extension)); 
				}
				
				return Return;
			}

			
			static NContainer::TCVector<NStr::CStr> fs_GetSortedHostnames(NContainer::TCVector<NStr::CStr> const &_Unsorted)
			{
				NContainer::TCVector<NStr::CStr> Sorted;
				for (auto Iter = _Unsorted.f_GetIterator(); Iter; ++Iter)
				{
					if (Sorted.f_Contains(*Iter) == -1 && !(*Iter).f_IsEmpty())
						Sorted.f_Insert(*Iter);
				}

				Sorted.f_Sort();
				return Sorted;
			}

			static X509 *fs_LoadCertificate(NContainer::TCVector<uint8> const &_CertificateData)
			{
				g_SSLLowLevel->f_UseInThread();
				if (_CertificateData.f_IsEmpty())
					DMibErrorNetSSL("Empty certificate data");

				ERR_clear_error();
				BIO* pMemoryBio = BIO_new_mem_buf( const_cast<void *>(static_cast<void const *>(_CertificateData.f_GetArray())), _CertificateData.f_GetLen());
				if (!pMemoryBio)
					DMibErrorNetSSL(fg_GetExceptionStr("Error creating BIO buffer"));
				auto Cleanup = g_OnScopeExit > [&]
					{
						BIO_free(pMemoryBio);
					}
				;

				ERR_clear_error();
				X509 *pCertificate = PEM_read_bio_X509(pMemoryBio, nullptr, nullptr, nullptr);;
				if (!pCertificate)
					DMibErrorNetSSL(fg_GetExceptionStr("Error reading x509 certificate"));

				return pCertificate;
			}
			
			static X509_REQ *fs_LoadCertificateRequest(NContainer::TCVector<uint8> const &_CertificateRequestData)
			{
				g_SSLLowLevel->f_UseInThread();
				if (_CertificateRequestData.f_IsEmpty())
					DMibErrorNetSSL("Empty certificate request data");

				ERR_clear_error();
				BIO* pMemoryBio = BIO_new_mem_buf( const_cast<void*>(static_cast<void const *>(_CertificateRequestData.f_GetArray())), _CertificateRequestData.f_GetLen());
				if (!pMemoryBio)
					DMibErrorNetSSL(fg_GetExceptionStr("Error creating BIO buffer"));
				auto Cleanup = g_OnScopeExit > [&]
					{
						BIO_free(pMemoryBio);
					}
				;

				X509_REQ *pCertificateRequest = nullptr;
				ERR_clear_error();
				pCertificateRequest = PEM_read_bio_X509_REQ(pMemoryBio, nullptr, nullptr, nullptr);
				if (!pCertificateRequest)
					DMibErrorNetSSL(fg_GetExceptionStr("Error reading x509 certificate request"));

				return pCertificateRequest;
			}

			static NTime::CTime fs_GetCertificateExpirationTime(NContainer::TCVector<uint8> const &_CertificateData)
			{
				g_SSLLowLevel->f_UseInThread();
				X509 *pCertificate = fs_LoadCertificate(_CertificateData);
				auto Cleanup0 = g_OnScopeExit > [&]
					{
						X509_free(pCertificate);
					}
				;
				NTime::CTime Time = NTime::CTime::fs_StartOfTime();

				ASN1_TIME* pTime = X509_get_notAfter(pCertificate);
				if (!pTime)
					return Time;
				if (pTime->type == V_ASN1_UTCTIME)
				{
					if (pTime->length < 10)
						return NTime::CTime::fs_StartOfTime();

					const char* pData = (const char*)pTime->data;

					for (int i = 0; i < 10; ++i)
					{
						if ((pData[i] > '9') || (pData[i] < '0'))
							return NTime::CTime::fs_StartOfTime();
					}

					int Years = (pData[0]-'0')*10+(pData[1]-'0');
					if (Years < 50) Years += 100;
					Years += 1900;

					int Months = (pData[2]-'0')*10+(pData[3]-'0');
					if ((Months > 12) || (Months < 1))
						return NTime::CTime::fs_StartOfTime();
					
					int Days = (pData[4]-'0')*10+(pData[5]-'0');
					int Hours = (pData[6]-'0')*10+(pData[7]-'0');
					int Minutes =  (pData[8]-'0')*10+(pData[9]-'0');
					int Seconds = 0;

					if 
						(
							pTime->length >=12
							&& (pData[10] >= '0') && (pData[10] <= '9')
							&& (pData[11] >= '0') && (pData[11] <= '9')
						)
					{
						Seconds = (pData[10]-'0')*10+(pData[11]-'0');
					}

					Time = NTime::CTimeConvert::fs_CreateTime(Years, Months, Days, Hours, Minutes, Seconds);
				}
				else if (pTime->type == V_ASN1_GENERALIZEDTIME)
				{
					if (pTime->length < 12)
						return NTime::CTime::fs_StartOfTime();

					const char* pData = (const char*)pTime->data;

					for (int i = 0; i < 12; ++i)
					{
						if ((pData[i] > '9') || (pData[i] < '0'))
							return NTime::CTime::fs_StartOfTime();
					}

					int Years = (pData[0]-'0')*1000+(pData[1]-'0')*100 + (pData[2]-'0')*10+(pData[3]-'0');
					int Months = (pData[4]-'0')*10+(pData[5]-'0');
					if (Months > 12 || Months < 1)
						return NTime::CTime::fs_StartOfTime();

					int Days = (pData[6]-'0')*10+(pData[7]-'0');
					int Hours = (pData[8]-'0')*10+(pData[9]-'0');
					int Minutes =  (pData[10]-'0')*10+(pData[11]-'0');
					int Seconds = 0;

					if 
						(
							pTime->length >= 14
							&& (pData[12] >= '0') && (pData[12] <= '9')
							&& (pData[13] >= '0') && (pData[13] <= '9')
						)
					{
						Seconds = (pData[12]-'0')*10+(pData[13]-'0');
					}

					Time = NTime::CTimeConvert::fs_CreateTime(Years, Months, Days, Hours, Minutes, Seconds);
				}

				return Time;
			}

			static NContainer::TCVector<uint8> fs_ConvertX509ToBinary(X509 *_pCertificate)
			{
				g_SSLLowLevel->f_UseInThread();
				if (!_pCertificate)
					DMibErrorNetSSL("x509 certificate in nullptr");

				ERR_clear_error();
				BIO* pMemoryBio = BIO_new(BIO_s_mem());
				if (!pMemoryBio)
					DMibErrorNetSSL(fg_GetExceptionStr("Error creating BIO"));
				auto Cleanup = g_OnScopeExit > [&]
					{
						BIO_free(pMemoryBio);
					}
				;

				ERR_clear_error();
				if (!PEM_write_bio_X509(pMemoryBio, _pCertificate))
					DMibErrorNetSSL(fg_GetExceptionStr("Error writing certificate to BIO"));
				
				NContainer::TCVector<uint8> Return;
				Return.f_SetLen(pMemoryBio->num_write);
				ERR_clear_error();
				if (!BIO_read(pMemoryBio, Return.f_GetArray(), Return.f_GetLen()))
					DMibErrorNetSSL(fg_GetExceptionStr("Error reading certificate from BIO"));
				return Return;
			}

			static NContainer::TCVector<uint8> fs_ConvertX509RequestToBinary(X509_REQ *_pCertificateRequest)
			{
				g_SSLLowLevel->f_UseInThread();
				if (!_pCertificateRequest)
					DMibErrorNetSSL("x509 certificate request in nullptr");

				ERR_clear_error();
				BIO* pMemoryBio = BIO_new(BIO_s_mem());
				if (!pMemoryBio)
					DMibErrorNetSSL(fg_GetExceptionStr("Error creating BIO"));
				auto Cleanup = g_OnScopeExit > [&]
					{
						BIO_free(pMemoryBio);
					}
				;

				ERR_clear_error();
				if (!PEM_write_bio_X509_REQ(pMemoryBio, _pCertificateRequest))
					DMibErrorNetSSL(fg_GetExceptionStr("Error writing request to BIO"));
				
				NContainer::TCVector<uint8> Return;
				Return.f_SetLen(pMemoryBio->num_write);
				ERR_clear_error();
				if (!BIO_read(pMemoryBio, Return.f_GetArray(), Return.f_GetLen()))
					DMibErrorNetSSL(fg_GetExceptionStr("Error reading request from BIO"));
				return Return;
			}

			static NContainer::TCVector<uint8, NMem::CAllocator_HeapSecure> fs_ConvertKeyToBinary(EVP_PKEY *_pKey)
			{
				g_SSLLowLevel->f_UseInThread();
				if (!_pKey)
					DMibErrorNetSSL("Key in nullptr");

				ERR_clear_error();
				BIO* pMemoryBio = BIO_new(BIO_s_mem());
				if (!pMemoryBio)
					DMibErrorNetSSL(fg_GetExceptionStr("Error creating BIO"));
				auto Cleanup = g_OnScopeExit > [&]
					{
						BIO_free(pMemoryBio);
					}
				;

				ERR_clear_error();
				if (!PEM_write_bio_PrivateKey(pMemoryBio, _pKey, nullptr, nullptr, 0, nullptr, nullptr))
					DMibErrorNetSSL(fg_GetExceptionStr("Error writing private key to BIO"));
				
				NContainer::TCVector<uint8, NMem::CAllocator_HeapSecure> Return;
				Return.f_SetLen(pMemoryBio->num_write);
				ERR_clear_error();
				if (!BIO_read(pMemoryBio, Return.f_GetArray(), Return.f_GetLen()))
					DMibErrorNetSSL(fg_GetExceptionStr("Error reading private key from BIO"));
				return Return;
			}

			static EVP_PKEY *fs_LoadPrivateKey(NContainer::TCVector<uint8, NMem::CAllocator_HeapSecure> const &_Data)
			{
				g_SSLLowLevel->f_UseInThread();
				ERR_clear_error();

				BIO* pMemoryBio = BIO_new_mem_buf(const_cast<void*>(static_cast<void const*>(_Data.f_GetArray())), _Data.f_GetLen());
				if (!pMemoryBio)
					DMibErrorNetSSL(fg_GetExceptionStr("Failed to create BIO buffer"));
				auto Cleanup0 = g_OnScopeExit > [&]
					{
						BIO_free(pMemoryBio);
					}
				;

				ERR_clear_error();
				EVP_PKEY* pKey = PEM_read_bio_PrivateKey(pMemoryBio, nullptr, nullptr, nullptr);
				if (!pKey)
					DMibErrorNetSSL(fg_GetExceptionStr("Failed to read private key"));
				
				return pKey;
			}

			static void fs_GenerateKey(EVP_PKEY *_pKey, CCertificateOptions const &_Options)
			{
				switch (_Options.m_KeySetting.f_GetTypeID())
				{
				case ESSLKeyType_RSA:
					{
						ERR_clear_error();
						RSA *pRSA = RSA_generate_key(_Options.m_KeySetting.f_Get<ESSLKeyType_RSA>().m_KeyLength, RSA_F4, nullptr, nullptr);
						if (!pRSA)
							DMibErrorNetSSL(fg_GetExceptionStr("Error generating RSA key"));
						ERR_clear_error();
						if (!EVP_PKEY_assign_RSA(_pKey, pRSA))
							DMibErrorNetSSL(fg_GetExceptionStr("Error assigning RSA key"));
						pRSA = nullptr;
					}
					break;
				case ESSLKeyType_EC_secp256r1:
				case ESSLKeyType_EC_secp384r1:
				case ESSLKeyType_EC_secp521r1:
					{
						ERR_clear_error();
						EC_KEY *pECKey;
						
						int CurveName;
						switch (_Options.m_KeySetting.f_GetTypeID())
						{
						case ESSLKeyType_EC_secp256r1:
							CurveName = NID_X9_62_prime256v1;
							break;
						case ESSLKeyType_EC_secp384r1:
							CurveName = NID_secp384r1;
							break;
						case ESSLKeyType_EC_secp521r1:
							CurveName = NID_secp521r1;
							break;
						}
						
						ERR_clear_error();
						pECKey = EC_KEY_new_by_curve_name(CurveName);
						if (!pECKey)
							DMibErrorNetSSL(fg_GetExceptionStr("Error creating elliptic curve key"));
						auto Cleanup = g_OnScopeExit > [&]
							{
								EC_KEY_free(pECKey);
							}
						;
						ERR_clear_error();
						if (EC_KEY_generate_key(pECKey) != 1)
							DMibErrorNetSSL(fg_GetExceptionStr("Error generating elliptic curve key"));
						EC_KEY_set_asn1_flag(pECKey, OPENSSL_EC_NAMED_CURVE);
						ERR_clear_error();
						if (!EVP_PKEY_assign_EC_KEY(_pKey, pECKey))
							DMibErrorNetSSL(fg_GetExceptionStr("Error assigning elliptic curve key"));
						Cleanup.f_Clear();
					}
					break;
				default:
					DMibErrorNetSSL("Invalid key type");
				}
			}
			
			static X509_CRL* fs_LoadCRL(NContainer::TCVector<uint8> const &_CRLData)
			{
				g_SSLLowLevel->f_UseInThread();
				ERR_clear_error();
				BIO* pMemoryBio = BIO_new_mem_buf(const_cast<void*>(static_cast<void const*>(_CRLData.f_GetArray())), _CRLData.f_GetLen());
				if (!pMemoryBio)
					DMibErrorNetSSL(fg_GetExceptionStr("Error creating BIO"));
				auto Cleanup = g_OnScopeExit > [&]
					{
						BIO_free(pMemoryBio);
					}
				;

				ERR_clear_error();
				X509_CRL *pCRL = PEM_read_bio_X509_CRL(pMemoryBio, nullptr, nullptr, nullptr);
				if (!pCRL)
					DMibErrorNetSSL(fg_GetExceptionStr("Error reading x509 certificate revocation list from BIO"));

				return pCRL;
			}

		protected:

			void fp_ProcessSettings()
			{	
				g_SSLLowLevel->f_UseInThread();
				bool bSetClientFlags = false;

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
						bSetClientFlags = true;
				}
				else if (f_IsClientContext() && mp_Settings.m_VerificationFlags & CSSLSettings::EVerificationFlag_UseOSStoreIfNoCASpecified)
				{
					fp_LoadTrustedStoreFromOS();
					bSetClientFlags = true;
				}

				if (bSetClientFlags)
					X509_STORE_set_flags(SSL_CTX_get_cert_store(mp_pContext), X509_V_FLAG_CB_ISSUER_CHECK|X509_V_FLAG_HANSOFT_CONTINUE_AFTER_VERIFY_LEAF_SIGNATURE_ERROR);
				
				SSL_CTX_set_verify(mp_pContext, VerifyFlags, fs_VerifyCallback);

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
				g_SSLLowLevel->f_UseInThread();
				bool bUsingCertificateAuthority = false;

				if (!mp_Settings.m_CAStoreLocation.f_IsEmpty())
				{
					X509_STORE* pStore = mp_pContext->cert_store;

					if (!NFile::CFile::fs_FileExists(mp_Settings.m_CAStoreLocation, NFile::EFileAttrib_Directory))
						DMibErrorNetSSL(fg_Format("Certificate store location '{}' does not exist", mp_Settings.m_CAStoreLocation));
					else
					{
						NContainer::TCVector<NStr::CStr> lCertificateFiles = NFile::CFile::fs_FindFiles(mp_Settings.m_CAStoreLocation + "/*", NFile::EFileAttrib_File, false);
						
						if (lCertificateFiles.f_IsEmpty())
							DMibErrorNetSSL(fg_Format("No certificates found at location '{}'", mp_Settings.m_CAStoreLocation));

						for (auto Iter = lCertificateFiles.f_GetIterator(); Iter; ++Iter)
						{
							NContainer::TCVector<uint8> CertificateData = NFile::CFile::fs_ReadFile(*Iter);
							if (CertificateData.f_IsEmpty())
								continue;

							bUsingCertificateAuthority = true;

							X509 *pCertificate = fs_LoadCertificate(CertificateData);
							auto Cleanup0 = g_OnScopeExit > [&]
								{
									X509_free(pCertificate);
								}
							;

							ERR_clear_error();
							if (!X509_STORE_add_cert(pStore, pCertificate))
								DMibErrorNetSSL(fg_GetExceptionStr(fg_Format("Failed to add certificate '{}' to store", *Iter)));
						}
						
						if (!bUsingCertificateAuthority)
							DMibErrorNetSSL(fg_Format("No certificates found at location '{}'", mp_Settings.m_CAStoreLocation));
					}
				}

				if (!mp_Settings.m_CACertificateData.f_IsEmpty())
				{
					X509_STORE* pStore = mp_pContext->cert_store;
					X509 *pCertificate = fs_LoadCertificate(mp_Settings.m_CACertificateData);
					auto Cleanup0 = g_OnScopeExit > [&]
						{
							X509_free(pCertificate);
						}
					;

					ERR_clear_error();
					if (!X509_STORE_add_cert(pStore, pCertificate))
						DMibErrorNetSSL(fg_GetExceptionStr("Failed to add certificate '{}' to store"));

					bUsingCertificateAuthority = true;
				}

				return bUsingCertificateAuthority;
			}

			bool fp_LoadPublicCertificate()
			{
				if (mp_Settings.m_PublicCertificateData.f_IsEmpty())
					return false;

				g_SSLLowLevel->f_UseInThread();
				X509 *pCertificate = fs_LoadCertificate(mp_Settings.m_PublicCertificateData);
				auto Cleanup0 = g_OnScopeExit > [&]
					{
						X509_free(pCertificate);
					}
				;

				ERR_clear_error();
				if (SSL_CTX_use_certificate(mp_pContext, pCertificate) <= 0)
					DMibErrorNetSSL(fg_GetExceptionStr("Failed to add certificate '{}' to store"));

				return true;
			}

			void fp_LoadCRLs()
			{
				g_SSLLowLevel->f_UseInThread();
				if (!mp_Settings.m_CRLData.f_IsEmpty())
				{
					ERR_clear_error();
					X509_STORE* pStore = SSL_CTX_get_cert_store(mp_pContext);
					if (!pStore)
						DMibErrorNetSSL(fg_GetExceptionStr("Failed to get cert store"));

					ERR_clear_error();
					X509_LOOKUP* pLookup = X509_STORE_add_lookup(pStore, X509_LOOKUP_file());
					if (!pLookup)
						DMibErrorNetSSL(fg_GetExceptionStr("Failed to add lookup file to store"));

					X509_CRL* pCRL = fs_LoadCRL(mp_Settings.m_CRLData);
					
					auto Cleanup = g_OnScopeExit > [&]
						{
							X509_CRL_free(pCRL);
						}
					;

					ERR_clear_error();
					if (!X509_STORE_add_crl(pLookup->store_ctx, pCRL))
						DMibErrorNetSSL(fg_GetExceptionStr("Failed to add certificate revocation list to store"));

					ERR_clear_error();
					if (!X509_STORE_set_flags(pStore, X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL))
						DMibErrorNetSSL(fg_GetExceptionStr("Failed to set store flags"));
				}
				
				if (!mp_Settings.m_PathToCRLs.f_IsEmpty())
				{
					ERR_clear_error();
					X509_STORE* pStore = SSL_CTX_get_cert_store(mp_pContext);
					if (!pStore)
						DMibErrorNetSSL(fg_GetExceptionStr("Failed to get cert store"));

					if (!NFile::CFile::fs_FileExists(mp_Settings.m_PathToCRLs, NFile::EFileAttrib_Directory))
						DMibErrorNetSSL(fg_Format("CRL path '{}' does not exist", mp_Settings.m_PathToCRLs));
					
					NContainer::TCVector<NStr::CStr> lCRLFiles = NFile::CFile::fs_FindFiles(mp_Settings.m_PathToCRLs + "/*", NFile::EFileAttrib_File, false);

					bool bAdded = false;
					for (auto Iter = lCRLFiles.f_GetIterator(); Iter; ++Iter)
					{
						NContainer::TCVector<uint8> CRLData = NFile::CFile::fs_ReadFile(*Iter);
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
							DMibErrorNetSSL(fg_GetExceptionStr("Failed to add certificate revocation list to store"));
						bAdded = true;
					}

					if (bAdded)
						X509_STORE_set_flags(pStore, X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);
				}
			}

			bool fp_LoadPrivateKey()
			{
				g_SSLLowLevel->f_UseInThread();
				if (mp_Settings.m_PrivateKeyData.f_IsEmpty())
					return false;

				EVP_PKEY* pKey = fs_LoadPrivateKey(mp_Settings.m_PrivateKeyData); 
				auto Cleanup = g_OnScopeExit > [&]
					{
						EVP_PKEY_free(pKey);
					}
				;

				if (f_IsServerContext())
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
								CurveName = NID_X9_62_prime256v1;
						}
						
						if (SSL_CTX_set_tmp_dh(mp_pContext, pDHParam) != 1)
							DMibErrorNetSSL(fg_GetExceptionStr("Failed to set tmp dh param in SSL context"));
						DH_free(pDHParam);
					}
					else if (auto pECKey = EVP_PKEY_get1_EC_KEY(pKey))
					{
						CurveName = EC_GROUP_get_curve_name(EC_KEY_get0_group(pECKey));
						if (!CurveName)
							CurveName = NID_secp521r1;
						EC_KEY_free(pECKey);
					}
					if (CurveName)
					{
						EC_KEY *pECDH = EC_KEY_new_by_curve_name(CurveName);
						if (pECDH)
						{
						    SSL_CTX_set_options(mp_pContext, SSL_OP_SINGLE_ECDH_USE);
							if (SSL_CTX_set_tmp_ecdh(mp_pContext, pECDH) != 1)
								SSL_CTX_set_ecdh_auto(mp_pContext, 1);
							EC_KEY_free(pECDH);		
						}
						else
							SSL_CTX_set_ecdh_auto(mp_pContext, 1);
					}
				}
				
				ERR_clear_error();
				if (SSL_CTX_use_PrivateKey(mp_pContext, pKey) <= 0)
					DMibErrorNetSSL(fg_GetExceptionStr("Failed to use private key in SSL context"));
				
				return true;
			}

			void fp_VerifyPublicCertAndPrivateKey()
			{
				g_SSLLowLevel->f_UseInThread();
				ERR_clear_error();
				if (!SSL_CTX_check_private_key(mp_pContext))
					DMibErrorNetSSL(fg_GetExceptionStr("Certificate private and public key verfication failed"));
			}

		#if defined(DPlatformFamily_Windows)

			#include <Wincrypt.h>
			#pragma comment(lib, "crypt32.lib")

			void fp_LoadTrustedStoreFromOS()
			{
				g_SSLLowLevel->f_UseInThread();
				
				X509_STORE* pStore = mp_pContext->cert_store;

				auto fl_LoadFromStore = [&] (LPCWSTR _pStore)
				{
					HCERTSTORE hStore = CertOpenSystemStore(NULL, _pStore);
					for (PCCERT_CONTEXT pCertContext = CertEnumCertificatesInStore(hStore, nullptr); pCertContext; pCertContext = CertEnumCertificatesInStore(hStore, pCertContext))
					{
						NStr::CStr OutputType = fsp_IsPKCS7(pCertContext->dwCertEncodingType) ? "PKCS7" : "CERTIFICATE";
						NContainer::TCVector<uint8> Data;
						Data.f_Insert(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded);
						NStr::CStr CertData = NDataProcessing::fg_Base64Encode(Data);
						NStr::CStr CertAsString = NStr::CStr::CFormat("-----BEGIN {}-----\n{}\n-----END {}-----\n") << OutputType << CertData << OutputType;

						NContainer::TCVector<uint8> lCertData;
						lCertData.f_SetLen(CertAsString.f_GetLen());
						NMem::fg_MemCopy(lCertData.f_GetArray(), CertAsString.f_GetStr(), CertAsString.f_GetLen());

						X509 *pCertificate;
						try
						{
							pCertificate = fs_LoadCertificate(lCertData);
						}
						catch (CExceptionNetSSL const &)
						{
							continue;
						}
						auto Cleanup0 = g_OnScopeExit > [&]
							{
								X509_free(pCertificate);
							}
						;

						X509_STORE_add_cert(pStore, pCertificate);
					}

					CertCloseStore(hStore, 0);
				};

				fl_LoadFromStore(L"ROOT");
				fl_LoadFromStore(L"CA");
			}

			static bool fsp_IsPKCS7(DWORD _EncodeType)
			{
				return ((_EncodeType & PKCS_7_ASN_ENCODING) == PKCS_7_ASN_ENCODING);
			}

		#elif defined(DPlatformFamily_OSX)
			
			void fp_LoadTrustedStoreFromOS()
			{
				g_SSLLowLevel->f_UseInThread();

				X509_STORE* pStore = mp_pContext->cert_store;
				
				auto fAddTrustStore = [&](CFArrayRef pCerts)
					{
						for (int i = 0; i < CFArrayGetCount(pCerts); ++i)
						{
							SecCertificateRef CertRef = reinterpret_cast<SecCertificateRef>(const_cast<void*>(CFArrayGetValueAtIndex(pCerts, i)));
							
							X509 *pCertificate;
			#if DPlatformVersionMax >= 1060
							if (CSystem::ms_PlatformVersion >= 10'06'00)
							{
								CFDataRef DERCert = SecCertificateCopyData(CertRef);
								if (!DERCert)
									continue;
								
								unsigned const char *pDERCert = CFDataGetBytePtr(DERCert);
								mint DataLength = CFDataGetLength(DERCert);
								pCertificate = d2i_X509(nullptr, &pDERCert, DataLength);
								CFRelease(DERCert);
							}
							else
			#endif
							{
								DMibDeprecatedSupressStart;
								// This code is not tested. Is it in the right format?
								CSSM_DATA certCSSMData;
								if (SecCertificateGetData(CertRef, &certCSSMData) != 0 || certCSSMData.Length == 0)
									continue;
								unsigned const char *pDERCert = certCSSMData.Data;
								mint DataLength = certCSSMData.Length;
								pCertificate = d2i_X509(nullptr, &pDERCert, DataLength);
								DMibDeprecatedSupressStop;
							}
							
							if (!pCertificate)
								continue;
							
							auto Cleanup = g_OnScopeExit > [&]
								{
									X509_free(pCertificate);
								}
							;

							X509_STORE_add_cert(pStore, pCertificate);
						}
						CFRelease(pCerts);
					}
				;

				if (CSystem::ms_PlatformVersion >= 10'05'00)
				{
					CFArrayRef pCerts;
					if (SecTrustSettingsCopyCertificates(kSecTrustSettingsDomainSystem, &pCerts) == 0)
						fAddTrustStore(pCerts);
					if (SecTrustSettingsCopyCertificates(kSecTrustSettingsDomainAdmin, &pCerts) == 0)
						fAddTrustStore(pCerts);
					if (SecTrustSettingsCopyCertificates(kSecTrustSettingsDomainUser, &pCerts) == 0)
						fAddTrustStore(pCerts);
 				}
				else
				{
					CFArrayRef pCerts;
					if (SecTrustCopyAnchorCertificates(&pCerts) == 0)
						fAddTrustStore(pCerts);
				}
			}
			
		#else

			void fp_LoadTrustedStoreFromOS()
			{
				g_SSLLowLevel->f_UseInThread();
				auto fl_LoadCerts =
					[&](NStr::CStr const  &_File) -> bool
					{
						try
						{
							if (!NFile::CFile::fs_FileExists(_File, NFile::EFileAttrib_File))
							{
								DMibLog(Debug, "Unable to find: {}", _File);
								return false;
							}
						}
						catch (NFile::CExceptionFile const  &_Exception)
						{
							DMibLog(Debug, "Exception trying to check file exists on: {}. The error reported was {}", _File, _Exception.f_GetErrorStr());
							return false;
						}
				
						int Ret = SSL_CTX_load_verify_locations(mp_pContext, _File.f_GetStr(), nullptr);
						if (Ret == 0)
						{
							DMibLog(Debug, "Failed to load SSL verify location: {}. The error reported was {}", _File, fg_GetErrors());
							return false;
						}
						else
						{
							DMibLog(Debug, "Successfully added {} to SSL verify locations", _File);
							return true;
						}
					};
				
				if (fl_LoadCerts("/etc/ssl/certs/ca-certificates.crt"))
					return;
				else if (fl_LoadCerts("/etc/ssl/certs/ca-bundle.crt"))
					return;
			}

		#endif

			SSL_CTX* mp_pContext;

			CSSLContext::EType mp_Type;
			CSSLContext::EState mp_State;

			CSSLSettings mp_Settings;

		};

		bool CSSLContext::CCertificateExtension::operator == (CCertificateExtension const &_Right) const
		{
			return NContainer::fg_TupleReferences(m_bCritical, m_Value) == NContainer::fg_TupleReferences(_Right.m_bCritical, _Right.m_Value); 
		}
		
		bool CSSLContext::CCertificateExtension::operator < (CCertificateExtension const &_Right) const
		{
			return NContainer::fg_TupleReferences(m_bCritical, m_Value) < NContainer::fg_TupleReferences(_Right.m_bCritical, _Right.m_Value); 
		}
		
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

		NPtr::TCUniquePointer<CSSLContext::CSession> CSSLContext::fp_CreateSession()
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

		CSSLSettings const& CSSLContext::f_GetSettings() const
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

		NStr::CStr CSSLContext::fs_GetCertificateName(NContainer::TCVector<uint8> const &_CertificateData)
		{
			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						return CSSLContext::CInternal::fs_GetCertificateName(_CertificateData);
					}
				)
			;
		}
		
		NStr::CStr CSSLContext::fs_GetCertificateFingerprint(NContainer::TCVector<uint8> const &_CertificateData)
		{
			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						return CSSLContext::CInternal::fs_GetCertificateFingerprint(_CertificateData);
					}
				)
			;
		}

		NStr::CStr CSSLContext::fs_GetIssuerName(NContainer::TCVector<uint8> const &_CertificateData)
		{
			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						return CSSLContext::CInternal::fs_GetIssuerName(_CertificateData);
					}
				)
			;
		}

		NContainer::TCVector<NStr::CStr> CSSLContext::fs_GetCertificateHostnames(NContainer::TCVector<uint8> const &_CertificateData, bool _bCheckCommonName)
		{
			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						return CSSLContext::CInternal::fs_GetCertificateHostnames(_CertificateData, _bCheckCommonName);
					}
				)
			;
		}
		
		NContainer::TCMap<NStr::CStr, NContainer::TCVector<CSSLContext::CCertificateExtension>> CSSLContext::fs_GetCertificateExtensions(NContainer::TCVector<uint8> const &_CertificateData)
		{
			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						return CSSLContext::CInternal::fs_GetCertificateExtensions(_CertificateData);
					}
				)
			;
		}

		NContainer::TCMap<NStr::CStr, NContainer::TCVector<CSSLContext::CCertificateExtension>> CSSLContext::fs_GetCertificateRequestExtensions
			(
				NContainer::TCVector<uint8> const &_CertificateData
			)
		{
			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						return CSSLContext::CInternal::fs_GetCertificateRequestExtensions(_CertificateData);
					}
				)
			;
		}

		NContainer::TCVector<NStr::CStr> CSSLContext::fs_GetSortedHostnames(NContainer::TCVector<NStr::CStr> const &_Unsorted)
		{
			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						return CSSLContext::CInternal::fs_GetSortedHostnames(_Unsorted);
					}
				)
			;
		}

		NStr::CStr CSSLContext::fs_GetCertificateHostnamesStr(NContainer::TCVector<uint8> const &_CertificateData)
		{
			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						return CSSLContext::CInternal::fs_GetCertificateHostnamesStr(_CertificateData);
					}
				)
			;
		}

		NTime::CTime CSSLContext::fs_GetCertificateExpirationTime(NContainer::TCVector<uint8> const &_CertificateData)
		{
			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						return CSSLContext::CInternal::fs_GetCertificateExpirationTime(_CertificateData);
					}
				)
			;
		}

		NStr::CStr CSSLContext::fs_GetCertificateDescription(NContainer::TCVector<uint8> const &_CertificateData)
		{
			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						return CSSLContext::CInternal::fs_GetCertificateDescription(_CertificateData);
					}
				)
			;
		}

		NStr::CStr CSSLContext::fs_GetCertificateInformation(NContainer::TCVector<uint8> const &_CertificateData)
		{
			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						return CSSLContext::CInternal::fs_GetCertificateInformation(_CertificateData);
					}
				)
			;
		}
		
		void CSSLContext::fs_RegisterExtension(NStr::CStr const &_OID, NStr::CStr const &_ShortName, NStr::CStr const &_LongName)
		{
			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						OBJ_create(_OID, _ShortName, _LongName);
					}
				)
			;
		}

		namespace
		{
			X509_EXTENSION *fg_CreateExtension(X509V3_CTX &_Context, int _nID, CSSLContext::CCertificateExtension _Extension)
			{
				X509_EXTENSION *pExtension = nullptr;

				ERR_clear_error();
				pExtension = X509V3_EXT_conf_nid(nullptr, &_Context, _nID, _Extension.m_Value.f_GetStrUniqueWritable());
				if (pExtension)
					return pExtension; 

				int Critical = _Extension.m_bCritical;
				ASN1_UTF8STRING *pValue = nullptr;

				ERR_clear_error();
				pValue = ASN1_UTF8STRING_new();
				if (!pValue)
					DMibErrorNetSSL(fg_GetExceptionStr("Failed to create ASN1 value"));

				auto Cleanup = g_OnScopeExit > [&]
					{
						pValue->length = 0;
						pValue->data = nullptr;
						ASN1_UTF8STRING_free(pValue);
					}
				;
				pValue->length = _Extension.m_Value.f_GetLen();
				pValue->data = (unsigned char *)_Extension.m_Value.f_GetStrUniqueWritable();
				ERR_clear_error();
				pExtension = X509_EXTENSION_create_by_NID(&pExtension, _nID, Critical, pValue);
				if (!pExtension)
					DMibErrorNetSSL(fg_GetExceptionStr("Failed to create extension"));
						
				return pExtension;
			}
			void fg_AddExtension(X509V3_CTX &_Context, X509 *_pCert, int _nID, CSSLContext::CCertificateExtension _Extension)
			{
				X509_EXTENSION *pExtension = nullptr;
				pExtension = fg_CreateExtension(_Context, _nID, _Extension);

				auto Cleanup1 = g_OnScopeExit > [&]
					{
						X509_EXTENSION_free(pExtension);
					}
				;
				
				ERR_clear_error();
				if (!X509_add_ext(_pCert,pExtension,-1))
					DMibErrorNetSSL(fg_GetExceptionStr("Error adding x509 extension"));
			}
			
			void fg_AddExtension(X509V3_CTX &_Context, X509_EXTENSIONS *&_pExtensions, int _nID, CSSLContext::CCertificateExtension _Extension)
			{
				X509_EXTENSION *pExtension = fg_CreateExtension(_Context, _nID, _Extension);
				auto Cleanup = g_OnScopeExit > [&]
					{
						X509_EXTENSION_free(pExtension);
					}
				;
				
				ERR_clear_error();
				X509v3_add_ext(&_pExtensions, pExtension, -1);
			}
			
			template <typename tf_CObject>
			void fg_AddHostnames(X509V3_CTX &_Context, tf_CObject *&_pObject, NContainer::TCVector<NStr::CStr> const &_Hostnames)
			{
				NContainer::TCVector<NStr::CStr> SortedHosts = CSSLContext::fs_GetSortedHostnames(_Hostnames);

				NStr::CStr Output;
				for (auto Iter = SortedHosts.f_GetIterator(); Iter; ++Iter)
				{
					if (Output.f_IsEmpty())
						Output = NStr::CStr::CFormat("DNS:{}") << (*Iter);
					else
						Output += NStr::CStr::CFormat(",DNS:{}") << (*Iter);
				}
				
				CSSLContext::CCertificateExtension Extension;
				Extension.m_Value = Output;
				fg_AddExtension(_Context, _pObject, NID_subject_alt_name, Extension);
			}
			
			template <typename tf_CObject>
			void fg_AddExtensions(X509V3_CTX &_Context, tf_CObject *&_pObject, NContainer::TCMap<NStr::CStr, NContainer::TCVector<CSSLContext::CCertificateExtension>> const &_Extensions)
			{
				for (auto iExtension = _Extensions.f_GetIterator(); iExtension; ++iExtension)
				{
					ERR_clear_error();
					int NumericID = OBJ_txt2nid(iExtension.f_GetKey());
					
					if (NumericID == NID_undef)
						DMibErrorNetSSL(fg_GetExceptionStr(fg_Format("Unknown extension '{}'", iExtension.f_GetKey())));

					for (auto &Extension : *iExtension)
						fg_AddExtension(_Context, _pObject, NumericID, Extension);
				}
			}
			
			const EVP_MD *fg_GetDigest(ESSLDigest _Digest, EVP_PKEY *_pKey)
			{
				switch (_Digest)
				{
				case ESSLDigest_Automatic:
					{
						if (auto pRSA = EVP_PKEY_get1_RSA(_pKey))
						{
							auto RSASize = RSA_size(pRSA) * 8;
							RSA_free(pRSA);

							if (RSASize >= 12288)
								return EVP_sha512();
							else if (RSASize >= 4096)
								return EVP_sha384();
							else
								return EVP_sha256();
						}
						else if (auto pECKey = EVP_PKEY_get1_EC_KEY(_pKey))
						{
							auto CurveName = EC_GROUP_get_curve_name(EC_KEY_get0_group(pECKey));
							
							switch (CurveName)
							{
							case NID_secp521r1:
								return EVP_sha512();
							case NID_secp384r1:
								return EVP_sha384();
							case NID_X9_62_prime256v1:
								return EVP_sha256();
							}
							EC_KEY_free(pECKey);
						}
						return EVP_sha384();
					}
				case ESSLDigest_SHA256: return EVP_sha256();
				case ESSLDigest_SHA384: return EVP_sha384();
				case ESSLDigest_SHA512: return EVP_sha512();
				}
				DMibNeverGetHere;
				return EVP_sha384();
			}
		}
		
		// openssl genrsa -des3 -out client.key 4096
		// openssl req -new -key client.key -out client.csr
		void CSSLContext::fs_GenerateClientCertificateRequest
			(
				CCertificateOptions const &_Options
				, NContainer::TCVector<uint8> &o_CertRequestData
				, NContainer::TCVector<uint8, NMem::CAllocator_HeapSecure> &o_KeyData
				, ESSLDigest _Digest
			)
		{
			fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						g_SSLLowLevel->f_UseInThread();
						o_CertRequestData.f_Clear();
			
						bool bGenerateNewKey = o_KeyData.f_IsEmpty(); 

						EVP_PKEY *pKey;
						if (bGenerateNewKey)
						{
							ERR_clear_error();
							pKey = EVP_PKEY_new();
							if (!pKey)
								DMibErrorNetSSL(fg_GetExceptionStr("Error creating key"));
						}
						else
							pKey = CSSLContext::CInternal::fs_LoadPrivateKey(o_KeyData);
			
						auto Cleanup0 = g_OnScopeExit > [&] ()
							{
								EVP_PKEY_free(pKey);
							}
						;
			
						ERR_clear_error();
						X509_REQ *pCertificateRequest = X509_REQ_new();
						if (!pCertificateRequest)
							DMibErrorNetSSL(fg_GetExceptionStr("Error creating certificate request"));
						auto Cleanup1 = g_OnScopeExit > [&] ()
							{
								X509_REQ_free(pCertificateRequest);
							}
						;

						if (bGenerateNewKey)
							CSSLContext::CInternal::fs_GenerateKey(pKey, _Options);
			
						ERR_clear_error();
						if (!X509_NAME_add_entry_by_txt(X509_REQ_get_subject_name(pCertificateRequest), "CN", MBSTRING_ASC, (const unsigned char*)_Options.m_Subject.f_GetStr(), -1, -1, 0))
							DMibErrorNetSSL(fg_GetExceptionStr("Error adding CN entry"));
			
						X509_EXTENSIONS *pExtensions = nullptr;
			
						auto Cleanup2 = g_OnScopeExit > [&]
							{
								if (pExtensions)
									sk_X509_EXTENSION_pop_free(pExtensions, X509_EXTENSION_free);
							}
						;
			
						{
							X509V3_CTX Context;
							X509V3_set_ctx_nodb(&Context);
							X509V3_set_ctx(&Context, nullptr, nullptr, pCertificateRequest, nullptr, 0);
							if (!_Options.m_Hostnames.f_IsEmpty())
								fg_AddHostnames(Context, pExtensions, _Options.m_Hostnames);
				
							if (!_Options.m_Extensions.f_IsEmpty())
								fg_AddExtensions(Context, pExtensions, _Options.m_Extensions);
						}

						if (pExtensions)
						{
							if (!X509_REQ_add_extensions(pCertificateRequest, pExtensions))
								DMibErrorNetSSL(fg_GetExceptionStr("Error adding x509 req extensions"));
						}

						ERR_clear_error();
						if (!X509_REQ_set_pubkey(pCertificateRequest, pKey))
							DMibErrorNetSSL(fg_GetExceptionStr("Error setting request public key"));

						ERR_clear_error();
						if (!X509_REQ_sign(pCertificateRequest, pKey, fg_GetDigest(_Digest, pKey)))
							DMibErrorNetSSL(fg_GetExceptionStr("Error signing request"));

						o_CertRequestData = CSSLContext::CInternal::fs_ConvertX509RequestToBinary(pCertificateRequest);
						if (bGenerateNewKey)
							o_KeyData = CSSLContext::CInternal::fs_ConvertKeyToBinary(pKey);
					}
				)
			;
		}
		
		// openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out client.crt

		void CSSLContext::fs_VerifyCertificateRequestSameKeyAsCertificate(NContainer::TCVector<uint8> const &_CertRequestData, NContainer::TCVector<uint8> const &_CertData)
		{
			fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						g_SSLLowLevel->f_UseInThread();
						
						X509_REQ *pCertificateRequest = CSSLContext::CInternal::fs_LoadCertificateRequest(_CertRequestData);
						auto Cleanup0 = g_OnScopeExit > [&] ()
							{
								X509_REQ_free(pCertificateRequest);
							}
						;

						X509 *pCertificate = CSSLContext::CInternal::fs_LoadCertificate(_CertData);
						auto Cleanup3 = g_OnScopeExit > [&] ()
							{
								X509_free(pCertificate);
							}
						;
			
						// Get public key from certificate
						ERR_clear_error();
						auto pPublicKey = X509_get_pubkey(pCertificate);
						if (!pPublicKey)
							DMibErrorNetSSL(fg_GetExceptionStr("Found no public key in certificate"));
						auto Cleanup = g_OnScopeExit > [&]
							{
								EVP_PKEY_free(pPublicKey);
							}
						;

						// Verify with certificate request
						ERR_clear_error();
						int VerifyResult = X509_REQ_verify(pCertificateRequest, pPublicKey);
						if (VerifyResult < 0)
							DMibErrorNetSSL(fg_GetExceptionStr("Signature verification error"));
						else if (VerifyResult == 0)
							DMibErrorNetSSL("Certificate request signature mismatch");
					}
				)
			;
		}

		void CSSLContext::fs_SignClientCertificate
			(
				NContainer::TCVector<uint8> const &_CACertificate
				, NContainer::TCVector<uint8, NMem::CAllocator_HeapSecure> const &_CAKey
				, NContainer::TCVector<uint8> const &_CertRequestData
				, NContainer::TCVector<uint8> &o_SignedCertificateData
				, CSignOptions const &_SignOptions
			)
		{
			fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						g_SSLLowLevel->f_UseInThread();
						o_SignedCertificateData.f_Clear();

						X509_REQ *pCertificateRequest = CSSLContext::CInternal::fs_LoadCertificateRequest(_CertRequestData);
						auto Cleanup0 = g_OnScopeExit > [&] ()
							{
								X509_REQ_free(pCertificateRequest);
							}
						;
			
						EVP_PKEY *pCAKey = CSSLContext::CInternal::fs_LoadPrivateKey(_CAKey);
						auto Cleanup2 = g_OnScopeExit > [&] ()
							{
								EVP_PKEY_free(pCAKey);
							}
						;

						X509 *pCACertificate = CSSLContext::CInternal::fs_LoadCertificate(_CACertificate);
						auto Cleanup3 = g_OnScopeExit > [&] ()
							{
								X509_free(pCACertificate);
							}
						;

						ERR_clear_error();
						X509 *pCertificate = X509_new();
						if (!pCertificate)
							DMibErrorNetSSL(fg_GetExceptionStr("Error creating certificate"));
						auto Cleanup1 = g_OnScopeExit > [&] ()
							{
								X509_free(pCertificate);
							}
						;
			
						{
							if 
								(
									(!pCertificateRequest->req_info)
									|| (!pCertificateRequest->req_info->pubkey)
									|| (!pCertificateRequest->req_info->pubkey->public_key)
									|| (!pCertificateRequest->req_info->pubkey->public_key->data)
								) 
							{
								DMibErrorNetSSL("The certificate request does not contain a public key");
							}
							ERR_clear_error();
							EVP_PKEY *pPublicKey = X509_REQ_get_pubkey(pCertificateRequest); 
							if (!pPublicKey)
								DMibErrorNetSSL(fg_GetExceptionStr("Error unpacking public key"));
				
							auto Cleanup = g_OnScopeExit > [&] ()
								{
									EVP_PKEY_free(pPublicKey);
								}
							;
							ERR_clear_error();
							int VerifyResult = X509_REQ_verify(pCertificateRequest, pPublicKey);
							if (VerifyResult < 0)
								DMibErrorNetSSL(fg_GetExceptionStr("Signature verification error"));
							else if (VerifyResult == 0)
								DMibErrorNetSSL("Certificate request signature mismatch");
						}
			
						ERR_clear_error();
						if (!X509_set_version(pCertificate, 2))
							DMibErrorNetSSL(fg_GetExceptionStr("Error setting x509 version"));

						ERR_clear_error();
						if (!ASN1_INTEGER_set(X509_get_serialNumber(pCertificate), _SignOptions.m_Serial))
							DMibErrorNetSSL(fg_GetExceptionStr("Error setting x509 serial"));
				
						ERR_clear_error();
						if (!X509_gmtime_adj(X509_get_notBefore(pCertificate), 0))
							DMibErrorNetSSL(fg_GetExceptionStr("Error setting x509 not before"));
				
						ERR_clear_error();
						if (!X509_gmtime_adj(X509_get_notAfter(pCertificate), (long)60*60*24*_SignOptions.m_Days))
							DMibErrorNetSSL(fg_GetExceptionStr("Error setting x509 not after"));

						ERR_clear_error();
						if (!X509_set_issuer_name(pCertificate, X509_get_subject_name(pCACertificate)))
							DMibErrorNetSSL(fg_GetExceptionStr("Error setting x509 issuer"));
			
						ERR_clear_error();
						if (!X509_set_subject_name(pCertificate, pCertificateRequest->req_info->subject))
							DMibErrorNetSSL(fg_GetExceptionStr("Error setting x509 subject name"));

						{
							ERR_clear_error();
							auto pPublicKey = X509_REQ_get_pubkey(pCertificateRequest);
							if (!pPublicKey)
								DMibErrorNetSSL(fg_GetExceptionStr("Found no public key in certificate"));
							auto Cleanup = g_OnScopeExit > [&]
								{
									EVP_PKEY_free(pPublicKey);
								}
							;
				
							ERR_clear_error();
							if (!X509_set_pubkey(pCertificate, pPublicKey))
								DMibErrorNetSSL(fg_GetExceptionStr("Error setting x509 public key"));
						}

						{
							ERR_clear_error();
							auto pCAPublicKey = X509_get_pubkey(pCACertificate);
							if (!pCAPublicKey)
								DMibErrorNetSSL(fg_GetExceptionStr("Error getting CA certificate public key"));
							auto Cleanup = g_OnScopeExit > [&]
								{
									EVP_PKEY_free(pCAPublicKey);
								}
							;
				
							EVP_PKEY_copy_parameters(pCAPublicKey, pCAKey);
						}

						{
							X509_EXTENSIONS *pExtensions = X509_REQ_get_extensions(pCertificateRequest);
			
							auto Cleanup = g_OnScopeExit > [&]
								{
									if (pExtensions)
										sk_X509_EXTENSION_pop_free(pExtensions, X509_EXTENSION_free);
								}
							;
				
							if (pExtensions)
							{
								ERR_clear_error();
								int nExtensions = X509v3_get_ext_count(pExtensions);
								if (nExtensions < 0)
									DMibErrorNetSSL(fg_GetExceptionStr("Failed to get extension count from certificate request"));
						
								for (int iExtension = 0; iExtension < nExtensions; ++iExtension)
								{
									ERR_clear_error();
									auto *pExtension = X509v3_get_ext(pExtensions, iExtension);
									if (!pExtension)
										DMibErrorNetSSL(fg_GetExceptionStr("Failed to get extension from certificate request"));
									ERR_clear_error();
									if (!X509_add_ext(pCertificate, pExtension, -1))
										DMibErrorNetSSL(fg_GetExceptionStr("Failed to add extension to certificate"));
								}
							}
						}

			
						ERR_clear_error();
						if (!X509_check_private_key(pCACertificate, pCAKey))
							DMibErrorNetSSL(fg_GetExceptionStr("CA certificate and CA private key do not match"));

						ERR_clear_error();
						if (!X509_sign(pCertificate, pCAKey, fg_GetDigest(_SignOptions.m_Digest, pCAKey)))
							DMibErrorNetSSL(fg_GetExceptionStr("Error signing certificate request"));

						o_SignedCertificateData = CSSLContext::CInternal::fs_ConvertX509ToBinary(pCertificate);
					}
				)
			;
		}
		
		// openssl genrsa -des3 -out ca.key 4096
		// openssl req -new -x509 -days 365 -key ca.key -out ca.crt
		
		void CSSLContext::fs_GenerateSelfSignedCertAndKey
			(
				CCertificateOptions const &_Options
				, NContainer::TCVector<uint8> &o_CertData
				, NContainer::TCVector<uint8, NMem::CAllocator_HeapSecure> &o_KeyData
				, CSignOptions const &_SignOptions
			)
		{
			fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						g_SSLLowLevel->f_UseInThread();
						o_CertData.f_Clear();
						o_KeyData.f_Clear();

						ERR_clear_error();
						X509 *pCertificate = X509_new();
						if (!pCertificate)
							DMibErrorNetSSL(fg_GetExceptionStr("Error creating certificate"));
						auto Cleanup0 = g_OnScopeExit > [&] ()
							{
								X509_free(pCertificate);
							}
						;
						ERR_clear_error();
						EVP_PKEY* pKey = EVP_PKEY_new();
						if (!pKey)
							DMibErrorNetSSL(fg_GetExceptionStr("Error creating key"));
						auto Cleanup1 = g_OnScopeExit > [&] ()
							{
								EVP_PKEY_free(pKey);
							}
						;
						
						CSSLContext::CInternal::fs_GenerateKey(pKey, _Options);
						
						ERR_clear_error();
						if (!X509_set_version(pCertificate, 2))
							DMibErrorNetSSL(fg_GetExceptionStr("Error setting x509 version"));

						ERR_clear_error();
						if (!ASN1_INTEGER_set(X509_get_serialNumber(pCertificate), _SignOptions.m_Serial))
							DMibErrorNetSSL(fg_GetExceptionStr("Error setting x509 serial"));
				
						ERR_clear_error();
						if (!X509_gmtime_adj(X509_get_notBefore(pCertificate), 0))
							DMibErrorNetSSL(fg_GetExceptionStr("Error setting x509 not before"));
				
						ERR_clear_error();
						if (!X509_gmtime_adj(X509_get_notAfter(pCertificate), (long)60*60*24*_SignOptions.m_Days))
							DMibErrorNetSSL(fg_GetExceptionStr("Error setting x509 not after"));

						ERR_clear_error();
						if (!X509_set_pubkey(pCertificate, pKey))
							DMibErrorNetSSL(fg_GetExceptionStr("Error setting x509 public key"));
				
						ERR_clear_error();
						if (!X509_NAME_add_entry_by_txt(X509_get_subject_name(pCertificate), "CN", MBSTRING_ASC, (const unsigned char*)_Options.m_Subject.f_GetStr(), -1, -1, 0))
							DMibErrorNetSSL(fg_GetExceptionStr(fg_Format("Error adding x509 CN '{}'", _Options.m_Subject)));
				
						// Self signed.
						ERR_clear_error();
						if (!X509_set_issuer_name(pCertificate, X509_get_subject_name(pCertificate)))
							DMibErrorNetSSL(fg_GetExceptionStr("Error setting x509 issuer"));

						// Set the subjectAltName
						{
							X509V3_CTX Context;
							X509V3_set_ctx_nodb(&Context);
							X509V3_set_ctx(&Context, pCertificate, pCertificate, nullptr, nullptr, 0);
				
							if (!_Options.m_Hostnames.f_IsEmpty())
								fg_AddHostnames(Context, pCertificate, _Options.m_Hostnames);

							if (!_Options.m_Extensions.f_IsEmpty())
								fg_AddExtensions(Context, pCertificate, _Options.m_Extensions);
						}

						ERR_clear_error();
						if (!X509_sign(pCertificate, pKey, fg_GetDigest(_SignOptions.m_Digest, pKey)))
							DMibErrorNetSSL(fg_GetExceptionStr("Error signing selfsigned certificate"));

						o_CertData = CSSLContext::CInternal::fs_ConvertX509ToBinary(pCertificate);
						o_KeyData = CSSLContext::CInternal::fs_ConvertKeyToBinary(pKey);
					}
				)
			;
		}

		// CSSLConnection methods.
		class CSSLConnection::CInternal
		{
		public:

			CInternal(CSSLConnection *_pSSL, NPtr::TCSharedPointer<CSSLContext> const &_pContext, FAuthenticationResultCallback &&_AuthenticationResultCallback, FUserTrustDecisionCallback &&_UserTrustCallback)
				: mp_pSSL(_pSSL)
				, mp_pSession(nullptr)
				, mp_pContext(_pContext)
				, mp_State(EState_None)
				, mp_bConnected(false)
				, mp_AuthenticationResultCallback(fg_Move(_AuthenticationResultCallback))
				, mp_UserTrustCallback(fg_Move(_UserTrustCallback))
				, mp_bHandshakeInProgress(false)
				, mp_bUsingTrustDecision(false)
			{
				mp_pSession = mp_pContext->fp_CreateSession();
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

			bool f_Decrypt(const void *_pDataIn, void *_pDataOut, int _Len)
			{
				g_SSLLowLevel->f_UseInThread();
				NMem::fg_MemCopy(_pDataOut, _pDataIn, _Len);

				EVP_DecryptInit(f_GetSSL()->enc_read_ctx, nullptr, nullptr, nullptr);

				int Len = _Len;
				EVP_DecryptUpdate(f_GetSSL()->enc_read_ctx, (unsigned char*)_pDataOut, &Len, (unsigned char*)_pDataIn, _Len);
				return true;
			} 

			bool f_GiveSocket(void *_pSocket)
			{
				g_SSLLowLevel->f_UseInThread();
				if (!SSL_set_fd(f_GetSSL(), (int)(mint)_pSocket))
					return false;

				return true;
			}
			
			bool f_HasSocket() const
			{
				g_SSLLowLevel->f_UseInThread();
				return SSL_get_fd(fg_RemoveQualifiers(*this).f_GetSSL()) >= 0;
			}

			void* f_GetSocket() const
			{
				g_SSLLowLevel->f_UseInThread();
				return (void*)(mint)SSL_get_fd(fg_RemoveQualifiers(*this).f_GetSSL());
			}

			NDataProcessing::CHashDigest_SHA256 f_GetSessionKeyDigest()
			{
				DMibRequire(mp_bConnected);
				return NDataProcessing::CHash_SHA256::fs_DigestFromData(f_GetSSL()->session->master_key, f_GetSSL()->session->master_key_length);
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
				g_SSLLowLevel->f_UseInThread();
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
						DMibErrorNet(NMib::NPlatform::fg_FormatErrno("SSL_shutdown", errno));
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
				g_SSLLowLevel->f_UseInThread();
				DMibRequire(_nLen > 0);
				DMibRequire(mp_bConnected);
				DMibRequire(!mp_bHandshakeInProgress);
				DMibRequire(mp_State == EState_None);

				CSocketOperationResult Result;
				ERR_clear_error();
				auto pSSL = f_GetSSL();
				auto SocketNumRead = pSSL->rbio->num_read;
				auto SocketNumWrite = pSSL->wbio->num_write;
				int Ret = SSL_write(pSSL, _pData, (int)_nLen);
				if (pSSL->rbio->num_read != SocketNumRead)
					Result.m_bReceivedNetwork = true;
				if (pSSL->rbio->num_write != SocketNumWrite)
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
						DMibErrorNet(NMib::NPlatform::fg_FormatErrno("send (write to SSL socket)", errno));
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
				g_SSLLowLevel->f_UseInThread();
				DMibRequire(_nLen > 0);
				DMibRequire(mp_bConnected);
				DMibRequire(!mp_bHandshakeInProgress);
				DMibRequire(mp_State == EState_None);
				
				CSocketOperationResult Result;
				ERR_clear_error();
				auto pSSL = f_GetSSL();
				auto SocketNumRead = pSSL->rbio->num_read;
				auto SocketNumWrite = pSSL->wbio->num_write;
				int Ret = SSL_read(pSSL, _pData, _nLen);
				if (pSSL->rbio->num_read != SocketNumRead)
					Result.m_bReceivedNetwork = true;
				if (pSSL->rbio->num_write != SocketNumWrite)
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
						DMibErrorNet(NMib::NPlatform::fg_FormatErrno("recv (read from SSL socket)", errno));
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
			NPtr::TCUniquePointer<CSSLContext::CSession> mp_pSession;
			NPtr::TCSharedPointer<CSSLContext> mp_pContext;

			NStr::CStr mp_Hostname;
			NStr::CStr mp_LastError;
			EState mp_State;
			FAuthenticationResultCallback mp_AuthenticationResultCallback;
			FUserTrustDecisionCallback mp_UserTrustCallback;

			CSSLConnectionResult mp_ExpectedResultCallback;

			bool mp_bConnected;
			bool mp_bHandshakeInProgress;
			bool mp_bUsingTrustDecision;
			
			bool fp_Process(bool _bAccept)
			{
				g_SSLLowLevel->f_UseInThread();
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
				g_SSLLowLevel->f_UseInThread();
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
				g_SSLLowLevel->f_UseInThread();
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

		CSSLConnection::CSSLConnection(NPtr::TCSharedPointer<CSSLContext> const &_pContext, FAuthenticationResultCallback &&_AuthenticationResultCallback, FUserTrustDecisionCallback &&_UserTrustDecisionCallback)
			: mp_pInternal(nullptr)
		{
			fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						mp_pInternal = fg_Construct(this, _pContext, fg_Move(_AuthenticationResultCallback), fg_Move(_UserTrustDecisionCallback));
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

		bool CSSLConnection::f_Decrypt(const void *_pDataIn, void *_pDataOut, int _Len)
		{
			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						return mp_pInternal->f_Decrypt(_pDataIn, _pDataOut, _Len);
					}
				)
			;
		}

		NDataProcessing::CHashDigest_SHA256 CSSLConnection::f_GetSessionKeyDigest() const
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

		void CSSLConnectionResult::f_LogError(int _Depth, int _Error)
		{
			bint bCreated = false;
			CCertificate& Certificate = mp_Certificates.f_Map(_Depth, bCreated);
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
			bint bCreated = false;
			int& Error = mp_MiscErrors.f_Map(_Error, bCreated);
			if (bCreated)
				Error = 0;

			++Error;

			if (_Error == EMiscError_HostnameMisMatch)
				mp_bVerificationErrorsOccured = true;
		}

		void CSSLConnectionResult::f_LogCertificate(int _Depth, NContainer::TCVector<uint8> const &_Certificate)
		{
			bint bCreated = false;
			CCertificate& Certificate = mp_Certificates.f_Map(_Depth, bCreated);
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

		bool CSSLConnectionResult::f_PeerCertificateMatchesRememberedCertificates(NContainer::TCVector<NContainer::TCVector<uint8>> const &_LocalStore) const
		{
			if (mp_Certificates.f_IsEmpty())
				return false;

			auto fl_VerifyAgainstLocalTrust = [=] (NContainer::TCVector<uint8> const &_Certificate) -> bool
			{
				if (_Certificate.f_IsEmpty())
					return false;

				return (mp_Certificates[0].m_Data == _Certificate);
			};

			for (auto Iter = _LocalStore.f_GetIterator(); Iter; ++Iter)
			{
				if (fl_VerifyAgainstLocalTrust(*Iter))
					return true;
			}

			return false;
		}

		bool CSSLConnectionResult::f_PeerCertificatesMatchesSpecificCertificate(NContainer::TCVector<uint8> const &_SpecificCertificate) const
		{
			g_SSLLowLevel->f_UseInThread();
			if (_SpecificCertificate.f_IsEmpty())
				return false;

			if (mp_Certificates.f_IsEmpty())
				return false;

			X509* pPeerCertificate = CSSLContext::CInternal::fs_LoadCertificate(_SpecificCertificate);
			auto Cleanup0 = g_OnScopeExit > [&]
				{
					X509_free(pPeerCertificate);
				}
			;

			NContainer::TCVector<uint8> ConvertedCert = CSSLContext::CInternal::fs_ConvertX509ToBinary(pPeerCertificate);
			
			bool bMatches = (mp_Certificates[0].m_Data == ConvertedCert);
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
				CCertificate const& Certificate = (*Iter);
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

			return CSSLContext::CInternal::fs_GetCertificateDescription(mp_Certificates[0].m_Data);
		}

		NStr::CStr CSSLConnectionResult::f_GetPeerCertificateInformation() const
		{
			if (mp_Certificates.f_IsEmpty())
				return NStr::CStr();

			return CSSLContext::CInternal::fs_GetCertificateInformation(mp_Certificates[0].m_Data);
		}

		NContainer::TCVector<uint8> CSSLConnectionResult::f_GetPeerCertificate() const
		{
			if (!mp_Certificates.f_IsEmpty())
				return mp_Certificates[0].m_Data;

			return NContainer::TCVector<uint8>();
		}
		
		NContainer::TCVector<NContainer::TCVector<uint8>> CSSLConnectionResult::f_GetCertificateChain() const
		{
			NContainer::TCVector<NContainer::TCVector<uint8>> CertificateChain;
			for (auto &Certificate : mp_Certificates)
				CertificateChain.f_Insert(Certificate.m_Data);
			
			return CertificateChain;
		}
		
		NStr::CStr CSSLConnectionResult::f_GetPeerCertificateName() const
		{
			if (mp_Certificates.f_IsEmpty())
				return NStr::CStr();

			return CSSLContext::fs_GetCertificateName(mp_Certificates[0].m_Data);
		}

		NStr::CStr CSSLConnectionResult::f_GetPeerCertificateFingerprint() const
		{
			if (mp_Certificates.f_IsEmpty())
				return NStr::CStr();

			return CSSLContext::fs_GetCertificateFingerprint(mp_Certificates[0].m_Data);
		}

		NStr::CStr CSSLConnectionResult::fp_GetLibraryStringForError(int _Error) const
		{
			return fg_RunProtectRegisters
				(
					[&]() -> decltype(auto)
					{
						g_SSLLowLevel->f_UseInThread();
						if (_Error == EMiscError_HostnameMisMatch)
							return (NStr::CStr::CFormat("Hostname mismatch (valid hostnames in certificate: {})") << CSSLContext::fs_GetCertificateHostnamesStr(f_GetPeerCertificate())).f_GetStr();
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
				return NStr::CStr::CFormat("Hostname mismatch (valid hostnames in certificate: {0})") << CSSLContext::fs_GetCertificateHostnamesStr(f_GetPeerCertificate());
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
				
		struct CEncryptAES::CInternal
		{
			CInternal(NStr::CStrSecure const &_Password, CSalt const *_pSalt, mint _nRounds)
			{
				fg_RunProtectRegisters
					(
						[&]() -> decltype(auto)
						{
							g_SSLLowLevel->f_UseInThread();
							f_GenerateKey(_Password, _pSalt, _nRounds);
						}
					)
				;
			}
			
			~CInternal()
			{
				NMem::fg_MemClear(m_Key, EVP_MAX_KEY_LENGTH);
				NMem::fg_MemClear(m_IV, EVP_MAX_IV_LENGTH);
			}
			
			void f_GenerateKey(NStr::CStrSecure const &_Password, CSalt const *_pSalt, mint _nRounds)
			{
				fg_RunProtectRegisters
					(
						[&]() -> decltype(auto)
						{
							EVP_CIPHER const* pCipher = EVP_get_cipherbyname("aes-256-cbc");
							EVP_MD const* pDigest = EVP_get_digestbyname("sha256");
				
							ERR_clear_error();
							if
								(
									!EVP_BytesToKey
									(
										pCipher
										, pDigest
										, _pSalt ? _pSalt->m_Salt : nullptr
										, (unsigned char const *)_Password.f_GetStr()
										, _Password.f_GetLen()
										, _nRounds
										, m_Key
										, m_IV
									)
								)
							{
								DMibErrorNetSSL(fg_GetExceptionStr("Failed to initialize cipher context"));
							}
						}
					)
				;
			}
			
			uint32 f_Encrypt(uint8 *_pSource, uint32 _SourceLen, uint8 *_pDest) const
			{
				return fg_RunProtectRegisters
					(
						[&]() -> decltype(auto)
						{
							g_SSLLowLevel->f_UseInThread();
							EVP_CIPHER_CTX *pCipherContext = nullptr;
							auto Cleanup = g_OnScopeExit > [&]
								{
									EVP_CIPHER_CTX_free(pCipherContext);
								}
							;
				
							ERR_clear_error();
							if (!(pCipherContext = EVP_CIPHER_CTX_new()))
								DMibErrorNetSSL(fg_GetExceptionStr("Failed to create cipher context"));
				
							ERR_clear_error();
							if (EVP_EncryptInit_ex(pCipherContext, EVP_aes_256_cbc(), nullptr, m_Key, m_IV) != 1)
								DMibErrorNetSSL(fg_GetExceptionStr("Failed to initialize cipher context"));
				
							ERR_clear_error();
							EVP_CIPHER_CTX_set_padding(pCipherContext, 0);
				
							int EncryptedLen = 0;
							ERR_clear_error();
							if (EVP_EncryptUpdate(pCipherContext, _pDest, &EncryptedLen, _pSource, (int)_SourceLen) != 1)
								DMibErrorNetSSL(fg_GetExceptionStr("Failed to encrypt data"));
				
							int FinalizeLen = 0;
							ERR_clear_error();
							if (EVP_EncryptFinal_ex(pCipherContext, _pDest + EncryptedLen, &FinalizeLen) != 1)
								DMibErrorNetSSL(fg_GetExceptionStr("Failed to finalize encrypted data"));
				
							return uint32(EncryptedLen + FinalizeLen);
						}
					)
				;
			}
		
			uint32 f_Decrypt(uint8 *_pSource, uint32 _SourceLen, uint8 *_pDest) const
			{
				return fg_RunProtectRegisters
					(
						[&]() -> decltype(auto)
						{
							g_SSLLowLevel->f_UseInThread();
							EVP_CIPHER_CTX *pCipherContext = nullptr;
							auto Cleanup = g_OnScopeExit > [&]
								{
									EVP_CIPHER_CTX_free(pCipherContext);
								}
							;
				
							ERR_clear_error();
							if (!(pCipherContext = EVP_CIPHER_CTX_new()))
								DMibErrorNetSSL(fg_GetExceptionStr("Failed to create cipher context"));
				
							ERR_clear_error();
							if (EVP_DecryptInit_ex(pCipherContext, EVP_aes_256_cbc(), nullptr, m_Key, m_IV) != 1)
								DMibErrorNetSSL(fg_GetExceptionStr("Failed to initialize cipher context"));
				
							ERR_clear_error();
							EVP_CIPHER_CTX_set_padding(pCipherContext, 0);
				
							int DecryptedLen = 0;
							ERR_clear_error();
							if (EVP_DecryptUpdate(pCipherContext, _pDest, &DecryptedLen, _pSource, (int)_SourceLen) != 1)
								DMibErrorNetSSL(fg_GetExceptionStr("Failed to decrypt"));
				
							int FinalLen = 0;
							ERR_clear_error();
							if (EVP_DecryptFinal_ex(pCipherContext, _pDest + DecryptedLen, &FinalLen) != 1)
								DMibErrorNetSSL(fg_GetExceptionStr("Failed to finalize decryption"));
				
							return uint32(DecryptedLen + FinalLen);
						}
					)
				;
			}
			
			uint8 m_Key[EVP_MAX_KEY_LENGTH];
			uint8 m_IV[EVP_MAX_IV_LENGTH];
		};
		
		CEncryptAES::CEncryptAES(NStr::CStrSecure const &_Password, CSalt const *_pSalt, mint _nRounds)
			: mp_pInternal(fg_Construct(_Password, _pSalt, _nRounds))
		{
		}
		
		CEncryptAES::~CEncryptAES()
		{
		}
		
		uint32 CEncryptAES::f_Encrypt(uint8 *_pSource, uint32 _SourceLen, uint8 *_pDest) const
		{
			return mp_pInternal->f_Encrypt(_pSource, _SourceLen, _pDest);
		}
		
		uint32 CEncryptAES::f_Decrypt(uint8 *_pSource, uint32 _SourceLen, uint8 *_pDest) const
		{
			return mp_pInternal->f_Decrypt(_pSource, _SourceLen, _pDest);
		}
		
		NDataProcessing::CHashDigest_SHA256 fg_MessageAuthenication_HMAC_SHA256(NContainer::TCVector<uint8> const &_Data, NContainer::TCVector<uint8, NMem::CAllocator_HeapSecure> const &_Key)
		{
			NDataProcessing::CHashDigest_SHA256 Return;
			unsigned int Size = Return.fs_GetSize();
			if 
				(
					!HMAC
					(
						EVP_sha256()
						, _Key.f_GetArray()
						, _Key.f_GetLen()
						, _Data.f_GetArray()
						, _Data.f_GetLen() 
						, Return.f_GetData()
						, &Size
					)
				)
			{
				DMibErrorNetSSL(NNet::fg_GetExceptionStr("Failed to run HMAC-SHA256"));
			}
			
			if (Size != Return.fs_GetSize())
				DMibErrorNetSSL("Failed to run HMAC-SHA256: Unexpected digest size");
			
			return Return;
		}

		NDataProcessing::CHashDigest_SHA1 fg_MessageAuthenication_HMAC_SHA1(NContainer::TCVector<uint8> const &_Data, NContainer::TCVector<uint8, NMem::CAllocator_HeapSecure> const &_Key)
		{
			NDataProcessing::CHashDigest_SHA1 Return;
			unsigned int Size = Return.fs_GetSize();
			if 
				(
					!HMAC
					(
						EVP_sha1()
						, _Key.f_GetArray()
						, _Key.f_GetLen()
						, _Data.f_GetArray()
						, _Data.f_GetLen() 
						, Return.f_GetData()
						, &Size
					)
				)
			{
				DMibErrorNetSSL(NNet::fg_GetExceptionStr("Failed to run HMAC-SHA1"));
			}
			
			if (Size != Return.fs_GetSize())
				DMibErrorNetSSL("Failed to run HMAC-SHA1: Unexpected digest size");
			
			return Return;
		}
	}
}

