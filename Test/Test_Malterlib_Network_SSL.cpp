// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Core/Core>
#include <Mib/Network/SSL>
#include <Mib/Test/Exception>

using namespace NMib;
using namespace NMib::NNet;
using namespace NMib::NStr;
using namespace NMib::NContainer;

class CSSL_Tests : public NMib::NTest::CTest
{
public:

	void f_DoTests()
	{
		DMibTestSuite("Certificate properties")
		{
			CSSLContext::fs_RegisterExtension
				(
					"1.3.6.1.4.1.555555.1.2"
					, "MalterlibTest"
					, "Malterlib Test"
				)
			;

			uint32 TestKeySize = 1024;
			CSSLSettings ServerSettings;
			CSSLContext::CCertificateOptions ServerOptions;
			ServerOptions.m_Subject = "localhost0";
			ServerOptions.m_Hostnames = fg_CreateVector<CStr>("localhost1", "localhost2");
			ServerOptions.m_KeyLength = TestKeySize;
			auto &ServerExtension = ServerOptions.m_Extensions["MalterlibTest"].f_Insert();
			ServerExtension.m_Value = "Test0";
			ServerExtension.m_bCritical = false;
			auto &ServerExtensionCritical = ServerOptions.m_Extensions["MalterlibTest"].f_Insert();
			ServerExtensionCritical.m_Value = "Test1";
			ServerExtensionCritical.m_bCritical = true;
			
			CSSLContext::fs_GenerateSelfSignedCertAndKey(ServerOptions, ServerSettings.m_PublicCertificateData, ServerSettings.m_PrivateKeyData, TestKeySize);
			ServerSettings.m_CACertificateData = ServerSettings.m_PublicCertificateData;
			
			auto ServerHostNames = CSSLContext::fs_GetCertificateHostnames(ServerSettings.m_PublicCertificateData, false);
			auto ServerExtensions = CSSLContext::fs_GetCertificateExtensions(ServerSettings.m_PublicCertificateData);
			auto Info = CSSLContext::fs_GetCertificateDescription(ServerSettings.m_PublicCertificateData);
			
			DMibExpect(ServerHostNames, ==, fg_CreateVector<CStr>("localhost1", "localhost2"));
			DMibExpect(ServerExtensions["MalterlibTest"], ==, ServerOptions.m_Extensions["MalterlibTest"]);

			{
				CSSLSettings ClientSettings;
				CSSLContext::CCertificateOptions ClientOptions;
				ClientOptions.m_Subject = "localhost3";
				ClientOptions.m_KeyLength = TestKeySize;
				ClientOptions.m_Hostnames = fg_CreateVector<CStr>("localhost4", "localhost5");
				auto &ClientExtension = ClientOptions.m_Extensions["MalterlibTest"].f_Insert();
				ClientExtension.m_Value = "Test2";
				ClientExtension.m_bCritical = false;
				auto &ClientExtensionCritical = ClientOptions.m_Extensions["MalterlibTest"].f_Insert();
				ClientExtensionCritical.m_Value = "Test3";
				ClientExtensionCritical.m_bCritical = true;
				
				TCVector<uint8> CertificateRequestData;
				CSSLContext::fs_GenerateClientCertificateRequest(ClientOptions, CertificateRequestData, ClientSettings.m_PrivateKeyData);
				CSSLContext::fs_SignClientCertificate(ServerSettings.m_PublicCertificateData, ServerSettings.m_PrivateKeyData, CertificateRequestData, ClientSettings.m_PublicCertificateData);
				
				auto ClientHostNames = CSSLContext::fs_GetCertificateHostnames(ClientSettings.m_PublicCertificateData, false);
				auto ClientExtensions = CSSLContext::fs_GetCertificateExtensions(ClientSettings.m_PublicCertificateData);
				
				DMibExpect(ClientHostNames, ==, fg_CreateVector<CStr>("localhost4", "localhost5"));
				DMibExpect(ClientExtensions["MalterlibTest"], ==, ClientOptions.m_Extensions["MalterlibTest"]);
			}
			{
				DMibTestPath("Extensions only");
				CSSLSettings ClientSettings;
				
				CSSLContext::CCertificateOptions ClientOptions;
				ClientOptions.m_Subject = "localhost3";
				ClientOptions.m_KeyLength = TestKeySize;
				auto &ClientExtension = ClientOptions.m_Extensions["MalterlibTest"].f_Insert();
				ClientExtension.m_Value = "Test2";
				ClientExtension.m_bCritical = false;
				auto &ClientExtensionCritical = ClientOptions.m_Extensions["MalterlibTest"].f_Insert();
				ClientExtensionCritical.m_Value = "Test3";
				ClientExtensionCritical.m_bCritical = true;
				
				TCVector<uint8> CertificateRequestData;
				CSSLContext::fs_GenerateClientCertificateRequest(ClientOptions, CertificateRequestData, ClientSettings.m_PrivateKeyData);
				CSSLContext::fs_SignClientCertificate(ServerSettings.m_PublicCertificateData, ServerSettings.m_PrivateKeyData, CertificateRequestData, ClientSettings.m_PublicCertificateData);
				
				auto ClientExtensions = CSSLContext::fs_GetCertificateExtensions(ClientSettings.m_PublicCertificateData);
				
				DMibExpect(ClientExtensions["MalterlibTest"], ==, ClientOptions.m_Extensions["MalterlibTest"]);
			}
		};
		
		DMibTestSuite("EncryptAES")
		{
			CStrSecure Password("MalterlibPasswordTest");
			
			TCVector<uint8> SaltArray;
			SaltArray.f_SetLen(8);
			NMib::NSys::fg_Security_GenerateHighEntropyData(SaltArray.f_GetArray(), SaltArray.f_GetLen());
			
			CSalt Salt;
			NMem::fg_MemCopy(Salt.m_Salt, SaltArray.f_GetArray(), 8);
			
			TCVector<uint8> PlainText;
			TCVector<uint8> Decrypted;
			TCVector<uint8> Encrypted;
			
			PlainText.f_SetLen(32);
			NMib::NSys::fg_Security_GenerateHighEntropyData(PlainText.f_GetArray(), PlainText.f_GetLen());
			
			uint32 EncryptedLen = fg_EncryptAES(Password, &Salt, PlainText.f_GetArray(), PlainText.f_GetLen(), Encrypted.f_GetArray(32));
			uint32 DecryptedLen = fg_DecryptAES(Password, &Salt, Encrypted.f_GetArray(), Encrypted.f_GetLen(), Decrypted.f_GetArray(32));
			
			DMibExpect(EncryptedLen, ==, DecryptedLen);
			DMibExpect(Decrypted, ==, PlainText);
			DMibExpect(Encrypted, !=, PlainText);
			DMibExpect(Decrypted, !=, Encrypted);
			
			{
				DMibTestPath("IncorrectPassword");
				CStrSecure IncorrectPassword("MalterlibPasswordTest2");
				fg_DecryptAES(IncorrectPassword, &Salt, Encrypted.f_GetArray(), Encrypted.f_GetLen(), Decrypted.f_GetArray());
				DMibExpect(Decrypted, !=, PlainText);
			}
			
			{
				DMibTestPath("IncorrectSalt");
				TCVector<uint8> IncorrectSaltArray;
				IncorrectSaltArray.f_SetLen(8);
				NMib::NSys::fg_Security_GenerateHighEntropyData(IncorrectSaltArray.f_GetArray(), IncorrectSaltArray.f_GetLen());
				
				CSalt IncorrectSalt;
				NMem::fg_MemCopy(IncorrectSalt.m_Salt, IncorrectSaltArray.f_GetArray(), 8);
				fg_DecryptAES(Password, &IncorrectSalt, Encrypted.f_GetArray(), Encrypted.f_GetLen(), Decrypted.f_GetArray());
				DMibExpect(Decrypted, !=, PlainText);
			}
			
			{
				DMibTestPath("Unaligned Plaintext");
				TCVector<uint8> Unaligned;
				Unaligned.f_SetLen(14);
				
				DMibTest
					(
						DMibExpr(TCThrowsException<NException::CException>())
						== DMibLExpr(fg_EncryptAES(Password, &Salt, Unaligned.f_GetArray(), Unaligned.f_GetLen(), Encrypted.f_GetArray(32)))
					)
				;
			}
			
			{
				DMibTestPath("Compare with OpenSSL enc");
				
				uint8 EncryptedByOpenSSL[] =
					{
						0x7e, 0x26, 0x44, 0x27, 0x23, 0x58, 0xfd, 0x32, 0xfa, 0x46, 0x80, 0xdc, 0xc0, 0x99, 0x45, 0x03,
						0x0d, 0x87, 0x20, 0xfc, 0x40, 0x5e, 0xb9, 0xd6, 0xed, 0xb9, 0x61, 0xc3, 0x98, 0x63, 0x58, 0xe8
					}
				;
				
				TCVector<uint8> EncryptedOpenSSL;
				EncryptedOpenSSL.f_SetLen(32);
				NMem::fg_MemCopy(EncryptedOpenSSL.f_GetArray(), EncryptedByOpenSSL, 32);
				
				TCVector<uint8> ToEncrypt;
				ToEncrypt.f_SetLen(32);
				NMem::fg_MemClear(ToEncrypt.f_GetArray(), ToEncrypt.f_GetLen());
				
				NStr::CStrSecure OpenSSLPassword("ABCDEFGH");
				fg_EncryptAES(OpenSSLPassword, nullptr, ToEncrypt.f_GetArray(), ToEncrypt.f_GetLen(), Encrypted.f_GetArray());
				DMibExpect(EncryptedOpenSSL, ==, Encrypted);
				
				fg_DecryptAES(OpenSSLPassword, nullptr, EncryptedOpenSSL.f_GetArray(), EncryptedOpenSSL.f_GetLen(), Decrypted.f_GetArray());
				DMibExpect(Decrypted, ==, ToEncrypt);
			}
		};
	}
};

DMibTestRegister(CSSL_Tests, Malterlib::Network);
