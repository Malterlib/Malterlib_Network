// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#include <Mib/Core/Core>
#include <Mib/Network/SSL>

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
	}
};

DMibTestRegister(CSSL_Tests, Malterlib::Network);
