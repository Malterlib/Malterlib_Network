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
					"1.3.6.1.4.1.47722.1.2"
					, "MalterlibTest"
					, "Malterlib Test"
				)
			;

			CSSLKeySetting TestKeySetting = CSSLKeySettings_EC_secp256r1{};
			CSSLSettings ServerSettings;
			CSSLContext::CCertificateOptions ServerOptions;
			ServerOptions.m_CommonName = "localhost0";
			ServerOptions.m_Hostnames = fg_CreateVector<CStr>("localhost1", "localhost2");
			ServerOptions.m_KeySetting = TestKeySetting;
			auto &ServerExtension = ServerOptions.m_Extensions["MalterlibTest"].f_Insert();
			ServerExtension.m_Value = "Test0";
			ServerExtension.m_bCritical = false;
			auto &ServerExtensionCritical = ServerOptions.m_Extensions["MalterlibTest"].f_Insert();
			ServerExtensionCritical.m_Value = "Test1";
			ServerExtensionCritical.m_bCritical = true;
			
			CSSLContext::fs_GenerateSelfSignedCertAndKey(ServerOptions, ServerSettings.m_PublicCertificateData, ServerSettings.m_PrivateKeyData);
			ServerSettings.m_CACertificateData = ServerSettings.m_PublicCertificateData;
			
			auto ServerHostNames = CSSLContext::fs_GetCertificateHostnames(ServerSettings.m_PublicCertificateData, false);
			auto ServerExtensions = CSSLContext::fs_GetCertificateExtensions(ServerSettings.m_PublicCertificateData);
			auto Info = CSSLContext::fs_GetCertificateDescription(ServerSettings.m_PublicCertificateData);
			
			DMibExpect(ServerHostNames, ==, fg_CreateVector<CStr>("localhost1", "localhost2"));
			DMibExpect(ServerExtensions["MalterlibTest"], ==, ServerOptions.m_Extensions["MalterlibTest"]);

			{
				CSSLSettings ClientSettings;
				CSSLContext::CCertificateOptions ClientOptions;
				ClientOptions.m_CommonName = "localhost3";
				ClientOptions.m_KeySetting = TestKeySetting;
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
				ClientOptions.m_CommonName = "localhost3";
				ClientOptions.m_KeySetting = TestKeySetting;
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
			
			CSecureByteVector Salt;
			NMib::NSys::fg_Security_GenerateHighEntropyData(Salt.f_GetArray(8), 8);
			
			CEncryptAES EncryptAES(NNet::CEncryptKeyIV::fs_GenerateKeyIV(Password, Salt, CKeyDerivationSettings_PKCS5_Deprecated{}));
			
			TCVector<uint8> PlainText;
			TCVector<uint8> Decrypted;
			TCVector<uint8> Encrypted;
			
			PlainText.f_SetLen(32);
			NMib::NSys::fg_Security_GenerateHighEntropyData(PlainText.f_GetArray(), PlainText.f_GetLen());
			
			uint32 EncryptedLen = EncryptAES.f_Encrypt(PlainText.f_GetArray(), PlainText.f_GetLen(), Encrypted.f_GetArray(32));
			uint32 DecryptedLen = EncryptAES.f_Decrypt(Encrypted.f_GetArray(), Encrypted.f_GetLen(), Decrypted.f_GetArray(32));
			
			DMibExpect(EncryptedLen, ==, DecryptedLen);
			DMibExpect(Decrypted, ==, PlainText);
			DMibExpect(Encrypted, !=, PlainText);
			DMibExpect(Decrypted, !=, Encrypted);
			
			{
				DMibTestPath("IncorrectPassword");
				CStrSecure IncorrectPassword("MalterlibPasswordTest2");
				CEncryptAES EncryptAES1(NNet::CEncryptKeyIV::fs_GenerateKeyIV(IncorrectPassword, Salt, CKeyDerivationSettings_PKCS5_Deprecated{}));
				EncryptAES1.f_Decrypt(Encrypted.f_GetArray(), Encrypted.f_GetLen(), Decrypted.f_GetArray());
				DMibExpect(Decrypted, !=, PlainText);
			}
			
			{
				DMibTestPath("IncorrectSalt");
				CSecureByteVector IncorrectSalt;
				NMib::NSys::fg_Security_GenerateHighEntropyData(IncorrectSalt.f_GetArray(8), 8);
				
				CEncryptAES EncryptAES2(NNet::CEncryptKeyIV::fs_GenerateKeyIV(Password, IncorrectSalt, CKeyDerivationSettings_PKCS5_Deprecated{}));
				EncryptAES2.f_Decrypt(Encrypted.f_GetArray(), Encrypted.f_GetLen(), Decrypted.f_GetArray());
				DMibExpect(Decrypted, !=, PlainText);
			}
			
			{
				DMibTestPath("Unaligned Plaintext");
				TCVector<uint8> Unaligned;
				Unaligned.f_SetLen(14);
				
				CEncryptAES EncryptAES3(NNet::CEncryptKeyIV::fs_GenerateKeyIV(Password, Salt, CKeyDerivationSettings_PKCS5_Deprecated{}));
				
				DMibTest
					(
						DMibExpr(TCThrowsException<NException::CException>())
						== DMibLExpr(EncryptAES3.f_Encrypt(Unaligned.f_GetArray(), Unaligned.f_GetLen(), Encrypted.f_GetArray(32)))
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
				CEncryptAES EncryptAES4(NNet::CEncryptKeyIV::fs_GenerateKeyIV(OpenSSLPassword, {}, CKeyDerivationSettings_PKCS5_Deprecated{ESSLDigest_SHA256, 1}, ESSLCrypto_AES_256_CBC));

				EncryptAES4.f_Encrypt(ToEncrypt.f_GetArray(), ToEncrypt.f_GetLen(), Encrypted.f_GetArray());
				DMibExpect(EncryptedOpenSSL, ==, Encrypted);
				
				EncryptAES4.f_Decrypt(EncryptedOpenSSL.f_GetArray(), EncryptedOpenSSL.f_GetLen(), Decrypted.f_GetArray());
				DMibExpect(Decrypted, ==, ToEncrypt);
			}
		};

		DMibTestSuite("Incremental Encrypt")
		{
			CStrSecure Password("MalterlibPasswordTest");
			// We use this buffer for both Key and IV
			CSecureByteVector Buffer
				{
					0x7e, 0x26, 0x44, 0x27, 0x23, 0x58, 0xfd, 0x32, 0xfa, 0x46, 0x80, 0xdc, 0xc0, 0x99, 0x45, 0x03,
					0x0d, 0x87, 0x20, 0xfc, 0x40, 0x5e, 0xb9, 0xd6, 0xed, 0xb9, 0x61, 0xc3, 0x98, 0x63, 0x58, 0xe8
				}
			;
			CSecureByteVector WrongBuffer
				{
					0x7e, 0x26, 0x44, 0x22, 0x32, 0x58, 0xfd, 0x32, 0xfa, 0x46, 0x80, 0xdc, 0xc0, 0x99, 0x45, 0x03,
					0x0d, 0x87, 0x20, 0xfc, 0x40, 0x5e, 0xb9, 0xd6, 0xed, 0xb9, 0x61, 0xc3, 0x98, 0x63, 0x58, 0xe8
				}
			;

			CSecureByteVector Salt;
			NMib::NSys::fg_Security_GenerateHighEntropyData(Salt.f_GetArray(8), 8);

			TCVector<uint8> PlainText;
			TCVector<uint8> Decrypted;
			TCVector<uint8> Encrypted;
			uint32 EncryptedLen;
			uint32 DecryptedLen;
			uint32 BlockSize;
			// Use multiple lengths: small single block, around the block size border, around two blocks, around the buffer length +/- block size, huge buffer, and
			// finally a value that is suitable for the rest of the tests
			int const Lengths[] = { 1, 2, 14, 15, 16, 17, 25, 31, 33, 8192 - 17, 8192 - 16 , 8192 - 15, 8192, 8193, 8192 + 15, 8192 + 16, 8192 + 17, 55555, 32 };

			for (auto Length : Lengths)
			{
				DMibTestPath(fg_Format("Buffer length: {}", Length));
				PlainText.f_SetLen(Length);
				NMisc::CRandomShiftRNG Rng;
				for (auto &Char : PlainText)
					Char = Rng.f_GetValue<uint8>();
				auto KeyIV = CEncryptKeyIV::fs_GenerateKeyIV(Password, Salt, CKeyDerivationSettings_PKCS5_Deprecated{});
				CIncrementalEncrypt EncryptAES(ESSLCryptoFlags_Encrypt | ESSLCryptoFlags_UsePadding, KeyIV);
				CIncrementalEncrypt DecryptAES(ESSLCryptoFlags_Decrypt | ESSLCryptoFlags_UsePadding, KeyIV);

				BlockSize = CEncryptKeyIV::fs_GetBlockSize(ESSLCrypto_AES_256_CBC);
				EncryptedLen = EncryptAES.f_Encrypt(PlainText.f_GetArray(), PlainText.f_GetLen(), Encrypted.f_GetArray(PlainText.f_GetLen() + BlockSize));
				EncryptedLen += EncryptAES.f_FinalizePaddedEncrypt(Encrypted.f_GetArray() + EncryptedLen, Encrypted.f_GetLen() - EncryptedLen);

				DecryptedLen = DecryptAES.f_Decrypt(Encrypted.f_GetArray(), EncryptedLen, Decrypted.f_GetArray(EncryptedLen + BlockSize));
				DecryptedLen += DecryptAES.f_FinalizePaddedDecrypt(Decrypted.f_GetArray() + DecryptedLen, Decrypted.f_GetLen() - DecryptedLen);
				Decrypted.f_SetLen(DecryptedLen);

				DMibExpect(EncryptedLen, ==, (DecryptedLen + BlockSize) / BlockSize * BlockSize);
				DMibExpect(Decrypted, ==, PlainText);
				DMibExpect(Encrypted, !=, PlainText);
				DMibExpect(Decrypted, !=, Encrypted);

				if (EncryptedLen > BlockSize)
				{
					// Check that we, after a re-initialize, can decrypt and finalize the last block to get the correct length
					CSecureByteVector IV;
					NMem::fg_MemCopy(IV.f_GetArray(BlockSize), Encrypted.f_GetArray() + EncryptedLen - 2 * BlockSize, BlockSize);
					CIncrementalEncrypt DecryptAES2(ESSLCryptoFlags_Decrypt | ESSLCryptoFlags_UsePadding, NNet::CEncryptKeyIV{KeyIV.m_Key, IV});
					DecryptedLen = DecryptAES2.f_Decrypt(Encrypted.f_GetArray() + EncryptedLen - BlockSize, BlockSize, Decrypted.f_GetArray(BlockSize * 2));
					DecryptedLen += DecryptAES2.f_FinalizePaddedDecrypt(Decrypted.f_GetArray() + DecryptedLen, Decrypted.f_GetLen() - DecryptedLen);
					DMibExpect(DecryptedLen, ==, Length % BlockSize);
				}

			}
 			{
				DMibTestPath("IncorrectPassword");
 				CStrSecure IncorrectPassword("MalterlibPasswordTest2");
				auto KeyIV = CEncryptKeyIV::fs_GenerateKeyIV(IncorrectPassword, Salt, CKeyDerivationSettings_PKCS5_Deprecated{});
				CIncrementalEncrypt EncryptAES1(ESSLCryptoFlags_Decrypt | ESSLCryptoFlags_UsePadding, KeyIV);
 				DecryptedLen = EncryptAES1.f_Decrypt(Encrypted.f_GetArray(), EncryptedLen, Decrypted.f_GetArray(EncryptedLen + BlockSize));
				DMibExpectExceptionType(EncryptAES1.f_FinalizePaddedDecrypt(Decrypted.f_GetArray() + DecryptedLen, Decrypted.f_GetLen() - DecryptedLen), CExceptionNetSSL);
 			}

 			{
				DMibTestPath("IncorrectSalt");
				CSecureByteVector IncorrectSalt;
				NMib::NSys::fg_Security_GenerateHighEntropyData(IncorrectSalt.f_GetArray(8), 8);
				auto KeyIV = CEncryptKeyIV::fs_GenerateKeyIV(Password, IncorrectSalt, CKeyDerivationSettings_PKCS5_Deprecated{});
				CIncrementalEncrypt EncryptAES2(ESSLCryptoFlags_Decrypt | ESSLCryptoFlags_UsePadding, KeyIV);
 				DecryptedLen = EncryptAES2.f_Decrypt(Encrypted.f_GetArray(), EncryptedLen, Decrypted.f_GetArray());
				DMibExpectExceptionType(EncryptAES2.f_FinalizePaddedDecrypt(Decrypted.f_GetArray() + DecryptedLen, Decrypted.f_GetLen() - DecryptedLen), CExceptionNetSSL);
 			}

			{
				DMibTestPath("Incorrect Key");
				CEncryptKeyIV KeyIV = {WrongBuffer, CEncryptKeyIV::fs_GenerateKeyIV(Password, Salt, CKeyDerivationSettings_PKCS5_Deprecated{}).m_IV};
				CIncrementalEncrypt EncryptAES1(ESSLCryptoFlags_Decrypt | ESSLCryptoFlags_UsePadding, KeyIV);
				DecryptedLen = EncryptAES1.f_Decrypt(Encrypted.f_GetArray(), EncryptedLen, Decrypted.f_GetArray(EncryptedLen + BlockSize));
				DMibExpectExceptionType(EncryptAES1.f_FinalizePaddedDecrypt(Decrypted.f_GetArray() + DecryptedLen, Decrypted.f_GetLen() - DecryptedLen), CExceptionNetSSL);
			}

			{
				// This test does not behave the same way as the incorrect key test, where the content of the final block did not decrypt correctly and finalization failed.
				// Nor is it an analogue to the the test with incorrect salt, which affects the key, which leads to incorrect decryption and finalization failure.
				//
				// After decryption the block is XORed with the IV. This means finalization will succeed, but the decrypted text will differ from the plain text.
				DMibTestPath("Incorrect IV");
				CEncryptKeyIV KeyIV = {CEncryptKeyIV::fs_GenerateKeyIV(Password, Salt, CKeyDerivationSettings_PKCS5_Deprecated{}).m_Key, WrongBuffer};
				CIncrementalEncrypt EncryptAES2(ESSLCryptoFlags_Decrypt | ESSLCryptoFlags_UsePadding, KeyIV);
				DecryptedLen = EncryptAES2.f_Decrypt(Encrypted.f_GetArray(), EncryptedLen, Decrypted.f_GetArray());
				DecryptedLen += EncryptAES2.f_FinalizePaddedDecrypt(Decrypted.f_GetArray() + DecryptedLen, Decrypted.f_GetLen() - DecryptedLen);
				Decrypted.f_SetLen(DecryptedLen);
				DMibExpect(Decrypted, !=, PlainText);
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
				auto KeyIV = CEncryptKeyIV::fs_GenerateKeyIV(OpenSSLPassword, {}, CKeyDerivationSettings_PKCS5_Deprecated{ESSLDigest_SHA256, 1}, ESSLCrypto_AES_256_CBC);
				CIncrementalEncrypt EncryptAES4(ESSLCryptoFlags_Encrypt | ESSLCryptoFlags_UsePadding, KeyIV);
				EncryptedLen = EncryptAES4.f_Encrypt(ToEncrypt.f_GetArray(), ToEncrypt.f_GetLen(), Encrypted.f_GetArray(ToEncrypt.f_GetLen() + BlockSize));
				EncryptedLen += EncryptAES4.f_FinalizePaddedEncrypt(Encrypted.f_GetArray() + EncryptedLen, Encrypted.f_GetLen() - EncryptedLen);
				// Remove the padding block from our encrypted data
				Encrypted.f_SetLen(EncryptedLen - BlockSize);
				DMibExpect(EncryptedOpenSSL, ==, Encrypted);

				// Cannot decrypt the OpenSSL block. It doesn't have correct padding.
			}
		};

		DMibTestSuite("Incremental Encrypt - No padding")
		{
			CStrSecure Password("MalterlibPasswordTest");
			// We use this buffer for both Key and IV
			CSecureByteVector Buffer
				{
					0x7e, 0x26, 0x44, 0x27, 0x23, 0x58, 0xfd, 0x32, 0xfa, 0x46, 0x80, 0xdc, 0xc0, 0x99, 0x45, 0x03,
					0x0d, 0x87, 0x20, 0xfc, 0x40, 0x5e, 0xb9, 0xd6, 0xed, 0xb9, 0x61, 0xc3, 0x98, 0x63, 0x58, 0xe8,
					0x7e, 0x26, 0x44, 0x22, 0x32, 0x58, 0xfd, 0x32, 0xfa, 0x46, 0x80, 0xdc, 0xc0, 0x99, 0x45, 0x03,
					0x0d, 0x87, 0x20, 0xfc, 0x40, 0x5e, 0xb9, 0xd6, 0xed, 0xb9, 0x61, 0xc3, 0x98, 0x63, 0x58, 0xe8
				}
			;

			CSecureByteVector Salt;
			NMib::NSys::fg_Security_GenerateHighEntropyData(Salt.f_GetArray(8), 8);

			TCMap<ESSLCrypto, CStr> Ciphers =
				{
					{ESSLCrypto_AES_256_CBC, "ESSLCrypto_AES_256_CBC"}
					, {ESSLCrypto_AES_128_CBC, "ESSLCrypto_AES_128_CBC"}
					, {ESSLCrypto_AES_256_OFB, "ESSLCrypto_AES_256_OFB"}
					, {ESSLCrypto_AES_128_OFB, "ESSLCrypto_AES_128_OFB"}
					, {ESSLCrypto_DES_EDE3_CBC, "ESSLCrypto_DES_EDE3_CBC"}
					, {ESSLCrypto_AES_256_ECB, "ESSLCrypto_AES_256_ECB"}
					, {ESSLCrypto_AES_128_ECB, "ESSLCrypto_AES_128_ECB"}
				}
			;
			TCVector<uint8> PlainText;
			TCVector<uint8> Decrypted;
			TCVector<uint8> Encrypted;
			uint32 EncryptedLen;
			uint32 DecryptedLen;
			// Use multiple lengths: We do not use paddingin this test so stick to blocks that are multiples of the block size
			int const Lengths[] = { 32, 256, 65536 };

			for (auto Length : Lengths)
			{
				PlainText.f_SetLen(Length);
				Encrypted.f_SetLen(Length);
				Decrypted.f_SetLen(Length);

				NMisc::CRandomShiftRNG Rng;
				for (auto &Char : PlainText)
					Char = Rng.f_GetValue<uint8>();

				for (auto const &Cipher : Ciphers)
				{
					ESSLCrypto const CipherKey = Ciphers.fs_GetKey(Cipher);
					DMibTestPath(fg_Format("Cipher: {} Length: {}", Cipher, Length));

					NNet::CEncryptKeyIV KeyIV{Buffer, Buffer, CipherKey};
					CIncrementalEncrypt EncryptAES(ESSLCryptoFlags_Encrypt, KeyIV);
					CIncrementalEncrypt DecryptAES(ESSLCryptoFlags_Decrypt, KeyIV);
					EncryptedLen = EncryptAES.f_Encrypt(PlainText.f_GetArray(), PlainText.f_GetLen(), Encrypted.f_GetArray());
					DecryptedLen = DecryptAES.f_Decrypt(Encrypted.f_GetArray(), EncryptedLen, Decrypted.f_GetArray());
					DMibExpect(Decrypted, ==, PlainText);
					DMibExpect(Encrypted, !=, PlainText);
					DMibExpect(Decrypted, !=, Encrypted);
					DMibExpect(EncryptedLen, ==, Length);
					DMibExpect(DecryptedLen, ==, Length);
				}
			}
		};

		DMibTestSuite("IncrementalHMAC")
		{
			CStrSecure Password("MalterlibPasswordTest");

			CSecureByteVector Salt;
			NMib::NSys::fg_Security_GenerateHighEntropyData(Salt.f_GetArray(8), 8);

			static const char *Text = "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.";
			static const char *KeyBytes = "abcdefghijklmnopqrstuvwxyz012345abcdefghijklmnopqrstuvwxyz012345";
			TCVector<uint8> PlainText;
			NMem::fg_MemCopy(PlainText.f_GetArray(fg_StrLen(Text)), Text, fg_StrLen(Text));
			CSecureByteVector Key;
			NMem::fg_MemCopy(Key.f_GetArray(fg_StrLen(KeyBytes)), KeyBytes, fg_StrLen(KeyBytes));

			auto ContinuousHMAC =  fg_MessageAuthenication_HMAC_SHA256(PlainText, Key);

			// Use multiple incremental lengths: full length and some powers of 2, and some odd ones
			static const int Lengths[] = { 89, 1, 8, 64, 3, 9 };

			for (auto Length : Lengths)
			{
				DMibTestPath(fg_Format("Buffer length: {}", Length));

				CIncrementalHMAC IncrementalHMAC(ESSLDigest_SHA256, Key);

				for (int i = 0; i < Lengths[0]; i += Lengths[i])
				{
					int ThisTime = fg_Min(Lengths[0] - i, Lengths[i]);
					IncrementalHMAC.f_Update(PlainText.f_GetArray() + i, ThisTime);
				}
				NDataProcessing::CHashDigest_SHA256 Result;
				auto nBytes = IncrementalHMAC.f_Finalize(Result.f_GetData(), Result.fs_GetSize());
				DMibExpect(Result, ==, ContinuousHMAC);
				DMibExpect(nBytes, ==, ContinuousHMAC.fs_GetSize());
			}

			{
				DMibTestPath("IncorrectKey");
				Key[0] = 'A';
				CIncrementalHMAC IncrementalHMAC(ESSLDigest_SHA256, Key);
				IncrementalHMAC.f_Update(PlainText.f_GetArray(), Lengths[0]);
				NDataProcessing::CHashDigest_SHA256 Result;
				auto nBytes = IncrementalHMAC.f_Finalize(Result.f_GetData(), Result.fs_GetSize());
				DMibExpect(Result, !=, ContinuousHMAC);
				DMibExpect(nBytes, ==, ContinuousHMAC.fs_GetSize());
			}
		};
	}
};

DMibTestRegister(CSSL_Tests, Malterlib::Network);
