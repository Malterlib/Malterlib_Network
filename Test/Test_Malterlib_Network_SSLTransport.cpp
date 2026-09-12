// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Core/Core>
#include <Mib/Test/Test>
#include <Mib/Cryptography/BoringSSL>

#include "../Source/Malterlib_Network_SSLTransport.h"

using namespace NMib;
using namespace NMib::NNetwork;
using namespace NMib::NStorage;

namespace
{
	struct CSSLTransport_Tests : public NMib::NTest::CTest
	{
		void f_DoTests()
		{
			DMibTestSuite("Cipher Queue Reclaim")
			{
				CSSLTransport Transport;

				constexpr umint c_nPieceBytes = 100;
				constexpr umint c_nPieces = 1024;
				uint8 Piece[c_nPieceBytes] = {};

				// Straddle every piece by one byte so the queue never empties.
				for (umint iPiece = 0; iPiece < c_nPieces; ++iPiece)
				{
					Transport.f_AppendCipherSegment(Piece, c_nPieceBytes, TCSharedPointer<CVirtualDestroyBase const>());
					Transport.f_ConsumeCipher(iPiece == 0 ? c_nPieceBytes - 1 : c_nPieceBytes);
				}

				DMibExpect(Transport.f_GetCipherPending(), ==, 1);
				DMibExpect(Transport.f_GetCipherQueueEntries(), <=, 2);

				CRYPTO_IVEC Fragments[CSSLTransport::mc_nMaxCipherFragments];
				umint nFragments = Transport.f_GetCipherFragments(Fragments);
				DMibExpect(nFragments, ==, 1);
				if (nFragments == 1)
				{
					DMibExpect(Fragments[0].len, ==, 1);
					DMibExpect((uint8 const *)Fragments[0].in, ==, Piece + c_nPieceBytes - 1);
				}

				Transport.f_ConsumeCipher(1);
				DMibExpect(Transport.f_GetCipherPending(), ==, 0);
				DMibExpect(Transport.f_GetCipherQueueEntries(), ==, 0);
			};

			DMibTestSuite("Cipher Queue Overflow")
			{
				CSSLTransport Transport;

				constexpr umint c_nPieceBytes = 10;
				constexpr umint c_nPieces = CSSLTransport::mc_nCipherQueueCapacity * 2 + 3;
				uint8 Pieces[c_nPieces][c_nPieceBytes];
				umint nMaxEntries = 0;
				for (umint iPiece = 0; iPiece < c_nPieces; ++iPiece)
				{
					for (umint iByte = 0; iByte < c_nPieceBytes; ++iByte)
						Pieces[iPiece][iByte] = uint8(iPiece * c_nPieceBytes + iByte);
					Transport.f_AppendCipherSegment(Pieces[iPiece], c_nPieceBytes, TCSharedPointer<CVirtualDestroyBase const>());
					nMaxEntries = fg_Max(nMaxEntries, Transport.f_GetCipherQueueEntries());
				}

				DMibExpect(nMaxEntries, <=, CSSLTransport::mc_nCipherQueueCapacity);
				DMibExpect(Transport.f_GetCipherPending(), ==, c_nPieces * c_nPieceBytes);

				CRYPTO_IVEC Fragments[CSSLTransport::mc_nMaxCipherFragments];
				umint nFragments = Transport.f_GetCipherFragments(Fragments);
				DMibExpect(nFragments, <=, CSSLTransport::mc_nMaxCipherFragments);

				uint8 Joined[c_nPieces * c_nPieceBytes];
				umint nJoined = 0;
				for (umint iFragment = 0; iFragment < nFragments; ++iFragment)
				{
					NMemory::fg_MemCopy(Joined + nJoined, Fragments[iFragment].in, Fragments[iFragment].len);
					nJoined += Fragments[iFragment].len;
				}
				DMibExpect(nJoined, ==, sizeof(Joined));
				DMibExpect(NMemory::fg_MemCmp(Joined, Pieces[0], sizeof(Joined)), ==, 0);

				Transport.f_ConsumeCipher(sizeof(Joined) - 1);
				DMibExpect(Transport.f_GetCipherPending(), ==, 1);
				nFragments = Transport.f_GetCipherFragments(Fragments);
				DMibExpect(nFragments, ==, 1);
				if (nFragments == 1)
					DMibExpect(*(uint8 const *)Fragments[0].in, ==, Joined[sizeof(Joined) - 1]);

				Transport.f_ConsumeCipher(1);
				DMibExpect(Transport.f_GetCipherQueueEntries(), ==, 0);
			};
		}
	};

	DMibTestRegister(CSSLTransport_Tests, Malterlib::Network);
}
