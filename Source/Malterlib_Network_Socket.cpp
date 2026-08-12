// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Network_Socket.h"

namespace NMib::NNetwork
{
	// Fallback for sockets without a vectored implementation: one send per span, stopping at
	// the first short write so the caller's progress accounting stays in order
	CSocketOperationResult ICSocket::f_SendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans)
	{
		CSocketOperationResult Result;
		for (umint iSpan = 0; iSpan < _nSpans; ++iSpan)
		{
			if (!_pSpans[iSpan].m_nBytes)
				continue;

			CSocketOperationResult SpanResult = f_Send(_pSpans[iSpan].m_pData, _pSpans[iSpan].m_nBytes);
			Result.m_nBytes += SpanResult.m_nBytes;
			Result.m_bSentNetwork |= SpanResult.m_bSentNetwork;
			Result.m_bReceivedNetwork |= SpanResult.m_bReceivedNetwork;

			if (SpanResult.m_nBytes != _pSpans[iSpan].m_nBytes)
				break;
		}

		return Result;
	}
}
