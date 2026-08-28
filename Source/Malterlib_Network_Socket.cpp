// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Network_Socket.h"
#include <Mib/Core/IoSubSystem>

#include <stdlib.h>

#include <Mib/Stream/BinaryStorage>

#if defined(DPlatformFamily_Windows)
#	include <Mib/Core/PlatformSpecific/WindowsError>
#else
#	include <Mib/Core/PlatformSpecific/PosixErrNo>
#endif

namespace NMib::NNetwork
{
	NStr::CStr fg_FormatSocketIoError(int32 _Error)
	{
#if defined(DPlatformFamily_Windows)
		return NStr::CStr(NPlatform::fg_Win32_GetLastErrorStr(uint32(_Error)));
#else
		return NPlatform::fg_ErrnoString<NStr::CStr>(int(_Error));
#endif
	}

#if DMibConfig_IoDebug_Enable
	// Null when the statistics are off, so a recording site asks and finds the counters in one read
	NSys::CNetIoStats *fg_NetIoStats()
	{
		auto &Io = NMib::NSys::fg_IoSubSystem();
		if (!Io.f_StatsEnabled())
			return nullptr;

		return &Io.m_NetIoStats;
	}
#endif

	umint fg_GetReceiveWindowBytes(NMib::NSys::CIoSubSystem &_Io, umint _nBufferBytes)
	{
		if (umint nWindow = _Io.f_ReceiveWindowBytesOverride())
		{
			// Floored at a few buffers whatever the override says: a window smaller than that
			// can park the stream while a record that straddles buffers is still incomplete,
			// and the bytes that would complete it then never arrive
			return fg_Max(nWindow, 4 * fg_Min(_nBufferBytes, TCLimitsInt<umint>::mc_Max / 4));
		}

		// Wide enough that a consumer legitimately holding a receive pipeline's worth of
		// zero copy views does not park the stream: the views pin whole receive buffers, so
		// the window has to leave headroom above what the consumer intends to hold
		// Saturating, for a 32 bit umint under a huge fragmentation: a wrapped window would
		// either park the stream after one buffer or read as unlimited
		return 64 * fg_Min(_nBufferBytes, TCLimitsInt<umint>::mc_Max / 64);
	}

	CInheritedSocketHandle::CInheritedSocketHandle(void *_pSocketHandle)
		: mp_pSocketHandle(_pSocketHandle)
		, mp_bOwned(true)
	{
	}

	CInheritedSocketHandle::CInheritedSocketHandle(CInheritedSocketHandle &&_Other)
		: mp_pSocketHandle(_Other.mp_pSocketHandle)
		, mp_bOwned(_Other.mp_bOwned)
	{
		_Other.mp_bOwned = false;
	}

	CInheritedSocketHandle &CInheritedSocketHandle::operator = (CInheritedSocketHandle &&_Other)
	{
		if (mp_bOwned)
			NMib::NSys::NNetwork::fg_CloseSocketHandle(mp_pSocketHandle);

		mp_pSocketHandle = _Other.mp_pSocketHandle;
		mp_bOwned = _Other.mp_bOwned;
		_Other.mp_bOwned = false;
		return *this;
	}

	CInheritedSocketHandle::~CInheritedSocketHandle()
	{
		if (mp_bOwned)
			NMib::NSys::NNetwork::fg_CloseSocketHandle(mp_pSocketHandle);
	}

	void *CInheritedSocketHandle::f_Detach()
	{
		mp_bOwned = false;
		return mp_pSocketHandle;
	}

	ICSocketCompletionIo::~ICSocketCompletionIo()
	{
	}

	bool ICSocketCompletionIo::f_ContinueSend(NSys::FIoCompletion &&, FSocketSendReleased &&)
	{
		return false;
	}

	bool ICSocketCompletionIo::f_SupportsSendStaging() const
	{
		return false;
	}

	bool ICSocketCompletionIo::f_IsSendWindowFull(umint, umint)
	{
		return false;
	}

	bool ICSocketCompletionIo::f_HasSendOperationInFlight() const
	{
		return false;
	}

	bool ICSocketCompletionIo::f_ReceiveStreamEndedByProtocol() const
	{
		return false;
	}

	void ICSocketCompletionIo::f_ResumeReceiveStream()
	{
	}

	umint ICSocketCompletionIo::f_GetReceiveBufferBytes() const
	{
		return 4096;
	}

	bool ICSocketCompletionIo::f_ResolveSend(NSys::CIoCompletion &)
	{
		return true;
	}

	void ICSocketCompletionIo::f_ResolveSendRelease(umint)
	{
	}

	bool ICSocketCompletionIo::f_ResolveReceiveSegmentShared(NSys::CIoStreamSegment &, NContainer::CSharedByteVector &, NSys::CIoCompletion &)
	{
		return false;
	}

	bool ICSocketCompletionIo::f_ResolveHeld(void *, umint, NSys::CIoCompletion &)
	{
		return false;
	}

	void ICSocketCompletionIo::f_OnCompletionActivated()
	{
	}

	bool ICSocketCompletionIo::f_SupportsCompletionSend() const
	{
		return true;
	}

	bool ICSocketCompletionIo::f_SupportsCompletionReceive() const
	{
		return true;
	}

	umint ICSocketCompletionIo::f_GetSendDepth() const
	{
		return 1;
	}

	bool ICSocketCompletionIo::f_SendReleaseIsPrompt() const
	{
		return true;
	}

	bool ICSocketCompletionIo::f_CanSubmitSend() const
	{
		return true;
	}

	bool ICSocketCompletionIo::f_HasPendingOutput() const
	{
		return false;
	}

	void ICSocket::f_SetTransferSizeHint(umint)
	{
	}

	void ICSocket::f_SetSendWindow(umint, bool)
	{
	}

	void ICSocket::f_SetInheritable()
	{
	}

	CSocket ICSocket::f_GiveUpSocket()
	{
		DMibErrorNet("This transport cannot hand its socket over");
		return CSocket();
	}

	void ICSocket::f_AdoptSocket(CSocket &&, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&)
	{
		DMibErrorNet("This transport cannot take over a socket");
	}

	bool ICSocket::f_QueryPathDeliveryRate(umint &, bool &)
	{
		return false;
	}

	ICSocketCompletionIo *ICSocket::f_GetCompletionIo()
	{
		return nullptr;
	}

	NMib::NSys::ICIoLoop *ICSocket::f_GetOwningIoLoop()
	{
		return nullptr;
	}

	void ICSocket::f_CloseAsync(NMib::NFunction::TCFunctionMovable<void ()> &&_fOnClosed)
	{
		f_Close();
		if (_fOnClosed)
			_fOnClosed();
	}

	void ICSocket::f_GiveUpForInheritAsync(NMib::NFunction::TCFunctionMovable<void (CInheritedSocketHandle &&_SocketHandle)> &&_fOnHandle)
	{
		_fOnHandle(CInheritedSocketHandle(f_GiveUpForInherit()));
	}

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
