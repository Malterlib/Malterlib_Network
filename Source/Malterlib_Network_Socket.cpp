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

	// Capacity window derived from connection buffer size, with debug override and minimum progress headroom.
	umint fg_GetReceiveWindowBytes(NMib::NSys::CIoSubSystem &_Io, umint _nBufferBytes)
	{
		if (umint nWindow = _Io.f_ReceiveWindowBytesOverride())
		{
			// Keep enough buffer headroom to complete a straddling record without parking on its own partial data.
			return fg_Max(nWindow, 4 * fg_Min(_nBufferBytes, TCLimitsInt<umint>::mc_Max / 4));
		}

		// Reserve headroom for retained views and saturate multiplication; wraparound could park immediately or disable the limit.
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

	// Continue the retained transfer with no new plaintext; false is terminal refusal.
	bool ICSocketCompletionIo::f_ContinueSend(NSys::FIoCompletion &&, FSocketSendReleased &&)
	{
		return false;
	}

	// Staged sends retain their callbacks until the generation carrying their ciphertext drains.
	bool ICSocketCompletionIo::f_SupportsSendStaging() const
	{
		return false;
	}

	// Ask before gathering and after release; a staging transport applies its own window and returns false.
	bool ICSocketCompletionIo::f_IsSendWindowFull(umint, umint)
	{
		return false;
	}

	// Counts kernel operations, excluding staged transfers awaiting an operation.
	bool ICSocketCompletionIo::f_HasSendOperationInFlight() const
	{
		return false;
	}

	// Protocol termination can precede kernel EOF; drain prior plaintext then end without waiting for peer FIN.
	bool ICSocketCompletionIo::f_ReceiveStreamEndedByProtocol() const
	{
		return false;
	}

	void ICSocketCompletionIo::f_ResumeReceiveStream()
	{
	}

	// Use the actual requested buffer capacity when sizing backpressure; TLS may require more than the payload fragmentation size.
	umint ICSocketCompletionIo::f_GetReceiveBufferBytes() const
	{
		return 4096;
	}

	// Resolve wire progress on the owner thread; false requests continuation without releasing the retained transfer.
	bool ICSocketCompletionIo::f_ResolveSend(NSys::CIoCompletion &)
	{
		return true;
	}

	// Release transport pins on the owner thread after the kernel release callback.
	void ICSocketCompletionIo::f_ResolveSendRelease(umint)
	{
	}

	// Returns a retaining payload view for pass-through data segments; false for terminal or processing segments.
	bool ICSocketCompletionIo::f_ResolveReceiveSegmentShared(NSys::CIoStreamSegment &, NContainer::CSharedByteVector &, NSys::CIoCompletion &)
	{
		return false;
	}

	// Drain held plaintext before accepting the next segment; false means no more held output.
	bool ICSocketCompletionIo::f_ResolveHeld(void *, umint, NSys::CIoCompletion &)
	{
		return false;
	}

	// Call before the first submitted operation so synchronous paths cannot overlap it.
	void ICSocketCompletionIo::f_OnCompletionActivated()
	{
	}

	// Choose transfer mode independently per direction; unsupported directions remain on readiness.
	bool ICSocketCompletionIo::f_SupportsCompletionSend() const
	{
		return true;
	}

	bool ICSocketCompletionIo::f_SupportsCompletionReceive() const
	{
		return true;
	}

	// Maximum unreleased send-buffer generations, not kernel operation concurrency.
	umint ICSocketCompletionIo::f_GetSendDepth() const
	{
		return 1;
	}

	// True permits recycling caller storage at completion; copying/sealing transports can answer true even over late-release sockets.
	bool ICSocketCompletionIo::f_SendReleaseIsPrompt() const
	{
		return true;
	}

	// False parks new sends until release; submitting empty operations instead could starve the notifications needed for progress.
	bool ICSocketCompletionIo::f_CanSubmitSend() const
	{
		return true;
	}

	// Transport-generated output needs explicit drain operations because completion sends provide no write-readiness edge.
	bool ICSocketCompletionIo::f_HasPendingOutput() const
	{
		return false;
	}

	// Sizes transport-owned buffering from a typical payload transfer; pass-through transports ignore it.
	void ICSocket::f_SetTransferSizeHint(umint)
	{
	}

	// Bounds unreleased bytes and platform buffers. A default window leaves adequate platform autotuning alone; listeners propagate settings.
	void ICSocket::f_SetSendWindow(umint, bool)
	{
	}

	// Set before starting for a receiving owner unable to replace permanent completion binding; listeners propagate it.
	void ICSocket::f_SetInheritable()
	{
	}

	// Only stateless wire transports can transfer the platform socket without deregistration; default refuses.
	CSocket ICSocket::f_GiveUpSocket()
	{
		DMibErrorNet("This transport cannot hand its socket over");
		return CSocket();
	}

	// Adopt an already-connected platform socket while retaining its registration.
	void ICSocket::f_AdoptSocket(CSocket &&, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&)
	{
		DMibErrorNet("This transport cannot take over a socket");
	}

	// Returns false until delivery-rate data is available. Application-limited samples must not shrink the window.
	bool ICSocket::f_QueryPathDeliveryRate(umint &, bool &)
	{
		return false;
	}

	// May become available after handshake; choose mode at protocol establishment rather than socket creation.
	ICSocketCompletionIo *ICSocket::f_GetCompletionIo()
	{
		return nullptr;
	}

	// Returns the fixed created-loop binding, or null for shared/no single underlying loop.
	NMib::NSys::ICIoLoop *ICSocket::f_GetOwningIoLoop()
	{
		return nullptr;
	}

	// Registered sockets complete close on their loop; unregistered sockets can complete inline. The socket object remains caller-owned.
	void ICSocket::f_CloseAsync(NMib::NFunction::TCFunctionMovable<void ()> &&_fOnClosed)
	{
		f_Close();
		if (_fOnClosed)
			_fOnClosed();
	}

	// The continuation receives the raw handle only after removal acknowledgement. The emptied socket object remains caller-owned.
	void ICSocket::f_GiveUpForInheritAsync(NMib::NFunction::TCFunctionMovable<void (CInheritedSocketHandle &&_SocketHandle)> &&_fOnHandle)
	{
		_fOnHandle(CInheritedSocketHandle(f_GiveUpForInherit()));
	}

	// Fallback for sockets without a vectored implementation: one send per span, stopping at
	// the first short write so the caller's progress accounting stays in order
	// Returns total progress across ordered spans, possibly ending inside a span; empty spans are skipped.
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
