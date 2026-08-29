// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Network_Socket.h"

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
	CNetIoStats g_NetIoStats;

	namespace
	{
		void fg_DumpNetIoStats()
		{
			auto fLoad = [](NAtomic::TCAtomic<uint64> const &_Value) -> uint64
				{
					return _Value.f_Load(NAtomic::gc_MemoryOrder_Relaxed);
				}
			;

			NSys::fg_ConsoleErrorOutput
				(
					NStr::fg_Format<NStr::CStrNonTracked>
						(
							"[net stats] send: readiness={} readinessBytes={} submits={} blocked={} syncParked={} continuations={}\n"
							, fLoad(g_NetIoStats.m_nSendReadinessCalls)
							, fLoad(g_NetIoStats.m_nSendReadinessBytes)
							, fLoad(g_NetIoStats.m_nSendSubmits)
							, fLoad(g_NetIoStats.m_nSendBlocked)
							, fLoad(g_NetIoStats.m_nSendSyncParked)
							, fLoad(g_NetIoStats.m_nSendContinuations)
						)
				)
			;

			uint64 nShared = fLoad(g_NetIoStats.m_nRecvSharedDeliveries);
			uint64 nCopy = fLoad(g_NetIoStats.m_nRecvCopyDeliveries);

			NSys::fg_ConsoleErrorOutput
				(
					NStr::fg_Format<NStr::CStrNonTracked>
						(
							"[net stats] recv: readiness={} readinessBytes={} shared={} sharedBytes={} copy={} copyBytes={} sslSegments={} sslNoProgress={} sslCompacts={}\n"
							, fLoad(g_NetIoStats.m_nRecvReadinessCalls)
							, fLoad(g_NetIoStats.m_nRecvReadinessBytes)
							, nShared
							, fLoad(g_NetIoStats.m_nRecvSharedBytes)
							, nCopy
							, fLoad(g_NetIoStats.m_nRecvCopyBytes)
							, fLoad(g_NetIoStats.m_nSslSegments)
							, fLoad(g_NetIoStats.m_nSslNoProgress)
							, fLoad(g_NetIoStats.m_nSslCompacts)
						)
				)
			;

			NSys::fg_ConsoleErrorOutput
				(
					NStr::fg_Format<NStr::CStrNonTracked>
						(
							"[net stats] storage copies: range={} feed={} feedConst={} consume={}\n"
							, NStream::g_BinaryStorageRangeCopyBytes.f_Load(NAtomic::gc_MemoryOrder_Relaxed)
							, NStream::g_BinaryStorageFeedCopyBytes.f_Load(NAtomic::gc_MemoryOrder_Relaxed)
							, NStream::g_BinaryStorageFeedConstCopyBytes.f_Load(NAtomic::gc_MemoryOrder_Relaxed)
							, NStream::g_BinaryStorageConsumeCopyBytes.f_Load(NAtomic::gc_MemoryOrder_Relaxed)
						)
				)
			;

			NSys::fg_ConsoleErrorOutput
				(
					NStr::fg_Format<NStr::CStrNonTracked>
						(
							"[net stats] ssl pump: submits={} inFlight={} beginRefused={} kernelRefused={} lastRefusal: pending={} pinned={} canBegin={} ops={}/{}\n"
							, fLoad(g_NetIoStats.m_nPumpSubmits)
							, fLoad(g_NetIoStats.m_nPumpInFlight)
							, fLoad(g_NetIoStats.m_nPumpBeginRefused)
							, fLoad(g_NetIoStats.m_nPumpKernelRefused)
							, fLoad(g_NetIoStats.m_LastPumpPending)
							, fLoad(g_NetIoStats.m_LastPumpPinned)
							, fLoad(g_NetIoStats.m_LastPumpCanBegin)
							, fLoad(g_NetIoStats.m_LastPumpOpsUnresolved)
							, fLoad(g_NetIoStats.m_LastPumpOpsInUse)
						)
				)
			;
		}
	}

	bool fg_NetIoStatsEnabled()
	{
		static bool s_bEnabled =
			(
				[]() -> bool
				{
					auto Setting = NMib::NSys::fg_Process_GetEnvironmentVariable_NonProtected(NStr::CStrNonTracked("MalterlibIoStats"));
					if (Setting == "1")
					{
						atexit(&fg_DumpNetIoStats);
						return true;
					}

					return false;
				}
				()
			)
		;

		return s_bEnabled;
	}
#endif

	umint fg_GetReceiveWindowBytes(umint _nBufferBytes)
	{
#if DMibConfig_IoDebug_Enable
		static umint s_nWindow =
			(
				[]() -> umint
				{
					auto Setting = NMib::NSys::fg_Process_GetEnvironmentVariable_NonProtected(NStr::CStrNonTracked("MalterlibReceiveWindow"));

					return Setting.f_ToIntExact(umint(0));
				}
				()
			)
		;

		if (s_nWindow)
		{
			// Floored at a few buffers whatever the override says: a window smaller than that
			// can park the stream while a record that straddles buffers is still incomplete,
			// and the bytes that would complete it then never arrive
			return fg_Max(s_nWindow, 4 * _nBufferBytes);
		}
#endif

		// Wide enough that a consumer legitimately holding a receive pipeline's worth of
		// zero copy views does not park the stream: the views pin whole receive buffers, so
		// the window has to leave headroom above what the consumer intends to hold
		return 64 * _nBufferBytes;
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

	bool ICSocketCompletionIo::f_SupportsSendStaging() const
	{
		return false;
	}

	bool ICSocketCompletionIo::f_HasSendOperationInFlight() const
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
