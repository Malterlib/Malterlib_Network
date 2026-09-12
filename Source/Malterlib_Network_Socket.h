// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include "Malterlib_Network.h"

#include <Mib/Core/IoSubSystem>

namespace NMib::NNetwork
{
	struct ICSocketConnectionInfo
	{
		virtual ~ICSocketConnectionInfo()
		{
		}
	};

	NStr::CStr fg_FormatSocketIoError(int32 _Error);

	// Owns a handed-off descriptor until adoption; dropping an abandoned upgrade closes it.
	class CInheritedSocketHandle
	{
		CInheritedSocketHandle(CInheritedSocketHandle const &) = delete;
		CInheritedSocketHandle &operator = (CInheritedSocketHandle const &) = delete;

	public:
		CInheritedSocketHandle() = default;
		explicit CInheritedSocketHandle(void *_pSocketHandle);
		CInheritedSocketHandle(CInheritedSocketHandle &&_Other);
		CInheritedSocketHandle &operator = (CInheritedSocketHandle &&_Other);
		~CInheritedSocketHandle();

		void *f_Detach();

	private:
		void *mp_pSocketHandle = nullptr;
		bool mp_bOwned = false;
	};

#if DMibConfig_IoDebug_Enable
	NSys::CNetIoStats *fg_NetIoStats();
#endif

	umint fg_GetReceiveWindowBytes(NMib::NSys::CIoSubSystem &_Io, umint _nBufferBytes);

	inline constexpr umint gc_SocketFramingMargin = 1024; // Headroom for framing and an interleaved control message without a tiny tail transfer.

	inline constexpr umint gc_SocketMaxSendWindowBytes = umint(1) << 30; // Bounds preallocated reservations and keeps gathers within 32-bit counts.

	// One owner sequences all interface calls before close. Callbacks may run on other threads; reschedule before calling back in.
	// Sends complete in submission order, once each; buffers remain immutable until release.
	// Resolve received segments on the owner thread. Processing sockets may complete inline without kernel work.
	struct ICSocketCompletionIo
	{
		virtual ~ICSocketCompletionIo();

		virtual umint f_SubmitSendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans, NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased) = 0;
		virtual bool f_ContinueSend(NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased);
		virtual bool f_SupportsSendStaging() const;
		virtual bool f_IsSendWindowFull(umint _nUnreleasedBytes, umint _nStartBytes);
		virtual bool f_HasSendOperationInFlight() const;

		virtual bool f_ReceiveStreamEndedByProtocol() const;
		virtual bool f_StartReceiveStream(NStorage::TCSharedPointer<NSys::CIoStreamBackpressure> _pBackpressure, NSys::FIoStreamSink &&_fSink) = 0;
		virtual void f_ResumeReceiveStream();
		virtual umint f_GetReceiveBufferBytes() const;

		virtual bool f_ResolveSend(NSys::CIoCompletion &_Result);
		virtual void f_ResolveSendRelease(umint _iTransfer);

		virtual bool f_ResolveReceiveSegmentShared(NSys::CIoStreamSegment &_Segment, NContainer::CSharedByteVector &o_Data, NSys::CIoCompletion &o_Result);
		virtual bool f_ResolveReceiveSegment(NSys::CIoStreamSegment &_Segment, void *_pDestination, umint _nDestination, NSys::CIoCompletion &o_Result) = 0;
		virtual bool f_ResolveHeld(void *_pDestination, umint _nDestination, NSys::CIoCompletion &o_Result);

		virtual void f_OnCompletionActivated();
		virtual bool f_SupportsCompletionSend() const;
		virtual bool f_SupportsCompletionReceive() const;
		virtual umint f_GetSendDepth() const;
		virtual bool f_SendReleaseIsPrompt() const;
		virtual bool f_CanSubmitSend() const;
		virtual bool f_HasPendingOutput() const;
	};

	class ICSocket
	{
	public:
		virtual ~ICSocket()
		{
		}

		virtual bool f_IsValid() const = 0;
		virtual bool f_HandshakeDone() const = 0;
		virtual void f_Close() = 0;
		virtual void f_CloseAsync(NMib::NFunction::TCFunctionMovable<void ()> &&_fOnClosed);
		virtual void f_Shutdown() = 0;
		virtual void f_SetAbortOnClose() = 0;
		virtual void f_Connect
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
				, CNetAddress const &_BindAddress = NMib::NNetwork::CNetAddress()
			) = 0
		;
		virtual void f_AsyncConnect
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
				, CNetAddress const &_BindAddress = NMib::NNetwork::CNetAddress()
			) = 0
		;
		virtual void f_Listen(NMib::NNetwork::CNetAddress const &_Address, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange, ENetFlag _Flags) = 0;
		virtual void f_ListenDatagram
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
				, ENetFlag _Flags
			) = 0
		;
		virtual NStorage::TCUniquePointer<ICSocket> f_Accept(NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange) = 0;
		virtual void f_InheritHandle(void *_pSocketHandle, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange) = 0;
		virtual void *f_GiveUpForInherit() = 0;
		virtual void f_GiveUpForInheritAsync(NMib::NFunction::TCFunctionMovable<void (CInheritedSocketHandle &&_SocketHandle)> &&_fOnHandle);

		virtual CSocket f_GiveUpSocket();
		virtual void f_AdoptSocket(CSocket &&_Socket, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange);
		virtual void *f_GetOSSocket() = 0;
		virtual void f_SetOnStateChange(NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange) = 0;
		virtual ENetTCPState f_GetState() = 0;
		virtual NStr::CStr f_GetCloseReason() = 0;
		virtual CSocketOperationResult f_Receive(void *_pData, umint _DataLen) = 0;
		virtual CSocketOperationResult f_Send(const void *_pData, umint _DataLen) = 0;
		virtual CSocketOperationResult f_SendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans);
		virtual umint f_SendDatagram(NMib::NNetwork::CNetAddress const &_Address, const void *_pData, umint _DataLen) = 0;
		virtual umint f_ReceiveDatagram(NMib::NNetwork::CNetAddress &_Address, void *_pData, umint _DataLen) = 0;
		virtual NMib::NNetwork::CNetAddress f_GetPeerAddress() const = 0;
		virtual uint32 f_GetListenPort() const = 0;
		virtual NStorage::TCUniquePointer<ICSocketConnectionInfo> f_GetConnectionInfo() const = 0;

		virtual void f_SetTransferSizeHint(umint _nBytes);
		virtual void f_SetSendWindow(umint _nBytes, bool _bConfigured);
		virtual void f_SetInheritable();

		virtual bool f_QueryPathDeliveryRate(umint &o_nBytes, bool &o_bAppLimited);
		virtual ICSocketCompletionIo *f_GetCompletionIo();
		virtual NMib::NSys::ICIoLoop *f_GetOwningIoLoop();

		static constexpr umint mc_MaxSendSpans = 64; // Callers must gather no more than this; larger arrays have no handling guarantee.
	};

	static_assert(ICSocket::mc_MaxSendSpans <= NSys::gc_IoLoopMaxSubmitSpans, "ICSocket::mc_MaxSendSpans exceeds what one io loop operation accepts");

	using FVirtualSocketFactory = NFunction::TCFunction<NStorage::TCUniquePointer<ICSocket> (NStr::CStr const &_Hostname)>;
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
