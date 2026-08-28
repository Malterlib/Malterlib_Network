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

	// Translates a completion error — the platform's socket error code — into the platform's
	// human readable message, for close reasons and logs
	NStr::CStr fg_FormatSocketIoError(int32 _Error);

	// A raw socket handle produced by an acknowledge-first handoff, owned until a transport
	// adopts it through f_InheritHandle. Dropping it closes the handle, so an abandoned upgrade
	// — an actor torn down mid-handoff — cannot leak the descriptor
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
	// Null when the statistics are off; the counters live on the io subsystem (m_NetIoStats)
	NSys::CNetIoStats *fg_NetIoStats();
#endif

	// The receive stream's flow-control window: how much buffer capacity may be outstanding
	// across the pipeline before the kernel side parks. Sized from the connection's buffer size;
	// MalterlibReceiveWindow (bytes) overrides it in io-debug builds
	umint fg_GetReceiveWindowBytes(NMib::NSys::CIoSubSystem &_Io, umint _nBufferBytes);

	// The allowance a framing layer adds on top of what it is asked to carry, so a full
	// fragment plus this layer's own headers and an interleaved control message still fit in
	// one transfer and one buffer instead of spilling a tiny tail into the next
	inline constexpr umint gc_SocketFramingMargin = 1024;

	// Completion transfers. Sends follow the NSys completion entry points: several may be
	// submitted ahead of their completions, which are reported one at a time in submission order,
	// each completion functor run exactly once, the buffers untouched until the released functor
	// says the kernel is done with them, and closing the socket cancels what is outstanding. Receives are a stream: one standing kernel receive delivers loop-owned
	// segments in order, and the caller resolves each on its own thread.
	//
	// A socket whose payload path is a pure kernel pass-through runs its functors on the loop's
	// thread, as the loop does. One that processes the bytes on the way through may instead answer
	// on the submitting thread, when it can do so out of what it already holds and there is no
	// operation for a loop to report.
	//
	// Synchronization across this whole interface is the caller's: every call — submits, stream
	// start and resume, and the close that ends the socket — must be sequenced by the socket's
	// single owner, and the last of them must happen-before the owner starts the close. Functors
	// the socket invokes (completions, releases, the sink, the backpressure resume) may run on
	// other threads; the owner reschedules onto its own sequence before calling back in
	struct ICSocketCompletionIo
	{
		virtual ~ICSocketCompletionIo();

		// Answers the bytes the socket took of the spans, which is what the transfer covers: every
		// one of them is reported by a Done completion, and a transfer that ends short reports an
		// error instead. Less than offered is a socket that could not take it all — a TLS socket
		// seals what its outbound room allows — and the rest stays the caller's to offer again.
		//
		// 0 is terminal: this socket will accept no further send, and has already put itself in a
		// state the caller's close path observes. There is no "not now" — an implementation that
		// could accept the operation later has to accept it now and report through the completion
		// instead, because nothing wakes the caller to try again.
		//
		// _fOnReleased runs exactly once per accepted send, at or after the completion, when the
		// kernel no longer references the operation's buffers: immediately after the completion
		// for an ordinary send, at the zero copy notification — which waits on the peer — for a
		// zero copy one. It runs on the loop's thread, or inline within the submit for a transfer
		// the socket answered without an operation, exactly as the completion itself may. It
		// carries the same transfer name the completion carried, so a caller with several
		// generations of buffers awaiting release can tell them apart
		virtual umint f_SubmitSendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans, NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased) = 0;

		// The continuation a resolve asked for with false: the socket still holds the caller's
		// transfer, and this carries on with it under fresh functors, offering no bytes of its
		// own. False is terminal, as for a submit. A socket whose resolves never ask for one
		// never sees it
		virtual bool f_ContinueSend(NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased);

		// Whether this socket accepts a send while an operation is already in flight, staging
		// its sealed batch so it leaves the moment the operation resolves. The caller then
		// keeps offering sends while f_CanSubmitSend allows, and a staged transfer reports
		// through its own functors when the generation carrying its batch has fully left
		virtual bool f_SupportsSendStaging() const;

		// Whether the bytes the caller holds unreleased have reached the window the path has
		// earned — asked before gathering another batch, with the caller’s own count of bytes
		// whose release functors have not run and the window a connection begins with. A full
		// answer leaves the batch in the caller’s queue; the next release re-asks. A socket
		// that stages its sends bounds them itself and answers false
		virtual bool f_IsSendWindowFull(umint _nUnreleasedBytes, umint _nStartBytes);

		// Whether a kernel operation is with the socket right now. A staging socket's caller
		// cannot tell this from its own transfer count — staged transfers are outstanding
		// without an operation — and the drain that carries pending output must run exactly
		// when there is none
		virtual bool f_HasSendOperationInFlight() const;

		// Whether the socket's own protocol ended the receive stream ahead of the kernel's
		// terminal: a TLS close_notify opened from a data segment. The caller then treats the
		// segment it is resolving as the stream's last once what was opened ahead of the end has
		// been drained, rather than waiting for a kernel terminal a peer that expects our
		// close_notify first never produces
		virtual bool f_ReceiveStreamEndedByProtocol() const;

		// Starts the standing receive. The sink runs on the loop's thread once per segment, in
		// stream order, ending with exactly one terminal segment; the caller hands each segment
		// to its own thread and resolves it there. _pBackpressure bounds how much buffer
		// capacity may be outstanding at once; when the limit parks the stream, its resume
		// functor fires on the release that crosses the resume threshold, and the caller answers
		// by calling f_ResumeReceiveStream
		virtual bool f_StartReceiveStream(NStorage::TCSharedPointer<NSys::CIoStreamBackpressure> _pBackpressure, NSys::FIoStreamSink &&_fSink) = 0;

		virtual void f_ResumeReceiveStream();

		// The size of one stream buffer as this socket will actually request it — what the
		// caller's receive window must be denominated in. An estimate from the caller's own
		// fragmentation size can undershoot (TLS floors its buffers at a whole record), and a
		// window smaller than a few buffers can park the stream while a unit that straddles
		// buffers is still incomplete
		virtual umint f_GetReceiveBufferBytes() const;

		// A socket whose payload path is a pure kernel pass-through has nothing to add here and
		// keeps the defaults. One that processes the bytes on the way through reports what the
		// kernel did and turns that into what the caller asked for in these, which the caller
		// calls on its own thread: the processing then only ever runs there, and needs no lock
		// against the loop.
		//
		// False means there is nothing to report for this transfer — the caller hears about it
		// when there is something to hear
		virtual bool f_ResolveSend(NSys::CIoCompletion &_Result);

		// The released half of a send, on the caller's thread: the implementation lets go of
		// whatever it pinned for that operation. The default has nothing pinned
		virtual void f_ResolveSendRelease(umint _iTransfer);

		// One segment of the receive stream resolved without a copy, on the caller's thread: the
		// bytes are handed back as a shared view of the very buffer the kernel filled, riding
		// its owner. True with the data for sockets whose segments are the payload as delivered;
		// false for sockets that process the bytes on the way through, which the caller then
		// drives through f_ResolveReceiveSegment instead. Never true for terminal segments
		virtual bool f_ResolveReceiveSegmentShared(NSys::CIoStreamSegment &_Segment, NContainer::CSharedByteVector &o_Data, NSys::CIoCompletion &o_Result);

		// One segment of the receive stream, on the caller's thread. The implementation consumes
		// the segment — taking over its buffer reference — and fills the caller's destination
		// with what the stream produced. False means the segment completed no readable unit yet
		// and there is nothing to deliver; the implementation may hold bytes across calls.
		// _o_Result reports the bytes written to the destination; a terminal segment resolves to
		// its own status
		virtual bool f_ResolveReceiveSegment(NSys::CIoStreamSegment &_Segment, void *_pDestination, umint _nDestination, NSys::CIoCompletion &o_Result) = 0;

		// More plaintext already held beyond what the last resolve could fit — the caller drains
		// it into fresh destinations before handing over the next segment. False means nothing
		// further is held
		virtual bool f_ResolveHeld(void *_pDestination, umint _nDestination, NSys::CIoCompletion &o_Result);

		// Told once, when the caller has decided to drive this socket with submitted operations.
		// A socket that processes bytes on the way through needs to know this before its first
		// operation, not as a side effect of it: its synchronous entry points have to start
		// refusing from that moment, or a send the kernel happens to accept inline would keep
		// taking a path that cannot be ordered against the operations
		virtual void f_OnCompletionActivated();

		// Whether this socket will carry that direction with submitted operations at all. A caller
		// that hears false drives that direction through the synchronous entry points instead, and
		// the two halves of one socket may differ: the buffers a direction owns are disjoint, so
		// one can be submitted while the other stays on readiness
		virtual bool f_SupportsCompletionSend() const;

		virtual bool f_SupportsCompletionReceive() const;

		// How many sends' buffers may await their release at once — the zero copy generation cap.
		// Not an operation concurrency: one send is in flight regardless, and the next is
		// submitted on its completion while the released buffers catch up
		virtual umint f_GetSendDepth() const;

		// Whether an accepted send's released functor runs directly after its completion, so
		// storage the caller recycles as soon as the transfer is reported is never still with
		// the kernel. A transport that copies or seals the caller's bytes at submit answers
		// true regardless of the socket beneath it
		virtual bool f_SendReleaseIsPrompt() const;

		// Whether a send operation submitted now could carry any bytes. False means everything
		// pending is blocked behind buffer-released notifications: the caller goes quiescent and
		// the release re-drives it, instead of submitting operations that can only report
		// nothing — a spin that keeps the loop thread too busy to reap the very notifications
		// that would end it
		virtual bool f_CanSubmitSend() const;

		// Whether the socket holds bytes of its own making that still have to reach the peer — a
		// transport that frames what it carries produces them without being asked, and no send of
		// the caller's is coming to carry them. Completion transfers have no write readiness to
		// notice that, so the caller asks, and submits an operation with nothing of its own in it
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
		// Synchronous close, complete on return: legal only for transports without created
		// loops; refuses for a socket on a created loop, where f_CloseAsync is the form. Dropping
		// the socket object is always legal and closes asynchronously
		virtual void f_Close() = 0;
		// Closes the socket and runs the continuation once the close is complete: the transport's
		// loop holds no reference to the file, the descriptor is closed and a listener's unix
		// socket file is removed. Runs on the loop's thread for a socket on a created loop, inline
		// otherwise; the socket object is empty afterwards and remains the caller's to destroy.
		// An owner that reuses a listener's address waits for it. The default wraps the
		// synchronous form, which is complete on return for transports without created loops
		virtual void f_CloseAsync(NMib::NFunction::TCFunctionMovable<void ()> &&_fOnClosed);
		virtual void f_Shutdown() = 0;
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

		// Acknowledge-first handoff: the continuation receives the handle once the transport's
		// loop holds no reference to the file, so the new owner may close, reuse, or re-register
		// the number freely. The continuation runs on the loop's thread for a socket on a created
		// loop, inline otherwise; the socket object is empty afterwards and remains the caller's
		// to destroy. The default wraps the synchronous form, which is acknowledge-first on
		// return for transports without created loops
		virtual void f_GiveUpForInheritAsync(NMib::NFunction::TCFunctionMovable<void (CInheritedSocketHandle &&_SocketHandle)> &&_fOnHandle);

		// Hands the platform socket over to another transport for an upgrade that keeps the
		// connection as the loop and the kernel know it: nothing is deregistered, rebound or given
		// up, so it needs no inheritable socket. Only a transport with no state of its own on the
		// wire can do this; the default refuses
		virtual CSocket f_GiveUpSocket();
		// The other side of that handoff: the transport starts on a connected socket it did not open
		virtual void f_AdoptSocket(CSocket &&_Socket, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange);
		virtual void *f_GetOSSocket() = 0;
		virtual void f_SetOnStateChange(NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange) = 0;
		virtual ENetTCPState f_GetState() = 0;
		virtual NStr::CStr f_GetCloseReason() = 0;
		virtual CSocketOperationResult f_Receive(void *_pData, umint _DataLen) = 0;
		virtual CSocketOperationResult f_Send(const void *_pData, umint _DataLen) = 0;

		// Sends the spans in order, as one kernel operation where the platform and socket
		// implementation support it. The result byte count is total progress across the
		// spans and may end mid span. Zero length spans are skipped
		virtual CSocketOperationResult f_SendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans);
		virtual umint f_SendDatagram(NMib::NNetwork::CNetAddress const &_Address, const void *_pData, umint _DataLen) = 0;
		virtual umint f_ReceiveDatagram(NMib::NNetwork::CNetAddress &_Address, void *_pData, umint _DataLen) = 0;
		virtual NMib::NNetwork::CNetAddress f_GetPeerAddress() const = 0;
		virtual uint32 f_GetListenPort() const = 0;
		virtual NStorage::TCUniquePointer<ICSocketConnectionInfo> f_GetConnectionInfo() const = 0;

		// What one transfer is worth to the consumer, so an implementation that buffers on the
		// way through can size that buffering to it. Implementations that hand the caller's memory
		// straight to the kernel have nothing to size and ignore it
		virtual void f_SetTransferSizeHint(umint _nBytes);

		// The bytes the connection may have in flight on its sends. For a copying socket the kernel
		// buffers hold them and are sized to it where the platform does not autotune them; for a zero
		// copy socket the unreleased bytes are bounded to it instead. Takes effect on the socket as it
		// is started, and a listen socket passes it on to the connections it accepts. _bConfigured is
		// false for the transport's own default, which leaves buffers the platform sizes well enough alone
		virtual void f_SetSendWindow(umint _nBytes, bool _bConfigured);

		// Marks the socket as one that will be given up, through f_GiveUpForInherit, to an owner that
		// cannot rebind a handle — a backend without a completion port, or a system without the
		// native replace. Before connect, listen or accept; a listen socket passes it to what it
		// accepts. Where a platform binds a socket to its loop for the handle's lifetime the socket
		// then forgoes that binding and runs on readiness alone, so any owner can bind it. Our own
		// loops take over bound handles as well, so a socket given up to one of them needs no mark
		virtual void f_SetInheritable();

		// The bytes the path can hold in flight, from what the kernel knows of the connection;
		// false until it knows enough, or where it cannot be asked
		virtual bool f_QueryPathDeliveryRate(umint &o_nBytes, bool &o_bAppLimited);

		// Null for platforms or loops without kernel-completed transfers. May flip from null to
		// non-null while a handshake is pending, so callers decide their mode once their protocol
		// is established, not at socket creation
		virtual ICSocketCompletionIo *f_GetCompletionIo();

		// The created io loop the underlying platform socket registered with, null when it is on
		// the shared poller — or when the implementation has no single platform socket to ask,
		// which the null default expresses. An upgrade reads it off the old socket to restore the
		// binding before the new transport re-registers the inherited handle
		virtual NMib::NSys::ICIoLoop *f_GetOwningIoLoop();

		// The number of spans every implementation is required to handle in one call. Passing more
		// than this is not supported: an implementation may consume them, stop at this many, or
		// stop earlier, so callers gather at most this many spans per send
		static constexpr umint mc_MaxSendSpans = 64;
	};

	// Completion submits forward span batches to the io loop unchanged, so the socket-level
	// promise must fit what one submitted operation carries
	static_assert(ICSocket::mc_MaxSendSpans <= NSys::gc_IoLoopMaxSubmitSpans, "ICSocket::mc_MaxSendSpans exceeds what one io loop operation accepts");

	using FVirtualSocketFactory = NFunction::TCFunction<NStorage::TCUniquePointer<ICSocket> (NStr::CStr const &_Hostname)>;
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
