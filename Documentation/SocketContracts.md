# Socket contracts

## fg_SendVectored

Send spans in order and return aggregate progress, possibly ending inside a span.

## fg_Receive

Zero progress can mean would-block or EOF; o_bEndOfStream distinguishes them. TLS requires EOF to detect
missing close notification.

## fg_GetOwningIoLoop

The started socket's fixed loop binding; null selects the shared poller.

## fg_SendReleaseIsPrompt

True only if send-buffer release immediately follows completion; false while zero-copy remains possible.

## fg_SetInheritable

Set before start for owners unable to replace permanent completion bindings. Registers readiness-only where
necessary and propagates from listeners to accepted sockets.

## fg_SetSendWindow

Bounds unreleased send bytes and sizes kernel buffers where platform autotuning does not provide the window.

## fg_SetAbortOnClose

TCP close discards queued data and releases zero-copy pages instead of waiting for retransmission. No effect
on Unix sockets.

## fg_QueryPathDeliveryRate

Returns delivery rate when available, otherwise false. Application-limited samples understate path capacity
and must not shrink the window.

## fg_ReownSocket

Transfers the state callback while retaining platform registration and kernel connection state; replays
initial readiness to the new owner.

## fg_RequestReadiness

Request only after would-block outside platform transfer functions; ordinary platform reads/writes request for
themselves.

## fg_InheritHandle2

Adopts and rebinds where supported. Throws when permanent completion binding cannot be replaced; such sources
must be created inheritable.

## fg_GiveUpForInherit

Synchronous handoff is permitted only for shared-poller or unregistered sockets; created loops require
asynchronous handoff.

## fg_GiveUpForInheritAsync

Consumes the platform socket. Returns the raw handle only after removal acknowledgement, on the loop thread
for registered sockets or inline when unregistered.

## fg_CloseAsync

Consumes the platform socket. Registered sockets close on their loop after removal; unregistered sockets close
inline. The continuation marks descriptor closure. Synchronous close is forbidden for created loops.

## ICSocketCompletionIo::f_SubmitSendVectored

Returns accepted plaintext bytes, possibly a prefix. Done covers every accepted byte; short completion is an
error. Zero is terminal refusal, never temporary backpressure. Completion precedes buffer release; both can
run on the loop thread or inline when no kernel operation is needed, carrying the same transfer ID.

## ICSocketCompletionIo::f_StartReceiveStream

Start one ordered receive stream ending in exactly one terminal segment. The sink runs on the loop thread;
resolve on the owner. Backpressure charges buffer capacity, and its cross-thread resume callback must
reschedule to the owner before resuming.

## ICSocketCompletionIo::f_ResolveReceiveSegment

Consume the segment and retain its owner as needed; resolve on the caller's sequence. False means no readable
unit yet. Report produced bytes in the result; a terminal resolves to its own status.

## ICSocket::f_Close

Synchronous close is forbidden on created loops; use asynchronous close. Dropping the socket object is always
legal.

## ICSocket::f_SetAbortOnClose

Abortive close discards queued output and releases kernel-held pages without waiting for the peer. For
graceful closure, shut down and drain first.
