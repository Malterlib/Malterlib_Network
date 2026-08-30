// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Network_Socket_SSL.h"

namespace NMib::NNetwork
{
	CSocket_SSL::CSocket_SSL
		(
			NStorage::TCSharedPointer<CSSLContext> const &_pContext
			, CSSLConnection::FAuthenticationResultCallback const &_AuthenticationResultCallback
			, CSSLConnection::FUserTrustDecisionCallback const &_UserTrustDecisionCallback
			, NStr::CStr const &_Hostname
		)
		: mp_pSSLContext(_pContext)
		, mp_AuthenticationResultCallback(_AuthenticationResultCallback)
		, mp_UserTrustDecisionCallback(_UserTrustDecisionCallback)
		, mp_SSLConnection(_pContext, fg_TempCopy(_AuthenticationResultCallback), fg_TempCopy(_UserTrustDecisionCallback), _Hostname)
	{
	}

	CSocket_SSL::~CSocket_SSL()
	{
		// Destroyed without a close: staged transfers still hold their callers' functors, and
		// dropping a functor unfired leaks the holds its caller counted against the operation —
		// they are counts, not references, and only firing releases them. Operations the kernel
		// holds are unaffected; the loop's cancellation completes those
		fp_FailAllSendOperations();
	}

	bool CSocket_SSL::f_IsValid() const
	{
		return mp_Socket.f_IsValid();
	}

	bool CSocket_SSL::f_HandshakeDone() const
	{
		return mp_State == EState_Done;
	}

	void CSocket_SSL::f_Close()
	{
		// Staged transfers wait in their records for an operation that, with the descriptor
		// going away, is never coming: nothing is left to resolve them and their callers'
		// destroy fences would wait on the stored functors forever. They fail now. An
		// operation the kernel still holds is unaffected — its functors ride the operation
		// and the loop's cancellation completes them
		mp_bSendFailed = true;
		fp_FailAllSendOperations();

		return mp_Socket.f_Close();
	}

	void CSocket_SSL::f_CloseAsync(NMib::NFunction::TCFunctionMovable<void ()> &&_fOnClosed)
	{
		mp_bSendFailed = true;
		fp_FailAllSendOperations();

		mp_Socket.f_CloseAsync(fg_Move(_fOnClosed));
	}

	void CSocket_SSL::f_Shutdown()
	{
		mp_State = EState_Shutdown;
		if (mp_SSLConnection.f_Shutdown())
		{
			mp_State = EState_ShutdownSocket;
			mp_Socket.f_Shutdown();
		}
	}

	NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> CSocket_SSL::fp_SharedOnStateChange()
	{
		return [this](ENetTCPState _StateAdded)
			{
				DMibLock(mp_fOnStateChangeLock);
				mp_fOnStateChange(_StateAdded);
			}
		;
	}

	void CSocket_SSL::f_Connect
		(
			NMib::NNetwork::CNetAddress const &_Address
			, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
			, NMib::NNetwork::CNetAddress const &_BindAddress
		)
	{
		if (!mp_pSSLContext->f_IsClientContext())
			DMibErrorNet("SSL context is not a client context when trying to connect");

		mp_fOnStateChange = fg_Move(_fOnStateChange);
		mp_Socket.f_Connect(_Address, fp_SharedOnStateChange(), _BindAddress);
		mp_State = EState_Connect;
		fp_HandleHandshake();
	}

	void CSocket_SSL::f_AsyncConnect
		(
			NMib::NNetwork::CNetAddress const &_Address
			, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
			, NMib::NNetwork::CNetAddress const &_BindAddress
		)
	{
		if (!mp_pSSLContext->f_IsClientContext())
			DMibErrorNet("SSL context is not a client context when trying to connect");

		mp_State = EState_Connect;
		mp_fOnStateChange = fg_Move(_fOnStateChange);
		return mp_Socket.f_AsyncConnect
			(
				_Address
				, [this](ENetTCPState _StateAdded)
				{
					{
						DMibLock(mp_fOnStateChangeLock);
						mp_fOnStateChange(_StateAdded);
					}
					if (_StateAdded == ENetTCPState_Connected)
						fp_AddTCPState(ENetTCPState_Read); // Kickstart process so user calls f_Receive to do the handshake
				}
				, _BindAddress
			)
		;
	}

	void CSocket_SSL::f_Listen
		(
			NMib::NNetwork::CNetAddress const &_Address
			, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
			, NMib::NNetwork::ENetFlag _Flags
		)
	{
		if (!mp_pSSLContext->f_IsServerContext())
			DMibErrorNet("SSL context is not a server context when trying to listen");

		mp_State = EState_Listen;
		mp_fOnStateChange = fg_Move(_fOnStateChange);
		return mp_Socket.f_Listen(_Address, fp_SharedOnStateChange(), _Flags);
	}

	void CSocket_SSL::f_ListenDatagram
		(
			NMib::NNetwork::CNetAddress const &_Address
			, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
			, NMib::NNetwork::ENetFlag _Flags
		)
	{
		DMibErrorNet("Datagrams not supported");
	}

	NStorage::TCUniquePointer<ICSocket> CSocket_SSL::f_Accept(NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		NStorage::TCUniquePointer<CSocket_SSL> pSocket = fg_Construct(mp_pSSLContext, mp_AuthenticationResultCallback, mp_UserTrustDecisionCallback, "");
		pSocket->mp_fOnStateChange = fg_Move(_fOnStateChange);
		pSocket->mp_Socket.f_Accept(&mp_Socket, pSocket->fp_SharedOnStateChange());
		if (!pSocket->mp_Socket.f_IsValid())
			return nullptr;
		pSocket->mp_State = EState_Accept;
		pSocket->mp_SSLConnection.f_GiveSocket(&pSocket->mp_Socket);
		pSocket->fp_HandleHandshake();
		return fg_Move(pSocket);
	}

	void CSocket_SSL::f_InheritHandle(void *_pSocketHandle, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		mp_fOnStateChange = fg_Move(_fOnStateChange);
		mp_Socket.f_InheritHandle2(_pSocketHandle, fp_SharedOnStateChange());
		if (!mp_Socket.f_IsValid())
			return;

		if (mp_pSSLContext->f_IsClientContext())
			mp_State = EState_Connected;
		else if (mp_pSSLContext->f_IsServerContext())
			mp_State = EState_Accept;
		else
			DMibErrorNet("SSL context is neither client nor server context when inheriting socket");

		mp_SSLConnection.f_GiveSocket(&mp_Socket);
		fp_HandleHandshake();
	}

	void *CSocket_SSL::f_GiveUpForInherit()
	{
		DMibErrorNet("Not implemented");
		return nullptr;
	}

	void *CSocket_SSL::f_GetOSSocket()
	{
		return mp_Socket.f_GetOSSocket();
	}

	void CSocket_SSL::f_SetOnStateChange(NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		{
			DMibLock(mp_fOnStateChangeLock);
			mp_fOnStateChange = fg_Move(_fOnStateChange);
		}
	}

	ENetTCPState CSocket_SSL::f_GetState()
	{
		return mp_Socket.f_GetState() | (ENetTCPState)mp_ExtraState.f_Exchange(0);
	}

	NStr::CStr CSocket_SSL::f_GetCloseReason()
	{
		NStr::CStr Ret;

		NStr::CStr SSLErrors = mp_SSLConnection.f_GetConnectionResult().f_GetErrorMessage();

		if (!SSLErrors.f_IsEmpty())
			NStr::fg_AddStrSep(Ret, SSLErrors, ", ");

		NStr::CStr LastError = mp_SSLConnection.f_GetLastError();
		if (!LastError.f_IsEmpty())
			NStr::fg_AddStrSep(Ret, LastError, ", ");

		if (Ret.f_IsEmpty())
			Ret = mp_Socket.f_GetCloseReason();

		return Ret;
	}

	void CSocket_SSL::fp_CheckBrokenState()
	{
		if (mp_bBrokenStateReported)
			return;
		if (mp_SSLConnection.f_BrokenState())
		{
			fp_AddTCPState(ENetTCPState_Closed);
			mp_bBrokenStateReported = true;
		}
	}

	CSocketOperationResult CSocket_SSL::f_Receive(void *_pData, umint _DataLen)
	{
		if (!fp_HandleHandshake())
			return {};
		if (mp_SSLConnection.f_BrokenState())
		{
			fp_CheckBrokenState();
			return {};
		}

		CSocketOperationResult Return;

		// Records open straight into the caller's buffer, so the ciphertext is read once into
		// memory this connection owns and the plaintext is written once where it was asked for. A
		// refusal means the connection is not in the state that allows it
		if (!mp_SSLConnection.f_TryOpenInto(_pData, _DataLen, Return))
			Return = mp_SSLConnection.f_Receive(_pData, _DataLen);

		if (!Return.m_nBytes)
			fp_CheckBrokenState();

		return Return;
	}

	CSocketOperationResult CSocket_SSL::f_Send(const void *_pData, umint _DataLen)
	{
		if (mp_State == EState_ShutdownSocket)
			return {};

		if (!fp_HandleHandshake())
		{
			DMibLog(DebugVerbose3, " **** CSocket_SSL handshake not done");
			return {};
		}
		if (mp_SSLConnection.f_BrokenState())
		{
			fp_CheckBrokenState();
			DMibLog(DebugVerbose3, " **** CSocket_SSL broken state");
			return {};
		}

		// The empty send is how write readiness arrives here, and what a stalled flush waits for:
		// records already produced are the transport's to deliver, and no other call would offer
		// them again
		if (!_DataLen)
			return mp_SSLConnection.f_FlushPending();

		// Same refusal as the vectored path: nothing more is handed to the library while what it
		// has already produced cannot be written
		if (mp_SSLConnection.f_IsSendBufferFull())
		{
			CSocketOperationResult FlushResult = mp_SSLConnection.f_FlushPending();

			if (mp_SSLConnection.f_IsSendBufferFull())
				return FlushResult;
		}

		CSocketOperationResult Return = mp_SSLConnection.f_Send(_pData, _DataLen);
		if (!Return.m_nBytes)
			fp_CheckBrokenState();

		return Return;
	}

	NMib::NSys::ICIoLoop *CSocket_SSL::f_GetOwningIoLoop()
	{
		return mp_Socket.f_GetOwningIoLoop();
	}

	// Completion transfers become possible once the ciphertext is this connection's own: the memory
	// handed to the kernel has to stay untouched until the completion, which the transport's two
	// buffers are what make true. Before the handshake the connection is still on the readiness
	// path, so this stays null until it is done
	ICSocketCompletionIo *CSocket_SSL::f_GetCompletionIo()
	{
		if (mp_State == EState_ShutdownSocket)
			return nullptr;

		if (!mp_SSLConnection.f_Connected() || mp_SSLConnection.f_HandshakeInProgress() || mp_SSLConnection.f_BrokenState())
			return nullptr;

		// Offered while either direction can be carried by submitted operations; which of them
		// actually is comes from the per direction answers below
		if (!mp_SSLConnection.f_SupportsCompletionIoSend() && !mp_SSLConnection.f_SupportsCompletionIoReceive())
			return nullptr;

		return mp_Socket.f_SupportsCompletionIo() ? this : nullptr;
	}

	void CSocket_SSL::f_OnCompletionActivated()
	{
		mp_bCompletionActive = true;

		// The records this connection stages are what a pipelined send hands over, so how many it
		// will carry is the transport's to answer, and it is settled before the first operation
		auto *pLoop = mp_Socket.f_GetOwningIoLoop();
		mp_SSLConnection.f_SetSendDepth(pLoop ? pLoop->f_GetCompletionSendDepth() : 1);

		// From here the receive stream is the connection's only reader; the synchronous fill
		// refusing is what keeps the shutdown and handshake paths off the descriptor too
		if (f_SupportsCompletionReceive())
			mp_SSLConnection.f_SetCompletionReceive(true);

		// And submitted operations the only writer: the transport must never flush sealed
		// records synchronously on its own, or the transfer whose seal left that way would
		// never resolve
		mp_SSLConnection.f_SetCompletionSend(true);
	}

	umint CSocket_SSL::f_GetSendDepth() const
	{
		return mp_SSLConnection.f_GetSendDepth();
	}

	bool CSocket_SSL::f_SupportsCompletionSend() const
	{
		return mp_SSLConnection.f_SupportsCompletionIoSend();
	}

	// Debug kill switch for staging: with MalterlibSSLSealAhead=0 the chain accepts one
	// transfer at a time, which is the single operation behavior the staging replaced
#if DMibConfig_IoDebug_Enable
	static bool fsg_SealAheadEnabled()
	{
		static bool s_bEnabled =
			(
				[]() -> bool
				{
					auto Setting = NMib::NSys::fg_Process_GetEnvironmentVariable_NonProtected(NStr::CStrNonTracked("MalterlibSSLSealAhead"));
					if (Setting == "0")
						return false;

					return true;
				}
				()
			)
		;

		return s_bEnabled;
	}
#else
	static constexpr bool fsg_SealAheadEnabled()
	{
		return true;
	}
#endif

	// A send can be accepted whenever a transfer slot is free and the transport can take
	// another seal: an operation already in flight no longer refuses — the new batch is sealed
	// into the fill generation now and leaves the moment the operation resolves, so the
	// encryption runs while the kernel is still carrying the previous batch
	bool CSocket_SSL::f_CanSubmitSend() const
	{
		auto fLatchRefusal = [](uint64 _Reason)
			{
#if DMibConfig_IoDebug_Enable
				if (fg_NetIoStatsEnabled())
					g_NetIoStats.m_LastPumpCanBegin.f_Store(_Reason, NAtomic::gc_MemoryOrder_Relaxed);
#endif
			}
		;

		if (mp_bSendFailed)
		{
			fLatchRefusal(1);

			return false;
		}

		if (mp_nSendOpsInFlight && !fsg_SealAheadEnabled())
		{
			fLatchRefusal(2);

			return false;
		}

		if (!mp_SSLConnection.f_CanBeginSend())
		{
			fLatchRefusal(5);

			return false;
		}

		if (!fp_HasFreeSendOperation())
		{
			fLatchRefusal(3);

			return false;
		}

		if (mp_SSLConnection.f_IsSendBufferFull())
		{
			fLatchRefusal(4);

			return false;
		}

		return true;
	}

	bool CSocket_SSL::f_SupportsSendStaging() const
	{
		return true;
	}

	bool CSocket_SSL::f_HasSendOperationInFlight() const
	{
		return mp_nSendOpsInFlight != 0;
	}

	bool CSocket_SSL::fp_HasFreeSendOperation() const
	{
		for (umint iOperation = 0; iOperation < mcp_nMaxSendOperations; ++iOperation)
		{
			if (!mp_SendOperations[iOperation].m_bInUse)
				return true;
		}

		return false;
	}

	bool CSocket_SSL::f_SupportsCompletionReceive() const
	{
		// Receives are only carried by the stream; a loop that cannot provide one leaves this
		// direction on readiness, whatever the connection's own setting says
		return mp_SSLConnection.f_SupportsCompletionIoReceive() && mp_Socket.f_SupportsReceiveStream();
	}

	// Every batch is sealed and submitted here and now, beside however many older generations
	// the kernel already holds; the loop completes operations in submission order, so the
	// record sequence stays intact. A batch that finds no pinnable generation parks its
	// functors and leaves with the drain a release runs; a call with no spans carries parked
	// ciphertext under the caller's fresh functors
	bool CSocket_SSL::f_SubmitSendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans, NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased)
	{
		if (mp_State == EState_ShutdownSocket || mp_SSLConnection.f_BrokenState() || mp_bSendFailed)
		{
			fp_CheckBrokenState();

			return false;
		}

		umint nCallPlaintext = 0;
		smint iOperation = -1;

		if (_nSpans)
		{
			iOperation = fp_AllocateSendOperation();
			if (iOperation < 0)
				return false;

			// A refusal here cannot be retried: this connection has no synchronous path left
			// to carry the plaintext, so the library declining to seal is the connection ending
			CSocketOperationResult Sealed;
			if (!mp_SSLConnection.f_TrySealVectored(_pSpans, _nSpans, Sealed))
			{
				mp_SendOperations[iOperation].m_bInUse = false;
				mp_SSLConnection.f_FailSend("Could not seal application data");
				fp_CheckBrokenState();

				return false;
			}

			// Spans that produced no records would have the caller offer the same bytes again
			// on every pass, forever; it is the connection failing, not an empty transfer
			if (!Sealed.m_nBytes)
			{
				mp_SendOperations[iOperation].m_bInUse = false;
				mp_SSLConnection.f_FailSend("Sealing produced no records");
				fp_CheckBrokenState();

				return false;
			}

			// Past this point the plaintext is spent: sealing advanced the record sequence
			// numbers, so the ciphertext cannot be produced again and the caller must not be
			// told to re-send it. The transfer resolves through the generation its seal landed in
			nCallPlaintext = Sealed.m_nBytes;
			mp_SendOperations[iOperation].m_iBuffer = mp_SSLConnection.f_GetFillBuffer();
			mp_SendOperations[iOperation].m_nPlaintext = nCallPlaintext;

			// A transfer only rides an operation carrying its own generation: the functors an
			// operation carries report to the reservation of the transfer that submitted it, so
			// letting them ride an OLDER generation's ciphertext would report one transfer's
			// bytes against another's reservation. When something older is next in line this
			// batch parks — its stored functors fire when its own generation drains — and the
			// drain carries the older generation under continuation functors of its own
			if (mp_SSLConnection.f_NextBeginSend() != (smint)mp_SendOperations[iOperation].m_iBuffer)
			{
				mp_SendOperations[iOperation].m_fOnComplete = fg_Move(_fOnComplete);
				mp_SendOperations[iOperation].m_fOnReleased = fg_Move(_fOnReleased);
				mp_SendOperations[iOperation].m_bHasFunctors = true;

				return true;
			}
		}

		// The oldest ciphertext the transport holds goes first, which is what keeps records in
		// the order they were sealed
		void const *pData = nullptr;
		umint nBytes = 0;
		umint iBuffer = 0;
		if (mp_SSLConnection.f_BeginSend(pData, nBytes, iBuffer))
		{
			if (fp_SubmitPinnedSend(pData, nBytes, iBuffer, fg_Move(_fOnComplete), fg_Move(_fOnReleased)))
				return true;

			// The submit failed terminally; the call's transfer record — if it made one — was
			// failed along with every other by the submit path
			return false;
		}

		// Nothing was left to move — every generation is blocked behind a buffer-released
		// notification, or there is genuinely nothing pending. The call's own batch, if any,
		// stays recorded and leaves with the next operation; the caller hears now for a call
		// that carried nothing, so a continuation with nothing to do is not left unanswered
		if (iOperation >= 0)
		{
			mp_SendOperations[iOperation].m_fOnComplete = fg_Move(_fOnComplete);
			mp_SendOperations[iOperation].m_fOnReleased = fg_Move(_fOnReleased);
			mp_SendOperations[iOperation].m_bHasFunctors = true;

			return true;
		}

		// The chain is parked behind a buffer-released notification (or has truly nothing
		// pending); the transfer this continuation inherited is done and hears the plaintext
		// the chain still held for it. The parked ciphertext leaves with the drain the next
		// release runs
		NMib::NSys::CIoCompletion Result;
		Result.m_nBytes = mp_nSendPlaintextHeld;
		mp_nSendPlaintextHeld = 0;
		_fOnComplete(Result);

#if DMibConfig_IoDebug_Enable
		if (fg_NetIoStatsEnabled())
			g_NetIoStats.m_nSendSyncParked.f_FetchAdd(1, NAtomic::gc_MemoryOrder_Relaxed);
#endif

		// No operation, so no kernel reference and nothing to wait for: the release runs inline
		_fOnReleased(NMib::NSys::CIoCompletion::mc_iTransferNone);

		return true;
	}

	auto CSocket_SSL::fp_AllocateSendOperation() -> smint
	{
		for (umint iOperation = 0; iOperation < mcp_nMaxSendOperations; ++iOperation)
		{
			if (mp_SendOperations[iOperation].m_bInUse)
				continue;

			mp_SendOperations[iOperation] = CSendOperation{};
			mp_SendOperations[iOperation].m_bInUse = true;

			return smint(iOperation);
		}

		return -1;
	}

	bool CSocket_SSL::fp_SubmitPinnedSend(void const *_pData, umint _nBytes, umint _iBuffer, NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased)
	{
		// The buffer belongs to the operation from here on. A submit that is refused or throws
		// leaves neither a completion nor a release to come, so the pin goes back here instead —
		// otherwise nothing can ever be sent on this connection again
		auto ReleaseHold = NMib::g_OnScopeExit / [&]
			{
				mp_SSLConnection.f_AbortSend(_iBuffer);
			}
		;

		NSys::CIoSpan Span{_pData, _nBytes};

		bool bSubmitted = mp_Socket.f_SubmitSendVectored
			(
				&Span
				, 1
				,
				[fOnComplete = fg_Move(_fOnComplete), pKeepAlive = mp_SSLConnection.f_GetPinnedKeepAlive(_iBuffer), iBuffer = _iBuffer]
				(NMib::NSys::CIoCompletion _Result) mutable
				{
					// The loop's whole part in this: naming which generation answered, on the
					// result itself so it arrives with it. What the bytes mean is worked out by
					// the actor, which is the only thread the record layer is ever reached from,
					// and is also why nothing here refers to the socket
					_Result.m_iTransfer = iBuffer;

					fOnComplete(_Result);
				}
				,
				[fOnReleased = fg_Move(_fOnReleased), iBuffer = _iBuffer]() mutable
				{
					// Named the same way the completion is, so the actor can hand the release
					// back to this socket for the generation it belongs to
					fOnReleased(iBuffer);
				}
			)
		;

		if (bSubmitted)
		{
			ReleaseHold.f_Clear();
			++mp_nSendOpsInFlight;

			return true;
		}

		// The ciphertext exists and cannot be produced a second time, so a transport that will
		// not carry it is the connection ending, not a refusal the caller could retry
		mp_SSLConnection.f_FailSend("Could not submit sealed records");
		fp_CheckBrokenState();
		fp_FailAllSendOperations();

		return false;
	}

	// Turns what the kernel sent into what the callers handed over. Called on the actor's
	// thread, which is what lets the transport be reached without a lock. The result names the
	// generation the operation carried; when its ciphertext has fully left, every staged
	// transfer whose seals it held fires its stored functors, the operation's own transfer is
	// reported through the returned result, and false asks the caller for a continuation — a
	// short send's remainder or a staged generation still needs an operation to carry it
	bool CSocket_SSL::f_ResolveSend(NMib::NSys::CIoCompletion &_Result)
	{
		umint iBuffer = _Result.m_iTransfer;
		if (iBuffer == NMib::NSys::CIoCompletion::mc_iTransferNone)
			return true;

		DMibFastCheck(mp_nSendOpsInFlight);
		if (mp_nSendOpsInFlight)
			--mp_nSendOpsInFlight;

		// Nothing left the machine, and nothing further is coming for these bytes. The
		// generation stays with the released notification still to come, but the connection is
		// over and every pending transfer hears it now
		if (_Result.m_Status != NSys::EIoCompletionStatus::mc_Done)
		{
			mp_bSendFailed = true;
			mp_nSendPlaintextHeld = 0;
			fp_FailAllSendOperations();

			return true;
		}

		if (mp_bSendFailed)
			return true;

		bool bDrained = mp_SSLConnection.f_SendCompleted(iBuffer, _Result.m_nBytes);

		umint nCarrierPlaintext = 0;
		if (bDrained)
		{
			NMib::NSys::CIoCompletion Done;
			Done.m_Status = NSys::EIoCompletionStatus::mc_Done;
			fp_ResolveOpsForBuffer(iBuffer, Done, nCarrierPlaintext);
		}

		// The operation chain reports once, when nothing is left to carry: carrier plaintext
		// accumulates across a short send's continuations, whose own calls hand over nothing
		mp_nSendPlaintextHeld += nCarrierPlaintext;

		// A short send's remainder and staged generations both still need carrying; the caller
		// answers false with a continuation, whose fresh functors ride the next operation. But
		// only when one can actually be begun: pending bytes parked behind pinned generations
		// wait for a release, and a continuation for them would have nothing to move — the
		// chain reports complete instead and the release upcall carries on from there
		if (mp_SSLConnection.f_GetPendingSendUnpinned() && mp_SSLConnection.f_CanBeginSend())
			return false;

		_Result.m_nBytes = mp_nSendPlaintextHeld;
		mp_nSendPlaintextHeld = 0;

		return true;
	}

	// The released half: the kernel is done with the generation's buffer and the transport may
	// fill it again
	void CSocket_SSL::f_ResolveSendRelease(umint _iTransfer)
	{
		if (_iTransfer == NMib::NSys::CIoCompletion::mc_iTransferNone)
			return;

		mp_SSLConnection.f_ReleaseSendBuffer(_iTransfer);

		fp_ReleaseOpsForBuffer(_iTransfer, _iTransfer);
	}

	void CSocket_SSL::fp_ResolveOpsForBuffer(umint _iBuffer, NMib::NSys::CIoCompletion const &_Result, umint &o_nCarrierPlaintext)
	{
		for (umint iOperation = 0; iOperation < mcp_nMaxSendOperations; ++iOperation)
		{
			CSendOperation &Operation = mp_SendOperations[iOperation];
			if (!Operation.m_bInUse || Operation.m_bResolved || Operation.m_iBuffer != _iBuffer)
				continue;

			Operation.m_bResolved = true;

			if (Operation.m_bHasFunctors)
			{
				// A staged transfer hears the plaintext it handed over through its own stored
				// functors. They are the caller's ordinary completion pair and enqueue on the
				// caller, so nothing re-enters this socket while the fan-out walks its state
				NMib::NSys::CIoCompletion Result = _Result;
				Result.m_nBytes = Operation.m_nPlaintext;
				Result.m_iTransfer = NMib::NSys::CIoCompletion::mc_iTransferNone;
				Operation.m_fOnComplete(Result);
			}
			else
			{
				// The operation's own transfer reports through the completion that is being
				// resolved right now
				o_nCarrierPlaintext += Operation.m_nPlaintext;
			}

			fp_TryFreeSendOperation(iOperation);
		}
	}

	void CSocket_SSL::fp_ReleaseOpsForBuffer(umint _iBuffer, umint _iTransfer)
	{
		for (umint iOperation = 0; iOperation < mcp_nMaxSendOperations; ++iOperation)
		{
			CSendOperation &Operation = mp_SendOperations[iOperation];
			if (!Operation.m_bInUse || Operation.m_bReleased || Operation.m_iBuffer != _iBuffer)
				continue;

			Operation.m_bReleased = true;
			if (Operation.m_bHasFunctors)
				Operation.m_fOnReleased(NMib::NSys::CIoCompletion::mc_iTransferNone);

			fp_TryFreeSendOperation(iOperation);
		}
	}

	// The connection is over: every pending staged transfer hears a failure through its stored
	// functors and settles its release inline — the kernel never references a transfer's own
	// memory on this socket, the plaintext was sealed into the generation buffers whose keep
	// alives ride the operations themselves
	void CSocket_SSL::fp_FailAllSendOperations()
	{
		NMib::NSys::CIoCompletion Failed;
		Failed.m_Status = NSys::EIoCompletionStatus::mc_Error;
		Failed.m_iTransfer = NMib::NSys::CIoCompletion::mc_iTransferNone;

		for (umint iOperation = 0; iOperation < mcp_nMaxSendOperations; ++iOperation)
		{
			CSendOperation &Operation = mp_SendOperations[iOperation];
			if (!Operation.m_bInUse)
				continue;

			if (!Operation.m_bResolved)
			{
				Operation.m_bResolved = true;
				if (Operation.m_bHasFunctors)
					Operation.m_fOnComplete(Failed);
			}

			if (!Operation.m_bReleased)
			{
				Operation.m_bReleased = true;
				if (Operation.m_bHasFunctors)
					Operation.m_fOnReleased(NMib::NSys::CIoCompletion::mc_iTransferNone);
			}

			fp_TryFreeSendOperation(iOperation);
		}
	}

	void CSocket_SSL::fp_TryFreeSendOperation(umint _iOperation)
	{
		CSendOperation &Operation = mp_SendOperations[_iOperation];

		if (Operation.m_bResolved && Operation.m_bReleased)
			Operation.m_bInUse = false;
	}

	// Records the library produced on its own, the tail of a send the transport could not
	// finish, and staged generations awaiting an operation. Only submittable output counts:
	// bytes parked behind pinned generations cannot be begun, and the release that unparks
	// them re-drives the caller
	bool CSocket_SSL::f_HasPendingOutput() const
	{
		return mp_SSLConnection.f_GetPendingSendUnpinned() != 0 && mp_SSLConnection.f_CanBeginSend();
	}

	// The stream's ciphertext lands in loop-owned buffers; this only forwards the arming, and
	// the records are opened on the actor's thread as each segment is resolved
	bool CSocket_SSL::f_StartReceiveStream(NStorage::TCSharedPointer<NSys::CIoStreamBackpressure> _pBackpressure, NSys::FIoStreamSink &&_fSink)
	{
		if (mp_State == EState_ShutdownSocket || mp_SSLConnection.f_BrokenState())
		{
			fp_CheckBrokenState();

			return false;
		}

		if (!mp_Socket.f_SupportsReceiveStream())
			return false;

		return mp_Socket.f_StartReceiveStream(mp_SSLConnection.f_GetInboundBufferSize(), fg_Move(_pBackpressure), fg_Move(_fSink));
	}

	void CSocket_SSL::f_ResumeReceiveStream()
	{
		mp_Socket.f_ResumeReceiveStream();
	}

	umint CSocket_SSL::f_GetReceiveBufferBytes() const
	{
		return mp_SSLConnection.f_GetInboundBufferSize();
	}

	// One segment of the stream, on the actor's thread: the ciphertext joins the queue, the
	// records it completed are opened straight into the caller's destination, and what did not
	// fit stays held for the drain calls. A terminal segment opens what is already held first —
	// the peer's close notice arrives in the bytes before its FIN, and opening it now is what
	// turns the end of the stream into a reported close rather than a wait that times out
	bool CSocket_SSL::f_ResolveReceiveSegment(NSys::CIoStreamSegment &_Segment, void *_pDestination, umint _nDestination, NSys::CIoCompletion &o_Result)
	{
		if (_Segment.m_Status == NSys::EIoCompletionStatus::mc_Done && _Segment.m_nBytes)
		{
#if DMibConfig_IoDebug_Enable
			if (fg_NetIoStatsEnabled())
				g_NetIoStats.m_nSslSegments.f_FetchAdd(1, NAtomic::gc_MemoryOrder_Relaxed);
#endif

			// The queue carries the buffer's reference from here; dropping it when the piece is
			// fully consumed is what frees the buffer
			mp_SSLConnection.f_AppendCipherSegment(_Segment.m_pData, _Segment.m_nBytes, fg_Move(_Segment.m_pOwner));
		}

		// A cancelled stream has nothing to deliver and no destination to deliver into; the
		// record layer is left alone
		if (_Segment.m_Status == NSys::EIoCompletionStatus::mc_Cancelled)
		{
			o_Result.m_Status = _Segment.m_Status;
			o_Result.m_nBytes = 0;

			return true;
		}

		// The connection can have failed while the segment was on its way — a send that could
		// not be submitted is enough — and the record layer may not be entered after that
		if (mp_State == EState_ShutdownSocket || mp_SSLConnection.f_BrokenState())
		{
			fp_CheckBrokenState();
			o_Result.m_Status = _Segment.m_Status;
			o_Result.m_nBytes = 0;

			return true;
		}

		CSocketOperationResult Opened;
		mp_SSLConnection.f_OpenHeld(_pDestination, _nDestination, Opened);

		// Opening a record can make the library produce one of its own
		mp_SSLConnection.f_FlushPending();

		if (mp_SSLConnection.f_BrokenState())
			fp_CheckBrokenState();

		o_Result.m_Status = NSys::EIoCompletionStatus::mc_Done;
		o_Result.m_nBytes = Opened.m_nBytes;

		// A data segment that completed no record has nothing to deliver yet; a terminal always
		// resolves, with its own status when nothing was opened ahead of it
		if (_Segment.m_Status != NSys::EIoCompletionStatus::mc_Done || !_Segment.m_nBytes)
		{
			// An end of the TCP stream is only an end of the TLS stream once the peer's
			// close_notify has been opened — everything above ran first, so a notice carried in
			// the bytes before the FIN has been seen by now. Without it the end is
			// unauthenticated truncation, which the readiness path reports as a read failure,
			// and the terminal is converted in place so the callers' own close classification
			// reads the converted status whether it consumes it now or after draining
			if (_Segment.m_Status == NSys::EIoCompletionStatus::mc_Done && !mp_SSLConnection.f_ReceivedShutdown())
			{
				_Segment.m_Status = NSys::EIoCompletionStatus::mc_Error;
				_Segment.m_Error = ECONNRESET;
			}

			if (!Opened.m_nBytes)
			{
				o_Result.m_Status = _Segment.m_Status;
				o_Result.m_Error = _Segment.m_Error;
			}

			return true;
		}

		// No record completed: stream buffers trapped in the queue carry window charges the
		// receive window may be parked over, and the completing bytes would then never arrive.
		// Copying them out releases the charges
		if (!Opened.m_nBytes)
		{
#if DMibConfig_IoDebug_Enable
			if (fg_NetIoStatsEnabled())
				g_NetIoStats.m_nSslNoProgress.f_FetchAdd(1, NAtomic::gc_MemoryOrder_Relaxed);
#endif

			mp_SSLConnection.f_CompactCipherIfStalled();
		}

		return Opened.m_nBytes != 0;
	}

	// Plaintext already held past what the last resolve could fit — records whole in the queue,
	// or the holdover of one opened for a destination too small for it
	bool CSocket_SSL::f_ResolveHeld(void *_pDestination, umint _nDestination, NSys::CIoCompletion &o_Result)
	{
		if (mp_State == EState_ShutdownSocket || mp_SSLConnection.f_BrokenState())
			return false;

		CSocketOperationResult Opened;
		mp_SSLConnection.f_OpenHeld(_pDestination, _nDestination, Opened);

		if (mp_SSLConnection.f_BrokenState())
			fp_CheckBrokenState();

		if (!Opened.m_nBytes)
			return false;

		o_Result.m_Status = NSys::EIoCompletionStatus::mc_Done;
		o_Result.m_nBytes = Opened.m_nBytes;

		return true;
	}

	void CSocket_SSL::f_SetTransferSizeHint(umint _nBytes)
	{
		mp_SSLConnection.f_SetTransferSizeHint(_nBytes);
	}

	void CSocket_SSL::f_SetSendWindow(umint _nBytes, bool _bConfigured)
	{
		mp_Socket.f_SetSendWindow(_nBytes, _bConfigured);
	}

	CSocketOperationResult CSocket_SSL::f_SendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans)
	{
		CSocketOperationResult Result;

		if (mp_State == EState_ShutdownSocket)
			return Result;

		if (!fp_HandleHandshake())
		{
			DMibLog(DebugVerbose3, " **** CSocket_SSL handshake not done");
			return Result;
		}
		if (mp_SSLConnection.f_BrokenState())
		{
			fp_CheckBrokenState();
			DMibLog(DebugVerbose3, " **** CSocket_SSL broken state");
			return Result;
		}

		// Once submitted operations drive the sends every outbound byte goes through the chain,
		// and this reports nothing sent, which is what asks the caller to submit. Only the send
		// direction is asked about; a connection that has left the state completion transfers
		// need falls back to the synchronous path, but not while an operation still holds part
		// of the buffer
		if (mp_bCompletionActive && ((f_GetCompletionIo() && f_SupportsCompletionSend()) || mp_SSLConnection.f_IsSendPinned()))
			return Result;

		// The spans are sealed where they lie, filling each record and putting several of them in
		// the buffer the flush drains, so the gather costs one encryption pass and one write with
		// no copy of the plaintext on the way. A refusal means the connection is not in the state
		// that allows it, and the staging path below carries the call instead
		if (!mp_SSLConnection.f_IsSendBufferFull() && mp_SSLConnection.f_TrySealVectored(_pSpans, _nSpans, Result))
		{
			Result += mp_SSLConnection.f_FlushPending();

			if (!Result.m_nBytes)
				fp_CheckBrokenState();

			return Result;
		}

		// Spans below a full record are staged together, which makes a queue of small messages one
		// maximum sized record instead of one small record per message. The batch then holds those
		// records back so the whole gather leaves as one transport write; it is closed below, on
		// every path out of the loop, because records the library has handed over are never offered
		// by it again
		{
			CSSLConnection::CSendBatch Batch(mp_SSLConnection);

			umint iSpan = 0;
			while (iSpan < _nSpans)
			{
				// A stalled transport is refused here rather than under the library, on a span
				// boundary the caller can retry from. The flush comes first so the refusal means
				// what it says: a buffer still full after one has just stalled the transport, which
				// is what asks for the write readiness that comes back for the rest
				if (mp_SSLConnection.f_IsSendBufferFull())
				{
					Result += mp_SSLConnection.f_FlushPending();

					if (mp_SSLConnection.f_IsSendBufferFull())
						break;
				}

				void const *pData = nullptr;
				umint nBytes = 0;
				umint nSpansTaken = 0;

				if (_pSpans[iSpan].m_nBytes >= mcp_nMaxRecordBytes)
				{
					// Already a record's worth: encrypted where it lies, uncopied
					pData = _pSpans[iSpan].m_pData;
					nBytes = _pSpans[iSpan].m_nBytes;
					nSpansTaken = 1;
				}
				else
				{
					mp_SendStaging.f_SetLen(0, false);

					while (iSpan + nSpansTaken < _nSpans)
					{
						NSys::CIoSpan const &Span = _pSpans[iSpan + nSpansTaken];

						if (mp_SendStaging.f_GetLen() && mp_SendStaging.f_GetLen() + Span.m_nBytes > mcp_nMaxRecordBytes)
							break;

						if (Span.m_nBytes)
							mp_SendStaging.f_InsertLast((uint8 const *)Span.m_pData, Span.m_nBytes);

						++nSpansTaken;

						if (mp_SendStaging.f_GetLen() >= mcp_nMaxRecordBytes)
							break;
					}

					pData = mp_SendStaging.f_GetArray();
					nBytes = mp_SendStaging.f_GetLen();
				}

				if (!nBytes)
				{
					iSpan += nSpansTaken;
					continue;
				}

				umint nAcceptedBefore = Result.m_nBytes;
				Result += mp_SSLConnection.f_Send(pData, nBytes);

				// A short write is the library refusing the rest; what it did take is progress
				// across the spans in order, which is what the result reports
				if (Result.m_nBytes - nAcceptedBefore != nBytes)
					break;

				iSpan += nSpansTaken;
			}
		}

		// What the batch held is offered here, and this is the only place that will: the caller is
		// being told its plaintext is gone. A flush that cannot finish ends on a transport that
		// would block, which is what asks for the write readiness that brings f_Send(nullptr, 0)
		// back here to finish it
		Result += mp_SSLConnection.f_FlushPending();

		if (!Result.m_nBytes)
			fp_CheckBrokenState();

		return Result;
	}

	umint CSocket_SSL::f_SendDatagram(NMib::NNetwork::CNetAddress const &_Address, const void *_pData, umint _DataLen)
	{
		DMibErrorNet("Datagrams not supported");
		return 0;
	}
	umint CSocket_SSL::f_ReceiveDatagram(NMib::NNetwork::CNetAddress &_Address, void *_pData, umint _DataLen)
	{
		DMibErrorNet("Datagrams not supported");
		return 0;
	}

	NMib::NNetwork::CNetAddress CSocket_SSL::f_GetPeerAddress() const
	{
		return mp_Socket.f_GetPeerAddress();
	}

	uint32 CSocket_SSL::f_GetListenPort() const
	{
		return mp_Socket.f_GetListenPort();
	}

	FVirtualSocketFactory CSocket_SSL::fs_GetFactory
		(
			NStorage::TCSharedPointer<CSSLContext> const &_pContext
			, CSSLConnection::FAuthenticationResultCallback const &_AuthenticationResultCallback
			, CSSLConnection::FUserTrustDecisionCallback const &_UserTrustDecisionCallback
		)
	{
		return [=](NStr::CStr const &_Hostname) -> NStorage::TCUniquePointer<ICSocket>
			{
				return fg_Construct<CSocket_SSL>(_pContext, _AuthenticationResultCallback, _UserTrustDecisionCallback, _Hostname);
			}
		;
	}

	void CSocket_SSL::fp_HandleHandshakeDone()
	{
		mp_State = EState_Done;
		fp_AddTCPState(ENetTCPState_Read | ENetTCPState_Write); // Allow user the chance to send or receive any deferred data
	}

	bool CSocket_SSL::fp_HandleHandshake()
	{
		switch (mp_State)
		{
		case EState_ShutdownSocket:
			return false;
		case EState_Shutdown:
			if (mp_SSLConnection.f_Shutdown())
			{
				mp_State = EState_ShutdownSocket;
				mp_Socket.f_Shutdown();
			}
			return false;
		case EState_Done:
			return true;
		case EState_Disconnected:
			return false;
		case EState_Connect:
			{
				mp_State = EState_Connected;
				mp_SSLConnection.f_GiveSocket(&mp_Socket);
			}
			break;
		case EState_Connected:
		case EState_None:
		case EState_Accept:
		case EState_Listen:
			break;
		}

		switch (mp_State)
		{
		case EState_Connected:
			{
				if (mp_SSLConnection.f_Connect())
				{
					fp_HandleHandshakeDone();
					return true;
				}
			}
			break;
		case EState_Accept:
			{
				if (mp_SSLConnection.f_Accept())
				{
					fp_HandleHandshakeDone();
					return true;
				}
			}
			break;
		default:
			DMibNeverGetHere;
		}
		if (mp_SSLConnection.f_HandshakeInProgress())
			return false;

		fp_AddTCPState(ENetTCPState_Closed);
		mp_State = EState_Disconnected;

		return false;
	}

	void CSocket_SSL::fp_AddTCPState(ENetTCPState _ToAdd)
	{
		mp_ExtraState.f_FetchOr(_ToAdd);
		{
			DMibLock(mp_fOnStateChangeLock);
			if (mp_fOnStateChange)
				mp_fOnStateChange(_ToAdd);
		}
	}

	NStorage::TCUniquePointer<ICSocketConnectionInfo> CSocket_SSL::f_GetConnectionInfo() const
	{
		NStorage::TCUniquePointer<CSocketConnectionInfo_SSL> pReturn = fg_Construct();

		auto &Result = mp_SSLConnection.f_GetConnectionResult();
		pReturn->m_PeerCertificate = Result.f_GetPeerCertificate();
		pReturn->m_CertificateChain = Result.f_GetCertificateChain();

		return fg_Move(pReturn);
	}
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
