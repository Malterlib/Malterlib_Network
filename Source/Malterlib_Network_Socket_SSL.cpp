// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Network_Socket_SSL.h"
#include <Mib/Core/IoSubSystem>

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
		// Staged callbacks must fire to release caller accounting; destroying them silently would strand holds.
		// Kernel-owned operations complete through loop cancellation.
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
		// Fail staged records now; no future kernel operation can resolve them after descriptor teardown.
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

	void CSocket_SSL::f_SetAbortOnClose()
	{
		mp_Socket.f_SetAbortOnClose();
	}

	void CSocket_SSL::f_Shutdown()
	{
		mp_State = EState_Shutdown;
		fp_ContinueShutdown();
	}

	// Delay TCP shutdown until buffered ciphertext has left through the synchronous flush or the completion drain;
	// the transport accepts whole records before the socket takes them, so write readiness drives this again
	void CSocket_SSL::fp_ContinueShutdown()
	{
		if (!mp_SSLConnection.f_Shutdown())
			return;

		if (mp_nSendOpsInFlight || mp_SSLConnection.f_GetPendingSend())
			return;

		mp_State = EState_ShutdownSocket;
		mp_Socket.f_Shutdown();
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

		// An empty send carries write readiness and retries records the library will not offer again.
		if (!_DataLen)
			return mp_SSLConnection.f_FlushPending();

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

	// Wait until handshake completes and transport-owned buffers can safely outlive kernel operations.
	ICSocketCompletionIo *CSocket_SSL::f_GetCompletionIo()
	{
		if (mp_State == EState_ShutdownSocket)
			return nullptr;

		if (!mp_SSLConnection.f_Connected() || mp_SSLConnection.f_HandshakeInProgress() || mp_SSLConnection.f_BrokenState())
			return nullptr;

		if (!mp_SSLConnection.f_SupportsCompletionIoSend() && !mp_SSLConnection.f_SupportsCompletionIoReceive())
			return nullptr;

		return mp_Socket.f_SupportsCompletionIo() ? this : nullptr;
	}

	void CSocket_SSL::f_OnCompletionActivated()
	{
		mp_bCompletionActive = true;

		// Set generation depth before any operation can pin ciphertext.
		auto *pLoop = mp_Socket.f_GetOwningIoLoop();
		mp_SSLConnection.f_SetSendDepth(pLoop ? pLoop->f_GetCompletionSendDepth() : 1);

		// A socket that releases its sends only at the peer's acknowledgement holds the window in
		// pinned generations, so the transport bounds those by the window in bytes
		if (mp_nSendWindowBytes && !mp_Socket.f_SendReleaseIsPrompt())
		{
			DMibFastCheck(!mp_nSendOpsInFlight);
			mp_SSLConnection.f_SetSendWindow(mp_nSendWindowBytes);
		}

		// The standing receive becomes the sole reader, including during shutdown.
		if (f_SupportsCompletionReceive())
			mp_SSLConnection.f_SetCompletionReceive(true);

		// Submitted sends become the sole writer; a synchronous flush would bypass transfer accounting. Receive-only activation keeps synchronous sends.
		if (f_SupportsCompletionSend())
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

#if DMibConfig_IoDebug_Enable
	static bool fsg_SealAheadEnabled(NMib::NSys::CIoSubSystem *_pIo)
	{
		return NMib::NSys::fg_ResolveIoKnob(_pIo->f_SslSealAhead(), true);
	}
#else
	static constexpr bool fsg_SealAheadEnabled(NMib::NSys::CIoSubSystem *)
	{
		return true;
	}
#endif

	// Accept while a transfer slot and seal capacity exist; older kernel sends need not finish before encryption proceeds.
	bool CSocket_SSL::f_CanSubmitSend() const
	{
		auto fLatchRefusal = [](uint64 _Reason)
			{
#if DMibConfig_IoDebug_Enable
				if (auto *pStats = fg_NetIoStats())
					pStats->m_LastPumpCanBegin.f_Store(_Reason, NAtomic::gc_MemoryOrder_Relaxed);
#endif
			}
		;

		if (mp_bSendFailed)
		{
			fLatchRefusal(1);

			return false;
		}

		if (mp_nSendOpsInFlight && !fsg_SealAheadEnabled(mp_pIo))
		{
			fLatchRefusal(2);

			return false;
		}

		if (!mp_SSLConnection.f_CanBeginSend())
		{
			fLatchRefusal(5);

			return false;
		}

		if (mp_SSLConnection.f_IsSendBufferFull())
		{
			fLatchRefusal(4);

			return false;
		}

		return true;
	}

	// The transport enforces its own window, but the actor's full-window ask must trigger growth before const gates reject the next seal.
	bool CSocket_SSL::f_IsSendWindowFull(umint _nUnreleasedBytes, umint _nStartBytes)
	{
		if (mp_bSendWindowWasFull || !mp_SSLConnection.f_CanBeginSend())
		{
			mp_bSendWindowWasFull = false;
			mp_SSLConnection.f_ConsiderSendWindowGrowth();
		}

		return false;
	}

	bool CSocket_SSL::f_SupportsSendStaging() const
	{
		return true;
	}

	bool CSocket_SSL::f_HasSendOperationInFlight() const
	{
		return mp_nSendOpsInFlight != 0;
	}

	// Generation lists preserve submission order for resolve and release callbacks.
	void CSocket_SSL::fp_LinkSendOperation(umint _iOperation)
	{
		CSendOperation &Operation = mp_SendOperations[_iOperation];
		DMibFastCheck(!Operation.m_bLinked);

		umint nHeads = mp_iBufferOperationHead.f_GetLen();
		if (Operation.m_iBuffer >= nHeads)
		{
			mp_iBufferOperationHead.f_SetLen(Operation.m_iBuffer + 1);
			for (umint iHead = nHeads; iHead <= Operation.m_iBuffer; ++iHead)
				mp_iBufferOperationHead[iHead] = -1;
		}

		int32 *piLink = &mp_iBufferOperationHead[Operation.m_iBuffer];
		while (*piLink >= 0)
			piLink = &mp_SendOperations[umint(*piLink)].m_iNextForBuffer;

		*piLink = int32(_iOperation);
		Operation.m_iNextForBuffer = -1;
		Operation.m_bLinked = true;
	}

	void CSocket_SSL::fp_FreeSendOperation(umint _iOperation)
	{
		CSendOperation &Operation = mp_SendOperations[_iOperation];

		if (Operation.m_bLinked)
		{
			int32 *piLink = &mp_iBufferOperationHead[Operation.m_iBuffer];
			while (*piLink >= 0 && umint(*piLink) != _iOperation)
				piLink = &mp_SendOperations[umint(*piLink)].m_iNextForBuffer;

			DMibFastCheck(*piLink >= 0);
			*piLink = Operation.m_iNextForBuffer;
		}

		Operation = CSendOperation{};
		Operation.m_iNextFree = mp_iFreeOperationHead;
		mp_iFreeOperationHead = int32(_iOperation);
	}

	bool CSocket_SSL::f_SupportsCompletionReceive() const
	{
		// Receives are only carried by the stream; a loop that cannot provide one leaves this
		// direction on readiness, whatever the connection's own setting says
		return mp_SSLConnection.f_SupportsCompletionIoReceive() && mp_Socket.f_SupportsReceiveStream();
	}

	// Returns sealed plaintext bytes; the remainder stays with the caller. Retain callbacks when no generation can be pinned.
	// Zero is terminal failure; submitted ciphertext must preserve seal order.
	umint CSocket_SSL::f_SubmitSendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans, NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased)
	{
		DMibFastCheck(_nSpans);

		if (mp_State == EState_ShutdownSocket || mp_SSLConnection.f_BrokenState() || mp_bSendFailed)
		{
			fp_CheckBrokenState();

			return 0;
		}

		smint iOperation = fp_AllocateSendOperation();
		if (iOperation < 0)
			return 0;

		// No synchronous fallback remains after activation; seal refusal is terminal.
		CSocketOperationResult Sealed;
		if (!mp_SSLConnection.f_TrySealVectored(_pSpans, _nSpans, Sealed))
		{
			fp_FreeSendOperation(umint(iOperation));
			mp_SSLConnection.f_FailSend("Could not seal application data");
			fp_CheckBrokenState();

			return 0;
		}

		// Zero sealed progress would retry the same plaintext forever; treat it as terminal.
		if (!Sealed.m_nBytes)
		{
			fp_FreeSendOperation(umint(iOperation));
			mp_SSLConnection.f_FailSend("Sealing produced no records");
			fp_CheckBrokenState();

			return 0;
		}

		// Sealing spends record sequence numbers; never ask the caller to resend accepted plaintext.
		umint nCallPlaintext = Sealed.m_nBytes;
		mp_SendOperations[iOperation].m_iBuffer = uint32(mp_SSLConnection.f_GetFillBuffer());
		mp_SendOperations[iOperation].m_nPlaintext = nCallPlaintext;
		fp_LinkSendOperation(umint(iOperation));

		// A transfer's callbacks must carry its own generation or byte reservations are credited incorrectly.
		// Park newer batches while older ciphertext drains under separate continuation callbacks.
		if (mp_SSLConnection.f_NextBeginSend() != (smint)mp_SendOperations[iOperation].m_iBuffer)
		{
			fp_ParkSendOperation(umint(iOperation), fg_Move(_fOnComplete), fg_Move(_fOnReleased));

			return nCallPlaintext;
		}

		return fp_CarrySend(iOperation, fg_Move(_fOnComplete), fg_Move(_fOnReleased)) ? nCallPlaintext : 0;
	}

	// A continuation: the caller's transfer was reported not over, and this moves whatever is
	// next in line under the functors it inherited
	bool CSocket_SSL::f_ContinueSend(NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased)
	{
		if (mp_State == EState_ShutdownSocket || mp_SSLConnection.f_BrokenState() || mp_bSendFailed)
		{
			fp_CheckBrokenState();

			return false;
		}

		return fp_CarrySend(-1, fg_Move(_fOnComplete), fg_Move(_fOnReleased));
	}

	// Retain staged callbacks until their own generation drains.
	void CSocket_SSL::fp_ParkSendOperation(umint _iOperation, NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased)
	{
		mp_SendOperations[_iOperation].m_fOnComplete = fg_Move(_fOnComplete);
		mp_SendOperations[_iOperation].m_fOnReleased = fg_Move(_fOnReleased);
		mp_SendOperations[_iOperation].m_bHasFunctors = true;
	}

	// Carry the oldest ciphertext first; -1 identifies a continuation with no newly sealed batch.
	bool CSocket_SSL::fp_CarrySend(smint _iOperation, NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased)
	{
		void const *pData = nullptr;
		umint nBytes = 0;
		umint iBuffer = 0;
		if (mp_SSLConnection.f_BeginSend(pData, nBytes, iBuffer))
		{
			return fp_SubmitPinnedSend(pData, nBytes, iBuffer, fg_Move(_fOnComplete), fg_Move(_fOnReleased));
		}

		// When no generation is pinnable, retain the batch until release drives another operation.
		if (_iOperation >= 0)
		{
			fp_ParkSendOperation(umint(_iOperation), fg_Move(_fOnComplete), fg_Move(_fOnReleased));

			return true;
		}

		// A parked chain reports its retained plaintext once; the next buffer release drains remaining ciphertext.
		NMib::NSys::CIoCompletion Result;
		Result.m_nBytes = mp_nSendPlaintextHeld;
		mp_nSendPlaintextHeld = 0;
		_fOnComplete(Result);

#if DMibConfig_IoDebug_Enable
		if (auto *pStats = fg_NetIoStats())
			pStats->m_nSendSyncParked.f_FetchAdd(1, NAtomic::gc_MemoryOrder_Relaxed);
#endif

		// No operation, so no kernel reference and nothing to wait for: the release runs inline
		_fOnReleased(NMib::NSys::CIoCompletion::mc_iTransferNone);

		return true;
	}

	auto CSocket_SSL::fp_AllocateSendOperation() -> smint
	{
		umint iOperation;
		if (mp_iFreeOperationHead >= 0)
		{
			iOperation = umint(mp_iFreeOperationHead);
			mp_iFreeOperationHead = mp_SendOperations[iOperation].m_iNextFree;
		}
		else
		{
			iOperation = mp_SendOperations.f_GetLen();
			mp_SendOperations.f_SetLen(iOperation + 1);
		}

		mp_SendOperations[iOperation] = CSendOperation{};
		mp_SendOperations[iOperation].m_bInUse = true;

		return smint(iOperation);
	}

	bool CSocket_SSL::fp_SubmitPinnedSend(void const *_pData, umint _nBytes, umint _iBuffer, NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased)
	{
		// Return pins on refusal or throw because neither completion nor release will arrive for an unaccepted operation.
		auto ReleaseHold = NMib::g_OnScopeExit / [&]
			{
				mp_SSLConnection.f_AbortSend(_iBuffer);
			}
		;

		NSys::CIoSpan Span{_pData, _nBytes};
		umint nScheduled = mp_Socket.f_SubmitSendVectored
			(
				&Span
				, 1
				,
				[fOnComplete = fg_Move(_fOnComplete), iBuffer = _iBuffer](NMib::NSys::CIoCompletion _Result) mutable
				{
					// The loop only names the generation; resolve transport state on the actor thread.
					_Result.m_iTransfer = iBuffer;

					fOnComplete(_Result);
				}
				,
				[fOnReleased = fg_Move(_fOnReleased), pKeepAlive = mp_SSLConnection.f_GetPinnedKeepAlive(_iBuffer), iBuffer = _iBuffer]() mutable
				{
					// Retain generation storage until kernel release, which may follow completion; return the same generation ID.
					fOnReleased(iBuffer);
				}
			)
		;

		if (nScheduled == _nBytes)
		{
			ReleaseHold.f_Clear();
			++mp_nSendOpsInFlight;

			return true;
		}

		// A generation must schedule whole. Any accepted operation retains its pin even if a partial schedule makes the connection fail.
		if (nScheduled)
		{
			ReleaseHold.f_Clear();
			++mp_nSendOpsInFlight;
			mp_SSLConnection.f_FailSend("Transport took part of a sealed record batch");
			fp_CheckBrokenState();
			fp_FailAllSendOperations();

			return false;
		}

		// Sealed ciphertext cannot be regenerated; submission refusal is terminal.
		mp_SSLConnection.f_FailSend("Could not submit sealed records");
		fp_CheckBrokenState();
		fp_FailAllSendOperations();

		return false;
	}

	// Resolve on the actor thread. Report staged transfers when their generation drains; false requests a continuation for remaining ciphertext.
	bool CSocket_SSL::f_ResolveSend(NMib::NSys::CIoCompletion &_Result)
	{
		umint iBuffer = _Result.m_iTransfer;
		if (iBuffer == NMib::NSys::CIoCompletion::mc_iTransferNone)
			return true;

		DMibFastCheck(mp_nSendOpsInFlight);
		if (mp_nSendOpsInFlight)
			--mp_nSendOpsInFlight;

		// Fail pending transfers now; retain the generation until its still-owed buffer release.
		if (_Result.m_Status != NSys::EIoCompletionStatus::mc_Done)
		{
			mp_bSendFailed = true;
			mp_nSendPlaintextHeld = 0;
			fp_FailAllSendOperations();

			return true;
		}

		if (mp_bSendFailed)
			return true;

		mp_SSLConnection.f_SendCompleted(iBuffer, _Result.m_nBytes);

		umint nCarrierPlaintext = 0;
		NMib::NSys::CIoCompletion Done;
		Done.m_Status = NSys::EIoCompletionStatus::mc_Done;
		fp_ResolveOpsForBuffer(iBuffer, Done, nCarrierPlaintext);

		// Accumulate carrier plaintext across continuations and report the chain once.
		mp_nSendPlaintextHeld += nCarrierPlaintext;

		// After draining ciphertext produced before seal failure, report the broken state without starting another continuation.
		if (mp_SSLConnection.f_BrokenState())
		{
			_Result.m_nBytes = mp_nSendPlaintextHeld;
			mp_nSendPlaintextHeld = 0;
			fp_CheckBrokenState();

			return true;
		}

		// Remember that resolve encountered a full window: release-driven submissions may never observe that moment themselves.
		if (!mp_SSLConnection.f_CanBeginSend())
			mp_bSendWindowWasFull = true;

		// Request continuation only for pinnable output; otherwise report the chain and let buffer release resume it.
		if (mp_SSLConnection.f_GetPendingSendUnpinned() && mp_SSLConnection.f_CanBeginSend())
			return false;

		_Result.m_nBytes = mp_nSendPlaintextHeld;
		mp_nSendPlaintextHeld = 0;

		// The last of a shutdown's output leaving is what its TCP shutdown waited for
		if (mp_State == EState_Shutdown && !mp_nSendOpsInFlight && !mp_SSLConnection.f_GetPendingSend())
			fp_ContinueShutdown();

		return true;
	}

	void CSocket_SSL::f_ResolveSendRelease(umint _iTransfer)
	{
		if (_iTransfer == NMib::NSys::CIoCompletion::mc_iTransferNone)
			return;

		mp_SSLConnection.f_ReleaseSendBuffer(_iTransfer);

		fp_ReleaseOpsForBuffer(_iTransfer, _iTransfer);

		if (mp_bSendWindowPending && !mp_SSLConnection.f_IsSendPinned())
		{
			mp_bSendWindowPending = false;
			mp_SSLConnection.f_SetSendWindow(mp_nSendWindowBytes);
		}
	}

	// Report staged transfers through their stored callbacks; return carrier plaintext through the currently resolving operation.
	void CSocket_SSL::fp_ResolveOpsForBuffer(umint _iBuffer, NMib::NSys::CIoCompletion const &_Result, umint &o_nCarrierPlaintext)
	{
		int32 iOperation = _iBuffer < mp_iBufferOperationHead.f_GetLen() ? mp_iBufferOperationHead[_iBuffer] : -1;
		while (iOperation >= 0)
		{
			CSendOperation &Operation = mp_SendOperations[umint(iOperation)];
			int32 iNext = Operation.m_iNextForBuffer;

			if (!Operation.m_bResolved)
			{
				Operation.m_bResolved = true;

				if (Operation.m_bHasFunctors)
				{
					// Stored callbacks enqueue on the caller; they must not reenter this socket during generation traversal.
					NMib::NSys::CIoCompletion Result = _Result;
					Result.m_nBytes = Operation.m_nPlaintext;
					Result.m_iTransfer = NMib::NSys::CIoCompletion::mc_iTransferNone;
					Operation.m_fOnComplete(Result);
				}
				else
				{
					o_nCarrierPlaintext += Operation.m_nPlaintext;
				}

				fp_TryFreeSendOperation(umint(iOperation));
			}

			iOperation = iNext;
		}
	}

	// Free each transfer only after both completion and release have been reported.
	void CSocket_SSL::fp_ReleaseOpsForBuffer(umint _iBuffer, umint _iTransfer)
	{
		int32 iOperation = _iBuffer < mp_iBufferOperationHead.f_GetLen() ? mp_iBufferOperationHead[_iBuffer] : -1;
		while (iOperation >= 0)
		{
			CSendOperation &Operation = mp_SendOperations[umint(iOperation)];
			int32 iNext = Operation.m_iNextForBuffer;

			if (!Operation.m_bReleased)
			{
				Operation.m_bReleased = true;
				if (Operation.m_bHasFunctors)
					Operation.m_fOnReleased(NMib::NSys::CIoCompletion::mc_iTransferNone);

				fp_TryFreeSendOperation(umint(iOperation));
			}

			iOperation = iNext;
		}
	}

	// Fail staged callbacks and release their plaintext holds now; kernel-owned generation storage remains retained by operations.
	void CSocket_SSL::fp_FailAllSendOperations()
	{
		NMib::NSys::CIoCompletion Failed;
		Failed.m_Status = NSys::EIoCompletionStatus::mc_Error;
		Failed.m_iTransfer = NMib::NSys::CIoCompletion::mc_iTransferNone;

		for (umint iOperation = 0; iOperation < mp_SendOperations.f_GetLen(); ++iOperation)
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
			fp_FreeSendOperation(_iOperation);
	}

	// close_notify or record failure ends the protocol stream even if the peer keeps TCP open.
	bool CSocket_SSL::f_ReceiveStreamEndedByProtocol() const
	{
		return mp_SSLConnection.f_ReceivedShutdown() || mp_SSLConnection.f_BrokenState();
	}

	bool CSocket_SSL::f_HasPendingOutput() const
	{
		return mp_SSLConnection.f_GetPendingSendUnpinned() != 0 && mp_SSLConnection.f_CanBeginSend();
	}

	// The loop delivers ciphertext; resolve records on the actor thread.
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

	// Drain buffered ciphertext before terminal status so close_notify preceding FIN is authenticated before EOF is classified.
	bool CSocket_SSL::f_ResolveReceiveSegment(NSys::CIoStreamSegment &_Segment, void *_pDestination, umint _nDestination, NSys::CIoCompletion &o_Result)
	{
		// A cancelled stream has nothing to deliver and no destination to deliver into; the
		// record layer is left alone
		if (_Segment.m_Status == NSys::EIoCompletionStatus::mc_Cancelled)
		{
			o_Result.m_Status = _Segment.m_Status;
			o_Result.m_nBytes = 0;

			return true;
		}

		// A queued segment can arrive after send-side failure; the record layer is never reentered
		// then, so holding its bytes would only grow the queue for as long as the peer keeps sending
		if (mp_State == EState_ShutdownSocket || mp_SSLConnection.f_BrokenState())
		{
			mp_SSLConnection.f_ClearCipherQueue();
			fp_CheckBrokenState();
			o_Result.m_Status = _Segment.m_Status;
			o_Result.m_nBytes = 0;

			return true;
		}

		if (_Segment.m_Status == NSys::EIoCompletionStatus::mc_Done && _Segment.m_nBytes)
		{
#if DMibConfig_IoDebug_Enable
			if (auto *pStats = fg_NetIoStats())
				pStats->m_nSslSegments.f_FetchAdd(1, NAtomic::gc_MemoryOrder_Relaxed);
#endif

			mp_SSLConnection.f_AppendCipherSegment(_Segment.m_pData, _Segment.m_nBytes, fg_Move(_Segment.m_pOwner));
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
			// After draining prior records, EOF without close_notify is truncation, the same verdict the readiness path gives it
			// (and what our own quiet-shutdown peers send). Convert the terminal status before deferred close classification
			if (_Segment.m_Status == NSys::EIoCompletionStatus::mc_Done && !mp_SSLConnection.f_ReceivedShutdown())
			{
				_Segment.m_Status = NSys::EIoCompletionStatus::mc_Error;
				_Segment.m_Error = NSys::gc_IoErrorConnectionReset;
			}

			if (!Opened.m_nBytes)
			{
				o_Result.m_Status = _Segment.m_Status;
				o_Result.m_Error = _Segment.m_Error;
			}

			return true;
		}

		// Copy stalled partial records out of charged buffers so backpressure can admit the bytes needed to complete them.
		if (!Opened.m_nBytes)
		{
#if DMibConfig_IoDebug_Enable
			if (auto *pStats = fg_NetIoStats())
				pStats->m_nSslNoProgress.f_FetchAdd(1, NAtomic::gc_MemoryOrder_Relaxed);
#endif

			mp_SSLConnection.f_CompactCipherIfStalled();
		}

		return Opened.m_nBytes != 0;
	}

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
		mp_nSendWindowBytes = _nBytes;
		mp_Socket.f_SetSendWindow(_nBytes, _bConfigured);

		// Apply a pending window only while no generation is pinned, including after the final release.
		mp_bSendWindowPending = false;
		if (mp_bCompletionActive && _nBytes && !mp_Socket.f_SendReleaseIsPrompt())
		{
			if (mp_SSLConnection.f_IsSendPinned())
				mp_bSendWindowPending = true;
			else
				mp_SSLConnection.f_SetSendWindow(_nBytes);
		}
	}

	void CSocket_SSL::f_SetInheritable()
	{
		mp_Socket.f_SetInheritable();
	}

	void CSocket_SSL::f_AdoptSocket(CSocket &&_Socket, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		mp_fOnStateChange = fg_Move(_fOnStateChange);
		mp_Socket.f_Adopt(fg_Move(_Socket), fp_SharedOnStateChange());
		if (!mp_Socket.f_IsValid())
			return;

		if (mp_pSSLContext->f_IsClientContext())
			mp_State = EState_Connected;
		else if (mp_pSSLContext->f_IsServerContext())
			mp_State = EState_Accept;
		else
			DMibErrorNet("SSL context is neither client nor server context when adopting socket");

		mp_SSLConnection.f_GiveSocket(&mp_Socket);
		fp_HandleHandshake();
	}

	bool CSocket_SSL::f_QueryPathDeliveryRate(umint &o_nBytes, bool &o_bAppLimited)
	{
		return mp_Socket.f_QueryPathDeliveryRate(o_nBytes, o_bAppLimited);
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

		// Never send synchronously while completion sends are active or any generation remains pinned.
		if (mp_bCompletionActive && ((f_GetCompletionIo() && f_SupportsCompletionSend()) || mp_SSLConnection.f_IsSendPinned()))
			return Result;

		// Direct sealing can refuse outside steady state; the staging fallback then owns progress.
		if (!mp_SSLConnection.f_IsSendBufferFull() && mp_SSLConnection.f_TrySealVectored(_pSpans, _nSpans, Result))
		{
			Result += mp_SSLConnection.f_FlushPending();

			if (!Result.m_nBytes)
				fp_CheckBrokenState();

			return Result;
		}

		// Batch small spans into full records and flush on every exit; the library never reoffers accepted output.
		{
			CSSLConnection::CSendBatch Batch(mp_SSLConnection);

			umint iSpan = 0;
			while (iSpan < _nSpans)
			{
				// Apply backpressure at a retryable span boundary above the library; flushing first establishes the would-block edge needed to resume.
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

				// Stop at the first short library write to preserve aggregate span progress.
				if (Result.m_nBytes - nAcceptedBefore != nBytes)
					break;

				iSpan += nSpansTaken;
			}
		}

		// Flush before reporting plaintext consumed; a stalled flush rearms write readiness to retry retained records.
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
			fp_ContinueShutdown();
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
