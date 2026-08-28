// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "Malterlib_Network_Socket_TCP.h"

namespace NMib::NNetwork
{
	CSocket_TCP::CSocket_TCP()
	{
	}

	CSocket_TCP::~CSocket_TCP()
	{
	}

	CSocket_TCP::CSocket_TCP(CSocket_TCP &&_Other)
		: mp_Socket(fg_Move(_Other.mp_Socket))
		, mp_nTransferSizeHint(fg_Exchange(_Other.mp_nTransferSizeHint, 0))
	{
	}

	CSocket_TCP &CSocket_TCP::operator =(CSocket_TCP &&_Other)
	{
		mp_Socket = fg_Move(_Other.mp_Socket);
		mp_nTransferSizeHint = fg_Exchange(_Other.mp_nTransferSizeHint, 0);
		return *this;
	}

	bool CSocket_TCP::f_IsValid() const
	{
		return mp_Socket.f_IsValid();
	}

	bool CSocket_TCP::f_HandshakeDone() const
	{
		return true;
	}

	void CSocket_TCP::f_Close()
	{
		return mp_Socket.f_Close();
	}

	void CSocket_TCP::f_CloseAsync(NMib::NFunction::TCFunctionMovable<void ()> &&_fOnClosed)
	{
		mp_Socket.f_CloseAsync(fg_Move(_fOnClosed));
	}

	void CSocket_TCP::f_Shutdown()
	{
		return mp_Socket.f_Shutdown();
	}

	void CSocket_TCP::f_Connect
		(
			NMib::NNetwork::CNetAddress const &_Address
			, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
			, NMib::NNetwork::CNetAddress const &_BindAddress
		)
	{
		return mp_Socket.f_Connect(_Address, fg_Move(_fOnStateChange), _BindAddress);
	}

	void CSocket_TCP::f_AsyncConnect
		(
			NMib::NNetwork::CNetAddress const &_Address
			, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
			, NMib::NNetwork::CNetAddress const &_BindAddress
		)
	{
		return mp_Socket.f_AsyncConnect(_Address, fg_Move(_fOnStateChange), _BindAddress);
	}

	void CSocket_TCP::f_Listen
		(
			NMib::NNetwork::CNetAddress const &_Address
			, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
			, NMib::NNetwork::ENetFlag _Flags
		)
	{
		return mp_Socket.f_Listen(_Address, fg_Move(_fOnStateChange), _Flags);
	}

	void CSocket_TCP::f_ListenDatagram
		(
			NMib::NNetwork::CNetAddress const &_Address
			, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
			, NMib::NNetwork::ENetFlag _Flags
		)
	{
		return mp_Socket.f_ListenDatagram(_Address, fg_Move(_fOnStateChange), _Flags);
	}

	NStorage::TCUniquePointer<ICSocket> CSocket_TCP::f_Accept(NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		NStorage::TCUniquePointer<CSocket_TCP> pSocket = fg_Construct();
		pSocket->mp_Socket.f_Accept(&mp_Socket, fg_Move(_fOnStateChange));
		if (!pSocket->mp_Socket.f_IsValid())
			return nullptr;
		return fg_Move(pSocket);
	}

	void CSocket_TCP::f_InheritHandle(void *_pSocketHandle, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		return mp_Socket.f_InheritHandle2(_pSocketHandle, fg_Move(_fOnStateChange));
	}

	void *CSocket_TCP::f_GiveUpForInherit()
	{
		return mp_Socket.f_GiveUpForInherit();
	}

	void CSocket_TCP::f_GiveUpForInheritAsync(NMib::NFunction::TCFunctionMovable<void (CInheritedSocketHandle &&_SocketHandle)> &&_fOnHandle)
	{
		mp_Socket.f_GiveUpForInheritAsync
			(
				[_fOnHandle = fg_Move(_fOnHandle)](void *_pSocketHandle) mutable
				{
					_fOnHandle(CInheritedSocketHandle(_pSocketHandle));
				}
			)
		;
	}

	NMib::NSys::ICIoLoop *CSocket_TCP::f_GetOwningIoLoop()
	{
		return mp_Socket.f_GetOwningIoLoop();
	}

	void *CSocket_TCP::f_GetOSSocket()
	{
		return mp_Socket.f_GetOSSocket();
	}

	void CSocket_TCP::f_SetOnStateChange(NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		return mp_Socket.f_SetOnStateChange(fg_Move(_fOnStateChange));
	}

	ENetTCPState CSocket_TCP::f_GetState()
	{
		return mp_Socket.f_GetState();
	}

	NStr::CStr CSocket_TCP::f_GetCloseReason()
	{
		return mp_Socket.f_GetCloseReason();
	}

	CSocketOperationResult CSocket_TCP::f_Receive(void *_pData, umint _DataLen)
	{
		// End of stream is reported through the close event instead
		bool bEndOfStream = false;

		CSocketOperationResult Result;
		Result.m_nBytes = mp_Socket.f_Receive(_pData, _DataLen, bEndOfStream);
		if (Result.m_nBytes != 0)
			Result.m_bReceivedNetwork = true;
		return Result;
	}

	CSocketOperationResult CSocket_TCP::f_Send(const void *_pData, umint _DataLen)
	{
		if (!_DataLen)
			return {};
		CSocketOperationResult Result;
		Result.m_nBytes = mp_Socket.f_Send(_pData, _DataLen);
		if (Result.m_nBytes != 0)
			Result.m_bSentNetwork = true;
		return Result;
	}

	CSocketOperationResult CSocket_TCP::f_SendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans)
	{
		if (!_nSpans)
			return {};
		CSocketOperationResult Result;
		Result.m_nBytes = mp_Socket.f_SendVectored(_pSpans, _nSpans);
		if (Result.m_nBytes != 0)
			Result.m_bSentNetwork = true;
		return Result;
	}

	// The spans handed over are the caller's own memory and go to the loop untouched, so the
	// loop's generation cap is the depth
	umint CSocket_TCP::f_GetSendDepth() const
	{
		auto *pLoop = mp_Socket.f_GetOwningIoLoop();

		return pLoop ? pLoop->f_GetCompletionSendDepth() : 1;
	}

	// The spans go to the loop untouched, so the loop's own release timing is the answer
	bool CSocket_TCP::f_SendReleaseIsPrompt() const
	{
		return mp_Socket.f_SendReleaseIsPrompt();
	}

	ICSocketCompletionIo *CSocket_TCP::f_GetCompletionIo()
	{
		return mp_Socket.f_SupportsCompletionIo() ? this : nullptr;
	}

	void CSocket_TCP::f_SetTransferSizeHint(umint _nBytes)
	{
		mp_nTransferSizeHint = _nBytes;
	}

	bool CSocket_TCP::f_IsSendWindowFull(umint _nUnreleasedBytes, umint _nStartBytes)
	{
		return mp_Socket.f_IsSendWindowFull(_nUnreleasedBytes, _nStartBytes);
	}

	void CSocket_TCP::f_SetSendWindow(umint _nBytes, bool _bConfigured)
	{
		mp_Socket.f_SetSendWindow(_nBytes, _bConfigured);
	}

	void CSocket_TCP::f_SetInheritable()
	{
		mp_Socket.f_SetInheritable();
	}

	CSocket CSocket_TCP::f_GiveUpSocket()
	{
		return fg_Move(mp_Socket);
	}

	void CSocket_TCP::f_AdoptSocket(CSocket &&_Socket, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange)
	{
		mp_Socket.f_Adopt(fg_Move(_Socket), fg_Move(_fOnStateChange));
	}

	bool CSocket_TCP::f_QueryPathDeliveryRate(umint &o_nBytes, bool &o_bAppLimited)
	{
		return mp_Socket.f_QueryPathDeliveryRate(o_nBytes, o_bAppLimited);
	}

	// Receives are only carried by the stream; a loop that cannot provide one leaves this
	// direction on readiness
	bool CSocket_TCP::f_SupportsCompletionReceive() const
	{
		return mp_Socket.f_SupportsReceiveStream();
	}

	umint CSocket_TCP::f_GetReceiveBufferBytes() const
	{
		return fg_Max(mp_nTransferSizeHint, umint(4096));
	}

	bool CSocket_TCP::f_StartReceiveStream(NStorage::TCSharedPointer<NSys::CIoStreamBackpressure> _pBackpressure, NSys::FIoStreamSink &&_fSink)
	{
		if (!mp_Socket.f_SupportsReceiveStream())
			return false;

		return mp_Socket.f_StartReceiveStream(fg_Max(mp_nTransferSizeHint, umint(4096)), fg_Move(_pBackpressure), fg_Move(_fSink));
	}

	void CSocket_TCP::f_ResumeReceiveStream()
	{
		mp_Socket.f_ResumeReceiveStream();
	}

	// The segments are the payload as delivered: the caller gets a shared view of the buffer the
	// kernel filled, riding its owner, and nothing is copied on the way
	bool CSocket_TCP::f_ResolveReceiveSegmentShared(NSys::CIoStreamSegment &_Segment, NContainer::CSharedByteVector &o_Data, NSys::CIoCompletion &o_Result)
	{
		if (_Segment.m_Status != NSys::EIoCompletionStatus::mc_Done || !_Segment.m_nBytes)
			return false;

		o_Result.m_Status = NSys::EIoCompletionStatus::mc_Done;
		o_Result.m_nBytes = _Segment.m_nBytes;
		o_Data = NContainer::CSharedByteVector(_Segment.m_pData, _Segment.m_nBytes, fg_Move(_Segment.m_pOwner));

		return true;
	}

	// Only terminals reach this — data goes through the shared resolve — and a terminal has
	// nothing to deliver beyond its status
	bool CSocket_TCP::f_ResolveReceiveSegment(NSys::CIoStreamSegment &_Segment, void *_pDestination, umint _nDestination, NSys::CIoCompletion &o_Result)
	{
		o_Result.m_Status = _Segment.m_Status;
		o_Result.m_Error = _Segment.m_Error;
		o_Result.m_nBytes = 0;

		return true;
	}

	umint CSocket_TCP::f_SubmitSendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans, NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased)
	{
		return mp_Socket.f_SubmitSendVectored
			(
				_pSpans
				, _nSpans
				, fg_Move(_fOnComplete)
				,
				[fOnReleased = fg_Move(_fOnReleased)]() mutable
				{
					fOnReleased(NMib::NSys::CIoCompletion::mc_iTransferNone);
				}
			)
		;
	}

	umint CSocket_TCP::f_SendDatagram(NMib::NNetwork::CNetAddress const &_Address, const void *_pData, umint _DataLen)
	{
		return mp_Socket.f_SendDatagram(_Address, _pData, _DataLen);
	}

	umint CSocket_TCP::f_ReceiveDatagram(NMib::NNetwork::CNetAddress &_Address, void *_pData, umint _DataLen)
	{
		return mp_Socket.f_ReceiveDatagram(_Address, _pData, _DataLen);
	}

	NMib::NNetwork::CNetAddress CSocket_TCP::f_GetPeerAddress() const
	{
		return mp_Socket.f_GetPeerAddress();
	}

	uint32 CSocket_TCP::f_GetListenPort() const
	{
		return mp_Socket.f_GetListenPort();
	}

	NStorage::TCUniquePointer<ICSocketConnectionInfo> CSocket_TCP::f_GetConnectionInfo() const
	{
		return nullptr;
	}

	FVirtualSocketFactory CSocket_TCP::fs_GetFactory()
	{
		return [](NStr::CStr const &_Hostname) -> NStorage::TCUniquePointer<ICSocket>
			{
				return fg_Construct<CSocket_TCP>();
			}
		;
	}
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
