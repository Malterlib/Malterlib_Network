// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include "Malterlib_Network_Socket.h"
#include "Malterlib_Network.h"

namespace NMib::NNetwork
{
	class CSocket_TCP final : public ICSocket, public ICSocketCompletionIo
	{
		CSocket_TCP(CSocket_TCP const &) = delete;
		CSocket_TCP &operator = (CSocket_TCP const &) = delete;

	public:
		CSocket_TCP();
		virtual ~CSocket_TCP() override;
		CSocket_TCP(CSocket_TCP &&_Other);
		CSocket_TCP &operator =(CSocket_TCP &&_Other);

		virtual bool f_IsValid() const override;
		virtual bool f_HandshakeDone() const override;
		virtual void f_Close() override;
		virtual void f_CloseAsync(NMib::NFunction::TCFunctionMovable<void ()> &&_fOnClosed) override;
		virtual void f_Shutdown() override;
		virtual void f_Connect
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
				, NMib::NNetwork::CNetAddress const &_BindAddress = NMib::NNetwork::CNetAddress()
			) override
		;
		virtual void f_AsyncConnect
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
				, NMib::NNetwork::CNetAddress const &_BindAddress = NMib::NNetwork::CNetAddress()
			) override
		;
		virtual void f_Listen
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
				, NMib::NNetwork::ENetFlag _Flags
			) override
		;
		virtual void f_ListenDatagram
			(
				NMib::NNetwork::CNetAddress const &_Address
				, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange
				, NMib::NNetwork::ENetFlag _Flags
			) override
		;
		virtual NStorage::TCUniquePointer<ICSocket> f_Accept(NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange) override;
		virtual void f_InheritHandle(void *_pSocketHandle, NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange) override;
		virtual void *f_GiveUpForInherit() override;
		virtual void f_GiveUpForInheritAsync(NMib::NFunction::TCFunctionMovable<void (CInheritedSocketHandle &&_SocketHandle)> &&_fOnHandle) override;
		virtual void *f_GetOSSocket() override;
		virtual void f_SetOnStateChange(NMib::NFunction::TCFunctionMovable<void (ENetTCPState _StateAdded)> &&_fOnStateChange) override;
		virtual ENetTCPState f_GetState() override;
		virtual NStr::CStr f_GetCloseReason() override;
		virtual CSocketOperationResult f_Receive(void *_pData, umint _DataLen) override;
		virtual CSocketOperationResult f_Send(const void *_pData, umint _DataLen) override;
		virtual CSocketOperationResult f_SendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans) override;
		virtual umint f_SendDatagram(NMib::NNetwork::CNetAddress const &_Address, const void *_pData, umint _DataLen) override;
		virtual umint f_ReceiveDatagram(NMib::NNetwork::CNetAddress &_Address, void *_pData, umint _DataLen) override;
		virtual NMib::NNetwork::CNetAddress f_GetPeerAddress() const override;
		virtual uint32 f_GetListenPort() const override;
		virtual NStorage::TCUniquePointer<ICSocketConnectionInfo> f_GetConnectionInfo() const override;

		virtual void f_SetTransferSizeHint(umint _nBytes) override;
		virtual ICSocketCompletionIo *f_GetCompletionIo() override;
		virtual umint f_GetSendDepth() const override;
		virtual NMib::NSys::ICIoLoop *f_GetOwningIoLoop() override;
		virtual bool f_SupportsCompletionReceive() const override;
		virtual umint f_GetReceiveBufferBytes() const override;
		virtual bool f_StartReceiveStream(NStorage::TCSharedPointer<NSys::CIoStreamBackpressure> _pBackpressure, NSys::FIoStreamSink &&_fSink) override;
		virtual void f_ResumeReceiveStream() override;
		virtual bool f_ResolveReceiveSegmentShared(NSys::CIoStreamSegment &_Segment, NContainer::CSharedByteVector &o_Data, NSys::CIoCompletion &o_Result) override;
		virtual bool f_ResolveReceiveSegment(NSys::CIoStreamSegment &_Segment, void *_pDestination, umint _nDestination, NSys::CIoCompletion &o_Result) override;
		virtual bool f_SubmitSendVectored(NSys::CIoSpan const *_pSpans, umint _nSpans, NSys::FIoCompletion &&_fOnComplete, FSocketSendReleased &&_fOnReleased) override;

		static FVirtualSocketFactory fs_GetFactory();

	private:
		CSocket mp_Socket;
		umint mp_nTransferSizeHint = 0;
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
