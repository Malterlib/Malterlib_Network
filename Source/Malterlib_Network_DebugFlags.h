// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include <Mib/Core/Core>

namespace NMib::NNetwork
{
	enum ESocketDebugFlag
	{
		ESocketDebugFlag_None = 0
		, ESocketDebugFlag_StopProcessing = DMibBit(0)
		, ESocketDebugFlag_FailSends = DMibBit(1)
		, ESocketDebugFlag_StopProcessingReceive = DMibBit(2)
		, ESocketDebugFlag_StopProcessingSend = DMibBit(3)
		, ESocketDebugFlag_DelayClose = DMibBit(4)
		, ESocketDebugFlag_StopWriteQueuedMessages = DMibBit(5)
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
