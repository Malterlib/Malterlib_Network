// Copyright © 2022 Favro Holding AB
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#pragma once

#include <Mib/Core/Core>

namespace NMib::NNetwork
{
	enum ESocketDebugFlag
	{
		ESocketDebugFlag_None = 0
		, ESocketDebugFlag_StopProcessing = DMibBit(0)
		, ESocketDebugFlag_FailSends = DMibBit(1)
	};
}

#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
