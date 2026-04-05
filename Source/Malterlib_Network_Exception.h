// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

#include <Mib/Exception/Exception>

namespace NMib::NNetwork
{
	DMibImpErrorClassDefine(CExceptionNet, NException::CException);

#	define DMibErrorNet(d_Description) DMibImpError(NMib::NNetwork::CExceptionNet, d_Description)

#	ifndef DMibPNoShortCuts
#		define DErrorNet DMibErrorNet
#	endif
}


#ifndef DMibPNoShortCuts
	using namespace NMib::NNetwork;
#endif
