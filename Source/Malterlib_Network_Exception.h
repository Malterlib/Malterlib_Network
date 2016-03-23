// Copyright © 2015 Hansoft AB 
// Distributed under the MIT license, see license text in LICENSE.Malterlib

#pragma once

#include <Mib/Exception/Exception>

namespace NMib
{
	namespace NNet
	{
		DMibImpErrorClass(CExceptionNet, NException::CException);

#		define DMibErrorNet(d_Description) DMibImpError(NMib::NNet::CExceptionNet, d_Description)

#		ifndef DMibPNoShortCuts
#			define DErrorNet DMibErrorNet
#		endif
	}
}


#ifndef DMibPNoShortCuts
	using namespace NMib::NNet;
#endif
