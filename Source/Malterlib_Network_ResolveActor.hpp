// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#pragma once

namespace NMib::NNetwork
{
	// Marks a valid m_Result discarded before the members release m_Cancel, since releasing it can set a cancellation error that must not be reported as unobserved
	template <typename t_CResult>
	CResolveActor::TCLookup<t_CResult>::~TCLookup()
	{
		if (m_Result.f_IsValid())
			m_Result.f_DiscardResult();
	}

	template <typename t_CResult>
	auto CResolveActor::TCLookup<t_CResult>::operator = (TCLookup &&_Other) -> TCLookup &
	{
		if (this == &_Other)
			return *this;

		if (m_Result.f_IsValid())
			m_Result.f_DiscardResult();

		m_Result = fg_Move(_Other.m_Result);
		m_Cancel = fg_Move(_Other.m_Cancel);

		return *this;
	}
}
