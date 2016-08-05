; Copyright © 2015 Hansoft AB 
; Distributed under the MIT license, see license text in LICENSE.Malterlib

;-----------------------------------------------------
PUBLIC fg_Malterlib_Network_SSL_SaveRegisters_X86_64
PUBLIC fg_Malterlib_Network_SSL_RestoreRegisters_X86_64

;-----------------------------------------------------
;_DATA SEGMENT DWORD PUBLIC USE32 'DATA'

;_DATA ENDS 

;-----------------------------------------------------
AMD64_CODE SEGMENT READ EXECUTE ALIGN(16)

;-----------------------------------------------------

CXMMWord STRUCT 
	m_Low DQ <>
	m_High DQ <>
CXMMWord ENDS

CRegisterState STRUCT 
	m_XMM6 CXMMWord <>
	m_XMM7 CXMMWord <>
	m_XMM8 CXMMWord <>
	m_XMM9 CXMMWord <>
	m_XMM10 CXMMWord <>
	m_XMM11 CXMMWord <>
	m_XMM12 CXMMWord <>
	m_XMM13 CXMMWord <>
	m_XMM14 CXMMWord <>
	m_XMM15 CXMMWord <>

	m_RDI DQ <>
	m_RSI DQ <>
	m_RBX DQ <>
	m_RBP DQ <>

	m_R12 DQ <>
	m_R13 DQ <>
	m_R14 DQ <>
	m_R15 DQ <>
CRegisterState ENDS

fg_Malterlib_Network_SSL_SaveRegisters_X86_64 PROC
; C

	mov rax, rcx
;	mov [rax].CRegisterState.m_RDI, rdi
;	mov [rax].CRegisterState.m_RSI, rsi
;	mov [rax].CRegisterState.m_RBX, rbx
;	mov [rax].CRegisterState.m_RBP, rbp
;	mov [rax].CRegisterState.m_R12, r12
;	mov [rax].CRegisterState.m_R13, r13
;	mov [rax].CRegisterState.m_R14, r14
;	mov [rax].CRegisterState.m_R15, r15
	
	movaps [rax].CRegisterState.m_XMM6, xmm6
	movaps [rax].CRegisterState.m_XMM7, xmm7
	movaps [rax].CRegisterState.m_XMM8, xmm8
	movaps [rax].CRegisterState.m_XMM9, xmm9
	movaps [rax].CRegisterState.m_XMM10, xmm10
	movaps [rax].CRegisterState.m_XMM11, xmm11
	movaps [rax].CRegisterState.m_XMM12, xmm12
	movaps [rax].CRegisterState.m_XMM13, xmm13
	movaps [rax].CRegisterState.m_XMM14, xmm14
	movaps [rax].CRegisterState.m_XMM15, xmm15

	ret

fg_Malterlib_Network_SSL_SaveRegisters_X86_64 ENDP

fg_Malterlib_Network_SSL_RestoreRegisters_X86_64 PROC
; C

	mov rax, rcx
;	mov rdi, [rax].CRegisterState.m_RDI
;	mov rsi, [rax].CRegisterState.m_RSI
;	mov rbx, [rax].CRegisterState.m_RBX
;	mov rbp, [rax].CRegisterState.m_RBP
;	mov r12, [rax].CRegisterState.m_R12
;	mov r13, [rax].CRegisterState.m_R13
;	mov r14, [rax].CRegisterState.m_R14
;	mov r15, [rax].CRegisterState.m_R15
	
	movaps xmm6, [rax].CRegisterState.m_XMM6
	movaps xmm7, [rax].CRegisterState.m_XMM7 
	movaps xmm8, [rax].CRegisterState.m_XMM8
	movaps xmm9, [rax].CRegisterState.m_XMM9
	movaps xmm10, [rax].CRegisterState.m_XMM10
	movaps xmm11, [rax].CRegisterState.m_XMM11 
	movaps xmm12, [rax].CRegisterState.m_XMM12
	movaps xmm13, [rax].CRegisterState.m_XMM13
	movaps xmm14, [rax].CRegisterState.m_XMM14
	movaps xmm15, [rax].CRegisterState.m_XMM15
	ret

fg_Malterlib_Network_SSL_RestoreRegisters_X86_64 ENDP

AMD64_CODE ENDS 

END
