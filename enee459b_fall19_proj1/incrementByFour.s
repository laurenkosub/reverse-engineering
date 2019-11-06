segment .text
BITS 64
global IncrementByFour
					; declare the 'function' symbol global
IncrementByFour:
	.var_8	equ -8			; declare some local constants to reference our
					;   stack frame in IDA Pro fashion

	push rbp			; save the previous frame pointer
	mov rbp, rsp			; setup a new frame for this function
	sub rsp, 8			;   and create 4 bytes of local variable space
                                        ;   because a float is 4 bytes

	mov BYTE [rbp+.var_8], 4	; local var (var_8) = 0
	movzx rax, BYTE [rbp+.var_8]	; now load local variable into eax
	add rax, rdi			; var_8 += first argument
                                        ; rax stores our return value
	mov rsp, rbp			; cleanup our stack frame
	pop rbp				; restore the pointer to the previous frame
	ret				; return from this function

