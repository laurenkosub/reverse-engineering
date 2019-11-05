segment .text
BITS 64
global AddValues
					; declare the 'function' symbol global
AddValues:
	.var_8	equ -8			; declare some local constants to reference our
					;   stack frame in IDA Pro fashion

	push rbp			; save the previous frame pointer
	mov rbp, rsp			; setup a new frame for this function
	sub rsp, 8			;   and create 8 bytes of local variable space

	mov BYTE [rbp+.var_8], 5	; initialize local variable to 5
	movzx rax, BYTE [rbp+.var_8]	; now load local variable into eax
	add rax, rdi			; 	and add the first argument to the local var
	add rax, rsi			; now add the second argument to the total
	mov rsp, rbp			; cleanup our stack frame
	pop rbp				; restore the pointer to the previous frame
	ret				; return from this function

