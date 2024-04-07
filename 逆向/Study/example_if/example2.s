	.file	"example2.c"
	.text
	.section	.rodata
.LC0:
	.string	"login success"
.LC1:
	.string	"password error"
.LC2:
	.string	"username error"
	.text
	.globl	login
	.type	login, @function
login:
.LFB0:
	.cfi_startproc
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register 5
	subl	$24, %esp
	movl	$0, -12(%ebp)
	cmpl	$123, 8(%ebp)
	jne	.L2
	cmpl	$456, 12(%ebp)
	jne	.L3
	movl	$1, -12(%ebp)
	subl	$12, %esp
	pushl	$.LC0
	call	printf
	addl	$16, %esp
	jmp	.L4
.L3:
	subl	$12, %esp
	pushl	$.LC1
	call	printf
	addl	$16, %esp
	jmp	.L4
.L2:
	subl	$12, %esp
	pushl	$.LC2
	call	printf
	addl	$16, %esp
.L4:
	movl	-12(%ebp), %eax
	leave
	.cfi_restore 5
	.cfi_def_cfa 4, 4
	ret
	.cfi_endproc
.LFE0:
	.size	login, .-login
	.globl	main
	.type	main, @function
main:
.LFB1:
	.cfi_startproc
	leal	4(%esp), %ecx
	.cfi_def_cfa 1, 0
	andl	$-16, %esp
	pushl	-4(%ecx)
	pushl	%ebp
	movl	%esp, %ebp
	.cfi_escape 0x10,0x5,0x2,0x75,0
	pushl	%ecx
	.cfi_escape 0xf,0x3,0x75,0x7c,0x6
	subl	$20, %esp
	subl	$8, %esp
	pushl	$457
	pushl	$123
	call	login
	addl	$16, %esp
	movl	%eax, -12(%ebp)
	movl	$0, %eax
	movl	-4(%ebp), %ecx
	.cfi_def_cfa 1, 0
	leave
	.cfi_restore 5
	leal	-4(%ecx), %esp
	.cfi_def_cfa 4, 4
	ret
	.cfi_endproc
.LFE1:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0"
	.section	.note.GNU-stack,"",@progbits
