	.file	"stack.c"
	.section	.rodata
.LC0:
	.string	"%c"
	.text
	.globl	bof
	.type	bof, @function
bof:
.LFB0:
	.cfi_startproc
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register 5
	subl	$56, %esp
	leal	-9(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC0, (%esp)
	call	__isoc99_scanf
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-33(%ebp), %eax
	movl	%eax, (%esp)
	call	strcpy
	call	getchar
	call	getchar
	call	getchar
	movl	$1, %eax
	leave
	.cfi_restore 5
	.cfi_def_cfa 4, 4
	ret
	.cfi_endproc
.LFE0:
	.size	bof, .-bof
	.section	.rodata
.LC1:
	.string	"pid = %d\n"
.LC2:
	.string	"r"
.LC3:
	.string	"badfile"
.LC4:
	.string	"Returned Properly"
	.text
	.globl	main
	.type	main, @function
main:
.LFB1:
	.cfi_startproc
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register 5
	andl	$-16, %esp
	subl	$544, %esp
	call	getpid
	movl	%eax, 4(%esp)
	movl	$.LC1, (%esp)
	call	printf
	movl	$.LC2, 4(%esp)
	movl	$.LC3, (%esp)
	call	fopen
	movl	%eax, 540(%esp)
	movl	540(%esp), %eax
	movl	%eax, 12(%esp)
	movl	$517, 8(%esp)
	movl	$1, 4(%esp)
	leal	23(%esp), %eax
	movl	%eax, (%esp)
	call	fread
	leal	23(%esp), %eax
	movl	%eax, (%esp)
	call	bof
	movl	$.LC4, (%esp)
	call	puts
	movl	$1, %eax
	leave
	.cfi_restore 5
	.cfi_def_cfa 4, 4
	ret
	.cfi_endproc
.LFE1:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 4.8.1-2ubuntu1~12.04) 4.8.1"
	.section	.note.GNU-stack,"",@progbits
