#include<stdio.h>
int main()
{
void (*ptr)();
char buf[0x100];
read(0,buf,0x100);
ptr=buf;
ptr();
}
