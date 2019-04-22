/*
 * main.c
 * Copyright (C) 2018 hzshang <hzshang15@gmail.com>
 *
 * Distributed under terms of the MIT license.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
typedef unsigned int uint;
typedef unsigned long long ll;
int main(int argc, char *argv[]){
    setbuf(stdin,0);
    setbuf(stdout,0);
    setbuf(stderr,0);
    printf("do you know heap chunk header?\n");
    int r=open("/dev/urandom",0);
    uint num=0;
    uint add=0;
    ulong check;
    for(int i=0;i<0x10;i++){
        ulong* ptr=malloc(num);
        printf("I called malloc(0x%x), tell me the magic number:",num);
        scanf("%ld",&check);
        if (check != ptr[-1]){
            printf("emm?\n");
            exit(0);
        }
        read(r,&add,sizeof(uint));
        num+=add%0x233;
    }
    printf("Welcome the world of heap overflow!\n");
    system("/bin/sh");
    return 0;
}
