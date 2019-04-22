/*
 * main.c
 * Copyright (C) 2018 hzshang <hzshang15@gmail.com>
 *
 * Distributed under terms of the MIT license.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
typedef void (*func)();
void bye(){
    puts("bye!");
    exit(0);
}
void hack(){
    system("/bin/sh");
}
int main(int argc, char *argv[]){
    setbuf(stdin,0);
    setbuf(stdout,0);
    setbuf(stderr,0);
    printf("Try to overflow your first heap!\n");
    char *heap=(char*)malloc(0x10);
    func* ptr=(func*)malloc(sizeof(func));
    *ptr=bye;
    read(0,heap,0x100);
    (*ptr)();

    return 0;
}
