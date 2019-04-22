/*
 * main.c
 * Copyright (C) 2018 hzshang <hzshang15@gmail.com>
 *
 * Distributed under terms of the MIT license.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#define POOL_SIZE 0x10
char* pool[POOL_SIZE];

void menu() {
    puts("1. Add note");
    puts("2. Show note");
    puts("3. Edit note");
    puts("4. Exit");
    printf(">> ");
}
int read_str(char *buf,int size){
    int n = read(0,buf,size);
    if (buf[n-1]=='\n')
        buf[n-1]='\x00';
}
int read_num(){
    char buf[0x20];
    memset(buf,0,sizeof(buf));
    read_str(buf,0x20);
    return atoi(buf);
}

void add_note() {
    int idx,size;
    for(idx = 0; idx < POOL_SIZE && pool[idx]; idx++);
    if (idx == POOL_SIZE) {
        puts("Full!");
        return;
    }
    printf("Size:");
    size=read_num();
    pool[idx]=(char*)malloc(size);
    if(pool[idx] == NULL)
        exit(1);
    printf("Content:");
    read_str(pool[idx],size);
}

void show_note(){
    printf("Input your id:");
    unsigned int idx=read_num();
    if(idx<POOL_SIZE && pool[idx]){
        puts(pool[idx]);
    }else{
        puts("Are u a hacker?");
    }
}
void edit_note(){
    printf("Input your id:");
    unsigned int idx=read_num();
    if(idx<POOL_SIZE && pool[idx]){
        printf("Content:");
        read_str(pool[idx],strlen(pool[idx]));
    }else{
        puts("Are u a hacker?");
    }
}

#define ll unsigned long long
int main(int argc, char *argv[]) {
    setbuf(stdin,0);
    setbuf(stdout,0);
    setbuf(stderr,0);
    while(1) {
        menu();
        switch(read_num()) {
        case 1:
            add_note();
            break;
        case 2:
            show_note();
            break;
        case 3:
            edit_note();
            break;
        case 4:
            exit(0);
            break;
        default:
            puts("em?");
            exit(0);
        }
    }
    return 0;
}

