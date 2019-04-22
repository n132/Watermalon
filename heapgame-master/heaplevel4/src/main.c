/*
 * main.c
 * Copyright (C) 2018 hzshang <hzshang15@gmail.com>
 *
 * Distributed under terms of the MIT license.
 */

#include <stdio.h>
#include <stdlib.h>
#define POOL_SIZE 0x10
char* pool[POOL_SIZE];

void menu() {
    puts("1. Add note");
    puts("2. Show note");
    puts("3. Delete note");
    puts("4. Exit");
    printf(">> ");
}

void add_note() {
    int idx;
    for(idx = 0; idx < POOL_SIZE && pool[idx]; idx++);
    if (idx == POOL_SIZE) {
        puts("Full!");
        return;
    }
    pool[idx]=(char*)malloc(0x68);
    printf("Content: ");
    fgets(pool[idx],0x68,stdin);
}
void show_note(){
    unsigned int idx;
    printf("Input your id:");
    scanf("%u",&idx);
    if(idx<POOL_SIZE && pool[idx]){
        puts(pool[idx]);
    }else{
        puts("Are u a hacker?");
    }
}
void dele_note(){
    unsigned int idx;
    printf("Input your id:");
    scanf("%u",&idx);
    if(idx<POOL_SIZE){
        free(pool[idx]);
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
        int opt;
        if (scanf("%d", &opt) != 1)
            break;
        getchar();
        switch(opt) {
        case 1:
            add_note();
            break;
        case 2:
            show_note();
            break;
        case 3:
            dele_note();
            break;
        case 4:
            exit(0);
            break;
        }
    }
    return 0;
}
