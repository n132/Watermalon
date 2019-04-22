/*
 * main.c
 * Copyright (C) 2018 hzshang <hzshang15@gmail.com>
 *
 * Distributed under terms of the MIT license.
 */

#include <stdio.h>
#include <stdlib.h>
#define SIZE 0x30
#define POOL_SIZE 0x10
struct _unit {
    char con[SIZE];
    void (*ptr)(struct _unit*);
};
typedef struct _unit unit;
unit* pool[POOL_SIZE];
void hack() {
    system("/bin/sh");
}
void menu() {
    puts("1. Add note");
    puts("2. Show note");
    puts("3. Delete note");
    puts("4. Exit");
    printf(">> ");
}
void destory(unit* self){
    free(self);
}
void add_note() {
    int idx;
    for(idx = 0; idx < POOL_SIZE && pool[idx]; idx++);
    if (idx == POOL_SIZE) {
        puts("Full!");
        return;
    }
    pool[idx]=(unit*)malloc(sizeof(unit));
    printf("Content: ");
    scanf("%47s",pool[idx]->con);
    pool[idx]->ptr=destory;
    printf("Note id: %d\n",idx);
}
void show_note(){
    puts("Not implement!");
}
void dele_note(){
    unsigned int idx;
    printf("Input your id:");
    scanf("%u",&idx);
    if(idx<POOL_SIZE){
        pool[idx]->ptr(pool[idx]);
    }else{
        puts("Are u a hacker?");
    }
}
int main(int argc, char *argv[]) {
    setbuf(stdin,0);
    setbuf(stdout,0);
    setbuf(stderr,0);
    while(1) {
        menu();
        int opt;
        if (scanf("%d", &opt) != 1)
            break;
        if (opt == 4)
            break;
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
        }
    }
    return 0;
}
