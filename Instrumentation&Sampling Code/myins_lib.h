#ifndef MYINS_LIB_H
#define MYINS_LIB_H

#include <stdio.h>

#include "hash.h"

#define CACHESIZE (32*1024)
#define CACHELINESIZE 64
#define CACHELINENUM (CACHESIZE/CACHELINESIZE)
#define WAY 4
#define WAYLINENUM (CACHELINENUM/WAY)

#ifndef UNIT_SIZE
#define UNIT_SIZE 1000
#endif
#ifndef SECTION_SIZE
#define SECTION_SIZE 10
#endif
#ifndef THRESHOLD_MISSRATE
#define THRESHOLD_MISSRATE 0.3
#endif

typedef enum CacheOP
{
    INIT,
    SETLINE,
    CLEAR
}CacheOP;

typedef struct cache_item{
    uint64_t lineaddr;
    struct cache_item *prev;
    struct cache_item *next;
}cache_item;

typedef struct cache{
    cache_item* head[WAYLINENUM];
    cache_item* tail[WAYLINENUM];
    int size[WAYLINENUM];
}cache;

int LRUCache(cache *c, CacheOP op, uint64_t addr){
    switch(op){
    case INIT:{
        int i=0;
        for(i=0; i < WAYLINENUM; i++){
            c->head[i] = NULL;
            c->tail[i] = NULL;
            c->size[i] = 0;
        }
        return 0;
    }
    case CLEAR:{
        int i=0;
        for(i=0; i < WAYLINENUM; i++){
            if(c->size[i] == 0) continue;
            cache_item* headnext = NULL;
            while(c->head[i] != NULL){
                headnext = c->head[i]->next;
                free(c->head[i]);
                c->head[i] = headnext;
            }
            c->tail[i] = NULL;
            c->size[i] = 0;
        }
        return 0;
    }
    case SETLINE:{
        uint64_t lineaddr = addr/CACHELINESIZE;
        unsigned int i = lineaddr%WAYLINENUM;
        if(c->size[i] == 0){
            c->head[i] = (cache_item*)malloc(sizeof(cache_item));
            c->tail[i] = c->head[i];
            c->size[i] = 1;
            c->head[i]->next = NULL;
            c->head[i]->prev = NULL;
            c->head[i]->lineaddr = lineaddr;
            return 1;
        }
        else{
            cache_item* phead = c->head[i];
            while(phead != NULL){
                if(phead->lineaddr == lineaddr && phead == c->head[i]) return 0;
                else if(phead->lineaddr == lineaddr && phead != c->head[i]){
                    if(phead->prev != NULL) phead->prev->next = phead->next;
                    if(phead->next != NULL) phead->next->prev = phead->prev;
                    if(phead == c->tail[i]) c->tail[i] = phead->prev;
                    phead->prev = NULL;
                    phead->next = c->head[i]; 
                    c->head[i]->prev = phead;
                    c->head[i] = phead;
                    return 0;
                }
                phead = phead->next;
            }
            if(phead == NULL){
                if(c->size[i] < WAY){
                    phead = (cache_item*)malloc(sizeof(cache_item));
                    phead->lineaddr = lineaddr;
                    c->head[i]->prev = phead;
                    phead->next = c->head[i];
                    c->head[i] = phead;
                    c->size[i] += 1;
                }
                else{
                    if(WAY == 1) c->head[i]->lineaddr = lineaddr;
                    else{
                        phead = c->tail[i];
                        phead->lineaddr = lineaddr;
                        phead->prev->next = NULL;
                        c->tail[i] = phead->prev;
                        phead->prev = NULL;
                        phead->next = c->head[i];
                        c->head[i]->prev = phead;
                        c->head[i] = phead;
                    }
                }
                return 1;
            }
        }
        break;
    }
    default:{
        return -1;
    }
    }
}

double average(double a[], int n){
    int i=0;
    double sum = 0;
    for(i=0; i<n; i++){
        sum += a[i];
    }
    return sum/n;
}

double variance(double a[], int n){
    int i=0;
    double sum = 0, av = average(a, n);
    for(i=0; i<n; i++){
        sum += (a[i]-av)*(a[i]-av);
    }
    return sum/n;
}

#endif
