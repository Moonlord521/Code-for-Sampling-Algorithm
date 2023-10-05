/*
 * =====================================================================================
 *
 *       Filename:  ins_lib.c
 *
 *    Description:  插桩lib
 *
 *        Version:  1.0
 *        Created:  06/15/2021 03:29:11 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Dr. Qidongsheng (qds), anyqds@mail.ustc.edu.cn
 *        Company:  USTC
 *
 * =====================================================================================
 */
#ifndef INS_LIB
#define INS_LIB

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/time.h>

#define CACHELINESIZE 64
#define MAXTRACEN 627917
#define GAPTRACEN 20000000

enum TraceType
{
    OTHER_T = 0,
    LOAD_T,
    STORE_T
};

unsigned long long tracen = 0;
static FILE *fp;
void InitInstrumentation(){
    if((fp = fopen("tracefile.txt", "w")) == NULL){
        printf("fail writing!\n");
        exit(0);
    }
    return;
}

void LoadInstrumentation(uint64_t addr, int size, char* FName, char* MName, int instIndex, int bbIndex, int line, char* filename, int lineir, int colir){
    tracen++;
    if (tracen%GAPTRACEN > MAXTRACEN) return;
//    if(fp) fprintf(fp, "%d,%d,%d,%d,%llu,%u,%d,%d,%d,%d,%d,%d,%d,%d,%s,%s,%d,%d\n", 0, 0, 0, 0, (long long unsigned int)addr/CACHELINESIZE, (unsigned int)(addr%CACHELINESIZE), LOAD_T, size, line, 0, 0, 0, 0, 0, FName, MName, instIndex, bbIndex);
    if(fp) fprintf(fp, "%s,%d,%d,%d,%llu,%u,%d,%d,%d,%d,%d,%d,%d,%d,%s,%s,%d,%d\n", filename, lineir, colir, 0, (long long unsigned int)addr/CACHELINESIZE, (unsigned int)(addr%CACHELINESIZE), LOAD_T, size, line, 0, 0, 0, 0, 0, FName, MName, instIndex, bbIndex);
    //fprintf(fp, "%d,%d,%d,%d,%llu,%u,%d,%d,%d,%d,%d,%d,%d,%d\n", 0, 0, 0, 0, (long long unsigned int)addr/CACHELINESIZE, (unsigned int)(addr%CACHELINESIZE), LOAD_T, size, 0, 0, 0, 0, 0, 0);
}

void StoreInstrumentation(uint64_t addr, int size, char* FName, char* MName, int instIndex, int bbIndex, int line, char* filename, int lineir, int colir){
    tracen++;
    if (tracen%GAPTRACEN > MAXTRACEN) return;
//    if(fp) fprintf(fp, "%d,%d,%d,%d,%llu,%u,%d,%d,%d,%d,%d,%d,%d,%d,%s,%s,%d,%d\n", 0, 0, 0, 0, (long long unsigned int)addr/CACHELINESIZE, (unsigned int)(addr%CACHELINESIZE), STORE_T, size, line, 0, 0, 0, 0, 0, FName, MName, instIndex, bbIndex);
    if(fp) fprintf(fp, "%s,%d,%d,%d,%llu,%u,%d,%d,%d,%d,%d,%d,%d,%d,%s,%s,%d,%d\n", filename, lineir, colir, 0, (long long unsigned int)addr/CACHELINESIZE, (unsigned int)(addr%CACHELINESIZE), STORE_T, size, line, 0, 0, 0, 0, 0, FName, MName, instIndex, bbIndex);
    //fprintf(fp, "%d,%d,%d,%d,%llu,%u,%d,%d,%d,%d,%d,%d,%d,%d\n", 0, 0, 0, 0, (long long unsigned int)addr/CACHELINESIZE, (unsigned int)(addr%CACHELINESIZE), STORE_T, size, 0, 0, 0, 0, 0, 0);
}

void FinatInstrumentation(){
    fclose(fp);
    return;
}

#endif
