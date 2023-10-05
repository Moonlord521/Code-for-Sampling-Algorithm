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

#include <cstdio>
#include <cstdlib>
#include <vector>
#include <string>
#include <map>
#include <iostream>
#include <algorithm>
#include "configs.hpp"
#include "missinfo.cpp"
#include "trace.cpp"
#include "cluster.cpp"
#include "cache.cpp"
using namespace std;

extern "C" {

unsigned long long tracen = 0;
static FILE *fp, *fp2, *fp3, *fp4;
static cache c;
int instrumentationActive = 0;

map<missinfo_key, missinfo_value> ins;

void InitInstrumentation(){
	LRUCache(&c, INIT, 0);
	return;
}

void FinatInstrumentation(){
	LRUCache(&c, CLEAR, 0);
  	
	if((fp4 = fopen("missinfo_all.txt", "w")) == NULL){
		printf("fail writing!\n");
		exit(0);
	}

	vector<pair<missinfo_key, missinfo_value>> insv(ins.begin(), ins.end());
	sort(insv.begin(), insv.end(), missinfocmp);
	for(auto ins_it=insv.begin(); ins_it!=insv.end(); ins_it++){
		if((double)(ins_it->second.misscnt)/(ins_it->second.accesscnt) >= T_MISSRATE) fprintf(fp4, "%s %s %d %d %llu %llu %.6lf\n", ins_it->first.mname.c_str(), ins_it->first.fname.c_str(), ins_it->first.bbindex, ins_it->first.insindex, (uint64_t)ins_it->second.accesscnt, (uint64_t)ins_it->second.misscnt, (double)(ins_it->second.misscnt)/(ins_it->second.accesscnt));
	}

	fclose(fp4);
	return;
}

void LoadInstrumentation(uint64_t addr, int size, char* FName, char* MName, int instIndex, int bbIndex, int line, char* filename, int lineir, int colir){
    	tracen++;
    	int indexW = tracen/UNIT_SIZE;
    	int indexB = tracen%UNIT_SIZE;
    	if (indexW%SECTION_SIZE == 0){
		int ismiss = LRUCache(&c, SETLINE, addr);
		missinfo_key key(FName, MName, bbIndex, instIndex);

		if(ins.find(key) == ins.end()){
			missinfo_value vtmp(1, ismiss?1:0);
			ins[key] = vtmp;
		}
		else{
			ins[key].accesscnt++;
			if(ismiss) ins[key].misscnt++;
		}
		
	}
	if(tracen % 10000000 == 0) cout << tracen << endl;
}


void StoreInstrumentation(uint64_t addr, int size, char* FName, char* MName, int instIndex, int bbIndex, int line, char* filename, int lineir, int colir){
    /*tracen++;
    int indexW = tracen/UNIT_SIZE;
    int indexB = tracen%UNIT_SIZE;
    if (indexW%SECTION_SIZE == 0){
        if(indexB == 0) misscnt = 0;
        misscnt += LRUCache(&c, SETLINE, addr);
        if(indexB == UNIT_SIZE-1){
            if((THRESHOLD_MISSRATE)*(UNIT_SIZE) > misscnt) instrumentationActive = 0;
            else instrumentationActive = 0;
            fprintf(fp2, "%d\n", misscnt);
        }
    }
    if(instrumentationActive){
        if(fp) fprintf(fp, "%s,%d,%d,%d,%llu,%u,%d,%d,%d,%d,%d,%d,%d,%d,%s,%s,%d,%d\n", filename, lineir, colir, 0, (long long unsigned int)addr/CACHELINESIZE, (unsigned int)(addr%CACHELINESIZE), STORE_T, size, line, 0, 0, 0, 0, 0, FName, MName, instIndex, bbIndex);
    } */
    LoadInstrumentation(addr, size, FName, MName, instIndex, bbIndex, line, filename, lineir, colir);
}

void PrefetchInstrumentation(uint64_t addr, int size, char* FName, char* MName, int instIndex, int bbIndex, int line, char* filename, int lineir, int colir){
    //tracen++;
    //if (tracen%GAPTRACEN > MAXTRACEN) return;
    //if(fp) fprintf(fp, "%s,%d,%d,%d,%llu,%u,%d,%d,%d,%d,%d,%d,%d,%d,%s,%s,%d,%d\n", filename, lineir, colir, 0, (long long unsigned int)addr/CACHELINESIZE, (unsigned int)(addr%CACHELINESIZE), PREFETCH_T, size, line, 0, 0, 0, 0, 0, FName, MName, instIndex, bbIndex);
}

}//extern "C"



#endif
