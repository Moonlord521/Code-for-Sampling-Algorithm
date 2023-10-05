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

map <string, int> funci;
unsigned int nexti = 0;
item it;
vector <cluster> cset;
trace tracebuf[UNIT_SIZE];
map<missinfo_key, missinfo_value> ins;

void InitInstrumentation(){
	if((fp = fopen("tracefile.txt", "w")) == NULL){
		printf("fail writing!\n");
		exit(0);
	}
	//if((fp2 = fopen("misscnt.txt", "w")) == NULL){
	//	printf("fail writing!\n");
	//	exit(0);
	//}
	LRUCache(&c, INIT, 0);
	return;
}

void FinatInstrumentation(){
	fclose(fp);
	//fclose(fp2);
	LRUCache(&c, CLEAR, 0);
  	
	if((fp3 = fopen("cluster.txt", "w")) == NULL){
        	printf("fail writing!\n");
        	exit(0);
	}
	if((fp4 = fopen("my_missinfo.txt", "w")) == NULL){
		printf("fail writing!\n");
		exit(0);
	}

	for(auto tmp:funci){
		fprintf(fp3, "%s, ", tmp.first.c_str());
	} 
	fprintf(fp3, "\n");
	for(cluster clu:cset){
		//if(clu.weight == 1) continue;
	        fprintf(fp3, "%d, ", clu.weight);
	        fprintf(fp3, "%.3lf, ", clu.misscnt);
		for(auto vec_it=clu.funccnt.begin(); vec_it!=clu.funccnt.end(); vec_it++){
			fprintf(fp3, "%.3lf, ", *vec_it);
		}
	        fprintf(fp3, "\n");

		for(auto ins_it = clu.ins.begin(); ins_it != clu.ins.end(); ins_it++){
			if(ins.find(ins_it->first) == ins.end()){
				ins[ins_it->first].accesscnt = ins_it->second.accesscnt*clu.weight/clu.sampleweight;
				ins[ins_it->first].misscnt = ins_it->second.misscnt*clu.weight/clu.sampleweight;
			}
			else{
				ins[ins_it->first].accesscnt += ins_it->second.accesscnt*clu.weight/clu.sampleweight;
				ins[ins_it->first].misscnt += ins_it->second.misscnt*clu.weight/clu.sampleweight;
			}
		}
	}
	vector<pair<missinfo_key, missinfo_value>> insv(ins.begin(), ins.end());
	sort(insv.begin(), insv.end(), missinfocmp);
	for(auto ins_it=insv.begin(); ins_it!=insv.end(); ins_it++){
		if((double)(ins_it->second.misscnt)/(ins_it->second.accesscnt) >= T_MISSRATE) fprintf(fp4, "%s %s %d %d %llu %llu %.6lf\n", ins_it->first.mname.c_str(), ins_it->first.fname.c_str(), ins_it->first.bbindex, ins_it->first.insindex, (uint64_t)ins_it->second.accesscnt, (uint64_t)ins_it->second.misscnt, (double)(ins_it->second.misscnt)/(ins_it->second.accesscnt));
	}

	fclose(fp3);
	fclose(fp4);
	return;
}

void LoadInstrumentation(uint64_t addr, int size, char* FName, char* MName, int instIndex, int bbIndex, int line, char* filename, int lineir, int colir){
    	tracen++;
    	int indexW = tracen/UNIT_SIZE;
    	int indexB = tracen%UNIT_SIZE;
    	if (indexW%SECTION_SIZE == 0){
        	if(indexB == 0){
			it.clear();
		}
        
		int ismiss = LRUCache(&c, SETLINE, addr);
		it.misscnt += ismiss;
		if(funci.find(FName) == funci.end()){
			funci[FName] = nexti++;
			it.funccnt.resize(nexti);
		}        
		it.funccnt[funci[FName]]++;

		tracebuf[indexB].write_trace(addr, size, FName, MName, instIndex, bbIndex, line, filename, lineir, colir, LOAD_T, ismiss);	

	        if(indexB == UNIT_SIZE-1){
	        	//fprintf(fp2, "%d, ", it.misscnt);
			//for(auto vec_it=it.funccnt.begin(); vec_it!=it.funccnt.end(); vec_it++){
			//	fprintf(fp2, "%d, ", *vec_it);
			//}
	        	//fprintf(fp2, "\n");
			
			int mind = -1, minclui = 0;
			for(int i=0; i<cset.size(); i++){
				if(mind==-1 || mind>cset[i].distance(it)){
					mind=cset[minclui].distance(it);
					minclui = i;
				}
			}
			if(mind == -1 || mind > T_DIST){
				cluster ctmp(it);
				fprintf(fp, "%d:\n", cset.size());
				for(int i=0; i<UNIT_SIZE; i++){
					tracebuf[i].print_trace(fp);
					ctmp.add_ins(missinfo_key(tracebuf[i].fname, tracebuf[i].mname, tracebuf[i].bbindex, tracebuf[i].insindex), tracebuf[i].miss);
				}
				cset.emplace_back(ctmp);
			}	
			else{
				cset[minclui].add_item(it);
				//if(P_BASE*(double)it.misscnt/cset[minclui].weight > ((double)rand()/32768)){
				if(P_BASE2*(double)it.misscnt > ((double)rand()/32768)){
					fprintf(fp, "%d:\n", minclui);
					for(int i=0; i<UNIT_SIZE; i++){
						tracebuf[i].print_trace(fp);
						cset[minclui].add_ins(missinfo_key(tracebuf[i].fname, tracebuf[i].mname, tracebuf[i].bbindex, tracebuf[i].insindex), tracebuf[i].miss);
					}
					cset[minclui].sampleweight++;
				}
			}
	        }
	}
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
