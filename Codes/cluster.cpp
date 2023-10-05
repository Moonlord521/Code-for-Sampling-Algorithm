#ifndef CLUSTER_CPP
#define CLUSTER_CPP
#include <vector>
#include <cmath>
#include <cstdio>
#include "configs.hpp"
#include "missinfo.cpp"
using namespace std;

class item{
	public:
	unsigned int misscnt;
	vector<int> funccnt;

	void clear();
};

class cluster{
	public:
	uint64_t weight;
	double misscnt;
	vector<double> funccnt;
	uint64_t sampleweight;
	map<missinfo_key, missinfo_value> ins;

	cluster(item& i);
	void add_item(item& i);
	double distance(item& i);
	void add_ins(const missinfo_key& key, bool miss);
};

void item::clear(){
	misscnt = 0;
	for(int i=0; i<funccnt.size(); i++) funccnt[i]=0;
}

cluster::cluster(item& i){
	misscnt = i.misscnt;
	funccnt.resize(i.funccnt.size());
	for(int ii=0; ii<funccnt.size(); ii++){
		funccnt[ii] = (double)i.funccnt[ii];
	}
	sampleweight = 1;
	weight = 1;
};

void cluster::add_item(item& i){
	misscnt = (misscnt*weight + (double)i.misscnt)/(weight+1);
	funccnt.resize(i.funccnt.size());
	for(int ii=0; ii<funccnt.size(); ii++){
		funccnt[ii] = (funccnt[ii]*weight + i.funccnt[ii])/(weight+1);
	}
	weight++;
};

double cluster::distance(item& i){
	double dmiss = (double)abs(misscnt - i.misscnt);
	double dfunc = 0.0;
	funccnt.resize(i.funccnt.size());
	for(int ii=0; ii<funccnt.size(); ii++){
		dfunc += (double)abs(funccnt[ii] - i.funccnt[ii])/funccnt.size();
	}
	return W_MISS*dmiss + W_FUNC*dfunc;
};

void cluster::add_ins(const missinfo_key& key, bool miss){
	if(ins.find(key) == ins.end()){
		ins[key] = missinfo_value(1, miss?1:0);
	}
	else{
		ins[key].accesscnt++;
		if(miss) ins[key].misscnt++;
	}
}

//bool cluster_compare(const cluster& c1, const cluster& c2){ return false;}
//unsigned int cluster_hash(const cluster& c){
//	return (c.weight*c.weight + (int)(c.misscnt)*(int)(c.misscnt))%HASH_MAX;
//}

#endif
