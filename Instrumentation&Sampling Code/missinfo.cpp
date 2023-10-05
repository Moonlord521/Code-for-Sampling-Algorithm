#ifndef MISSINFO_CPP
#define MISSINFO_CPP
#include <string>
#include <map>
using namespace std;

class missinfo_key{
	public:
	string fname;
	string mname;
	int bbindex;
	int insindex;

	missinfo_key(const string& _fname, const string& _mname, const int _bbindex, const int _insindex):fname(_fname),mname(_mname),bbindex(_bbindex),insindex(_insindex){};
	missinfo_key(){};
	bool operator<(const missinfo_key& other) const;
	bool operator==(const missinfo_key& other) const;
};

bool missinfo_key::operator<(const missinfo_key& other) const{
	if(fname < other.fname) return true;
	else if(fname == other.fname){	
		if(mname < other.mname) return true;
		else if(mname == other.mname){	
			if(bbindex < other.bbindex) return true;
			else if(bbindex == other.bbindex){	
				if(insindex < other.insindex) return true;
			}
		}
	}
	return false;
}

bool missinfo_key::operator==(const missinfo_key& other) const{
	return (fname == other.fname)&&(mname == other.mname)&&(bbindex == other.bbindex)&&(insindex == other.insindex);
}

class missinfo_value{
	public:
	uint64_t accesscnt;
	uint64_t misscnt;

	missinfo_value(int ac, int mc):accesscnt(ac),misscnt(mc){};
	missinfo_value():accesscnt(0),misscnt(0){};
};

void add_ins(map<missinfo_key, missinfo_value>& ins, const missinfo_key& key, bool miss){
	if(ins.find(key) == ins.end()){
		ins[key] = missinfo_value(1, miss?1:0);
	}
	else{
		ins[key].accesscnt++;
		if(miss) ins[key].misscnt++;
	}
}

bool missinfocmp(pair<missinfo_key, missinfo_value>& a, pair<missinfo_key, missinfo_value>& b){
	return a.second.misscnt > b.second.misscnt;
}

#endif
