#ifndef TRACE_CPP
#define TRACE_CPP
#include <string>
#include "configs.hpp"
using namespace std;

enum TraceType
{
    OTHER_T = 0,
    LOAD_T,
    STORE_T,
    PREFETCH_T
};

class trace{
	public:
	string mname;
	string fname;
	string filename;
	uint64_t addr;
	int size;
	int lineir;
	int colir;
	int type;
	int line;
	int insindex;
	int bbindex;
	bool miss;

	void write_trace(uint64_t _addr, int _size, char* _fname, char* _mname, int _insindex, int _bbindex, int _line, char* _filename, int _lineir, int _colir, int _type, bool _miss);
	void print_trace(FILE* fp);
};

void trace::write_trace(uint64_t _addr, int _size, char* _fname, char* _mname, int _insindex, int _bbindex, int _line, char* _filename, int _lineir, int _colir, int _type, bool _miss){
	addr = _addr;
	size = _size;
	fname = _fname;
	mname = _mname;
	insindex = _insindex;
	bbindex = _bbindex;
	line = _line;
	filename = _filename;
	lineir = _lineir;
	colir = _colir;
	type = _type;
	miss = _miss;
}

void trace::print_trace(FILE* fp){
	if(fp) fprintf(fp, "%s,%d,%d,%d,%llu,%u,%d,%d,%d,%d,%d,%d,%d,%d,%s,%s,%d,%d,%d\n", filename.c_str(), lineir, colir, 0, (long long unsigned int)addr/CACHELINESIZE, (unsigned int)(addr%CACHELINESIZE), type, size, line, 0, 0, 0, 0, 0, fname.c_str(), mname.c_str(), insindex, bbindex, miss?1:0);
}

#endif
