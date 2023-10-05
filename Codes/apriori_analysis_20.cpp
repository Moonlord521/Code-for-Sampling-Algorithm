#include "mrc.h"
#include "stdint.h"
#include<stdio.h>
#include<stdlib.h>
#include<math.h>
#include<time.h>
#include<iostream>
#include<vector>
#include <algorithm>
#include<unordered_map>
#include<map>
#include<set>
#include<string.h>
#include <stdlib.h>
#include<iomanip>  
#include<numeric>
#include<float.h>
#include<limits.h>
#include<iomanip>
#include<fstream>
#include <cstdlib>
#include <sstream>
#include<queue>
#include<exception>
#define PADDING 8
#define fp_opt_malloc_pad fp_output
using namespace std;
/*
#define CACHE_LINE_SIZE 64
#define SAMPLE_LENGTH 10
#define MAX_LINE 1024
#define MIN_CONFIDENCE 0.5
#define MIN_DISTANCE 0.02
#define IF_CAL_ADTW 1
#define IF_CORRECTION_L2 1
#define IF_SECRET 1
#define TOP_K 5
//#define fp_LOG cout
#define LOUVAIN_INPUT_TYPEID -1
*/

struct community
{
    int cid;
    set<int>vs;
    int max_delta_q_cid;
    double max_delta_q;
};
typedef struct 
{
    int typeID;
    int fieldID;
    string name;
    unsigned long long access_time;
    int fsize;
} Item;
typedef struct 
{
    int threadIndex;
    int traceIndex;
    uint64_t addr;
    int tid;
    int fid;
    int fsize;
    unsigned long long sec,usec;
    int is_write,size;
    string name;
    int structindex;
    int ismiss;
} Trace_Item;
typedef struct 
{
    int tid;
    int fid;
    string name;
    vector<long>sec;
    vector<long>usec;
    vector<int>rw;
}frequent_Item_time_serial;
typedef struct 
{
    int typeID;
    string name;
    string secret_name;
    vector<string>field_name;
    vector<string>secret_field_name;
    vector<int>field_size;
    vector<long>ac_time;
    vector<int>field_origin_typeid;
    vector<int>array_idx;
    vector<int>dim;
    vector<string>field_type_name;
	int if_malloc;
    vector<int> field_miss;
    vector<int> field_hit;
}types;
typedef struct 
{
    int typeID;
	int idx;
    string name;
    int size;
    int dim;
    string shape;
	int field_typeID;
	int if_hot;
}afield;
typedef struct
{
    double ave_mr;
    double ave_mr_reduce;
    int index;
    int typeId;
    int linecount;
    int isreorder;
}mr_index;
typedef struct {
    int access_num;
    int miss_num;
    double missrate;
    int typeId;
}access_item;

class AprioriAnalysis
{
    public:
    FILE *fp_access;
    int threadIndex;
    int traceIndex;
    trace_item *tracev;
    trace_item *tracev2;
    Trace_Item *access_trace;
    int access_num;
    int trace_num;
    int nglobal;
    int aglobal;
    fp_his *fp_h;
    rt_his *rt_h;
    aet_his *aet_h;
    double rtmrg;
    double fpmrg;
    double aetmrg;
    double lrumrg;
    double urg;
    int clg;
    uint64_t addr;
    int c;
    int tyid,fidx,isWrite,size,fsize,tyid_array_idx;
    unsigned long long sec,usec;
    char name[128];
    vector<Item>l1_item;
    vector<Item>l1_frequent_item;
    vector<int>tIDs;
    vector<int>thresholds;
    vector<vector<long> >l2_matrix;
    vector<vector<double> >adtw_matrix;
    vector<vector<double> >adtw_matrix_s;
    vector<vector<double> >adtw_similarity_matrix;
    vector<vector<long> >lcs_matrix;
    vector<vector<unsigned> >l1_cluster;
    double avg_adtw;
    vector<mr_index> mrofindex;
    vector<access_item> accessv;
    int countpo;

    int time_window_threshold_us;
    int trace_window_len;
    unsigned long long access_len;
    map<int,long> ac_times;
    vector<int>topk_typeid;
    map<int, int>typeid_to_idx;

    vector<Item>l1_frequent_item_tmp;
    vector<types>tys;
    ofstream fp_output;
//    ofstream //fp_output_secret;
    ofstream fp_LOG;
    ifstream fp_config;
    ofstream fp_opt;
    ofstream fp_opt_malloc;
    //ofstream fp_opt_malloc_pad;
	vector<vector<int> > clusters;

    int CACHE_LINE_SIZE ;   //64
    int SAMPLE_LENGTH;     // 10
    int MAX_LINE;           //1024;
    double MIN_CONFIDENCE;   //0.5
    double MIN_DISTANCE;    // 0.02
    int IF_CAL_ADTW;      // 1
    int IF_CORRECTION_L2;  // 1
    int IF_SECRET;        //1
    int TOP_K ;            //5
    int LOUVAIN_INPUT_TYPEID; //-1
    int FIELD_NUM_THRESHOLD; //-1
	int malloc_flag;
	set<int>malloc_typeid;
	set<int>no_malloc_typeid;
	set<int>str_typeid;

    vector<string> fmname;

    AprioriAnalysis()
    {

        CACHE_LINE_SIZE = 64 ;   
        SAMPLE_LENGTH   = 10 ;
        MAX_LINE = 1024;
        MIN_CONFIDENCE = 0.5;
        MIN_DISTANCE  = 0.02;
        IF_CAL_ADTW  = 1;
        IF_CORRECTION_L2 = 1;
        IF_SECRET = 1;
        TOP_K  = 5 ;
        LOUVAIN_INPUT_TYPEID = -1;
        FIELD_NUM_THRESHOLD = 2;

        FILE* fp_access_info;
        char tmp[128];
        if ((fp_access_info = fopen ("./TraceFileList.txt", "r")) == NULL)  
        {
            printf ("fail reading TraceFileList.txt\n");
            //return ;
            exit (0);
        }
        
        while(!feof(fp_access_info))
        {
            fscanf(fp_access_info,"%d %s\n",&nglobal,tmp);
        }
        fp_LOG<<"tracefile.txt 's length = "<<nglobal<<endl;
        fclose(fp_access_info);

    };
    ~AprioriAnalysis()
    {
//        fclose(fp_access);
//        fp_output.close();
        //fp_output_secret.close();
//        fp_LOG.close();
//        fp_config.close();
        free(tracev);
        //free(tracev2);
//        free(access_trace);
//        free(fp_h);
//        free(rt_h);
//        free(aet_h);
//		fp_opt.close();
//		fp_opt_malloc.close();
	//	fp_opt_malloc_pad.close();

    };
    void get_L1();
    void get_L2();
    void cache_miss_analysis();
    void get_access();
    void cache_miss_analysis_2(int tyid_idx, vector<int> &flags);
    void cache_miss_analysis_4(int tyid_idx, vector<vector<int>> &result);
    double cal_mr_of_lru(trace_item *tracev, int n, int c, double *cache_u_r, int *cl);
    void cal_isnew(trace_item *tracev, int n);
    double cal_mr_of_str();
    void print_access();
    void handlehit(int typeId);
    void handlemiss(int typeId);




    void get_trace();
    void cal_rt_his(rt_his *rt_h, trace_item *tracev, int n);
    void cal_fp_his(fp_his *fp_h, rt_his *rt_h);
    void cal_aet_his(aet_his *aet_h, rt_his *rt_h);
    void mr_sort();

    double cal_mr_from_rt(rt_his *rt_h, fp_his *fp_h, int c);
    double cal_mr_from_fp(fp_his *fp_h, int c);
    double cal_mr_from_aet(aet_his *aet_h, rt_his *fp_h, int c);
    double cal_Q(community c,long **correlation_count,double m, long *ki);
    void print_community(community *cs, int n,long **correlation_count,double m, long *ki);
    void louvain_cluster(long **correlation_count,int n_field,community *cs,double m,long *ki);
    void matrix_cluster(int tope_k_typeid);
    
    long get_timediff(long s1,long us1,long s2,long us2);
    
    long new_cal_dtw_rws(frequent_Item_time_serial s1,frequent_Item_time_serial s2,long len[3],int begin_and_end[4]);
    void mean_adtw_matrices();
    void mean_support_matrices();
    void new_apriori_adtw_clustering_single_type_s();
    void new_apriori_adtw_clustering_next_single_type_s();
    int get_lcs(frequent_Item_time_serial s1,frequent_Item_time_serial s2,int begin_and_end[4]);
    vector<vector<int>> cal_continuous_size(vector<int> data, int stride);
    map<int, int> stride_statistics(vector<int> data);
    void get_topk_typeid();
    void topk_louvain_cluster();
    void dec_l1_resv();
	void unfold_malloc_str();
	void louvain_malloc(vector<afield> data);
	void padding_opt(vector<vector<vector<afield>>> hot, vector<vector<afield>> cold, vector<int> tids, vector<long> ats);
	int padding_opti(vector<vector<vector<afield>>> hot, vector<vector<afield>>cold, vector<int> tids, vector<long> ats, int i);
	vector<vector<int>> padding_opti_single(vector<vector<afield>> hot, vector<afield>cold, int tids, int if_hot_pad);
	vector<vector<int>> padding_opt_single(int tyid, vector<int> flags, int if_hot_pad);
	int cal_str_val_pad(int tid);
    void bb_seq(trace_item* tracev, int n);
	//void print_debug_log(string s);
} ;
//void AprioriAnalysis::print_debug_log(string s)
//{
	//fp_LOG<<__LINE__<<" "<<__FUNCTION__<<" "<<s<<endl;
//}

int AprioriAnalysis:: cal_str_val_pad(int tid) {
	int idx = typeid_to_idx[tid];
	int val_pad = 0;
	int size;
	types t =  tys[idx];
	int cur_val_pad;
	for (int i = 0; i < t.field_size.size(); i++) {
		if (str_typeid.count(t.field_origin_typeid[i + 1]) == 1) {
			cur_val_pad  = cal_str_val_pad(t.field_origin_typeid[i + 1]);
		} else {
			if (t.dim[i] > 1) {
				size = t.field_size[i] / t.dim[i];
			} else {
				size = t.field_size[i];
			}
			cur_val_pad = min(size, PADDING);
		}
		val_pad = max(cur_val_pad, val_pad);
	}
	return val_pad;
}
vector<vector<int>> AprioriAnalysis:: padding_opti_single(vector<vector<afield>> hot, vector<afield> cold, int tids, int if_hot_pad) {
	int offset = 0;
	int rsvd;
	int val_padding;
	string iname = tys[typeid_to_idx[tids]].name;
	int size;
	int count = 0;
	vector<afield>padds;
	vector<int>pdx;
	afield p;
	p.typeID = -1;
	fp_opt_malloc_pad << "typedef struct { // typeID = " << tids << endl;
	int idx_ = 0;
	for (int j = 0; j < hot.size(); j++) {
		for (int k = 0; k < hot[j].size(); k++) {
			if (str_typeid.count(hot[j][k].field_typeID) == 1) {
				val_padding = cal_str_val_pad(hot[j][k].field_typeID);
			} else {
				if (hot[j][k].dim < 2) { // deal with array
					size = hot[j][k].size;
				} else {
					size = hot[j][k].size / hot[j][k].dim;
				}
				val_padding = min(size, PADDING);
			}
			rsvd = val_padding - (offset % val_padding);
			if (rsvd != val_padding) {
				offset += rsvd;
				vector<afield>tmp;
				while (rsvd != 0) {
					val_padding /= 2;
					if (rsvd >= val_padding) {
						p.name =  iname  + "_rsvd" ;//+ to_string(count);
						p.size =  val_padding;
						p.shape =  "UINT" + to_string(val_padding * 8);
						pdx.push_back(idx_);
						rsvd -= val_padding;
						tmp.push_back(p);
					}
				}
				for (int pp = tmp.size() - 1; pp >= 0; pp-- ) {
					padds.push_back(tmp[pp]);
				}
			} 
			offset += hot[j][k].size;
			idx_++;
		}
	}
	
	map<int, int> ps;
	for (int j = 0; j < cold.size(); j++) {
		ps[cold[j].size]++;
	}
	
	for (int j = 0; j < padds.size(); j++) {
		if (padds[j].size == 1 && ps[1] > 0) {
			padds[j] = cold[0];
			cold.erase(cold.begin());
			ps[1]--;
		}
	}
	for (int j = 0; j < padds.size(); j++) {
		if (padds[j].size == 2) {
			if (ps[2] > 0) {
				int k;
				for (k = 0; k < cold.size(); k++) {
					if (cold[k].size == 2) {
						break;
					}
				}
				padds[j]= cold[k];
				cold.erase(cold.begin() + k);
				ps[2]--;
			} else if (ps[1] >= 2) {
				padds[j] = cold[0];
				padds.insert(padds.begin() + j, cold[1]);
				pdx.insert(pdx.begin() + j, pdx[j]);
				j++;
				cold.erase(cold.begin());
				cold.erase(cold.begin());
				ps[1] -= 2;
			}
		}
	}
	for (int j = 0; j < padds.size(); j++) {
		if (padds[j].size == 4) {
			if (ps[4] > 0) {
				int k;
				for (k = 0; k < cold.size(); k++) {
					if (cold[k].size == 4) {
						break;
					}
				}
				padds[j]= cold[k];
				cold.erase(cold.begin() + k);
				ps[4]--;
			} else if (ps[2] >= 2) {
				int k;
				for (k = 0; k < cold.size(); k++) {
					if (cold[k].size == 2) {
						break;
					}
				}
				padds[j]= cold[k];
				cold.erase(cold.begin() + k);
				padds.insert(padds.begin() + j, cold[k]);
				pdx.insert(pdx.begin() + j, pdx[j]);
				cold.erase(cold.begin() + k);
				ps[2] -= 2;
				j++;
			} else if (ps[2] == 1 && ps[1] >= 2) {
				int k;
				for (k = 0; k < cold.size(); k++) {
					if (cold[k].size == 2) {
						break;
					}
				}
				padds[j]= cold[k];
				cold.erase(cold.begin() + k);
				ps[2]--;	
				padds.insert(padds.begin() + j, cold[0]);	
				cold.erase(cold.begin());
				pdx.insert(pdx.begin() + j, pdx[j]);
				padds.insert(padds.begin() + j, cold[0]);
				pdx.insert(pdx.begin() + j, pdx[j]);
				cold.erase(cold.begin());
				ps[1] -= 2;
				j += 2;
			} else if (ps[2] == 0 && ps[1] >= 4) {	
				padds[j]= cold[0];
				cold.erase(cold.begin());
				padds.insert(padds.begin() + j, cold[0]);	
				pdx.insert(pdx.begin() + j, pdx[j]);
				cold.erase(cold.begin());
				padds.insert(padds.begin() + j, cold[0]);
				pdx.insert(pdx.begin() + j, pdx[j]);
				cold.erase(cold.begin());
				padds.insert(padds.begin() + j, cold[0]);
				pdx.insert(pdx.begin() + j, pdx[j]);
				cold.erase(cold.begin());
				ps[1] -= 4;
				j += 3;
			}
		}
	}	
	offset = 0;
	idx_ = 0;
	int ppp = 0;
	count = 0;
	vector<vector<int>> result;
	if (if_hot_pad == 1) {
		for (int j = 0; j < padds.size(); j++) {
			if (padds[j].typeID == -1) {
				int psize = padds[j].size;
				for (int c = hot.size() - 1; c >= 0; c--) {
					int flag = 0;
					for (int cc = 0; cc < hot[c].size(); cc++) {
						if (hot[c][cc].size == psize) {
							padds[j] = hot[c][cc];
							//hot[c].erase(hot[c].begin() + cc);
							hot[c][cc].field_typeID = -1;
							flag = 1;
							break;
						}
					}
					if (flag == 1) {
						break;
					}
				}
			}
		}
	}
	for (int j = 0; j < hot.size(); j++) {
		vector<int>rtmp;
		fp_opt_malloc_pad << "\t//cluster" << endl;
		for (int k = 0; k < hot[j].size(); k++) {
			if (ppp < pdx.size()){
				while (pdx[ppp] == idx_) {
					if (padds[ppp].typeID != -1) {
						fp_opt_malloc_pad<<"\t" << padds[ppp].shape << "\t" << padds[ppp].name << "";
						if(padds[ppp].dim != 0) fp_opt_malloc_pad<<"[" << padds[ppp].dim <<"]";
						fp_opt_malloc_pad << ";" << "// size = " << padds[ppp].size << "B" ;
						offset += padds[ppp].size;
						if (padds[ppp].if_hot == 1) {
							fp_opt_malloc_pad << " (hot padding)" << endl;
						} else {	
							fp_opt_malloc_pad << " (cold padding)" << endl;
						}
						
						//fp_opt_malloc_pad << endl;
						rtmp.push_back(padds[ppp].idx);
					} else{
						//fp_opt_malloc_pad <<"\t//"<<padds[ppp].shape <<"\t" <<padds[ppp].name << count;
						//fp_opt_malloc_pad <<";// add rsvd, size = " << padds[ppp].size << "B"<< endl;
						count++;
						offset += padds[ppp].size;
						//", idx = "  <<idx_ << endl; 
					}
					ppp++;
				}
			}
			if (hot[j][k].field_typeID != -1) {
				fp_opt_malloc_pad<<"\t" << hot[j][k].shape << "\t" << hot[j][k].name << "";
				rtmp.push_back(hot[j][k].idx);
        	    if(hot[j][k].dim != 0) fp_opt_malloc_pad<<"[" << hot[j][k].dim <<"]";
				fp_opt_malloc_pad << ";" << "// size = " << hot[j][k].size << "B" <<endl;
				offset += hot[j][k].size;
				idx_++;
			}
		}
		result.push_back(rtmp);
	}
	//fp_opt_malloc_pad << "size = " << offset << endl;	
	fp_opt_malloc_pad << "\t//cold || (a cluster with only one hot data && size < 8B)" << endl;
	vector<int>cold_idx;
	for (int j = 0; j < cold.size(); j++) {
			if (str_typeid.count(cold[j].field_typeID) == 1) {
				val_padding = cal_str_val_pad(cold[j].field_typeID);
			} else {
				if (cold[j].dim < 2) { // deal with array
					size = cold[j].size;
				} else {
					size = cold[j].size / cold[j].dim;
				}
				val_padding = min(size, PADDING);
			}
			rsvd = val_padding - (offset % val_padding);
			//fp_opt_malloc_pad <<offset << "-" << val_padding << "-" << rsvd << endl;
			if (rsvd != val_padding) {
				offset += rsvd;
				vector<afield>tmp;
				while (rsvd != 0) {
					val_padding /= 2;
					if (rsvd >= val_padding) {
						p.name =  iname  + "_rsvd" + to_string(count);
						p.size =  val_padding;
						p.shape =  "UINT" + to_string(val_padding * 8);
						//p.idx = idx_;
						//fp_opt_malloc_pad <<"\t"<<p.shape <<"\t" <<p.name <<";// rsvd's size = " << p.size << "B"<< ", idx = "  <<p.idx << endl; 
						rsvd -= val_padding;
						count++;
						tmp.push_back(p);
					}
				}
				for (int pp = tmp.size() - 1; pp >= 0; pp-- ) {
					//fp_opt_malloc_pad <<"\t//"<<tmp[pp].shape <<"\t" <<tmp[pp].name;
					//fp_opt_malloc_pad <<";// add rsvd, size = " << tmp[pp].size << "B"<< endl;
					//padds.push_back(tmp[pp]);
					//fp_opt_malloc_pad <<"\t"<<tmp[pp].shape <<"\t" <<tmp[pp].name <<";// rsvd's size = " << tmp[pp].size << "B"<< ", idx = "  <<idx_ << endl; 
				}

			} 
			offset += cold[j].size;
			fp_opt_malloc_pad<<"\t" << cold[j].shape << "\t" << cold[j].name << "";
			cold_idx.push_back(cold[j].idx);
			if(cold[j].dim != 0) fp_opt_malloc_pad<<"[" << cold[j].dim <<"]";
			fp_opt_malloc_pad << ";" << "// size = " << cold[j].size << "B" <<endl;
	}
	result.push_back(cold_idx);
	if (offset % 64 != 0) {
  		int s = 64 - offset % 64;
		//fp_opt_malloc_pad <<"//\t"<<"UINT8"  <<"\t" <<iname << "_rsvd" << count << "[" << s << "]";
		//fp_opt_malloc_pad <<";// add rsvd, size = " << s << "B"<< endl;
		offset += s;
	}
	fp_opt_malloc_pad << "}" << iname << ";" << endl; //"//padding_opt_size = " << offset << endl;
	//ssize[i] = offset;
	//update size in data
	/*
	for (int ii = 0; ii < hot.size(); ii++) {
		for (int j = 0; j < hot[ii].size(); j++) {
			for (int k = 0; k < hot[ii][j].size(); k++) {
				if( hot[ii][j][k].field_typeID == tids[i]) {
					hot[ii][j][k].size = hot[ii][j][k].dim * offset;
					cout << hot[ii][j][k].typeID << " = typeID, " <<hot[ii][j][k].field_typeID << " hot, size update :" << hot[ii][j][k].size << endl;
				}
			}
		}
		for (int j = 0; j < cold[ii].size(); j++) {
			if (cold[ii][j].field_typeID == tids[i]) {
				cold[ii][j].size = cold[ii][j].dim * offset;
				cout << cold[ii][j].field_typeID << " cold, size update :" << cold[ii][j].size << endl;
			}
		}
	}
	*/
	//return offset;
	return result;
}
vector<vector<int>> AprioriAnalysis:: padding_opt_single(int tyid, vector<int> flags, int if_hot_pad) {
	vector<vector<afield>> hot;
	vector<afield> cold;	
	vector<int>hot_padding_idx;
	types t = tys[tyid];
	vector<afield>hot_fields;
	vector<afield>cold_fields;
	for (int i = 0; i < t.field_name.size(); i++) {
		afield tmp;
		tmp.typeID = t.typeID;
		tmp.idx = i;
		tmp.name = t.field_name[i];
		tmp.size = t.field_size[i];
		tmp.shape = t.field_type_name[i];
		tmp.dim = t.dim[i];
		tmp.field_typeID = t.field_origin_typeid[i + 1];
		if (flags[i] == 1) {
			tmp.if_hot = 1;
			hot_fields.push_back(tmp);
		} else {
			tmp.if_hot = 0;
			cold_fields.push_back(tmp);
		}
	}
	for (int i = 0; i < l1_cluster.size(); i++) {
		if (l1_cluster[i].size() == 1 &&  t.field_size[l1_frequent_item[l1_cluster[i][0]].fieldID] < 8) {
			hot_padding_idx.push_back(i);
			//flags[l1_frequent_item[l1_cluster[i][0]].fieldID] = 0;
			for (int j = 0; j < hot_fields.size(); j++) {
				if (hot_fields[j].idx == l1_frequent_item[l1_cluster[i][0]].fieldID) {
					cold_fields.push_back(hot_fields[j]);
					break;
				}
			}
		}
	}
	for (int c = hot_padding_idx.size() - 1; c >= 0; c--) {
		l1_cluster.erase(l1_cluster.begin() + hot_padding_idx[c]);
	}

	int len = cold_fields.size();
    for (int x = 0; x < len; x++) {
       for (int y = x + 1; y < len; y++) {
           if (cold_fields[x].size > cold_fields[y].size ) {	
				swap(cold_fields[x], cold_fields[y]);
			}
    	 }
     }
	 cold = cold_fields;
 	 vector<vector<afield>>tmp;
	for (int c = 0; c < l1_cluster.size(); c++) {
			vector<afield> ttmp;
			for (int cc = 0; cc < l1_cluster[c].size(); cc++) {
				for (int j = 0; j < hot_fields.size(); j++) {
					if (hot_fields[j].idx == l1_frequent_item[l1_cluster[c][cc]].fieldID) {
						ttmp.push_back(hot_fields[j]);
						break;
				}
			}
			}
			tmp.push_back(ttmp);
	}
	hot = tmp;
    return padding_opti_single(hot, cold, t.typeID, if_hot_pad);
}
int AprioriAnalysis:: padding_opti(vector<vector<vector<afield>>> hot, vector<vector<afield>> cold, vector<int> tids, vector<long> ats, int i) {
	//cout << i << ":" << tids[i] <<  endl;
	int offset = 0;
	int rsvd;
	int val_padding;
	string iname = tys[typeid_to_idx[tids[i]]].name;
	int size;
	int count = 0;
	vector<afield>padds;
	vector<int>pdx;
	afield p;
	p.typeID = -1;
	fp_opt_malloc_pad << "typedef struct { // typeID = " << tids[i] << ", access_time = " << ats[i] << endl;
	int idx_ = 0;
	for (int j = 0; j < hot[i].size(); j++) {
		//fp_opt_malloc_pad << "\t//cluster" << endl;
		for (int k = 0; k < hot[i][j].size(); k++) {
			if (str_typeid.count(hot[i][j][k].field_typeID) == 1) {
				val_padding = cal_str_val_pad(hot[i][j][k].field_typeID);
			} else {
				if (hot[i][j][k].dim < 2) { // deal with array
					size = hot[i][j][k].size;
				} else {
					size = hot[i][j][k].size / hot[i][j][k].dim;
				}
				val_padding = min(size, PADDING);
			}
			rsvd = val_padding - (offset % val_padding);
			//fp_opt_malloc_pad <<offset << "-" << val_padding << "-" << rsvd << endl;
			if (rsvd != val_padding) {
				offset += rsvd;
				vector<afield>tmp;
				while (rsvd != 0) {
					val_padding /= 2;
					if (rsvd >= val_padding) {
						p.name =  iname  + "_rsvd" ;//+ to_string(count);
						p.size =  val_padding;
						p.shape =  "UINT" + to_string(val_padding * 8);
						pdx.push_back(idx_);
						//p.idx = idx_;
						//fp_opt_malloc_pad <<"\t"<<p.shape <<"\t" <<p.name <<";// rsvd's size = " << p.size << "B"<< ", idx = "  <<p.idx << endl; 
						rsvd -= val_padding;
						//count++;
						tmp.push_back(p);
					}
				}
				for (int pp = tmp.size() - 1; pp >= 0; pp-- ) {
					padds.push_back(tmp[pp]);
					//fp_opt_malloc_pad <<"\t"<<tmp[pp].shape <<"\t" <<tmp[pp].name <<";// rsvd's size = " << tmp[pp].size << "B"<< ", idx = "  <<idx_ << endl; 
				}

			} 
			offset += hot[i][j][k].size;
			/*
			fp_opt_malloc_pad<<"\t" << hot[i][j][k].shape << "\t" << hot[i][j][k].name << "";
            if(hot[i][j][k].dim != 0) fp_opt_malloc_pad<<"[" << hot[i][j][k].dim <<"]";
			fp_opt_malloc_pad << ";" << "// size = " << hot[i][j][k].size << "B" <<endl;
			*/
			idx_++;
		}
	}
	
	map<int, int> ps;
	for (int j = 0; j < cold[i].size(); j++) {
		ps[cold[i][j].size]++;
	}
	/*
	for (auto it = ps.begin(); it != ps.end(); it++) {
		fp_opt_malloc_pad << it->first << ";" << it->second << endl;
	}
	*/
	
	for (int j = 0; j < padds.size(); j++) {
		if (padds[j].size == 1 && ps[1] > 0) {
			padds[j] = cold[i][0];
			cold[i].erase(cold[i].begin());
			ps[1]--;
		}
	}
	for (int j = 0; j < padds.size(); j++) {
		if (padds[j].size == 2) {
			if (ps[2] > 0) {
				int k;
				for (k = 0; k < cold[i].size(); k++) {
					if (cold[i][k].size == 2) {
						break;
					}
				}
				padds[j]= cold[i][k];
				cold[i].erase(cold[i].begin() + k);
				ps[2]--;
			} else if (ps[1] >= 2) {
				padds[j] = cold[i][0];
				padds.insert(padds.begin() + j, cold[i][1]);
				pdx.insert(pdx.begin() + j, pdx[j]);
				j++;
				cold[i].erase(cold[i].begin());
				cold[i].erase(cold[i].begin());
				ps[1] -= 2;
			}
		}
	}
	for (int j = 0; j < padds.size(); j++) {
		if (padds[j].size == 4) {
			if (ps[4] > 0) {
				int k;
				for (k = 0; k < cold[i].size(); k++) {
					if (cold[i][k].size == 4) {
						break;
					}
				}
				padds[j]= cold[i][k];
				cold[i].erase(cold[i].begin() + k);
				ps[4]--;
			} else if (ps[2] >= 2) {
				int k;
				for (k = 0; k < cold[i].size(); k++) {
					if (cold[i][k].size == 2) {
						break;
					}
				}
				padds[j]= cold[i][k];
				cold[i].erase(cold[i].begin() + k);
				padds.insert(padds.begin() + j, cold[i][k]);
				pdx.insert(pdx.begin() + j, pdx[j]);
				cold[i].erase(cold[i].begin() + k);
				ps[2] -= 2;
				j++;
			} else if (ps[2] == 1 && ps[1] >= 2) {
				int k;
				for (k = 0; k < cold[i].size(); k++) {
					if (cold[i][k].size == 2) {
						break;
					}
				}
				padds[j]= cold[i][k];
				cold[i].erase(cold[i].begin() + k);
				ps[2]--;	
				padds.insert(padds.begin() + j, cold[i][0]);	
				cold[i].erase(cold[i].begin());
				pdx.insert(pdx.begin() + j, pdx[j]);
				padds.insert(padds.begin() + j, cold[i][0]);
				pdx.insert(pdx.begin() + j, pdx[j]);
				cold[i].erase(cold[i].begin());
				ps[1] -= 2;
				j += 2;
			} else if (ps[2] == 0 && ps[1] >= 4) {	
				padds[j]= cold[i][0];
				cold[i].erase(cold[i].begin());
				padds.insert(padds.begin() + j, cold[i][0]);	
				pdx.insert(pdx.begin() + j, pdx[j]);
				cold[i].erase(cold[i].begin());
				padds.insert(padds.begin() + j, cold[i][0]);
				pdx.insert(pdx.begin() + j, pdx[j]);
				cold[i].erase(cold[i].begin());
				padds.insert(padds.begin() + j, cold[i][0]);
				pdx.insert(pdx.begin() + j, pdx[j]);
				cold[i].erase(cold[i].begin());
				ps[1] -= 4;
				j += 3;
			}
		}
	}	
	offset = 0;
	idx_ = 0;
	int ppp = 0;
	count = 0;
	for (int j = 0; j < hot[i].size(); j++) {
		fp_opt_malloc_pad << "\t//cluster" << endl;
		for (int k = 0; k < hot[i][j].size(); k++) {
			if (ppp < pdx.size()){
				while (pdx[ppp] == idx_) {
					if (padds[ppp].typeID != -1) {
						fp_opt_malloc_pad<<"\t" << padds[ppp].shape << "\t" << padds[ppp].name << "";
						if(padds[ppp].dim != 0) fp_opt_malloc_pad<<"[" << padds[ppp].dim <<"]";
						fp_opt_malloc_pad << ";" << "// size = " << padds[ppp].size << "B" ;
						offset += padds[ppp].size;
						if (padds[ppp].if_hot == 1) {
							fp_opt_malloc_pad << " (hot padding)" << endl;
						} else {	
							fp_opt_malloc_pad << " (cold padding)" << endl;
						}
					} else{
						fp_opt_malloc_pad <<"\t"<<padds[ppp].shape <<"\t" <<padds[ppp].name << count;
						fp_opt_malloc_pad <<";// add rsvd, size = " << padds[ppp].size << "B"<< endl;
						count++;
						offset += padds[ppp].size;
						//", idx = "  <<idx_ << endl; 
					}
					ppp++;
				}
			}
			fp_opt_malloc_pad<<"\t" << hot[i][j][k].shape << "\t" << hot[i][j][k].name << "";
            if(hot[i][j][k].dim != 0) fp_opt_malloc_pad<<"[" << hot[i][j][k].dim <<"]";
			fp_opt_malloc_pad << ";" << "// size = " << hot[i][j][k].size << "B" <<endl;
			offset += hot[i][j][k].size;
			idx_++;
		}
	}
	//fp_opt_malloc_pad << "size = " << offset << endl;	
	fp_opt_malloc_pad << "\t//cold || (a cluster with only one hot data && size < 8B)" << endl;
	for (int j = 0; j < cold[i].size(); j++) {
			if (str_typeid.count(cold[i][j].field_typeID) == 1) {
				val_padding = cal_str_val_pad(cold[i][j].field_typeID);
			} else {
				if (cold[i][j].dim < 2) { // deal with array
					size = cold[i][j].size;
				} else {
					size = cold[i][j].size / cold[i][j].dim;
				}
				val_padding = min(size, PADDING);
			}
			rsvd = val_padding - (offset % val_padding);
			//fp_opt_malloc_pad <<offset << "-" << val_padding << "-" << rsvd << endl;
			if (rsvd != val_padding) {
				offset += rsvd;
				vector<afield>tmp;
				while (rsvd != 0) {
					val_padding /= 2;
					if (rsvd >= val_padding) {
						p.name =  iname  + "_rsvd" + to_string(count);
						p.size =  val_padding;
						p.shape =  "UINT" + to_string(val_padding * 8);
						//p.idx = idx_;
						//fp_opt_malloc_pad <<"\t"<<p.shape <<"\t" <<p.name <<";// rsvd's size = " << p.size << "B"<< ", idx = "  <<p.idx << endl; 
						rsvd -= val_padding;
						count++;
						tmp.push_back(p);
					}
				}
				for (int pp = tmp.size() - 1; pp >= 0; pp-- ) {
					fp_opt_malloc_pad <<"\t"<<tmp[pp].shape <<"\t" <<tmp[pp].name;
					fp_opt_malloc_pad <<";// add rsvd, size = " << tmp[pp].size << "B"<< endl;
					//padds.push_back(tmp[pp]);
					//fp_opt_malloc_pad <<"\t"<<tmp[pp].shape <<"\t" <<tmp[pp].name <<";// rsvd's size = " << tmp[pp].size << "B"<< ", idx = "  <<idx_ << endl; 
				}

			} 
			offset += cold[i][j].size;
			fp_opt_malloc_pad<<"\t" << cold[i][j].shape << "\t" << cold[i][j].name << "";
			if(cold[i][j].dim != 0) fp_opt_malloc_pad<<"[" << cold[i][j].dim <<"]";
			fp_opt_malloc_pad << ";" << "// size = " << cold[i][j].size << "B" <<endl;
	}
	if (offset % 64 != 0) {
  		int s = 64 - offset % 64;
		fp_opt_malloc_pad <<"\t"<<"UINT8"  <<"\t" <<iname << "_rsvd" << count << "[" << s << "]";
		fp_opt_malloc_pad <<";// add rsvd, size = " << s << "B"<< endl;
		offset += s;
	}
	fp_opt_malloc_pad << "}" << iname << ";" <<"//size = " << offset << endl;
	//ssize[i] = offset;
	//update size in data
	/*
	for (int ii = 0; ii < hot.size(); ii++) {
		for (int j = 0; j < hot[ii].size(); j++) {
			for (int k = 0; k < hot[ii][j].size(); k++) {
				if( hot[ii][j][k].field_typeID == tids[i]) {
					hot[ii][j][k].size = hot[ii][j][k].dim * offset;
					cout << hot[ii][j][k].typeID << " = typeID, " <<hot[ii][j][k].field_typeID << " hot, size update :" << hot[ii][j][k].size << endl;
				}
			}
		}
		for (int j = 0; j < cold[ii].size(); j++) {
			if (cold[ii][j].field_typeID == tids[i]) {
				cold[ii][j].size = cold[ii][j].dim * offset;
				cout << cold[ii][j].field_typeID << " cold, size update :" << cold[ii][j].size << endl;
			}
		}
	}
	*/
	return offset;
}
void AprioriAnalysis:: padding_opt(vector<vector<vector<afield>>> hot, vector<vector<afield>> cold, vector<int> tids, vector<long> ats)
{
	vector<vector<int>>sub_tids;
	for (int i = 0; i < tids.size(); i++) {
		vector<int> tmp;
		for (int j = 0; j < hot[i].size(); j++) {
			for (int k = 0; k < hot[i][j].size(); k++) {
				if (malloc_typeid.count(hot[i][j][k].field_typeID) == 1){
					tmp.push_back(hot[i][j][k].field_typeID);
				}
			}
		}
		for (int j = 0; j < cold[i].size(); j++) {
			if (malloc_typeid.count(cold[i][j].field_typeID) == 1){
					tmp.push_back(cold[i][j].field_typeID);
			}
		}
	/*	
		fp_opt_malloc << i << ":" << tids[i] << "--";
		for (int j = 0; j < tmp.size(); j++) {
			fp_opt_malloc << tmp[j] << "**";
		}
		fp_opt_malloc << endl;
		*/
		sub_tids.push_back(tmp);
	}
	set<int>opted;
//	vector<int>ssize(tids.size(), 0);
	while (1) {
		for (int i = 0; i < sub_tids.size(); i++) {
			//fp_opt_malloc << i << ":" << sub_tids[i].size() << "--";
			//for (int j = 0; j < sub_tids[i].size(); j++) {
				//fp_opt_malloc << sub_tids[i][j] << "**";
			//}
			//fp_opt_malloc << endl;
			if (sub_tids[i].size() == 0 && opted.count(tids[i]) == 0) {
				int offset = padding_opti(hot, cold, tids, ats, i);  //update i's size
				//cout << i << "-" << tids[i] << endl;
			
			for (int ii = 0; ii < hot.size(); ii++) {
				for (int j = 0; j < hot[ii].size(); j++) {
					for (int k = 0; k < hot[ii][j].size(); k++) {
						if( hot[ii][j][k].field_typeID == tids[i]) {
							hot[ii][j][k].size = hot[ii][j][k].dim * offset;
						//	cout << hot[ii][j][k].typeID << " = typeID, " <<hot[ii][j][k].field_typeID << " hot, size update :" << hot[ii][j][k].size << endl;
						}
					}
				}
				for (int j = 0; j < cold[ii].size(); j++) {
					if (cold[ii][j].field_typeID == tids[i]) {
						cold[ii][j].size = cold[ii][j].dim * offset;
						//cout << cold[ii][j].field_typeID << " cold, size update :" << cold[ii][j].size << endl;
					}
				}
			}
				opted.insert(tids[i]);
			}
		}
		for (int i = 0; i < sub_tids.size(); i++) {
			if (sub_tids[i].size() == 0)
				continue;
			int left = 0;
			for (int j = 0; j < sub_tids[i].size(); j++) {
				if (opted.count(sub_tids[i][j]) == 0) {
					sub_tids[i][left++] = sub_tids[i][j];
				}
			}
			sub_tids[i].resize(left);
			//cout << i << endl;
		}
		if (opted.size() == tids.size()) {
			break;
		}
	}
	//output new result 
}

void AprioriAnalysis::louvain_malloc(vector<afield> data)
{   
	fp_LOG<<"---------->line: "<<__LINE__<<" "<<__FUNCTION__<<" is running."<<endl; 
	fp_LOG<<"malloc struct louvain clustering"<<endl; 
    int i, j, k;
	vector<int>res_idx;
	for (int i = 0; i < data.size(); i++) {
		for (int j = 0; j < l1_frequent_item.size(); j++) {
			if (data[i].typeID == l1_frequent_item[j].typeID && data[i].idx == l1_frequent_item[j].fieldID) {
				res_idx.push_back(j);
				break;
			}
		}
	}
	int n_field = res_idx.size();
    long **correlation_count=new long*[n_field];
    for(i=0;i<n_field;i++)
    {
        correlation_count[i]=new long[n_field];
    }
    for(i=0;i<n_field;i++)
    {   for(j=i;j<n_field;j++)
        {
            correlation_count[i][j]=correlation_count[j][i]=l2_matrix[res_idx[i]][res_idx[j]];
            if(i==j) correlation_count[i][j]=0;
        }
    }
    
    fp_LOG<<"Correlation_count matrix:"<<endl;
    for(i=0;i<n_field;i++)
    {    for(j=0;j<n_field;j++)
        {
            fp_LOG<<*(*(correlation_count+i) + j)<<"\t";
        }
        fp_LOG<<endl;
    }
    
//    vector<Item>l1_frequent_item_tmp;
	//fp_LOG << " L1  frequent Item" << endl;
	//for (i = 0; i < l1_frequent_item.size(); i++) {
	
	//	fp_LOG << l1_frequent_item[i].typeID << " " << l1_frequent_item[i].fieldID << endl;
	//}

   l1_frequent_item_tmp.clear();
   l1_frequent_item_tmp.resize(res_idx.size());
    for(i=0;i<res_idx.size();i++)
    {
        l1_frequent_item_tmp[i] = l1_frequent_item[res_idx[i]];
    }
	//fp_LOG << "l1 f i tmp" << endl;
	//for (i = 0; i < l1_frequent_item_tmp.size(); i++) {
	
		//fp_LOG << l1_frequent_item_tmp[i].typeID << " " << l1_frequent_item_tmp[i].fieldID << endl;
	//}

//    l1_frequent_item.clear();
//    l1_frequent_item.resize(l1_frequent_item_tmp.size());
  //  for(i=0;i<l1_frequent_item_tmp.size();i++)
    //{
      //  l1_frequent_item[i] = l1_frequent_item_tmp[i];
    //}
   // l1_frequent_item_tmp.clear();    

    community *cs=new community[n_field] ;
    for(i=0;i<n_field;i++)
    {
        cs[i].cid=i;
        cs[i].max_delta_q_cid=-1; //-1表示没有发生社区合并
        cs[i].vs.insert(i);
        cs[i].max_delta_q=0; //ΔQ 初始没有增益为0
    }
    double m=0.0;
    long *ki =new long[n_field];
    for(i=0;i<n_field;i++)
    {
        ki[i]=0;
        for(j=0;j<n_field;j++)
        { 
            m=m+*(*(correlation_count+i) + j);
            ki[i]+=*(*(correlation_count+i) + j);
        } 
    }   
    m=m/2.0;
    fp_LOG<<"Initial communities:"<<endl;
    //fp_output<<"\n(1) Initial Hot Data Cluster"<<endl;
    //fp_output_secret<<"\n(1) Initial Hot Data Cluster"<<endl;
    //print_community(cs,n_field,correlation_count,m,ki);
    fp_LOG<<"Q : m= "<<m<<endl<<"Q : ki= {";
    for(i=0;i<n_field;i++)
        fp_LOG<<ki[i]<<"  ";
    fp_LOG<<"}"<<endl;
    k=0;
    community *tmp_cs = new community[n_field];
    while(1)
    {
        louvain_cluster(correlation_count,n_field,cs,m,ki);   
        j=0;
        for(i=0;i<n_field;i++)
        {//判断当前是否还有ΔQ增益，没有则不再迭代
            if(cs[i].max_delta_q>0) 
            {
                j=1;
                break;
            } 
        }
        if(j==0) 
        {
			fp_LOG<<"No ΔQ>0, End"<<endl;
            for (int i = 0; i < n_field; i++){
				vector<int>ctmp;
				for (auto it = cs[i].vs.begin(); it != cs[i].vs.end(); it++) {
				//	fp_LOG << *it << ",";
					ctmp.push_back(*it);
				}
				//fp_LOG << endl;
				int len = ctmp.size();
            	for (int x = 0; x < len; x++) {
                	for (int y = x + 1; y < len; y++) {
                    	if (l1_frequent_item[res_idx[ctmp[x]]].fsize > l1_frequent_item[res_idx[ctmp[y]]].fsize )
                        {	//swap(ctmp[x], ctmp[y]);
							swap(ctmp[x], ctmp[y]);
						}
                	}
            	}
				clusters.push_back(ctmp);
			}
			break;
        }
        j=0;
        for(i=0;i<n_field;i++)
        {
            if(cs[i].max_delta_q_cid>=-1) 
            {
                //fp_LOG << i << endl;
				tmp_cs[j].cid=j;
                tmp_cs[j].max_delta_q=0.0;
                tmp_cs[j].max_delta_q_cid=-1;
				tmp_cs[j].vs.clear();
                if(cs[i].max_delta_q_cid>=0) 
                {                
                    tmp_cs[j].vs.insert(cs[i].vs.begin(),cs[i].vs.end());
                    tmp_cs[j].vs.insert(cs[cs[i].max_delta_q_cid].vs.begin(),cs[cs[i].max_delta_q_cid].vs.end());
                    cs[cs[i].max_delta_q_cid].max_delta_q_cid=-2; //合并社区只需处理一个
                }
                if(cs[i].max_delta_q_cid==-1)
                {
                    tmp_cs[j].vs.insert(cs[i].vs.begin(),cs[i].vs.end());
                }
				/*
                for (auto it = tmp_cs[j].vs.begin(); it != tmp_cs[j].vs.end(); it++) {
					fp_LOG << *it << ";";
				}
				fp_LOG << endl;
				*/
				j++;

            }
			
		}
        k++;
        fp_LOG<<k<<"'s louvain_cluster result:"<<endl;
       // fp_output<<endl<<k<<")'s Louvain Cluster Result:"<<endl;
        //fp_output_secret<<endl<<k<<")'s Louvain Cluster Result:"<<endl;
        n_field=j;
        for(i=0;i<n_field;i++)
        {
            cs[i]=tmp_cs[i];
			//fp_LOG << tmp_cs[i].cid << "\t" << tmp_cs[i].max_delta_q << "\t" << tmp_cs[i].max_delta_q_cid << endl;
        }
       // print_community(cs,n_field,correlation_count,m,ki);
        //if(k==5) break; //迭代次数控制
    }
    delete [] tmp_cs;
   // fp_output<<"\n(2) Cold Data Access"<<endl;
    //fp_output_secret<<"\n(2) Cold Data Access"<<endl;
    //fp_output<<"\nEvery Struct Type : Merge or Split"<<endl<<endl;
    //fp_output_secret<<"\nEvery Struct Type : Merge or Split"<<endl << endl;
    delete [] ki;
    delete [] cs;
    for(i=0;i<n_field;i++)
    {
        delete [] correlation_count[i] ;
    }
    delete [] correlation_count;
}
void AprioriAnalysis:: unfold_malloc_str() {
    fp_output << "\n2.Multiple Struct Optimization"<< endl;
	//fp_opt_malloc_pad = fp_output;
	malloc_flag = 1;
	//set<int>malloc_typeid;
	//set<int>no_malloc_typeid;
	for (int i = 0; i < tys.size(); i++) {
		if (tys[i].if_malloc == 1) {
			malloc_typeid.insert(tys[i].typeID);
		} else {
			no_malloc_typeid.insert(tys[i].typeID);
		}
	}

	vector<int> tids;	
	vector<long> ats;
	for (auto it = malloc_typeid.begin(); it != malloc_typeid.end(); it++) {
		int ix = typeid_to_idx[*it];
		long at = 0;
		for (int iix = 0; iix < tys[ix].ac_time.size(); iix++) {
			at += tys[ix].ac_time[iix];
		}
		tids.push_back(*it);
		ats.push_back(at);
	}
	/*
	for (int c = 0; c < tids.size(); c++) {
		cout << tids[c] << ":" << ats[c] << endl;
	} */
	for (int x = 0; x < tids.size(); x++) {
		for (int y = x + 1; y < tids.size(); y++) {
			if (ats[x] < ats[y]) {
				swap(ats[x], ats[y]);
				swap(tids[x], tids[y]);
			}
		}
	}
	/*
	for (int c = 0; c < tids.size(); c++) {
		cout << tids[c] << ":" << ats[c] << endl;
	}
	*/
	//for (auto it = malloc_typeid.begin(); it != malloc_typeid.end(); it++) {
	//	cout << *it << "**" << endl;
	vector<vector<vector<afield>>> hot;
	vector<vector<afield>> cold;
	for (int w = 0; w < tids.size(); w++) {
		
		//int idx = typeid_to_idx[*it];
		int idx = typeid_to_idx[tids[w]];
		types t = tys[idx];
		fp_opt_malloc << "//***********typeID = "<<t.typeID <<"*************" << endl;
		vector<afield>hot_fields;
		vector<afield>cold_fields;
		for (int i = 0; i < t.field_name.size(); i++) {
			afield tmp;
			tmp.typeID = t.typeID;
			tmp.idx = i;
			tmp.name = t.field_name[i];
			tmp.size = t.field_size[i];
			tmp.shape = t.field_type_name[i];
			tmp.dim = t.dim[i];
			tmp.field_typeID = t.field_origin_typeid[i + 1];
			int j = 0;
			for (j = 0; j < l1_frequent_item.size(); j++) {
				if (t.typeID == l1_frequent_item[j].typeID && i == l1_frequent_item[j].fieldID) {
					tmp.if_hot = 1;
					hot_fields.push_back(tmp);
					break;
				}
			}
			if (j == l1_frequent_item.size()) {
				tmp.if_hot = 0;
				cold_fields.push_back(tmp);
			}
		}

		/*
		cout << "hot data" << endl;
		for (int k = 0; k < hot_fields.size(); k++) {
			cout << hot_fields[k].typeID << "," << hot_fields[k].idx << "," << hot_fields[k].name << "," << hot_fields[k].size << "," << hot_fields[k].shape << "," << hot_fields[k].dim << "," << hot_fields[k].field_typeID << endl;
		}
		cout << "cold data" << endl;
		for (int k = 0; k < cold_fields.size(); k++) {
			cout << cold_fields[k].typeID << "," << cold_fields[k].idx << "," << cold_fields[k].name << "," << cold_fields[k].size << "," << cold_fields[k].shape << "," << cold_fields[k].dim <<  "," << cold_fields[k].field_typeID << endl;
		}
		*/
		
		while (1) {
			vector<int> idxs;
			for (int i = 0; i < hot_fields.size(); i++) {
				int field_typeid = hot_fields[i].field_typeID;
				if (no_malloc_typeid.count(field_typeid) == 1) { //no ptr/array type ,to be done
					//int tyidx = typeid_to_idx[field_typeid];
					idxs.push_back(i);
				}
			}
			if (idxs.size() == 0) {
				break;
			} else {
				for (int i = 0; i < idxs.size(); i++) {
					string pre_name = hot_fields[idxs[i]].name;
					int field_typeid =  hot_fields[idxs[i]].field_typeID;
					int tyidx = typeid_to_idx[field_typeid];
					types t = tys[tyidx];
					for (int j = 0; j < t.field_name.size(); j++ ) {
						afield tmp;
						tmp.typeID = t.typeID;
						tmp.idx = j;
						tmp.name = pre_name + "." + t.field_name[j];
						tmp.size = t.field_size[j];
						tmp.shape = t.field_type_name[j];
						tmp.dim = t.dim[j];
						tmp.field_typeID = t.field_origin_typeid[j + 1];
						int k = 0;
						for (k = 0; k < l1_frequent_item.size(); k++) {
							if (t.typeID == l1_frequent_item[k].typeID && j == l1_frequent_item[k].fieldID) {
								hot_fields.push_back(tmp);
								break;
							}
						}
						if (k == l1_frequent_item.size()) {
							cold_fields.push_back(tmp);
						}	
					}
				}
				int left = 0;
				for(int right = 0; right < hot_fields.size(); right++) {
					int i = 0;
					for (i = 0; i < idxs.size(); i++) {
						if (right == idxs[i]) {
							break;
						}
					}
					if (i == idxs.size()) {
						hot_fields[left++] = hot_fields[right];
					}
				}
				hot_fields.resize(left);
			}
		}
		/*
		cout << "hot data" << endl;
		for (int k = 0; k < hot_fields.size(); k++) {
			cout << hot_fields[k].typeID << "," << hot_fields[k].idx << "," << hot_fields[k].name << "," << hot_fields[k].size << "," << hot_fields[k].shape << "," << hot_fields[k].dim << "," << hot_fields[k].field_typeID << endl;
		}
		cout << "cold data" << endl;
		for (int k = 0; k < cold_fields.size(); k++) {
			cout << cold_fields[k].typeID << "," << cold_fields[k].idx << "," << cold_fields[k].name << "," << cold_fields[k].size << "," << cold_fields[k].shape << "," << cold_fields[k].dim <<  "," << cold_fields[k].field_typeID << endl;
		}
		*/
		clusters.clear();
		louvain_malloc(hot_fields);
		//cout << "test" << endl;
		/*for (int c = 0; c < clusters.size(); c++) {
			for (int cc = 0; cc < clusters[c].size(); cc++) {
				fp_LOG << clusters[c][cc] << "_";
			}
			fp_LOG << endl;
		}
		*/
		///*
		vector<int>hot_padding_idx;
        for (int c = 0; c < clusters.size(); c++) {
			if (clusters[c].size() == 1 && hot_fields[clusters[c][0]].size < 8) {
				hot_padding_idx.push_back(c);
				cold_fields.push_back(hot_fields[clusters[c][0]]);
			}
		}
		for (int c = hot_padding_idx.size() - 1; c >= 0; c--) {
			clusters.erase(clusters.begin() + hot_padding_idx[c]);
		}
	   //*/
		int len = cold_fields.size();
        for (int x = 0; x < len; x++) {
            for (int y = x + 1; y < len; y++) {
                   if (cold_fields[x].size > cold_fields[y].size )
                   {	//swap(ctmp[x], ctmp[y]);
							swap(cold_fields[x], cold_fields[y]);
					}
                }
        }
		cold.push_back(cold_fields);
		vector<vector<afield>>tmp;
		fp_opt_malloc<<"typedef struct {" << endl;
		for (int c = 0; c < clusters.size(); c++) {
			vector<afield> ttmp;
        	fp_opt_malloc<<"//cluster" << endl;
			for (int cc = 0; cc < clusters[c].size(); cc++) {
				//fp_LOG << clusters[c][cc] << "_";
				fp_opt_malloc<<"\t" << hot_fields[clusters[c][cc]].shape << "\t" << hot_fields[clusters[c][cc]].name << "";
                if(hot_fields[clusters[c][cc]].dim != 0) fp_opt_malloc<<"[" << hot_fields[clusters[c][cc]].dim <<"]";
				fp_opt_malloc << ";" << "// size = " << hot_fields[clusters[c][cc]].size << "B" <<endl;
				ttmp.push_back(hot_fields[clusters[c][cc]]);
			}
			tmp.push_back(ttmp);
			//fp_LOG << endl;
		}
		hot.push_back(tmp);
        fp_opt_malloc<<"//cold data" << endl;
		for (int cc = 0; cc < cold_fields.size(); cc++) {
				fp_opt_malloc<<"\t" << cold_fields[cc].shape << "\t" << cold_fields[cc].name << "";
                if(cold_fields[cc].dim != 0) fp_opt_malloc<<"[" << cold_fields[cc].dim <<"]";
				fp_opt_malloc << ";" << "// size = " << cold_fields[cc].size << "B";
                if(cold_fields[cc].if_hot != 0) fp_opt_malloc<<", a cluster with only one hot data && size < 8B";
				fp_opt_malloc << endl;

		}
		fp_opt_malloc<<"}"<< t.name <<"; // access_time = " << ats[w] << endl;
		fp_opt_malloc << "//**********************************" << endl;
		/*
		for (int h = 0; h < hot[w].size(); h++) {
			fp_opt_malloc << "!!!!";
			for (int hh = 0; hh < hot[w][h].size(); hh++) {
				fp_opt_malloc << hot[w][h][hh].name << endl;
			}
		}
		fp_opt_malloc << "cold" << "!!!" << endl;
		for (int co = 0; co < cold[w].size(); co++) {
			fp_opt_malloc << cold[w][co].name << endl;
		}
		*/	
	}
	//cout << endl;
	//for (auto it = no_malloc_typeid.begin(); it != no_malloc_typeid.end(); it++) {
	//	cout << *it << "--";
//	}
//	cout << endl;
	padding_opt(hot, cold, tids, ats);	
	malloc_flag = 0;

}
void AprioriAnalysis::dec_l1_resv() {
    int j = 0;
    for (int i = 0; i < l1_frequent_item.size(); i++) {
        if (l1_frequent_item[i].name != "rsvd") {
            l1_frequent_item[j++] = l1_frequent_item[i];
        }
    }
    l1_frequent_item.resize(j);
}
void AprioriAnalysis::topk_louvain_cluster() {
    get_topk_typeid();
    fp_output<<"\n\n2.Mutiple Struct Optimization"<<endl;
    //fp_output_secret<<"\n\n2.Mutiple Struct Optimization"<<endl;
    for (int i = 0; i < topk_typeid.size(); i++) {
        fp_output << "No. " << i + 1 << "--Multiple Struct Optimization （top_k = " << topk_typeid.size() << " ）, typeid = " << topk_typeid[i] << endl;
        //fp_output_secret << "No. " << i + 1 << "--Multiple Struct Optimization （top_k = " << topk_typeid.size() << " ）, typeid = " << topk_typeid[i] << endl;
        matrix_cluster(topk_typeid[i]);
    }
}
void AprioriAnalysis::get_topk_typeid() {
    int i, j;
    vector<vector<int> >tyids;
    for(i=0;i<l1_frequent_item.size();i++)
    {
        for(j=0;j<tyids.size();j++)
            if(l1_frequent_item[i].typeID==tyids[j][0])
                break;
       	if(j==tyids.size())
        {
           	vector<int>tmp;
           	tmp.push_back(l1_frequent_item[i].typeID);
           	tmp.push_back(i);
           	tyids.push_back(tmp);
        }
        else
        {   
           	tyids[j].push_back(i);
        }
    }

	vector<pair<int, int> >ac_time_descending_order;
    for(i = 0 ; i<tyids.size(); i++)
    {
       	ac_time_descending_order.push_back(make_pair(tyids[i][0] , ac_times[tyids[i][0]]));
    }
	
    sort(ac_time_descending_order.begin(), ac_time_descending_order.end(), [](const pair<int,int>& u, const pair<int,int>& v) {
           return u.second > v.second;
       });
	int top_k = TOP_K > tyids.size()?tyids.size():TOP_K;
    for(i = 0 ;i < top_k; i++)
       	topk_typeid.push_back(ac_time_descending_order[i].first);
}
map<int, int> AprioriAnalysis::stride_statistics(vector<int> data) {
    map<int, int> result;
    for (int i = 1; i < data.size(); i++) {
        int stride = abs(data[i] - data[i - 1]);
        result[stride]++;
    }
    return result;
}
vector<vector<int>> AprioriAnalysis:: cal_continuous_size(vector<int> data, int stride) { //0903
	vector<vector<int>> result; 
    if (data.size() == 0)
		return result;  
	int left = 0;
	int right = 0;
    int cur_stride;
	for (int i = 1; i < data.size(); i++) { 
        cur_stride = abs(data[i] - data[i - 1]);
        if (cur_stride > stride || cur_stride == 0) {
			right = i - 1;
            int size = right - left + 1;
            if (size >= 2) { //连续访问的大小至少为2
                result.push_back(vector<int>{size, left, right});
            }
			left = i;
        }
	}
	right = data.size() - 1;
	int size = right - left + 1;
    if (size >= 2) {
        result.push_back(vector<int>{size, left, right});
    }
	return result;
}

int AprioriAnalysis::get_lcs(frequent_Item_time_serial s1,frequent_Item_time_serial s2,int begin_and_end[4])
{//测试OK
    long len1 = s1.sec.size();  
	long len2 = s2.sec.size(); //长度较短的放在后面s2
    if(len1 == 0 || len2 == 0)
    {
        begin_and_end[2]=begin_and_end[0]=-1;
        begin_and_end[3]=begin_and_end[1]=-1;
        return 0 ;
    }
    int flag = 0;
    int i  = 0 , j = 0;
    int count = 0;
	
    while(i < len1 && j < len2) 
    {
        if(s1.sec[i]==s2.sec[j]&&s1.usec[i]==s2.usec[j])
	    {
	        count++;
            i++;
            j++;       
            if(flag == 0)
            {
                begin_and_end[0]=i-1;
                begin_and_end[1]=j-1;
                flag=1;
            }
            else
            {
                begin_and_end[2]=i-1;
                begin_and_end[3]=j-1;
                flag=2;
            }
	    }
        else
        {
            long timediff =  (s1.sec[i] - s2.sec[j]) * 1000000 + s1.usec[i] - s2.usec[j];
            if(timediff < 0)
                i++;
            else
                j++;
        }
	}
    if(flag==1)
    {//至少存在一个共同访问
        begin_and_end[2]=begin_and_end[0];
        begin_and_end[3]=begin_and_end[1];
    }
    if(flag==0 )
    {
        begin_and_end[2]=begin_and_end[0]=-1;
        begin_and_end[3]=begin_and_end[1]=-1;
    }
    
    if( flag != 0)
    {
        i = begin_and_end[2] ;
        while(i  < len1)
        {
            if(s1.sec[i] == s2.sec[begin_and_end[3]] && s1.usec[i] == s2.usec[begin_and_end[3]])
                i++;
            else
                break;
        }
        begin_and_end[2] = i - 1 ; 

        j = begin_and_end[3] ;
        while(j  < len2)
        {
            if(s1.sec[begin_and_end[2]] == s2.sec[j] && s1.usec[begin_and_end[2]] == s2.usec[j])
                j++;
            else
                break;
        }
        begin_and_end[3] = j - 1 ; 
    }
	return count;
}


void AprioriAnalysis::new_apriori_adtw_clustering_next_single_type_s()
{
    //测试OK
    int i,j,ii,jj;
    vector<vector<unsigned> >tmp_cluster;
    for(i=0;i<l1_cluster.size();i++)
    {
        vector<unsigned> tmp_c;
        for(j=0;j<l1_cluster[i].size();j++)
            tmp_c.push_back(l1_cluster[i][j]);
        tmp_cluster.push_back(tmp_c);    
    }
    while(1)
    {    
        vector<vector<double> >affms;
        affms.resize(tmp_cluster.size());
        for(i=0;i<affms.size();i++)
        {
            affms[i].resize(tmp_cluster.size());
        }
        for(i=0;i<tmp_cluster.size();i++)
        {
            vector<unsigned>tmpi;
            for(j=0;j<tmp_cluster[i].size();j++)
                tmpi.push_back(tmp_cluster[i][j]);
            for(j=i;j<tmp_cluster.size();j++)
            {
                vector<unsigned>tmpj;
                for(ii=0;ii<tmp_cluster[j].size();ii++)
                    tmpj.push_back(tmp_cluster[j][ii]);

                double tmp_ij_adtw = DBL_MAX;
                for(ii=0;ii<tmpi.size();ii++)
                    for(jj=0;jj<tmpj.size();jj++)
                    {
                        if(adtw_matrix[tmpi[ii]][tmpj[jj]]!=-1.0&&tmp_ij_adtw>adtw_matrix[tmpi[ii]][tmpj[jj]])
                        {
                            tmp_ij_adtw = adtw_matrix[tmpi[ii]][tmpj[jj]];
                        }
                    }
                if(tmp_ij_adtw != DBL_MAX)
                {
                    affms[i][j]=affms[j][i]=tmp_ij_adtw;                
                }
                else
                {
                    affms[i][j]=affms[j][i]=-1.0;
                }
            }
        }
        fp_LOG<<"affms matrices assigned done"<<endl;
        avg_adtw = 0;
        int count_edge = 0;
        for(i=0;i<affms.size();i++)
        {
            for(j=i;j<affms[i].size();j++)
            {
                if(affms[i][j]!=-1.0)  //+++ &&affms[i][j]<=avg_adtw
                {
                    count_edge++;
                    avg_adtw+=affms[i][j];
                }
            }    
        }
        vector<vector<unsigned> >new_tmp_cluster;
        if(count_edge!=0)
        {
            //avg_adtw/=count_edge;
            avg_adtw = 0.1;
            fp_LOG<<"avg_count_distance = "<<avg_adtw<<endl;
            fp_LOG<<"count_edge = "<<count_edge<<endl;
            while (1)
            {           
                int mi = -1;
                int mj = -1;
                double madtw = DBL_MAX; 
                for(ii=0;ii<affms.size();ii++)
                    for(jj=ii;jj<affms[ii].size();jj++)
                    {
                        if(madtw>affms[ii][jj]&&affms[ii][jj]!=-1.0)//&&adtw_matrix_s[tyids[i][ii+1]][tyids[i][jj+1]]<MIN_DISTANCE&&adtw_matrix_s[tyids[i][ii+1]][tyids[i][jj+1]]!=-1.0
                        {
                            madtw = affms[ii][jj];
                            mi = ii;
                            mj = jj;
                        }
                    }
                fp_LOG<<"mi = "<<mi<<" mj = "<<mj<<" current_min_count_distance = "<<madtw<<endl; 
                if(madtw>avg_adtw) 
                {
                    fp_LOG<<" current_min_count_distance ( "<<madtw<<" ) > avg_count_distance ( "<<avg_adtw<<" ) , The while loop break."<<endl;
                    unsigned *flags = new unsigned[affms.size()]();
                    for(ii=0;ii<new_tmp_cluster.size();ii++)
                        for(jj=0;jj<new_tmp_cluster[ii].size();jj++)
                        {
                            flags[new_tmp_cluster[ii][jj]]=1;
                        }
                    for(ii=0;ii<affms.size();ii++)
                        if(flags[ii]!=1)
                        {
                            vector<unsigned>tmp;
                            tmp.push_back(ii);
                            new_tmp_cluster.push_back(tmp);
                        }
                    delete []flags;
                    break;
                }
                int edge_fsize = 0;
                int edge_fsizei = 0;
                int edge_fsizej = 0;
                for(int si =0 ;si<tmp_cluster[mi].size();si++)
                    edge_fsizei += l1_frequent_item[tmp_cluster[mi][si]].fsize;
                for(int sj =0 ;sj<tmp_cluster[mj].size();sj++)
                    edge_fsizej += l1_frequent_item[tmp_cluster[mj][sj]].fsize;
                edge_fsize = edge_fsizei +edge_fsizej;
                if(mi==mj) edge_fsize/=2;
                int mi_cidx,mj_cidx;
                mi_cidx=mj_cidx=-1;
                for(ii=0;ii<new_tmp_cluster.size();ii++)
                    for(jj=0;jj<new_tmp_cluster[ii].size();jj++)
                    {
                        if(mi==new_tmp_cluster[ii][jj])
                        {
                            mi_cidx=ii;
                        }
                
                        if(mj==new_tmp_cluster[ii][jj])
                        {
                            mj_cidx=ii;
                        }
                    }
            
                    if(mi_cidx==-1&&mj_cidx==-1&&edge_fsize<=CACHE_LINE_SIZE)
                    {
                        vector<unsigned>tmp;
                        if(mi==mj)
                            tmp.push_back(mi);
                        else
                        {
                            tmp.push_back(mi);
                            tmp.push_back(mj);
                        }
                        new_tmp_cluster.push_back(tmp);
                    }
                    if(mi_cidx==-1&&mj_cidx!=-1&&edge_fsize<=CACHE_LINE_SIZE)
                    {
                        int sizej = 0;
                        for(int sj=0;sj<new_tmp_cluster[mj_cidx].size();sj++)
                        {
                            for(int sjj=0;sjj<tmp_cluster[new_tmp_cluster[mj_cidx][sj]].size();sjj++)
                                sizej += l1_frequent_item[tmp_cluster[new_tmp_cluster[mj_cidx][sj]][sjj]].fsize;
                        }
                        sizej += edge_fsizei;
                        if(sizej<=CACHE_LINE_SIZE)
                            new_tmp_cluster[mj_cidx].push_back(mi);
                    }
        
                    if(mi_cidx!=-1&&mj_cidx==-1&&edge_fsize<=CACHE_LINE_SIZE)
                    {
                        int sizei = 0;
                        for(int si=0;si<new_tmp_cluster[mi_cidx].size();si++)
                        {
                            for(int sii=0;sii<tmp_cluster[new_tmp_cluster[mi_cidx][si]].size();sii++)
                                sizei += l1_frequent_item[tmp_cluster[new_tmp_cluster[mi_cidx][si]][sii]].fsize;
                        }
                        sizei += edge_fsizej;
                        if(sizei<=CACHE_LINE_SIZE)
                            new_tmp_cluster[mi_cidx].push_back(mj);
                    }
                    if(mi_cidx!=-1&&mj_cidx!=-1&&mi_cidx!=mj_cidx&&edge_fsize<=CACHE_LINE_SIZE)
                    {
                        int sizej = 0;
                        for(int sj=0;sj<new_tmp_cluster[mj_cidx].size();sj++)
                        {
                            for(int sjj=0;sjj<tmp_cluster[new_tmp_cluster[mj_cidx][sj]].size();sjj++)
                                sizej += l1_frequent_item[tmp_cluster[new_tmp_cluster[mj_cidx][sj]][sjj]].fsize;
                        }
                        int sizei = 0;
                        for(int si=0;si<new_tmp_cluster[mi_cidx].size();si++)
                        {
                            for(int sii=0;sii<tmp_cluster[new_tmp_cluster[mi_cidx][si]].size();sii++)
                                sizei += l1_frequent_item[tmp_cluster[new_tmp_cluster[mi_cidx][si]][sii]].fsize;
                        }
                        sizei+=sizej;
                        if(sizei<=CACHE_LINE_SIZE)
                        {
                            for(int kk =0 ;kk<new_tmp_cluster[mj_cidx].size(); kk++)
                                new_tmp_cluster[mi_cidx].push_back(new_tmp_cluster[mj_cidx][kk]);
                            new_tmp_cluster.erase(new_tmp_cluster.begin()+mj_cidx);
                        }
                        
                    }
                    affms[mi][mj] = -1.0;
                    unsigned count = 0;
                    for(ii=0;ii<new_tmp_cluster.size();ii++)
                    {
                        count+=new_tmp_cluster[ii].size();
                    }
                    if(count==affms.size()){
                        fp_LOG<<"cluster.size == affms.size() , The while loop break."<<endl;
                        break;
                    }
                        
            }//聚类结束
            vector<vector<unsigned> >tc;
            for(i=0;i<new_tmp_cluster.size();i++)
            {   
                vector<unsigned>tmp;
                for(j=0;j<new_tmp_cluster[i].size();j++)
                {    
                    for(int k=0;k<tmp_cluster[new_tmp_cluster[i][j]].size();k++)
                    {
                        tmp.push_back(tmp_cluster[new_tmp_cluster[i][j]][k]);
                    }
                }
                tc.push_back(tmp);
            }
            if(tmp_cluster==tc)
            {
                fp_LOG<<"current_cluster = pre_last_cluster , The while loop break."<<endl;
                new_tmp_cluster.clear();
                tc.clear();
                break;
            }   
            tmp_cluster.clear();
            new_tmp_cluster.clear();
            for(i=0;i<tc.size();i++)
            {
                vector<unsigned>tmp;
                for(j=0;j<tc[i].size();j++)
                {
                    tmp.push_back(tc[i][j]);
                }
                tmp_cluster.push_back(tmp);
            }
            tc.clear();
        }
        else
        {
            fp_LOG<<"count_edge = 0"<<endl;
            fp_LOG<<"clustering done!"<<endl;
            break;
        }
        
        int tyid_idx;
        /*
        for(tyid_idx=0;tyid_idx<tys.size();tyid_idx++)
        {
            if(tys[tyid_idx].typeID == l1_frequent_item[tmp_cluster[0][0]].typeID)
                break;
        }
        */
        tyid_idx = typeid_to_idx[l1_frequent_item[tmp_cluster[0][0]].typeID];
        fp_output<<"Next Layer Optimization Struct Define"<<endl;
        //fp_output_secret<<"Next Layer Optimization Struct Define"<<endl;
        fp_output<<"typeID = "<<tys[tyid_idx].typeID<<", name="<<tys[tyid_idx].name.data()<<endl<<"{"<<endl;
        //fp_output_secret<<"typeID = "<<tys[tyid_idx].typeID<<", name="<<tys[tyid_idx].secret_name.data()<<endl<<"{"<<endl;

        fp_output<<"\t/************hot field************/"<<endl;
        //fp_output_secret<<"\t/************hot field************/"<<endl;
        fp_output<<"\t/***           split          ***/"<<endl;
        //fp_output_secret<<"\t/***           split          ***/"<<endl;
        vector<int>flags(tys[tyid_idx].field_name.size(),0);
        fp_LOG<<"next cluster:"<<endl;
        for(i=0;i<tmp_cluster.size();i++)
        {
            int size = 0;
            fp_LOG<<"{";
            long sum_ac_times = 0;
            int len = tmp_cluster[i].size();
            for (int x = 0; x < len; x++) {
                for (int y = x + 1; y < len; y++) {
                    //if (l1_frequent_item[tmp_cluster[i][x]].fsize > l1_frequent_item[tmp_cluster[i][y]].fsize )
                    if(tys[tyid_idx].field_size[l1_frequent_item[tmp_cluster[i][x]].fieldID] > tys[tyid_idx].field_size[l1_frequent_item[tmp_cluster[i][y]].fieldID] )
                        swap(tmp_cluster[i][x], tmp_cluster[i][y]);
                }
            }
            for(j=0;j<tmp_cluster[i].size();j++)
            {
                fp_LOG<<tmp_cluster[i][j]<<":<"<<l1_frequent_item[tmp_cluster[i][j]].typeID<<","<<l1_frequent_item[tmp_cluster[i][j]].fieldID<<">-"<<l1_frequent_item[tmp_cluster[i][j]].name.data();
                if(j==tmp_cluster[i].size()-1)
                    fp_LOG<<" ";
                else
                    fp_LOG<<",";
                size += l1_frequent_item[tmp_cluster[i][j]].fsize;
                sum_ac_times += tys[tyid_idx].ac_time[l1_frequent_item[tmp_cluster[i][j]].fieldID];
                fp_output<<"\t"<<tys[tyid_idx].field_name[l1_frequent_item[tmp_cluster[i][j]].fieldID].data()<<"\t"<<tys[tyid_idx].field_size[l1_frequent_item[tmp_cluster[i][j]].fieldID]<<" B"<<endl;
                 //fp_output_secret<<"\t"<<tys[tyid_idx].secret_field_name[l1_frequent_item[tmp_cluster[i][j]].fieldID].data()<<"\t"<<tys[tyid_idx].field_size[l1_frequent_item[tmp_cluster[i][j]].fieldID]<<" B"<<endl;
                flags[l1_frequent_item[tmp_cluster[i][j]].fieldID]=1;
            }   
            fp_LOG<<"}\tcsize = "<<size<<" B"<<endl;
            fp_output<<"\t****access_rate = "<<(double)sum_ac_times/(double)ac_times[tys[tyid_idx].typeID]<<"****"<<endl;
            //fp_output_secret<<"\t****access_rate = "<<(double)sum_ac_times/(double)ac_times[tys[tyid_idx].typeID]<<"****"<<endl;
            fp_output<<"\t-----------------------------------"<<endl;
            //fp_output_secret<<"\t-----------------------------------"<<endl;
        }
        fp_output<<"\t/************cold field************/"<<endl;
        //fp_output_secret<<"\t/************cold field************/"<<endl;
        fp_output<<"\t/***        split or merge     ***/"<<endl;
        //fp_output_secret<<"\t/***        split or merge     ***/"<<endl;
        for(int i=0;i<tys[tyid_idx].field_name.size();i++)
        {
            if(flags[i]==0)
            {
                //fp_output<<"\t"<<tys[tyid_idx].field_name[i].data()<<"\t"<<tys[tyid_idx].field_size[i]<<" B"<<endl;
                ////fp_output_secret<<"\t"<<tys[tyid_idx].secret_field_name[i].data()<<"\t"<<tys[tyid_idx].field_size[i]<<" B"<<endl;    
                fp_output<<"\t"<<tys[tyid_idx].field_name[i].data()<<"\t"<<tys[tyid_idx].field_size[i]<<" B\t****access_rate = "<<(double)tys[tyid_idx].ac_time[i]/(double)ac_times[tys[tyid_idx].typeID]<<"****"<<endl;
                //fp_output_secret<<"\t"<<tys[tyid_idx].secret_field_name[i].data()<<"\t"<<tys[tyid_idx].field_size[i]<<" B\t****access_rate = "<<(double)tys[tyid_idx].ac_time[i]/(double)ac_times[tys[tyid_idx].typeID]<<"****"<<endl;    
            }
        }
        fp_output<<"}"<<endl;
        //fp_output_secret<<"}"<<endl;
    }
}
void AprioriAnalysis::mean_support_matrices()
{
    int i,j;
    vector<vector<long> >tmp_support_matrix;
    tmp_support_matrix.resize(l2_matrix.size());
    for(i=0;i<tmp_support_matrix.size();i++)
        tmp_support_matrix[i].resize(l2_matrix.size());
    long count_tmp_support_matrix = 0;
    for(i=0;i<tmp_support_matrix.size();i++)
        for(j=0;j<tmp_support_matrix.size();j++)
        {
            tmp_support_matrix[i][j] = 0;
        }
    FILE *fp_support_matrix;
    if ((fp_support_matrix = fopen ("support_matrices.txt", "r")) == NULL)  
    {
        printf ("fail reading support_matrices.txt\n");
        //return;
		//exit (0);
    }
    char buf[MAX_LINE];  /*缓冲区*/
    long tmp;
    while(1)
    {
        if(fscanf(fp_support_matrix,"%s\n",buf)==EOF) break;
        count_tmp_support_matrix++;
        for(i=0;i<l1_frequent_item.size();i++)
        {   
            for(j=0;j<l1_frequent_item.size();j++)
            {
                long tmp;
                fscanf(fp_support_matrix,"%ld",&tmp); 
                tmp_support_matrix[i][j] +=tmp;
            }
        }
    }
    for(i=0;i<tmp_support_matrix.size();i++)
    {   
        for(j=0;j<tmp_support_matrix.size();j++)
        {
            tmp_support_matrix[i][j] /= count_tmp_support_matrix;
        }
    }
    /*
    fp_LOG<<"mean_support_matrices"<<endl<<setw(15)<<" ";
    for(i=0;i<l1_frequent_item.size();i++)
        fp_LOG<<setw(15)<<l1_frequent_item[i].name;
    fp_LOG<<endl;
    */
    for(i=0;i<tmp_support_matrix.size();i++)
    {
        //fp_LOG<<setw(15)<<l1_frequent_item[i].name;
        for(j=0;j<tmp_support_matrix[i].size();j++)
        {
            l2_matrix[i][j] = tmp_support_matrix[i][j];    
            //fp_LOG<<setw(15)<<l2_matrix[i][j];
        }
        //fp_LOG<<endl;
    }
    fclose(fp_support_matrix);
}
void AprioriAnalysis::mean_adtw_matrices()
{
	//LOG<<"line: "<<__LINE__<<" "<<__FUNCTION__<<" is running."<<endl;
    int i,j;
    adtw_matrix.resize(l1_frequent_item.size());
    adtw_matrix_s.resize(l1_frequent_item.size());
    for(i=0;i<l1_frequent_item.size();i++)
    {
        adtw_matrix[i].resize(l1_frequent_item.size());
        adtw_matrix_s[i].resize(l1_frequent_item.size());
    }
    vector<vector<double> >tmp_adtw_matrix;
    tmp_adtw_matrix.resize(l1_frequent_item.size());
    for(i=0;i<tmp_adtw_matrix.size();i++)
        tmp_adtw_matrix[i].resize(l1_frequent_item.size());
    
    vector<vector<int> >count_tmp_adtw_matrix;
    count_tmp_adtw_matrix.resize(l1_frequent_item.size());
    for(i=0;i<count_tmp_adtw_matrix.size();i++)
        count_tmp_adtw_matrix[i].resize(l1_frequent_item.size());
    for(i=0;i<tmp_adtw_matrix.size();i++)
        for(j=0;j<tmp_adtw_matrix.size();j++)
        {
            tmp_adtw_matrix[i][j] = 0;
            count_tmp_adtw_matrix[i][j]= 0;
        }
    FILE *fp_adtw_matrix;
    if ((fp_adtw_matrix = fopen ("adtw_matrices.txt", "r")) == NULL)  
    {
        printf ("fail reading adtw_matrices.txt\n");
        //return ;
		//exit (0);
    }
    char buf[MAX_LINE];  /*缓冲区*/
    double tmp;
    while(1)
    {
        if(fscanf(fp_adtw_matrix,"%s\n",buf)==EOF) break;
        for(i=0;i<l1_frequent_item.size();i++)
        {   
            for(j=0;j<l1_frequent_item.size();j++)
            {
                double tmp;
                fscanf(fp_adtw_matrix,"%lf",&tmp); 
                if(tmp!=-1)
                {
                    tmp_adtw_matrix[i][j] +=tmp;
                    count_tmp_adtw_matrix[i][j]++;
                }
            }
        }
    }
    for(i=0;i<tmp_adtw_matrix.size();i++)
    {   
        for(j=0;j<tmp_adtw_matrix.size();j++)
        {
            if(count_tmp_adtw_matrix[i][j]==0)
                tmp_adtw_matrix[i][j] = -1;
            else
                tmp_adtw_matrix[i][j] /= count_tmp_adtw_matrix[i][j];
        }
    }
    
    //fp_LOG<<"mean_adtw_matrices"<<endl<<setw(15)<<" ";
    //for(i=0;i<l1_frequent_item.size();i++)
        //fp_LOG<<setw(15)<<l1_frequent_item[i].name;
    //fp_LOG<<endl;
    for(i=0;i<adtw_matrix.size();i++)
    {
        //fp_LOG<<setw(15)<<l1_frequent_item[i].name;
        for(j=0;j<adtw_matrix[i].size();j++)
        {
            adtw_matrix[i][j] = tmp_adtw_matrix[i][j];
            adtw_matrix_s[i][j] = tmp_adtw_matrix[i][j];    
            //fp_LOG<<setw(15)<<adtw_matrix[i][j];
        }
        //fp_LOG<<endl;
    }
    
    fclose(fp_adtw_matrix);
}


long AprioriAnalysis::get_timediff(long s1,long us1,long s2,long us2)
{
    return labs((s1-s2)*1000000+us1-us2);
}

long AprioriAnalysis::new_cal_dtw_rws(frequent_Item_time_serial s1,frequent_Item_time_serial s2,long len[3],int begin_and_end[4])
{//直接算dtw，不用内存签名，不用减一下，测试ok
//考虑不用时间，参数，用读写0/1序列
    //int begin_and_end[4];
    //get_both_begin_and_end(s1,s2,begin_and_end);
    //cout<<begin_and_end[0]<<" "<<begin_and_end[1]<<" "<<begin_and_end[2]<<" "<<begin_and_end[3]<<endl;
    if(begin_and_end[0]==-1)
        return -1;
    frequent_Item_time_serial ss1,ss2;
    int i,j;
    ss1.fid=s1.fid;
    ss1.name=s1.name;
    ss1.tid=s1.tid;
    //fp_LOG<<"rw1:";
    for(i=begin_and_end[0];i<=begin_and_end[2];i++)
    {
        ss1.rw.push_back(s1.rw[i]);
        //fp_LOG<<s1.rw[i]<<" ";
    }
    //fp_LOG<<endl;
    ss2.fid=s2.fid;
    ss2.name=s2.name;
    ss2.tid=s2.tid;
    for(i=begin_and_end[1];i<=begin_and_end[3];i++)
    {
        ss2.rw.push_back(s2.rw[i]);
        //fp_LOG<<s2.rw[i]<<" ";
    }
    //fp_LOG<<endl;
    int n= ss1.rw.size();
    int m= ss2.rw.size();
    int n_m = n-m;
    int w = max(SAMPLE_LENGTH,abs(n_m));
    //fp_LOG<<"n=:"<<n<<",m=:"<<m<<",w="<<w<<endl;
    vector<vector<int> >G(n+1);
    vector<vector<int> >path(n+1);
    
    for(i=0;i<=n;i++)
    {
        G[i].resize(m+1);
        path[i].resize(m+1);
    }
    for(i=0;i<=n;i++)
        for(j=0;j<=m;j++)
        {
            G[i][j] = INT_MAX;
            path[i][j] = -1;  //0:right(i-1), 1:down(j-1):, 2:right_down(i-1,j-1)
        }

    G[0][0] = 0;  //开头和结束肯定为0


    for(i=1;i<=n;i++)
        for(j=max(1,i-w);j<=min(m,i+w);j++)  
            G[i][j] = 0;

    for(i=1;i<=n;i++)
        for(j=max(1,i-w);j<=min(m,i+w);j++)    
        {
            int cost = ss1.rw[i-1]-ss2.rw[j-1];
            cost = abs(cost);
            G[i][j]  = cost + min(G[i-1][j-1],min(G[i-1][j],G[i][j-1]));
           
            if(G[i-1][j] <= G[i-1][j-1] && G[i-1][j] <= G[i][j-1])
                path[i][j] = 0;
            if(G[i][j-1] <= G[i-1][j-1]  && G[i][j-1] <= G[i-1][j] )
                path[i][j] = 1;
             if(G[i-1][j-1] <= G[i-1][j] && G[i-1][j-1] <= G[i][j-1])
                path[i][j] = 2;  //优先，最短
        }
    i = n ;
    j = m ;
    long path_len = 1 ;
    while(i>=1&&j>=1&&path[i][j]!=-1)
    {
        if(path[i][j] == 2)
        {
            i--;
            j--;
        }
        if(path[i][j] == 1)
        {
            j--;
        }
        if(path[i][j] == 0)
        {
            i--;
        }
        path_len++;
    }
    len[0] = ss1.rw.size();
    len[1] = ss2.rw.size();
    len[2] = path_len;
    
    return G[n][m];  //未归一化
}
double AprioriAnalysis::cal_Q(community c,long **correlation_count,double m, long *ki)
{
    set<int>::iterator iti;
    set<int>::iterator itj;
    double q=0;
    double Aij;
    for (iti = c.vs.begin(); iti != c.vs.end(); iti++)
    {
        for (itj = c.vs.begin(); itj != c.vs.end(); itj++)
        {
            Aij= (double)*(*(correlation_count + (*iti)) + *itj);
            q=q+Aij-(double)ki[*(iti)]*(double)ki[*(itj)]/2/m;
        }
    }
    //double w=cal_w(c,CA);
    //q=w*q;
    return q/2/m;
}
void AprioriAnalysis::print_community(community *cs, int n,long **correlation_count,double m, long *ki)
{
    set<int>::iterator it;
    double cq=0.0;
    double q=0.0;
    for(int i=0;i<n;i++)
    {
        fp_LOG<<"cid:"<<cs[i].cid;
        q=cal_Q(cs[i],correlation_count,m,ki);
        fp_LOG<<"\t Q = "<<q<<"\t Vs{ ";
        
        for (it = cs[i].vs.begin(); it != cs[i].vs.end(); it++)
        {
            fp_LOG<<*it<<" "; 
        }
        fp_LOG<<"}--{";
        fp_output<<"________________________________________________"<<endl;
        //fp_output_secret<<"________________________________________________"<<endl;
        fp_output<<"struct cluster_"<<i<<" {"<<endl;
        //fp_output_secret<<"struct cluster_"<<i<<" {"<<endl;
        int count=0;
        long sum_access_times = 0;
        for (it = cs[i].vs.begin(); it != cs[i].vs.end(); it++)
        {
            sum_access_times += l1_frequent_item_tmp[*it].access_time;
            fp_LOG<<"<"<<l1_frequent_item_tmp[*it].typeID<<","<<l1_frequent_item_tmp[*it].fieldID<<">-"<<l1_frequent_item_tmp[*it].name;
            fp_output<<"\t<"<<l1_frequent_item_tmp[*it].typeID<<","<<l1_frequent_item_tmp[*it].fieldID<<">-";
            //fp_output_secret<<"\t<"<<l1_frequent_item_tmp[*it].typeID<<","<<l1_frequent_item_tmp[*it].fieldID<<">-";
            /*
            for(int t = 0;t<tys.size();t++)
            {
                if(tys[t].typeID==l1_frequent_item[*it].typeID)
                {
                    //fp_output_secret<<tys[t].secret_field_name[l1_frequent_item[*it].fieldID]<<endl;
                    break;
                }
            }
            */
            //fp_output_secret<<tys[typeid_to_idx[l1_frequent_item_tmp[*it].typeID]].secret_field_name[l1_frequent_item_tmp[*it].fieldID]<<endl;

            fp_output<<l1_frequent_item_tmp[*it].name<<endl;               

            if(count==cs[i].vs.size()-1)
                {
                    fp_LOG<<" ";
                    //fp_output<<" ";
                    ////fp_output_secret<<" ";
                }
            else
            {
                fp_LOG<<"、";
                //fp_output<<"、";
                ////fp_output_secret<<"、";
                count++;
            } 
        }
        fp_LOG<<"}"<<endl;
        fp_output<<"}//access_times = "<<sum_access_times<<endl;
        //fp_output_secret<<"}//access_times = "<<sum_access_times<<endl;
        cq = cq + q;
    }
    fp_LOG<<"Sum of  Q = :"<<cq<<endl;
}
void AprioriAnalysis::louvain_cluster(long **correlation_count,int n_field,community *cs,double m,long *ki)
{
    int i,j;
    set<int>::iterator it;
    set<int>::iterator itj;
    int iteration=0;
    community *tmp = new community[n_field];
    while(1)
    {
        for(i=0;i<n_field;i++)
            tmp[i]=cs[i];
        iteration++;
        double q1,q2,q3,delta_q;
        for(i=0;i<n_field;i++)
        {
            int max_delta_q_cid=cs[i].max_delta_q_cid;
            q1=cal_Q(cs[i],correlation_count,m,ki);
            for (j = 0; j < n_field; j++)
            {
                if(i==j) continue; 
                q2 = cal_Q(cs[j],correlation_count,m,ki);
                community cij;
                cij.vs.insert(cs[i].vs.begin(),cs[i].vs.end());
                cij.vs.insert(cs[j].vs.begin(),cs[j].vs.end());
                q3 =cal_Q(cij,correlation_count,m,ki);
                delta_q=q3-q1-q2;           
                if(cs[i].max_delta_q<delta_q&&delta_q>0&&cs[j].max_delta_q<delta_q) //
                {
                    cs[i].max_delta_q=delta_q;
                    cs[i].max_delta_q_cid=j;
                }
            }
            if(cs[i].max_delta_q_cid!=max_delta_q_cid) 
            {
                if(max_delta_q_cid!=-1)
                {
                    cs[max_delta_q_cid].max_delta_q_cid=-1;
                    cs[max_delta_q_cid].max_delta_q=0;
                }

                if(cs[i].max_delta_q_cid!=-1)
                {
                    if(cs[cs[i].max_delta_q_cid].max_delta_q_cid!=-1)
                    {
                        cs[cs[cs[i].max_delta_q_cid].max_delta_q_cid].max_delta_q_cid=-1;
                        cs[cs[cs[i].max_delta_q_cid].max_delta_q_cid].max_delta_q=0;
                    }
                    cs[cs[i].max_delta_q_cid].max_delta_q_cid=i;
                    cs[cs[i].max_delta_q_cid].max_delta_q=cs[i].max_delta_q;
                }
            }
        }
        int k=0;
        for(i=0;i<n_field;i++)
        {
            if(cs[i].max_delta_q_cid==tmp[i].max_delta_q_cid&&cs[i].max_delta_q==tmp[i].max_delta_q) k++;
        }//社区信息不再发生变化
        if(k==n_field) 
        {
            fp_LOG<<"*************************************************************"<<endl;
            if (malloc_flag != 1)
				fp_output<<"*************************************************************"<<endl;
            //fp_output_secret<<"*************************************************************"<<endl;
            /*
			for (int i = 0; i < n_field; i++) for (int i = 0; i < n_field; i++) {
				fp_LOG << i << "\t" << cs[i].max_delta_q << "\t" << cs[i].max_delta_q_cid << ":";
				for (auto it = cs[i].vs.begin(); it != cs[i].vs.end(); it++) {
					fp_LOG << *it << "*";
				}
				fp_LOG << endl;

			}*/
			break;
        }
    }
    delete [] tmp;
}
void AprioriAnalysis::matrix_cluster(int tope_k_typeid)
{   
	fp_LOG<<"---------->line: "<<__LINE__<<" "<<__FUNCTION__<<" is running."<<endl;
    int i,j,k;
    vector<int>res_idx;
    for(i=0;i<l1_frequent_item.size();i++)
    {
        /*
        for(j=0;j<tys.size();j++)
        {
            if(tys[j].field_origin_typeid[0]==l1_frequent_item[i].typeID)
            {
                break;
            }
        }
        */
        j = typeid_to_idx[l1_frequent_item[i].typeID];
        int field_typeID = tys[j].field_origin_typeid[l1_frequent_item[i].fieldID+1];
        
        for(k=0;k<tys.size();k++)
        {
            if(tys[k].typeID == field_typeID)
            {
                break;
            }
        }
        
        //k = typeid_to_idx[field_typeID];
        if(k==tys.size())
        {
            res_idx.push_back(i);
        }
    }
	/*
	fp_LOG << "res_idx :" << endl;
	for (i = 0; i < res_idx.size(); i++) {
		fp_LOG << res_idx[i] << " ";
	}
	fp_LOG << endl;
    */
 	set<int>typeID_set;
	for(i=0;i<tys.size();i++)
	{	
		typeID_set.insert(tys[i].typeID);
	}
	/*
	fp_LOG << "typeID_set" << endl;
	for (auto it = typeID_set.begin(); it != typeID_set.end(); it++) {
		fp_LOG << *it << " ";
	}
	fp_LOG << endl;
	*/
	vector<pair<int ,int> >resv;
	queue<int>q;
    q.push(tope_k_typeid);
	/*
    if(LOUVAIN_INPUT_TYPEID != -1)
	{	
		q.push(LOUVAIN_INPUT_TYPEID);
	}
	else
	{
		vector<vector<int> >tyids;
    	for(i=0;i<l1_frequent_item.size();i++)
    	{
        	for(j=0;j<tyids.size();j++)
            	if(l1_frequent_item[i].typeID==tyids[j][0])
                	break;
       	 	if(j==tyids.size())
        	{
            	vector<int>tmp;
            	tmp.push_back(l1_frequent_item[i].typeID);
            	tmp.push_back(i);
            	tyids.push_back(tmp);
        	}
        	else
        	{   
            	tyids[j].push_back(i);
        	}
    	}

		vector<pair<int, int> >ac_time_descending_order;
    	for(i = 0 ; i<tyids.size(); i++)
    	{
        	ac_time_descending_order.push_back(make_pair(tyids[i][0] , ac_times[tyids[i][0]]));
    	}
	
    	sort(ac_time_descending_order.begin(), ac_time_descending_order.end(), [](const pair<int,int>& u, const pair<int,int>& v) {
            return u.second > v.second;
        });
		int top_k = TOP_K > tyids.size()?tyids.size():TOP_K;
    	for(i = 0 ;i < top_k; i++)
        	q.push(ac_time_descending_order[i].first);
	}
    */
	map<int, int>if_scanned;
    for (auto it = typeID_set.begin(); it != typeID_set.end(); it++) {
        if_scanned[*it] = 0;
    }
	while(!q.empty())
	{
		int t = q.front();
		q.pop();
        if(if_scanned[t] == 0) {
            if_scanned[t] = 1;
            for(i=0;i<tys.size();i++)
		    {
			    if(tys[i].typeID == t)
			    {
				    for(j=1;j<tys[i].field_origin_typeid.size();j++)
				    
                    {
                        //这里运行过程中出了bug
					    if(typeID_set.count(tys[i].field_origin_typeid[j]) == 1) {
                            if(if_scanned[tys[i].field_origin_typeid[j]] == 0) {
                                q.push(tys[i].field_origin_typeid[j]);
                            }
                        }else
						    resv.push_back(make_pair(tys[i].typeID, j-1));
				    }
				    break;
			    }
		    }
        }
	}
    vector<int>new_res_idx;
    for(i=0;i<res_idx.size();i++)  //ptr访问同理，访问到热数据
	{
		
		for(j=0;j<resv.size();j++)
		{
			if(resv[j].first == l1_frequent_item[res_idx[i]].typeID && resv[j].second == l1_frequent_item[res_idx[i]].fieldID)
				break;
		}
		if(j != resv.size())
			new_res_idx.push_back(res_idx[i]);
	}
	res_idx.clear();
	//fp_LOG << "new res idx" << endl;
	for(i=0;i<new_res_idx.size();i++)
	{
		res_idx.push_back(new_res_idx[i]);
		//fp_LOG << new_res_idx[i] << " ";
	}
	//fp_LOG << endl;

    fp_LOG<<"Louvain Clustering"<<endl;
    
    int n_field=res_idx.size();
    long **correlation_count=new long*[n_field];
    for(i=0;i<n_field;i++)
    {
        correlation_count[i]=new long[n_field];
    }
    for(i=0;i<n_field;i++)
    {   for(j=i;j<n_field;j++)
        {
            correlation_count[i][j]=correlation_count[j][i]=l2_matrix[res_idx[i]][res_idx[j]];
            if(i==j) correlation_count[i][j]=0;
        }
    }
    
    fp_LOG<<"Correlation_count matrix:"<<endl;
    for(i=0;i<n_field;i++)
    {    for(j=0;j<n_field;j++)
        {
            fp_LOG<<*(*(correlation_count+i) + j)<<"\t";
        }
        fp_LOG<<endl;
    }
    
//    vector<Item>l1_frequent_item_tmp;
	//fp_LOG << " L1  frequent Item" << endl;
	//for (i = 0; i < l1_frequent_item.size(); i++) {
	
	//	fp_LOG << l1_frequent_item[i].typeID << " " << l1_frequent_item[i].fieldID << endl;
	//}

   l1_frequent_item_tmp.clear();
   l1_frequent_item_tmp.resize(res_idx.size());
    for(i=0;i<res_idx.size();i++)
    {
        l1_frequent_item_tmp[i] = l1_frequent_item[res_idx[i]];
    }
	//fp_LOG << "l1 f i tmp" << endl;
	//for (i = 0; i < l1_frequent_item_tmp.size(); i++) {
	
		//fp_LOG << l1_frequent_item_tmp[i].typeID << " " << l1_frequent_item_tmp[i].fieldID << endl;
	//}

//    l1_frequent_item.clear();
//    l1_frequent_item.resize(l1_frequent_item_tmp.size());
  //  for(i=0;i<l1_frequent_item_tmp.size();i++)
    //{
      //  l1_frequent_item[i] = l1_frequent_item_tmp[i];
    //}
   // l1_frequent_item_tmp.clear();    

    community *cs=new community[n_field] ;
    for(i=0;i<n_field;i++)
    {
        cs[i].cid=i;
        cs[i].max_delta_q_cid=-1; //-1表示没有发生社区合并
        cs[i].vs.insert(i);
        cs[i].max_delta_q=0; //ΔQ 初始没有增益为0
    }
    double m=0.0;
    long *ki =new long[n_field];
    for(i=0;i<n_field;i++)
    {
        ki[i]=0;
        for(j=0;j<n_field;j++)
        { 
            m=m+*(*(correlation_count+i) + j);
            ki[i]+=*(*(correlation_count+i) + j);
        } 
    }   
    m=m/2.0;
    fp_LOG<<"Initial communities:"<<endl;
    fp_output<<"\n(1) Initial Hot Data Cluster"<<endl;
    //fp_output_secret<<"\n(1) Initial Hot Data Cluster"<<endl;
    print_community(cs,n_field,correlation_count,m,ki);
    fp_LOG<<"Q : m= "<<m<<endl<<"Q : ki= {";
    for(i=0;i<n_field;i++)
        fp_LOG<<ki[i]<<"  ";
    fp_LOG<<"}"<<endl;
    k=0;
    community *tmp_cs = new community[n_field];
    while(1)
    {
        louvain_cluster(correlation_count,n_field,cs,m,ki);   
        j=0;
        for(i=0;i<n_field;i++)
        {//判断当前是否还有ΔQ增益，没有则不再迭代
            if(cs[i].max_delta_q>0) 
            {
                j=1;
                break;
            } 
        }
        if(j==0) 
        {
            fp_LOG<<"No ΔQ>0, End"<<endl;
            break;
        }
        j=0;
        for(i=0;i<n_field;i++)
        {
            if(cs[i].max_delta_q_cid>=-1) 
            {
                tmp_cs[j].cid=j;
                tmp_cs[j].max_delta_q=0.0;
                tmp_cs[j].max_delta_q_cid=-1;
                tmp_cs[j].vs.clear();

                if(cs[i].max_delta_q_cid>=0) 
                {                
                    tmp_cs[j].vs.insert(cs[i].vs.begin(),cs[i].vs.end());
                    tmp_cs[j].vs.insert(cs[cs[i].max_delta_q_cid].vs.begin(),cs[cs[i].max_delta_q_cid].vs.end());
                    cs[cs[i].max_delta_q_cid].max_delta_q_cid=-2; //合并社区只需处理一个
                }
                if(cs[i].max_delta_q_cid==-1)
                {
                    tmp_cs[j].vs.insert(cs[i].vs.begin(),cs[i].vs.end());
                }
                j++;
            }   
        }
        k++;
        fp_LOG<<k<<"'s louvain_cluster result:"<<endl;
        fp_output<<endl<<k<<")'s Louvain Cluster Result:"<<endl;
        //fp_output_secret<<endl<<k<<")'s Louvain Cluster Result:"<<endl;
        n_field=j;
        for(i=0;i<n_field;i++)
        {
            cs[i]=tmp_cs[i];
        }
        print_community(cs,n_field,correlation_count,m,ki);
        //if(k==5) break; //迭代次数控制
    }
    delete [] tmp_cs;
    fp_output<<"\n(2) Cold Data Access"<<endl;
    //fp_output_secret<<"\n(2) Cold Data Access"<<endl;
    fp_output<<"\nEvery Struct Type : Merge or Split"<<endl<<endl;
    //fp_output_secret<<"\nEvery Struct Type : Merge or Split"<<endl << endl;
    delete [] ki;
    delete [] cs;
    for(i=0;i<n_field;i++)
    {
        delete [] correlation_count[i] ;
    }
    delete [] correlation_count;
}
void AprioriAnalysis::get_L1()
{
	//print_debug_log("run");
	fp_LOG<<"---------->line: "<<__LINE__<<" "<<__FUNCTION__<<" is running."<<endl;
    fp_LOG<<"apriori_cluster_analysis\nGet L1 Set"<<endl;
    int i,j;
    unsigned long long p1_10_access_len = access_len/10;
    unsigned long long nnn=0;
    while(fscanf(fp_access,"%d %d %ld %d %d %llu %llu %d %d %d %s %d\n",&threadIndex,&traceIndex,&addr,&tyid,&fidx,&sec,&usec,&isWrite,&size,&fsize,name,&tyid_array_idx)!=EOF)
    {
        nnn++;
        if(p1_10_access_len!=0&&nnn%p1_10_access_len==0)
            fp_LOG<<(double)nnn/(double)access_len*100<<"% of the access.txt is analysed!"<<endl;
        for(i=0 ; i< l1_item.size();i++)
        {
            if(l1_item[i].typeID==tyid&&l1_item[i].fieldID==fidx)
            {
                l1_item[i].access_time++;
                break;
            }
        }
        if(i==l1_item.size())
        {
            Item tmp;
            tmp.access_time=1;
            tmp.fieldID=fidx;
            tmp.typeID=tyid;
            tmp.name=name;
            tmp.fsize=fsize;
            l1_item.push_back(tmp);
        }
        memset(name, '\0', sizeof(name));
        tys[typeid_to_idx[tyid]].array_idx.push_back(tyid_array_idx);
        /*
        for (i = 0; i < tys.size(); i++) {
			if (tys[i].typeID == tyid) {
				tys[i].array_idx.push_back(tyid_array_idx);
				break;
			}
		}
        */
    }
    fp_LOG<<"L1 Sets"<<endl;
    fp_LOG<<setw(10)<<"typeID"<<setw(10)<<"fieldID"<<setw(10)<<"name"<<setw(10)<<"fsize"<<setw(10)<<"access_time"<<endl;
    for(i=0;i<l1_item.size();i++)
    {
        fp_LOG<<setw(10)<<l1_item[i].typeID<<setw(10)<<l1_item[i].fieldID<<setw(10)<<l1_item[i].name<<setw(10)<<l1_item[i].fsize<<setw(10)<<l1_item[i].access_time<<endl;
    }
    
    for(i=0;i<l1_item.size();i++)
    {
        map<int,long>::iterator it = ac_times.find(l1_item[i].typeID);
        if(it!=ac_times.end())
        {
            it->second+=l1_item[i].access_time;
        }
        else
        {
            ac_times[l1_item[i].typeID] = l1_item[i].access_time;
        }
    }
    // for(map<int,long>::iterator it = ac_times.begin();it!=ac_times.end();it++)
    // {
    //     fp_LOG<<it->first<<" "<<it->second<<endl;
    // } 
    for(int t = 0;t<tys.size();t++ )
    {
        tys[t].ac_time.resize(tys[t].field_name.size(),0);
    }
    
    for(i=0;i<l1_item.size();i++)
    {
        tys[typeid_to_idx[l1_item[i].typeID]].ac_time[l1_item[i].fieldID] = l1_item[i].access_time;
        /*
        for(int t = 0;t<tys.size();t++ )
        {
            if(tys[t].typeID == l1_item[i].typeID)
            {
                tys[t].ac_time[l1_item[i].fieldID] = l1_item[i].access_time;
            }
        }
        */
    }
    vector<int>counts;
    vector<long>sums;
    for(i=0;i<l1_item.size();i++)
    {
        for(j=0;j<tIDs.size();j++)
        {
            if(tIDs[j]==l1_item[i].typeID)
            {
                break;
            }
        }
        if(j==tIDs.size())
        {
            tIDs.push_back(l1_item[i].typeID);
            counts.push_back(1);
            sums.push_back(l1_item[i].access_time);
        }
        else
        {
            counts[j]++;
            sums[j]+=l1_item[i].access_time;
        }
    }
    fp_LOG<<"L1 mini support thresholds"<<endl;
    fp_LOG<<setw(10)<<"typeID"<<setw(10)<<"thresholds"<<endl;
    for(j=0;j<tIDs.size();j++)
    {
        //fp_LOG<<"sumj= "<<sums[j]<<"countj= "<<counts[j]<<endl;
        thresholds.push_back(sums[j]/counts[j]/counts[j]);
        //thresholds.push_back(sums[j]/counts[j]);
        fp_LOG<<setw(10)<<tIDs[j]<<setw(10)<<thresholds[j]<<endl;
    }
    fp_LOG<<"Frequent L1 Sets"<<endl;
    fp_LOG<<setw(10)<<"l2midx"<<setw(10)<<"typeID"<<setw(10)<<"fieldID"<<setw(10)<<"name"<<setw(10)<<"size"<<setw(10)<<"access_time"<<endl;
    for(i=0;i<l1_item.size();i++)
    {
        for(j=0;j<tIDs.size();j++)
        {
            if(l1_item[i].typeID==tIDs[j])
                break;
        }
        if(l1_item[i].access_time>=thresholds[j])
        {
            int k=0;
            for(k= 0;k<l1_frequent_item.size();k++)
            {
                if(l1_item[i].typeID<l1_frequent_item[k].typeID||(l1_item[i].typeID==l1_frequent_item[k].typeID && l1_item[i].fieldID<l1_frequent_item[k].fieldID))
                    break;
            }
            l1_frequent_item.insert(l1_frequent_item.begin() + k , l1_item[i]);
        }
    }
    FILE *fp_l1_frequent_item;
    if ((fp_l1_frequent_item = fopen ("l1_frequent_items.txt", "a")) == NULL)  
    {
        printf ("fail reading l1_frequent_item.txt\n");
		return ;
		//exit (0);
    }
    ///默认每次热数据抓到的情况是一样的，实验验证🆗，均值化处理
    fprintf(fp_l1_frequent_item,"l2midx\ttypeID\tfieldID\tname\tsize\taccess_time\n");
    dec_l1_resv();
    for(i=0;i<l1_frequent_item.size();i++)
    {
        fp_LOG<<setw(10)<<i<<setw(10)<<l1_frequent_item[i].typeID<<setw(10)<<l1_frequent_item[i].fieldID<<setw(10)<<l1_frequent_item[i].name<<setw(10)<<l1_frequent_item[i].fsize<<setw(10)<<l1_frequent_item[i].access_time<<endl;
        fprintf(fp_l1_frequent_item,"%d\t%d\t%d\t%s\t%d\t%llu\n",i,l1_frequent_item[i].typeID,l1_frequent_item[i].fieldID,l1_frequent_item[i].name.data(),l1_frequent_item[i].fsize,l1_frequent_item[i].access_time);
    }
    fclose(fp_l1_frequent_item);

}
void AprioriAnalysis::get_L2()
{//slide window
	fp_LOG<<"---------->line: "<<__LINE__<<" "<<__FUNCTION__<<" is running."<<endl;
    fp_LOG<<"L2 Set analysis"<<endl;
    rewind(fp_access);
    int i,j;
    l2_matrix.resize(l1_frequent_item.size());
    for(i=0;i<l2_matrix.size();i++)
    {
        l2_matrix[i].resize(l1_frequent_item.size()); //初始化0
    }
    //vector<Trace_Item>trace_window;
    //queue<Trace_Item>trace_window; 
    Trace_Item *trace_window = new Trace_Item[trace_window_len];

   
    frequent_Item_time_serial *fits = new frequent_Item_time_serial[l1_frequent_item.size()];
    for(i=0;i<l2_matrix.size();i++)
    {
        fits[i].fid=l1_frequent_item[i].fieldID;
        fits[i].tid=l1_frequent_item[i].typeID;
        fits[i].name=l1_frequent_item[i].name;
        fits[i].sec.clear();
        fits[i].usec.clear();
        fits[i].rw.clear();
    }
    i=0;
    unsigned long long p1_10_access_len = access_len/10;
    unsigned long long nnn=0;
    while(i<trace_window_len&&(fscanf(fp_access,"%d %d %ld %d %d %llu %llu %d %d %d %s %d\n",&threadIndex,&traceIndex,&addr,&tyid,&fidx,&sec,&usec,&isWrite,&size,&fsize,name, &tyid_array_idx)!=EOF))
    {
        nnn++;
        if(p1_10_access_len!=0&&nnn%p1_10_access_len==0)
            fp_LOG<<(double)nnn/(double)access_len*100<<"% of the access.txt is analysed!"<<endl;
        Trace_Item tmp;
        tmp.threadIndex = threadIndex;
        tmp.addr = addr;
        tmp.tid=tyid;
        tmp.fid=fidx;
        tmp.sec=sec;
        tmp.usec=usec;
        tmp.is_write=isWrite;
        tmp.size=size;
        tmp.name=name;
        tmp.fsize=fsize;
        //trace_window.push_back(tmp);
        //trace_window.push(tmp);
        trace_window[i] = tmp ;
		i++;
        memset(name, '\0', sizeof(name));

        for(j=0;j<l1_frequent_item.size();j++)
        {
            if(tyid==fits[j].tid&&fidx==fits[j].fid)
            {
                fits[j].sec.push_back(sec);
                fits[j].usec.push_back(usec);
                fits[j].rw.push_back(isWrite);
                break;
            }
        }
    }
    memset(name, '\0', sizeof(name));
    while(fscanf(fp_access,"%d %d %ld %d %d %llu %llu %d %d %d %s %d\n",&threadIndex,&traceIndex, &addr,&tyid,&fidx,&sec,&usec,&isWrite,&size,&fsize,name, &tyid_array_idx)!=EOF)
    {
        nnn++;
        if(p1_10_access_len!=0&&nnn%p1_10_access_len==0)
            fp_LOG<<(double)nnn/(double)access_len*100<<"% of the access.txt is analysed!"<<endl;
        for(j=0;j<l1_frequent_item.size();j++)
        {
            if(tyid==fits[j].tid&&fidx==fits[j].fid)
            {
                fits[j].sec.push_back(sec);
                fits[j].usec.push_back(usec);
                fits[j].rw.push_back(isWrite);
                break;
            }
        }       
        Trace_Item tmp;
        tmp.threadIndex = threadIndex;
        tmp.addr = addr;
        tmp.tid=tyid;
        tmp.fid=fidx;
        tmp.sec=sec;
        tmp.usec=usec;
        tmp.is_write=isWrite;
        tmp.size=size;
        tmp.name=name;
        tmp.fsize=fsize;
        for(i=0;i<l1_frequent_item.size();i++)
        {
            if(trace_window[0].tid==l1_frequent_item[i].typeID&&trace_window[0].fid==l1_frequent_item[i].fieldID) break;
        }
        if(i!=l1_frequent_item.size())
        {
            //for(j=1;j<trace_window.size();j++)
            for(j=1;j<trace_window_len;j++)
            {
                long timediff = get_timediff(trace_window[j].sec,trace_window[j].usec,trace_window[0].sec,trace_window[0].usec);
                if(timediff<time_window_threshold_us)
                {
                    int k;
                    for(k=0;k<l1_frequent_item.size();k++)
                    {
                        if(trace_window[j].tid==l1_frequent_item[k].typeID&&trace_window[j].fid==l1_frequent_item[k].fieldID)
                            break;
                    }
                    if(k!=l1_frequent_item.size())
                    {
                        //l2_matrix[i][k]++;
                        if(trace_window[j].threadIndex == trace_window[0].threadIndex){
                            l2_matrix[i][k]++;
                        }
                        else{ 
                            if(trace_window[j].is_write == 1 || trace_window[0].is_write == 1)
                                l2_matrix[i][k]--;
                            else
                                l2_matrix[i][k]++;
                        }
                    }
                }
            }
        }
        for(i = 0 ;i<trace_window_len-1 ; i++)
			trace_window[i] = trace_window[i+1];
		trace_window[i] = tmp;
		//trace_window.erase(trace_window.begin());
        //trace_window.push_back(tmp);
    }
    //EOF之后的window的处理
	int trace_window_empty = trace_window_len ;
    while(trace_window_empty != 0)
    //while(!trace_window.empty())
    {
        for(i=0;i<l1_frequent_item.size();i++)
        {
            if(trace_window[0].tid==l1_frequent_item[i].typeID&&trace_window[0].fid==l1_frequent_item[i].fieldID) break;
        }
        if(i!=l1_frequent_item.size())
        {
            for(j=1;j<trace_window_empty ; j++)
            //for(j=1;j<trace_window.size();j++)
            {
                long timediff = get_timediff(trace_window[j].sec,trace_window[j].usec,trace_window[0].sec,trace_window[0].usec);
                if(timediff<time_window_threshold_us)
                {
                    int k;
                    for(k=0;k<l1_frequent_item.size();k++)
                    {
                        if(trace_window[j].tid==l1_frequent_item[k].typeID&&trace_window[j].fid==l1_frequent_item[k].fieldID)
                            break;
                    }
                    if(k!=l1_frequent_item.size())
                    {
                        //l2_matrix[i][k]++;
                        if(trace_window[j].threadIndex == trace_window[0].threadIndex){
                            l2_matrix[i][k]++;
                        }
                        else{ 
                            if(trace_window[j].is_write == 1 || trace_window[0].is_write == 1)
                                l2_matrix[i][k]--;
                            else
                                l2_matrix[i][k]++;
                        }
                    }
                }
            }
        }
       // trace_window.erase(trace_window.begin());
	   trace_window_empty--;
	   for(i=0 ;i<trace_window_empty;i++)
	   {
	   		trace_window[i] = trace_window[i+1];
	   }
    }
	delete []trace_window;
    for(i=0;i<l2_matrix.size();i++){
        for(j=i+1;j<l2_matrix.size();j++)
        {
            long sum = l2_matrix[i][j]+l2_matrix[j][i];
            l2_matrix[i][j]=l2_matrix[j][i]=sum;
            if(l2_matrix[i][j] < 0){
                l2_matrix[i][j]=l2_matrix[j][i]=0;
            }
        }
         if(l2_matrix[i][i] < 0){
            l2_matrix[i][i]=0;
        }
    }
    /*
    fp_LOG<<"L2 Set Support Matrix"<<endl<<setw(10)<<" ";
    for(i=0;i<l1_frequent_item.size();i++)
    {
        fp_LOG<<setw(10)<<l1_frequent_item[i].name;
    }
    fp_LOG<<endl;
    for(i=0;i<l2_matrix.size();i++)
    {   
        fp_LOG<<setw(10)<<l1_frequent_item[i].name;
        for(j=0;j<l2_matrix.size();j++)
        {
            //if(i==j) l2_matrix[i][j]=0;
            fp_LOG<<setw(10)<<l2_matrix[i][j];
        }
        fp_LOG<<endl;
    }
    */
    FILE *fp_support_matrix;
    if ((fp_support_matrix = fopen ("support_matrices.txt", "a")) == NULL)  
    {
        printf ("fail reading support_matrices.txt.txt\n");
        //return ;
		//exit (0);
    }
    fprintf(fp_support_matrix,"support_matrix\n");
    for(i=0;i<l2_matrix.size();i++)
    {   
        for(j=0;j<l2_matrix.size();j++)
        {
            fprintf(fp_support_matrix,"%ld\t",l2_matrix[i][j]);
        }
        fprintf(fp_support_matrix,"\n");
    }
    fclose(fp_support_matrix);
    mean_support_matrices();

 //置信度超过1，阈值为1，同一时刻访问才计数，例如同一时刻访问：a.b++：abab,则a:2,b:2,ab:2+1+1=4,4/2=2>1

if(IF_CAL_ADTW==1){
    vector<vector<int> >tyids;
    for(i=0;i<l1_frequent_item.size();i++)
    {
        for(j=0;j<tyids.size();j++)
            if(l1_frequent_item[i].typeID==tyids[j][0])
                break;
        if(j==tyids.size())
        {
            vector<int>tmp;
            tmp.push_back(l1_frequent_item[i].typeID);
            tmp.push_back(i);
            tyids.push_back(tmp);
        }
        else
        {   
            tyids[j].push_back(i);
        }
    }
    // for(i=0;i<tyids.size();i++)
    // {
    //     for(j=0;j<tyids[i].size();j++)
    //         cout<<tyids[i][j]<<" ";
    //     cout<<endl;
    // }
    vector<pair<int, int> >ac_time_descending_order;
    for(i = 0 ; i<tyids.size(); i++)
    {
        ac_time_descending_order.push_back(make_pair(tyids[i][0] , ac_times[tyids[i][0]]));
    }
	
    sort(ac_time_descending_order.begin(), ac_time_descending_order.end(), [](const pair<int,int>& u, const pair<int,int>& v) {
            return u.second > v.second;
        });
    // for(i = 0 ; i<ac_time_descending_order.size(); i++)
    // {
    //     cout<<ac_time_descending_order[i].first<<" "<<ac_time_descending_order[i].second<<endl;
    // }
    int top_k = TOP_K > tyids.size()?tyids.size():TOP_K;
	set<int>ty_set;
    for(i = 0 ;i < top_k; i++)
        ty_set.insert(ac_time_descending_order[i].first);
    // for(auto it = ty_set.begin() ; it != ty_set.end(); it++ )
    //     cout<<*it<<" ";
    //     cout<<endl;
      
    fp_LOG<<"Get adtw_matrix"<<endl;
    fp_LOG<<"min confidence degree = "<<MIN_CONFIDENCE<<endl;
    fp_LOG<<"computational presentation of interest"<<endl;
    
    vector<vector<long> >dtw_matrix(l1_frequent_item.size());
    lcs_matrix.resize(l1_frequent_item.size());
    vector<vector<double> >a_matrix(l1_frequent_item.size());
    adtw_matrix.resize(l1_frequent_item.size());
    for(i=0;i<l1_frequent_item.size();i++)
    {
        lcs_matrix[i].resize(l1_frequent_item.size());
        dtw_matrix[i].resize(l1_frequent_item.size());
        a_matrix[i].resize(l1_frequent_item.size());
        adtw_matrix[i].resize(l1_frequent_item.size());
    }
    for(i=0;i<l1_frequent_item.size();i++)
        for(j=i+1;j<l1_frequent_item.size();j++)
        {
            if(ty_set.count(l1_frequent_item[i].typeID) == 0 || ty_set.count(l1_frequent_item[j].typeID) == 0)
            {
                dtw_matrix[i][j]=dtw_matrix[j][i]=-2;
                a_matrix[i][j]=a_matrix[j][i]=-2.0;
                adtw_matrix[i][j]=adtw_matrix[j][i]=-2.0;
                lcs_matrix[i][j]=lcs_matrix[j][i]=-2;
                continue;
            }
		/*
            fp_LOG<<"***********************"<<endl;
            fp_LOG<<"i = "<<i<<", j ="<<j<<endl;
            fp_LOG<<"iname = "<<l1_frequent_item[i].name<<",";
            fp_LOG<<"jname = "<<l1_frequent_item[j].name<<endl;
          */  
            //long lcs= l2_matrix[i][j];

            int begin_and_end[4];
            int lcs = 0; 
            //lcs = get_lcs(fits[i],fits[j],begin_and_end);


            lcs_matrix[i][j]=lcs_matrix[j][i]=lcs;
            //fp_LOG<<"length of longest common subsequence = "<<lcs<<endl;

            long min = l1_frequent_item[i].access_time;
            if(min>l1_frequent_item[j].access_time)
                min =l1_frequent_item[j].access_time;
            double tv = (double)lcs/(double)min;
            //fp_LOG<<"degree of confidence = "<<tv<<endl;
            if(tv<MIN_CONFIDENCE)
            {
                dtw_matrix[i][j]=dtw_matrix[j][i]=-1;
                a_matrix[i][j]=a_matrix[j][i]=-1.0;
                adtw_matrix[i][j]=adtw_matrix[j][i]=-1.0;
            }
            else
            {
                long lenij[3];
                long dtw = -1;
                //dtw=new_cal_dtw_rws(fits[i],fits[j],lenij,begin_and_end);
                if(dtw==-1)
                {
                     dtw_matrix[i][j]=dtw_matrix[j][i]=-1;
                     a_matrix[i][j]=a_matrix[j][i]=-1;  //没采样了可以不考虑周期性数据?
                     adtw_matrix[i][j]=adtw_matrix[j][i]=-1.0;
                }
                else
                {
                    dtw_matrix[i][j]=dtw_matrix[j][i]=dtw;
                    //a_matrix[i][j]=a_matrix[j][i]=1.0-(double)(lcs)/(double)(lenij[0]+lenij[1]);  //没采样了可以不考虑周期性数据?
                    a_matrix[i][j]=a_matrix[j][i]=1.0-(double)(lcs*lcs)/(double)(lenij[0]*lenij[1]);  //没采样了可以不考虑周期性数据?
                    adtw_matrix[i][j]=adtw_matrix[j][i]=a_matrix[i][j]*(double)dtw_matrix[i][j]/(double)(lenij[2]);  //归一化
                }
            }
			int i_tid,j_tid;
			/*
            for(int ii = 0 ; ii < tys.size() ; ii++)
			{
				if(l1_frequent_item[i].typeID == tys[ii].typeID)
					i_tid = tys[ii].field_origin_typeid[l1_frequent_item[i].fieldID+1];
				if(l1_frequent_item[j].typeID == tys[ii].typeID)
					j_tid = tys[ii].field_origin_typeid[l1_frequent_item[j].fieldID+1];
			}
            */
            i_tid = tys[typeid_to_idx[l1_frequent_item[i].typeID]].field_origin_typeid[l1_frequent_item[i].fieldID+1];
            j_tid = tys[typeid_to_idx[l1_frequent_item[j].typeID]].field_origin_typeid[l1_frequent_item[j].fieldID+1];

            if(adtw_matrix[i][j] != -1.0)
            //if(adtw_matrix[i][j] != -1.0)
			{
				fp_LOG<<"***********************"<<endl;
				if(i_tid == l1_frequent_item[j].typeID || j_tid == l1_frequent_item[i].typeID)
				{
					//fp_LOG<<i_tid<<" "<<j_tid<<endl;
					//fp_LOG<<l1_frequent_item[j].typeID <<" " <<l1_frequent_item[i].typeID<<endl;
					fp_LOG<<"i is a member of j or j is a member of i , skip display the calculation."<<endl;
				}
				else{
					//fp_LOG<<i_tid<<" "<<j_tid<<endl;
            		fp_LOG<<"i = "<<i<<", j ="<<j<<endl;
            		fp_LOG<<"i-name = "<<l1_frequent_item[i].name<<" , ";
            		fp_LOG<<"j-name = "<<l1_frequent_item[j].name<<endl;
                
            		fp_LOG<<"i-length = "<<l1_frequent_item[i].access_time<<" , ";
            		fp_LOG<<"j-length = "<<l1_frequent_item[j].access_time<<endl;
				
					fp_LOG<<"length of longest common subsequence = "<<lcs<<endl;
                	fp_LOG<<"degree of confidence = "<<tv<<endl;
					fp_LOG<<"adtw = "<<adtw_matrix[i][j]<<endl;
				}
			}

        }
    /*
    fp_LOG<<"dtw_matrix:"<<endl<<setw(10)<<" ";
    for(i=0;i<l1_frequent_item.size();i++)
        fp_LOG<<setw(10)<<l1_frequent_item[i].name;
    fp_LOG<<endl;
    for(i=0;i<l1_frequent_item.size();i++)
    {   fp_LOG<<setw(10)<<l1_frequent_item[i].name;
        for(j=0;j<l1_frequent_item.size();j++)
            {
                fp_LOG<<setw(10)<<dtw_matrix[i][j];
            }
        fp_LOG<<endl;
    }
    fp_LOG<<"a_matrix:"<<endl<<setw(10)<<" ";
    for(i=0;i<l1_frequent_item.size();i++)
        fp_LOG<<setw(10)<<l1_frequent_item[i].name;
    fp_LOG<<endl;
    for(i=0;i<l1_frequent_item.size();i++)
    {   fp_LOG<<setw(10)<<l1_frequent_item[i].name;
        for(j=0;j<l1_frequent_item.size();j++)
            {
                fp_LOG<<setw(10)<<a_matrix[i][j];
            }
        fp_LOG<<endl;
    }

    fp_LOG<<"adtw_matrix:"<<endl<<setw(15)<<" ";
    for(i=0;i<l1_frequent_item.size();i++)
        fp_LOG<<setw(15)<<l1_frequent_item[i].name;
    fp_LOG<<endl;
    for(i=0;i<l1_frequent_item.size();i++)
    {   fp_LOG<<setw(15)<<l1_frequent_item[i].name;
        for(j=0;j<l1_frequent_item.size();j++)
            {
                fp_LOG<<setw(15)<<adtw_matrix[i][j];
            }
        fp_LOG<<endl;
    }
    */

    FILE *fp_adtw_matrix;
    if ((fp_adtw_matrix = fopen ("adtw_matrices.txt", "a")) == NULL)  
    {
        printf ("fail reading adtw_matrices.txt\n");
        //exit (0);
    }
   
    fprintf(fp_adtw_matrix,"adtw_matrix\n");
    for(i=0;i<l1_frequent_item.size();i++)
    {   
        for(j=0;j<l1_frequent_item.size();j++)
        {
            fprintf(fp_adtw_matrix,"%lf\t",adtw_matrix[i][j]);
        }
        fprintf(fp_adtw_matrix,"\n");
    }
    fclose(fp_adtw_matrix);
}  
    delete [] fits;
}

int findfmindex(vector<string> fmname, string s){
    int i=0;
    //printf("%d ",fmname.size());
    for(; i<fmname.size(); i++){
         if(fmname[i] == s)return i;
    }
    return -1;
}

void AprioriAnalysis::get_trace()
{
    char file_name[]="tracefile.txt";
    tracev = (trace_item*)malloc(sizeof(trace_item)*nglobal);
    char str[1024];
    char str2[1024];
    char *buf = str;
    int lastfmindex = 0;
    int nextfmindex = 0;
    FILE *f = fopen(file_name, "r");
    if(f == NULL){
        nglobal = 0;
        printf("error! cannot find file %s\n", file_name);
        exit(0);
    }
    else{
        printf("openfile %s ok\n", file_name);
    }
    int count = 0;
    int sid, coreid, ttinum, countnum, offset, opttype, optbytes, line, funcaddr, pid, jobid, cyclenum;
    char funcname[255];
    uint64_t cachelineid;
    printf("starting while\n");
    fgets(buf, 1024, f);
    while(fgets(buf, 1024, f) != NULL){
        char *p = str2;
        p = strtok(buf, ",");
        p = strtok(NULL, ",");
        p = strtok(NULL, ",");
        p = strtok(NULL, ",");
        p = strtok(NULL, ",");
        uint64_t addr;
        sscanf(p, "%llu", &addr);
        tracev[count].realaddr = addr;
        tracev[count].addr = addr / CACHESETS % M;
        tracev[count].setid = addr % CACHESETS;
        
        p = strtok(NULL, ",");
        int offset;
        sscanf(p, "%d", &offset);
        tracev[count].offset = offset;

        p = strtok(NULL, ",");
        int instype;
        sscanf(p, "%d", &instype);
        tracev[count].instype = instype;
        
        int size;
        p = strtok(NULL, ",");
        sscanf(p, "%d", &size);
        tracev[count].size = size;
        int tmp;
        p = strtok(NULL, ",");
        sscanf(p, "%d", &tmp);
        tracev[count].line = tmp;
        p = strtok(NULL, ",");
        sscanf(p, "%d", &tmp);
        tracev[count].funcaddr = tmp;
        p = strtok(NULL, ",");
        p = strtok(NULL, ",");
        p = strtok(NULL, ",");
        p = strtok(NULL, ",");

        int itmp = 0;
        string s;
        s.resize(1024);
        p = strtok(NULL, ",");
        //if(strlen(p) >= MAXFNAMELEN){
        //    p[MAXFNAMELEN-1]='\0';
        //    printf("Warning: Function name too long\n");
	//}
        sscanf(p, "%s", &(s)[0]);//cout << *s;
        if(!fmname.empty() && fmname[lastfmindex] == s){
            tracev[count].fnameindex = lastfmindex;
        }
        else if((itmp = findfmindex(fmname, s)) == -1){
            fmname.push_back(s);
            lastfmindex = nextfmindex;
            tracev[count].fnameindex = nextfmindex;
            printf("%d:%s\n",nextfmindex, fmname[tracev[count].fnameindex].c_str());
            nextfmindex++;
        }
        else{
            tracev[count].fnameindex = itmp;
            lastfmindex = itmp;
        }
        p = strtok(NULL, ",");
        //if(strlen(p) >= MAXMNAMELEN){
        //    p[MAXMNAMELEN-1]='\0';
        //    printf("Warning: Module name too long\n");
        //}
        sscanf(p, "%s", &tracev[count].mname);
        p = strtok(NULL, ",");
        sscanf(p, "%d", &tmp);
        tracev[count].insindex = tmp;
        p = strtok(NULL, ",");
        sscanf(p, "%d", &tmp);
        tracev[count].bbindex = tmp;
        count++;
        if(count > nglobal){
            //TODO
            cout<<"tracefile size error!"<<endl;
            exit(0);
        }
        buf = str;
    }
    fclose(f);
    nglobal = count;
    printf("count : %d\n", count);
}

void AprioriAnalysis::get_access()
{
    char file_name[]="access.txt";
    char str[255];
    char str2[255];
    char *buf = str;
    FILE *f = fopen(file_name, "r");
    if(f == NULL){
        access_num = 0;
        printf("error! cannot find file %s\n", file_name);
        exit(0);
    }
    else{
        printf("openfile %s ok\n", file_name);
    }
    int count = 0;
    char funcname[255];
    uint64_t cachelineid;
    printf("starting while\n");
    rewind(f);
    while(fscanf(f,"%d %d %ld %d %d %llu %llu %d %d %d %s %d\n",&threadIndex,&traceIndex,&addr,&tyid,&fidx,&sec,&usec,&isWrite,&size,&fsize,name,&tyid_array_idx)!=EOF){
        access_trace[count].threadIndex = threadIndex;
        access_trace[count].traceIndex = traceIndex;
        access_trace[count].addr = addr;
        access_trace[count].tid = tyid;
        access_trace[count].fid = fidx;
        access_trace[count].sec = sec;
        access_trace[count].usec = usec;
        access_trace[count].is_write = isWrite;
        access_trace[count].size = size;
        access_trace[count].fsize = fsize;
        access_trace[count].structindex = tyid_array_idx;
        count++;
    }
    fclose(f);
    access_num = count;
    printf("access count : %d\n", count);
}


void AprioriAnalysis::cal_fp_his(fp_his *fp_h, rt_his *rt_h){
    int i;
    int j;
    int t;
    double fp;
    for(j = 0; j < KN; j++){
        for(i = 0; i < MAXN; i++){
            int w = i + 1;
            fp = rt_h->m[j];
            for(t = w + 1; t < MAXN + 1; t++){
                fp -= (double)(t - w) * rt_h->item[j][t - 1].rtpercentage;
            }
            fp_h->item[j][i].length = w;
            fp_h->item[j][i].footprint = fp;
        }
        for(i = 1; i < MAXN; i++){
            fp_h->item[j][i].footprint += 1 - fp_h->item[j][0].footprint;
        }
        fp_h->item[j][0].footprint = 1;
        fp_h->m[j] = rt_h->m[j];
        fp_h->n[j] = rt_h->n[j];
    }
    return;
}

void AprioriAnalysis::cal_rt_his(rt_his *rt_h, trace_item *tracev, int n){
    int a[KN][M] = {{0}};
    int b[KN] = {0};
    int m[KN] = {0};
    int i;
    int j;
    for(j = 0; j < KN; j++){
        for(i = 0; i < MAXN; i++){
            rt_h->item[j][i].reusetime = i + 1;
            rt_h->item[j][i].rtnum = 0;
            rt_h->item[j][i].rtpercentage = 0;
        }
    }
    for(i = 0; i < n; i++){
        int rti;
        int addr = tracev[i].addr;
        int setid = tracev[i].setid;
        b[setid]++;
        if(a[setid][addr] == 0){
            rti = MAXN;
            m[setid]++;
        }
        else{
            rti = b[setid] - a[setid][addr];
        }
        a[setid][addr] = b[setid] + 1;
        if(rti >= MAXN){
            rti = MAXN - 1;
        }
        rt_h->item[setid][rti].rtnum++;
        tracev[i].reusetime = rti + 1;
    }
    for(j = 0; j < KN; j++){
        for(i = 0; i < MAXN; i++){
            double fn = b[j];
            if(fn == 0){
                rt_h->item[j][i].rtpercentage = 0;
                continue;
            }
            rt_h->item[j][i].rtpercentage = (double)rt_h->item[j][i].rtnum / fn;
        }
        rt_h->n[j] = b[j];
//        printf("b[i]:%d\n", b[j]);
        rt_h->m[j] = m[j];
    }
    return;
}
void AprioriAnalysis::cal_aet_his(aet_his *aet_h, rt_his *rt_h){
    int i;
    int j;
    for(j = 0; j < KN; j++){
        double cachesize = 0;
        double aetc = 0;
        double pt = 1;
        for(i = 0; i < MAXN; i++){
            pt -= rt_h->item[j][i].rtpercentage;
            cachesize += pt;
            aetc++;
            aet_h->item[j][i].cachesize = cachesize;
            aet_h->item[j][i].aetc = aetc;
        }
    }
    return;
}

double AprioriAnalysis::cal_mr_from_aet(aet_his *aet_h, rt_his *rt_h, int c){
    int i;
    int j = 0;
    double aetc;
    double ret = 0;
    for(j = 0; j < KN; j++){
        for(i = 0; i < MAXN; i++){
            if(c <= aet_h->item[j][i].cachesize){
                aetc = aet_h->item[j][i].aetc;
                break;
            }
        }
        if(i == MAXN){
            ret += (double)rt_h->m[j];
            continue;
        }
        for(i = 0; i < MAXN; i++){
            if(rt_h->item[j][i].reusetime >= aetc){
                ret += (double)rt_h->item[j][i].rtnum;
            }
        }
    }
    ret /= (double)nglobal;
    return ret;
}

double AprioriAnalysis::cal_mr_from_fp(fp_his *fp_h, int c){
    double ret = 0;
    int i;
    int j;
    int l;
    for(j = 0; j < KN; j++){
        l = MAXN;
        for(i = 0; i < MAXN; i++){
            if(fp_h->item[j][i].footprint >= (double)c){
                l = i;
                break;
            }
        }
        if(i == MAXN){
            ret += (double)fp_h->m[j];
            continue;
        }
        ret += (fp_h->item[j][l].footprint - fp_h->item[j][l-1].footprint) * fp_h->n[j];
    }
    ret /= (double)nglobal;
    return ret;
}
double AprioriAnalysis::cal_mr_from_rt(rt_his *rt_h, fp_his *fp_h, int c){
    double ret = 0;
    int i;
    int j;
    int l = MAXN;
    double cd = (double)c;
    double nd = 0;
    for(j = 0; j < KN; j++){
        l = MAXN;
        nd += (double)rt_h->n[j];
        for(i = 0; i < MAXN; i++){
            if(fp_h->item[j][i].footprint >= cd){
                l = i;
                break;
            }
        }
        if(l == MAXN){
            ret += (double)rt_h->m[j];
            continue;
        }
        for(i = l; i < MAXN; i++){
            ret += (double)rt_h->item[j][i].rtnum;
        }
    }
    ret /= nd;
    return ret;
}

int find(int a[], int c, int addr){
    int i;
    for(i = 0; i < c; i++){
        if(a[i] == addr){
            return i;
        }
    }
    return c;
}

int count1(uint64_t v){
    int ret = 0;
    while(v != 0){
        ret += v & 0x01;
        v >>= 1;
    }
    return ret;
}
void AprioriAnalysis::handlehit(int typeId)
{
    int i;
    for(i = 0; i < accessv.size(); i++){
        if(accessv[i].typeId == typeId){
            accessv[i].access_num++;
            return;
        }
    }
    access_item tmp;
    tmp.typeId = typeId;
    tmp.access_num = 1;
    tmp.miss_num = 0;
    accessv.push_back(tmp);
}
void AprioriAnalysis::handlemiss(int typeId)
{
    int i;
    for(i = 0; i < accessv.size(); i++){
        if(accessv[i].typeId == typeId){
            accessv[i].access_num++;
            accessv[i].miss_num++;
            return;
        }
    }
    access_item tmp;
    tmp.typeId = typeId;
    tmp.access_num = 1;
    tmp.miss_num = 1;
    accessv.push_back(tmp);
}

double AprioriAnalysis::cal_mr_of_str(){
    int i;
    for(i = 0; i < access_len; i++){
        int index = access_trace[i].traceIndex;
        int typeId = access_trace[i].tid;
        int field = access_trace[i].fid;
        if(tracev[index].ismiss == 1){
            handlemiss(typeId);
            tys[typeid_to_idx[typeId]].field_miss[field]++;
        }
        else{
            handlehit(typeId);
            tys[typeid_to_idx[typeId]].field_hit[field]++;
        }
    }
}

void AprioriAnalysis::print_access(){
    int i;
    fp_LOG<<"No.\taccess \t miss_num \t miss rate \t typeId \t typename"<<endl;
    for(i = 0; i < accessv.size(); i++){
        accessv[i].missrate = (double)accessv[i].miss_num / (double)accessv[i].access_num;
        fp_LOG<<"No."<<i+1<<":\t"<<accessv[i].access_num<<" \t "<<accessv[i].miss_num<<" \t "<<accessv[i].missrate<<" \t "<<accessv[i].typeId << " \t "<<tys[typeid_to_idx[accessv[i].typeId]].name<<endl;
    }
}

//假设cacheline的大小为64B
double AprioriAnalysis::cal_mr_of_lru(trace_item *tracev, int n, int c, double *cache_u_r, int *cache_load){
    double ret;
    double ur;
    if(c > 10 || c < 1){
        return 0.0;
    }
    int a[KN][12];
    uint64_t b[KN][12];
    int i;
    int j;
    for(i = 0; i < 12; i++){
        for(j = 0; j < KN; j++){
            a[j][i] = -1;
            b[j][i] = 0x00;
        }
    }
    int misscount = 0;
    int sizecount = 0;
    for(i = 0; i < n; i++){
        int setid = tracev[i].setid;
        int addr = tracev[i].addr;
        int size = tracev[i].size;
//        sizecount += size;
        int offset = tracev[i].offset;
        uint64_t value = (0xffffffffffffffff << (64 - size))>> offset;
//        int64_t value = 0xffffffffffffffff;
        int index = find(a[setid], c, addr);
//        cout<<i<<"  "<<value<<"  "<<size<<"  "<<offset<<"  "<<setid<<"  "<<addr<<endl;
        if(index == c){
            misscount++;
            tracev[i].ismiss = 1;
            sizecount += count1(b[setid][c - 1]);
        }
        else{
            tracev[i].ismiss = 0;
            tracev[i].hithis = index;
            value |= b[setid][index];
//            cout<<count1(b[setid][index]);
        }
        for(j = index; j > 0; j--){
            a[setid][j] = a[setid][j - 1];
            b[setid][j] = b[setid][j - 1];
        }
        a[setid][0] = addr;
        b[setid][0] = value;
        int mpi = 200;
        tracev[i].isprefmiss = 0;
        tracev[i].isprefsucc = 1;
        if(i < mpi)continue;
        int snum = 0;
        for(j = i; j > i - mpi; j--){
            int setid2 = tracev[j].setid;
            int addr2 = tracev[j].addr;
            if(setid2 == setid && addr2 != addr){
                snum++;
            }
            if(setid2 == setid && tracev[j].hithis == c - 1){
                tracev[i].isprefmiss++;
            }
        }
        if(snum >= c){
            tracev[i].isprefsucc = 0;
        }
    }
    for(i = 0; i < KN; i++){
        for(j = 0; j < c; j++){
            sizecount += count1(b[i][j]);
        }
    }
    double miss = (double)misscount;
    double nd = (double)n;
    ret = miss / nd;
    ur = (double)sizecount / (double)SizeC / miss;
    *cache_u_r = ur;
    *cache_load = misscount;
    return ret;
}

typedef struct{
    int all;
    int loadnew;
    int storenew;
    int loadold;
    int storeold;
    int missnum;
    int type;//1:load new, 2: load old, 3:store new, 4:store old
}aaaa;

void AprioriAnalysis::cal_isnew(trace_item* tracev, int n){
    int i;
    map<int, map<int, map<int, int>>> premap;
    map<int, int> newmap;
    map<int, int> oldmap;
    map<int, aaaa> funcaddrcountmap;
    int isnewnum = 0;
    int newload = 0;
    int newstore = 0;
    int oldload = 0;
    int oldstore = 0;
    for(i = 0; i < n; i++){
        int setid = tracev[i].setid;
        int addr = tracev[i].addr;
        int offset = tracev[i].offset;
        int funcaddr = tracev[i].funcaddr;
        int iswrite = tracev[i].instype;
        int ismiss = tracev[i].ismiss;
        if(funcaddrcountmap.count(funcaddr) == 0){
            aaaa tmp;
            tmp.all = 0;
            tmp.loadnew = 0;
            tmp.loadold = 0;
            tmp.storenew = 0;
            tmp.storeold = 0;
            tmp.missnum = 0;
            funcaddrcountmap[funcaddr] = tmp;
        }
        funcaddrcountmap[funcaddr].all++;
        funcaddrcountmap[funcaddr].missnum += ismiss;
        int flag = 0;
        if(premap.count(setid) != 0){
            if(premap[setid].count(addr) != 0){
                if(premap[setid][addr].count(offset) != 0){
                    tracev[i].isnew = 0;
                    if(oldmap.count(funcaddr) == 0){
                        oldmap[funcaddr] = 1;
                    }
                    else{
                        oldmap[funcaddr]++;
                    }
                    isnewnum++;
                    if(iswrite == 0){
                        newload++;
                        funcaddrcountmap[funcaddr].loadnew++;
                    }
                    else{
                        newstore++;
                        funcaddrcountmap[funcaddr].storenew++;
                    }
                    flag = 1;
                }
            }
        }
        if(flag == 0){
            if(iswrite == 0){
                oldload++;
                funcaddrcountmap[funcaddr].loadold++;
            }
            else{
                oldstore++;
                funcaddrcountmap[funcaddr].storeold++;
            }
            premap[setid][addr][offset] = 1;
            if(newmap.count(funcaddr) == 0){
                newmap[funcaddr] = 1;
            }
            else{
                newmap[funcaddr]++;
            }
        }
    }
    printf("isnew num : %d \n", isnewnum);
    printf("loadnew num : %d \n", newload);
    printf("storenew num : %d \n", newstore);
    printf("loadold num : %d \n", oldload);
    printf("storeold num : %d \n", oldstore);
    premap.clear();
    cout<<"loadnew  loadold  storenew  storeold  missnum  missrate"<<endl;

    for(auto it = funcaddrcountmap.begin(); it != funcaddrcountmap.end(); it++){
        if(it->second.all < 100)continue;
        cout<<it->first<<"  "<<it->second.all<<"  "<<it->second.loadnew<<"  "<<it->second.loadold<<"  "<<it->second.storenew<<"  "<<it->second.storeold<<"  "<<it->second.missnum<<"  "<<(float)(it->second.missnum) / (float)(it->second.all)<<endl;
//        it->second.type = caltype(it->second);
    }
}
void AprioriAnalysis::mr_sort()
{
    int i;
    sort(mrofindex.begin(), mrofindex.end(), [](const mr_index &a, const mr_index &b){
//                return (a.ave_mr_reduce / a.linecount) > (b.ave_mr_reduce / b.linecount);
                return (a.ave_mr_reduce) > (b.ave_mr_reduce);
            });
    fp_output<<endl<<endl<<"miss rate reduce sort:"<<endl<<"No.  \ttypeID\tave_mr:\tmiss reduce"<<endl;
    for(i = 0; i < mrofindex.size(); i++){
        if(mrofindex[i].ave_mr_reduce <= 0)break;
        fp_output<<i<<"   \t"<<mrofindex[i].typeId<<"   \t"<<mrofindex[i].ave_mr<<"   \t"<<mrofindex[i].ave_mr_reduce<<"   \t"<<tys[typeid_to_idx[mrofindex[i].typeId]].name<<endl;
//        //fp_output_secret<<i<<"   \t"<<mrofindex[i].typeId<<"   \t"<<mrofindex[i].ave_mr<<"   \t"<<mrofindex[i].ave_mr_reduce<<"   \t"<<tys[mrofindex[i].typeId].name<<endl;
    }
}

void AprioriAnalysis::bb_seq(trace_item* tracev, int n){
    int fnameindex = -1;
    char mname[20] = "begin";
    set<pair<int,int> >s;
    set<pair<int,int> >::iterator it;
    map<pair<int,string>,map<vector<int>,int>> ma;
    map<pair<int,string>,pair<int,int>> masummaxfreq;
    int i=0;
    ins_pos ipos;
    while(i<n){
        if(0 == strcmp(mname,"begin")){
            fnameindex = tracev[i].fnameindex;
            strcpy(mname,tracev[i].mname);
            s.insert(make_pair(tracev[i].bbindex,tracev[i].insindex));
            i++;
        }else if(0 == strcmp(mname,tracev[i].mname) && fnameindex == tracev[i].fnameindex){
            if(1 == s.count(make_pair(tracev[i].bbindex,tracev[i].insindex))){
                while(i<n && 0==strcmp(mname,tracev[i].mname) && fnameindex == tracev[i].fnameindex){
                    i++;
                }
            }else{
                s.insert(make_pair(tracev[i].bbindex,tracev[i].insindex));
                i++;
            }
        }else{
            it = s.begin();
            vector<int> vec;     //保存去重后的bb序列
            int sbegin = -1;
            while(it!=s.end()){
                if(sbegin!=it->first){
                    vec.push_back(it->first);
                    sbegin = it->first;
                }
                it++;
            }
            string str(mname);
            if(ma.find(make_pair(fnameindex,str))==ma.end()){
                map<vector<int>,int> tmpp;
                tmpp.insert(make_pair(vec,1));
                ma[make_pair(fnameindex,str)] = tmpp;
            }else{
                ma[make_pair(fnameindex,str)][vec]++;
            }
            s.clear();
            fnameindex = -1;
            strcpy(mname,"begin");
            i++;
        }
    }
    //todo：将最后一部分的s进行分析，加入ma
    map<pair<int,string>,map<vector<int>,int>>::iterator itma = ma.begin();
    while(itma!=ma.end()){
        map<vector<int>,int> curtmp = itma->second;
        map<vector<int>,int>::iterator itcurtmp = curtmp.begin();
        int sumfreq = 0;
        int maxfreq = 0;
        while(itcurtmp!=curtmp.end()){
            maxfreq = itcurtmp->second>maxfreq?itcurtmp->second:maxfreq;
            sumfreq+=itcurtmp->second;
            itcurtmp++;
        }
        masummaxfreq[make_pair(itma->first.first,itma->first.second)] = make_pair(sumfreq,maxfreq);
        itma++;
    }
    

    FILE* fp_finstseqinfo = fopen("finstseqinfo.txt", "w");
    //输出ma中文件名，函数index，对应出现次数最多的指令序列
    itma = ma.begin();
    while(itma!=ma.end()){
        pair<int,string> fnfindex = itma->first;
        map<vector<int>,int> bseqfreq = itma->second;
        map<vector<int>,int>::iterator itbseqfreq = bseqfreq.begin();
        int maxfreqq = masummaxfreq[fnfindex].second;
        while(itbseqfreq!=bseqfreq.end()){
            if(itbseqfreq->second==maxfreqq){
                fprintf(fp_finstseqinfo, "%s %s %d %d",fmname[fnfindex.first].c_str(),fnfindex.second.c_str(),maxfreqq,itbseqfreq->first.size());
                vector<int> bbseqs = itbseqfreq->first;
                for(int ibb=0;ibb<bbseqs.size();ibb++){
                    fprintf(fp_finstseqinfo," %d",bbseqs[ibb]);
                }
                fprintf(fp_finstseqinfo,"\n");
                break;
            }
            itbseqfreq++;
        }
        itma++;
    }
    fclose(fp_finstseqinfo);
}

bool missinfocmp(pair<ins_pos, pair<int, int>> a, pair<ins_pos, pair<int, int>> b){
    return a.second.second > b.second.second;
    //return a.second.first > b.second.first;
}

int main(){
    AprioriAnalysis AA;
    double junk1;
    int junk2;
    
    FILE* fp_missinfo = fopen("missinfo.txt", "w");
    
    map<ins_pos, pair<int, int>> indexinfo;
    map<ins_pos, pair<int, int>>::iterator indexinfo_it, indexinfo_end;
    //vector<int> misstime;
    //vector<int> accesstime;
    int nextindex = 0;
    ins_pos ipos;
    
    AA.get_trace();
    int c = K;
    AA.cal_mr_of_lru(AA.tracev, AA.nglobal, c, &junk1, &junk2);

    AA.cal_isnew(AA.tracev, AA.nglobal);

    
    //ofstream fout;
    //fout.open("mylog.txt", ios::out);
    //fout << "fmname:" << endl;
    //for(int i=0; i<AA.fmname.size(); i++){
    //    fout << i << ':' << AA.fmname[i].c_str() << '\n';
    //}
    //fout << "inspos:\n" << endl;

    printf("load ins only\n");
    for(int i=0; i<AA.nglobal; i++){
        if(AA.tracev[i].instype == 2) continue;
        //fprintf(fp,"%d,%d,%d,%d,%d,%d,%llu,%d,%s,%s,%d,%d,%d\n",AA.tracev[i].setid,AA.tracev[i].addr,AA.tracev[i].reusetime,
        //AA.tracev[i].size,AA.tracev[i].line,AA.tracev[i].funcaddr,(long long unsigned)AA.tracev[i].realaddr,AA.tracev[i].offset,
        //AA.tracev[i].mname,AA.fmname[AA.tracev[i].fnameindex].c_str(),AA.tracev[i].bbindex,AA.tracev[i].insindex,AA.tracev[i].ismiss);
        
        ipos.bbindex = AA.tracev[i].bbindex;
        ipos.insindex = AA.tracev[i].insindex;
        strcpy(ipos.mname, AA.tracev[i].mname);
        ipos.fnameindex = AA.tracev[i].fnameindex;
        //ipos.line = AA.tracev[i].line;
        if((indexinfo_it = indexinfo.find(ipos)) == indexinfo.end()){
            indexinfo.insert(pair <ins_pos, pair<int, int>> (ipos, pair<int, int>(1,0)));
            //printf("%s, %d:%s, %d, %d");
            //fout << ipos.mname << ", " << ipos.fnameindex << ':' << AA.fmname[ipos.fnameindex].c_str() << ", " << ipos.bbindex << ", " << ipos.insindex << "\n";
        }
        else indexinfo_it->second.first++;
//        if(AA.tracev[i].ismiss && AA.tracev[i].instype != 3){
        if(AA.tracev[i].ismiss && AA.tracev[i].instype != 3 && AA.tracev[i].isprefmiss == 0 && AA.tracev[i].isprefsucc == 1){
             indexinfo_it->second.second++;
             //fout << ipos.mname << ", " << ipos.fnameindex << ':' << AA.fmname[ipos.fnameindex].c_str() << ", " << ipos.bbindex << ", " << ipos.insindex << "\n";
        }
    }
    indexinfo_it = indexinfo.begin();
    indexinfo_end = indexinfo.end();
    while(indexinfo_it != indexinfo_end){
        if((float)indexinfo_it->second.second/indexinfo_it->second.first < T_MISSRATE){
            map<ins_pos, pair<int, int>>::iterator indexinfo_tmp = indexinfo_it++;
            indexinfo.erase(indexinfo_tmp);
        }
        else indexinfo_it++;
    }
    
    vector<pair<ins_pos, pair<int, int>>> vsort(indexinfo.begin(), indexinfo.end());
    printf("vector size:%d, starting sort\n", vsort.size());
    sort(vsort.begin(), vsort.end(), missinfocmp);
    printf("sort complete\n");

    vector<pair<ins_pos, pair<int, int>>>::iterator vsort_it = vsort.begin();
    vector<pair<ins_pos, pair<int, int>>>::iterator vsort_end = vsort.end();
    //fprintf(fp_missinfo, "modulename, funcname, bbindex, insindex, line, accesscnt, misscnt, missrate\n");
    
    while(vsort_it != vsort_end){
        fprintf(fp_missinfo, "%s %s %d %d %d %d %f\n", vsort_it->first.mname, AA.fmname[vsort_it->first.fnameindex].c_str(), vsort_it->first.bbindex, vsort_it->first.insindex, /*vsort_it->first.line,*/ vsort_it->second.first, vsort_it->second.second, (float)vsort_it->second.second/vsort_it->second.first);
        vsort_it++;
    }
    printf("main complete\n");




    printf("starting anaysis\n");
    AA.bb_seq(AA.tracev, AA.nglobal);
    /**
    //对于vsort去重
    vsort_it = vsort.begin();
    vsort_end = vsort.end();
    set<int> fnameindexset;
    while(vsort_it != vsort_end){
        if(fnameindexset.count(vsort_it->first.fnameindex)==1){
            vsort_it++;
            continue;
        }
        fnameindexset.insert(vsort_it->first.fnameindex);
        vsort_it++;
    }
    //对去重后的set中的所有fnameindex进行处理
    
    FILE* fp_finstseqinfo = fopen("finstseqinfo.txt", "w");

    for (auto iter = fnameindexset.begin(); iter != fnameindexset.end(); ++iter){
        map<vector<int>,int> seqmap;  //存放当前函数的指令序列
        //对于每个函数，遍历tracev，获取指令序列
        int funcnameindex = *iter;
        vector<int> instseq; //存放fnameindex的执行序列
        set<int> instseqset;
        int seqstart = 0;
        printf("AA.nglobal is %d ,\n",AA.nglobal);
        for(int tvi=0;tvi<AA.nglobal;tvi++){
            if(AA.tracev[tvi].fnameindex == funcnameindex){
                seqstart = seqstart+1;
                //判断当前序列是否包含循环
                if(instseqset.count(AA.tracev[tvi].insindex)==1){
                    if(tvi+1 == AA.nglobal || AA.tracev[tvi+1].fnameindex != funcnameindex){
                        seqstart = 0;
                        instseq.clear();
                        instseqset.clear();
                        continue;
                    }
                }else{
                    instseq.push_back(AA.tracev[tvi].insindex);
                    instseqset.insert(AA.tracev[tvi].insindex);
                }
            }else{
                if(instseq.size()!=0){
                    //输出当前指令序列
                    map<vector<int>,int>::iterator seqinstiter;
                    seqinstiter = seqmap.find(instseq);
                    if(seqinstiter==seqmap.end()){
                        seqmap.insert(make_pair(instseq,1));  //后续清空vector是否会影响此处pair                       
                    }else{
                        seqmap[instseq] = seqinstiter->second+1;
                    }
                    seqstart = 0;
                    instseq.clear();
                    instseqset.clear();
                }
            }
        }
        printf("first loop finished\n");
        //输出当前函数的指令序列(函数idx，当前指令序列出现次数，所有指令序列总次数,频率,bbindex流，)
        map<vector<int>,int>::const_iterator seqmapiter = seqmap.begin();
        map<vector<int>,int>::const_iterator seqmapend = seqmap.begin();
        int sumcount = 0;
        for(; seqmapiter != seqmapend; ++seqmapiter){
            sumcount += seqmapiter->second;
        }
        seqmapiter = seqmap.begin();
        for(; seqmapiter != seqmapend; ++ seqmapiter){
            fprintf(fp_finstseqinfo, "%d %d %d ", funcnameindex, seqmapiter->first,sumcount);
            //bbindex流
            for(int bbi=0;bbi<((seqmapiter->first).size());bbi++){
                fprintf(fp_finstseqinfo,"%d ",seqmapiter->first[bbi]);
            }
            fprintf(fp_finstseqinfo,"\n");
        }
    }
    fclose(fp_finstseqinfo);
    printf("anaysis finished\n");
    **/
}
