//-pref插件文件，输入原程序的中间代码和需要预取的指令序列，输出插入自动预取的中间代码。
//#include "llvm/IR/BasicBlock.h"
//#include "llvm/IR/Constants.h"
//#include "llvm/IR/DataLayout.h"
//#include "llvm/IR/DebugInfoMetadata.h"
//#include "llvm/IR/DebugLoc.h"
//#include "llvm/IR/Metadata.h"
//#include "llvm/IR/Function.h"
//#include "llvm/IR/IRBuilder.h"
//#include "llvm/IR/LLVMContext.h"
//#include "llvm/IR/Module.h"
//#include "llvm/IR/Type.h"
//#include "llvm/IR/Value.h"
//#include "llvm/Pass.h"
//
//#include "llvm/Support/Casting.h"
//#include "llvm/Support/raw_ostream.h"
//
//#include <cstdio>
//#include <cstdlib>
//#include <sstream>
//#include <iostream>
//#include <fstream>
//#include <cstring>
//#include <set>
//#include <string>
//#include <vector>
//#include <map>

#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/ValueMap.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Support/raw_ostream.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <iostream>
#include <map>
#include <llvm/Support/Debug.h>
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"

#include "llvm/Support/Casting.h"
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <cstring>
#include <set>
#include <string>
#include <vector>
#include "llvm/Transforms/Instrumentation/Pref.h"
#include "llvm/Support/CommandLine.h"

using namespace llvm;
using namespace std;

#define PREF_LATENCY 200

namespace llvm{
   void initializePrefPass(PassRegistry &);
}

enum INSTYPE
{
    OTHERS = 0,
    LOADINS,
    STOREINS,
    ALLOCAINS,
    CALLINS,
    RETURNINS
};

static cl::opt<std::string> MissInfoFileName(
	"missinfo-filename",
	cl::desc("missinfo filename full path"),cl::Hidden,
        cl::init("missinfo.txt"));

static cl::opt<std::string> FuncinstInfoFileName(
	"funcinstinfo-filename",
	cl::desc("funcinstinfo filename full path"),cl::Hidden,
        cl::init("funcinstinfo.txt"));

static cl::opt<std::string> TopInfoFileName(
	"topinfo-filename",
	cl::desc("funcinstinfo filename full path"),cl::Hidden,
        cl::init("topinfo.txt"));


typedef struct{
    char modulename[1024];
    char funcname[1024];
    int bbindex;
    int insindex;
    int accesscnt;
    int misscnt;
    Instruction* inst;
    int issuccess;
    int instaddnum;
    int typenum;
    int insttypes[10];//type1:add, type2:mul, type3:cast type4:pref type5:phi type6:gep type7:load
} missinfoitem;

typedef struct{
    char modulename[1024];
    char funcname[1024];
    int bbindex;
    int insindex;
    int funcinstnum;
    int hotinstnum;
    int basictype;
    int vectorsize;
    int isinsert;
    int sucnum;
    int failnum;
    int accesscnt;
    int misscnt;
    int v[16][3];
    char gname[16][1024];
} notloopinfoitem;

typedef struct{
    int issuccess;
    int instaddnum;
    int typenum;
    int insttypes[10];
} nlinfoitem;

namespace
{
    struct Pref : public ModulePass 
    {
        static char ID;
        Pref () : ModulePass (ID) {
            initializePrefPass(*PassRegistry::getPassRegistry());
        }
        bool runOnModule (Module& M) override;
//    struct Pref : public FunctionPass 
//    {
//        static char ID;
//        Pref () : FunctionPass (ID) {}
//        bool runOnFunction (Function& F) override;
        void getAnalysisUsage(AnalysisUsage& AU) const {
            AU.addRequired<LoopInfoWrapperPass>();
        }

private:
        LLVMContext* context;
        map<BasicBlock*, int> bb2index_m;
        map<int, BasicBlock*> index2bb_m;
        map<int, int> pre_index_m;
        set<BasicBlock*> bbset;
        vector<BasicBlock*> bbv;
        set<BasicBlock*> retbbset;
        vector<set<BasicBlock*>> loopset;
        vector<vector<BasicBlock*>> loopinfov;
        vector<int> looptype;
        set<Value*> heapvset;
        vector<missinfoitem> missinfo_v;
        vector<notloopinfoitem> notloop_v;
        vector<vector<nlinfoitem>> nl_vv;
        int funcinscount;
        int funchotinscount;
        int topstart;
        int topend;
        double minrate;
        int type;
        int all;
        int success;
        int notinaloop;
        int notinaloopsuccess;
        int inserttype[10] = {0};
        int abi;
        int cannotinsert;
        int numinsert;
        int typeinsert;
        int issuccess;
        int instaddnum;
        int typenum;
        int insttype;
        int accesscnt;
        int misscnt;
    
//        map<int, map<int, BasicBlock*>> index_bb_mm;
        vector<vector<BasicBlock*>> index_bb_vv;
        map<BasicBlock*, int> bb_index1_m;
        map<BasicBlock*, int> bb_index2_m;
        //void LoadHandler(Function* const F,BasicBlock::iterator& ins,BasicBlock::iterator& insert_ins);
        bool isValueable(float addcycle, vector<Instruction*> &preinsts, int loadnum, int missnum);
        void LoadHandler(Instruction* inst, int precount, int prenum, int vindex);
        void notloophandler(Module &M);
        Instruction* findpreinsts(vector<Instruction*> &preinsts, Instruction* inst, int loopindex, map<Value*, Value*> &premap);
        bool checkpreinsts(vector<Instruction*> &preinsts);
        int createinst(Instruction* iinst, Instruction* inst, map<Value*, Value*> &premap);
        void countloop(Loop* L, unsigned nest);
        void loopanalysis(Function &F);
        void loopanalysis2(Function &F);
        void readpreflist();
        void readtopfile();
        void printout();
        void printout2();
        bool isnotinaloop(unsigned int i);
        void printtype(Module &M);
        int findprecount(Instruction* inst);
        bool findfuncname(StringRef funcname);
        Instruction* findmissinst(missinfoitem tmp, Function* f);
        void bbindexinsert(BasicBlock* bb, unsigned int bbindex);
        Value* findloopphivalue(PHINode* phii, int loopindex);
        Instruction* findprestore(LoadInst* li);
        void dfs(BasicBlock* b,int curinstnum);
        void dfs(BasicBlock* b,int curinstnum,missinfoitem tmp);
        int valueindex(vector<Value*> &valuev, Value* v);
        void getfuncinscount(Module &M);
    };//endof struct myHello
}//end of namespase

Instruction* Pref::findprestore(LoadInst* li){
    BasicBlock* bb = li->getParent();
    for(auto it = bb->begin(); it != bb->end(); it++){
        if(&(*it) == li){
            break;
        }
        if(StoreInst* si = dyn_cast<StoreInst>(&(*it))){
            if(si->getPointerOperand() == li->getPointerOperand()){
                return &(*it);
            }
        }
    }
    return NULL;
}

Instruction* Pref::findpreinsts(vector<Instruction*> &preinsts, Instruction* inst, int loopindex, map<Value*, Value*> &premap){
    errs()<<"findpreinsts"<<*inst<<"\n";
    preinsts.push_back(inst);
    unsigned int it = 0;
    Instruction* ret = NULL;
    while(it < preinsts.size()){
        Instruction* tmpi = preinsts[it];
//        Instruction* ti;
        for(Use &U : tmpi -> operands()){
            Value* v = U.get();
            if(Instruction *ti = dyn_cast<Instruction>(v)){
                if(find(preinsts.begin(), preinsts.end(), ti) == preinsts.end() && ti->getParent() == inst->getParent()){
                    if(PHINode *phii = dyn_cast<PHINode>(ti)){
                        ret = ti;
                        continue;
                    }
                    preinsts.push_back(ti);
                    if(LoadInst* li = dyn_cast<LoadInst>(ti)){
                        Instruction* storei = findprestore(li);
                        if(storei != NULL){
                            StoreInst* si = dyn_cast<StoreInst>(storei);
                            preinsts.push_back(storei);
                            errs()<<"loadi"<<*li<<"\n";
                            errs()<<"storei"<<*storei<<"\n";
                            Value* v = si->getValueOperand();
                            premap[li] = v;
                            premap[si] = v;
                        }
                    }
                }
            }
        }
        it++;
    }
    if(ret == NULL){
        //todo
        errs()<<"ret == NULL\n";
        if(loopset.size() == 0){
            errs()<<"not in a loop\n";
//            Function* f = inst->getFunction();
//            int usenum = 0;
//            for(auto it = f->users().begin(); it != f->users().end(); it++){
//                errs()<<"  it:  "<<**it<<"\n";
//                if(Instruction* itmp = dyn_cast<Instruction>(*it)){
//                    DILocation* loc = itmp->getDebugLoc();
//                    if(loc){
//                        errs()<<"filename:"<<loc->getFilename()<<"\n";
//                        errs()<<"line:"<<loc->getLine()<<"\n";
//                    }
//                }
//                usenum++;
//            }
//            errs()<<"function use num:"<<usenum<<"\n";
            return ret;
        }
        if(loopindex == -1){
            errs()<<"not in a loop2\n";
            return ret;
        }
        for(auto it = loopset[loopindex].begin(); it != loopset[loopindex].end(); it++){
            BasicBlock* tmp = *it;
            Instruction *inst = tmp->getTerminator();
            int sucnum = inst->getNumSuccessors();
            if(sucnum <= 1){
                continue;
            }
            BasicBlock* b1 = inst->getSuccessor(0);
            BasicBlock* b2 = inst->getSuccessor(1);
            if((loopset[loopindex].count(b1) == 0 && loopset[loopindex].count(b2) == 1) || (loopset[loopindex].count(b1) == 1 && loopset[loopindex].count(b2) == 0)){
                Value* v = inst->getOperand(0);
                errs()<<"value v: "<<*v<<"\n";
                Instruction* vi = dyn_cast<Instruction>(v);
                if(vi == NULL){
                    errs()<<"can not find indexi1\n";
                    continue;
                }
                Value* v1 = vi->getOperand(0);
                errs()<<"value v1: "<<*v1<<"\n";
                Instruction* vi1 = dyn_cast<Instruction>(v1);
                if(vi1 == NULL){
                    errs()<<"can not find indexi2\n";
                    continue;
                }
                Value* v2 = vi1->getOperand(0);
                errs()<<"value v2: "<<*v2<<"\n";
                AllocaInst *li = dyn_cast<AllocaInst>(v2);
                if(li == NULL){
                    errs()<<"can not find indexi3\n";
                    Instruction * tmpi = dyn_cast<Instruction>(v2);
                    if(tmpi != NULL){
                        Value* v3 = tmpi->getOperand(0);
                        li = dyn_cast<AllocaInst>(v3);
                    }
                }
                if(li == NULL){
                    errs()<<"can not find index33\n";
                    continue;
                }

                if(li != NULL){
                    ret = (Instruction*)li;
                }
            }
        }
    }
//    errs()<<"can not find indexi\n";
    return ret;
}

//根据原指令和变量替换关系，插入新的指令
int Pref::createinst(Instruction* iinst, Instruction* inst, map<Value*, Value*> &premap){
    //初始化
    IRBuilder<> builder(inst);
    builder.SetInsertPoint(inst);
    if(premap.count(iinst) == 1){
        return 0;
    }
    int n = iinst->getNumOperands();
    vector<Value*> opv;
    //获取原指令所有的参数，并根据premap替换新的参数
    for(int i = 0; i < n; i++){
        Value* v = iinst->getOperand(i);
        if(premap.count(v) == 1){
            opv.push_back(premap[v]);
        }
        else{
            opv.push_back(v);
        }
    }
    //根据不同的指令，插入不同的指令
    ArrayRef<Value*> opa = ArrayRef<Value*>(opv);
    ArrayRef<Value*> opa2 = opa.drop_front();
    if(GetElementPtrInst* gepinst = dyn_cast<GetElementPtrInst>(iinst)){
        Value* v;
//        v = builder.CreateGEP(gepinst->getSourceElementType(), opv[0], opv[1]);
        v = builder.CreateGEP(gepinst->getSourceElementType(), opv[0], opa2);
        insttype = 6;
        errs()<<*v<<"\n";
        premap[iinst] = v;
    }
    else if(CastInst* cinst = dyn_cast<CastInst>(iinst)){
        Value* v;
        v = builder.CreateCast(cinst->getOpcode(), opv[0], cinst->getType());
        insttype = 3;
        errs()<<*v<<"\n";
        premap[iinst] = v;
    }
    else if(iinst->getOpcode() == Instruction::Add){
        Value* v = builder.CreateAdd(opv[0], opv[1]);
        insttype = 1;
        errs()<<*v<<"\n";
        premap[iinst] = v;
    }
    else if(iinst->getOpcode() == Instruction::Mul){
        Value* v = builder.CreateMul(opv[0], opv[1]);
        insttype = 2;
        errs()<<*v<<"\n";
        premap[iinst] = v;
    }
    else if(iinst->getOpcode() == Instruction::Sub){
        Value* v = builder.CreateSub(opv[0], opv[1]);
        insttype = 1;
        errs()<<*v<<"\n";
        premap[iinst] = v;
    }
    else if(iinst->getOpcode() == Instruction::Shl){
        Value* v = builder.CreateShl(opv[0], opv[1]);
        insttype = 7;
        errs()<<*v<<"\n";
        premap[iinst] = v;
    }
    else if(iinst->getOpcode() == Instruction::LShr){
        Value* v = builder.CreateLShr(opv[0], opv[1]);
        insttype = 7;
        errs()<<*v<<"\n";
        premap[iinst] = v;
    }
//    else if(iinst != inst){
//        if(LoadInst* loadinst = dyn_cast<LoadInst>(iinst)){
//            Value* v = builder.CreateLoad(loadinst->getType(), opv[0]);
//            errs()<<*v<<"\n";
//            premap[iinst] = v;
//        }
//        else{
//            return 0;
//        }
//    }
    //原指令为load指令时，插入prefetch指令
    else if(LoadInst* loadinst = dyn_cast<LoadInst>(iinst)){
        Value *actualAddr = builder.CreatePointerCast(opv[0],IntegerType::getInt8PtrTy (*context));
        insttype = 3;
        Function *func_prefetch = Intrinsic::getDeclaration(iinst->getModule(),Intrinsic::prefetch,actualAddr->getType());
        if(!func_prefetch) errs() << "function not found...\n";
        Value *Zero = ConstantInt::get(Type::getInt32Ty(*context),0);
        Value *Three = ConstantInt::get(Type::getInt32Ty(*context),3);
        Value *One = ConstantInt::get(Type::getInt32Ty(*context),1);
        errs()<<*actualAddr<<"\n";
        Value* v = builder.CreateCall(func_prefetch,{actualAddr,Zero,Three,One});
        errs()<<*v<<"\n";
        return 1;
    }
    return 0;
}

//bool Pref::checkpreinsts(vector<Instruction*> &preinsts){
//    for(unsigned int i = 0; i < preinsts.size(); i++){
//        Instruction* inst = preinsts[i];
//        if(LoadInst* LI = dyn_cast<LoadInst>(inst)){
//            Value *addr = LI -> getPointerOperand();
//            if(AllocaInst* AI = dyn_cast<AllocaInst>(addr)){
//                continue;
//            }
//            else{
//                return false;
//            }
//        }
//    }
//    return true;
//}

Value* Pref::findloopphivalue(PHINode* phii, int loopindex){
    int n = phii->getNumIncomingValues();
    if((int)loopset.size() <= loopindex)return NULL;
    for(int i = 0; i < n; i++){
        BasicBlock* tmpbb = phii->getIncomingBlock(i);
        if(loopset[loopindex].count(tmpbb) != 0){
            return phii->getIncomingValue(i);
        }
    }
    return NULL;
}

bool Pref::isValueable(float addcycle, vector<Instruction*> &preinsts, int loadnum, int missnum){
    float cycle = addcycle;
    float misscycle = 50;
    for(int i = 0; i < (int)preinsts.size(); i++){
        Instruction* iinst = preinsts[i];
        if(GetElementPtrInst* gepinst = dyn_cast<GetElementPtrInst>(iinst)){
            cycle += 0.25;
        }
        else if(CastInst* cinst = dyn_cast<CastInst>(iinst)){
            cycle += 0.25;
        }
        else if(iinst->getOpcode() == Instruction::Add){
            cycle += 0.25;
        }
        else if(iinst->getOpcode() == Instruction::Mul){
            cycle += 1;
        }
        else if(iinst->getOpcode() == Instruction::Sub){
            cycle += 0.25;
        }
        else if(iinst->getOpcode() == Instruction::Shl){
            cycle += 0.25;
        }
        else if(iinst->getOpcode() == Instruction::LShr){
            cycle += 0.25;
        }
        else if(LoadInst* loadinst = dyn_cast<LoadInst>(iinst)){
            cycle += 1.25;
            break;
        }
    }
//    errs()<<cycle<<"  "<<loadnum<<"   "<<missnum<<"\n";
    if(loadnum * cycle < misscycle * missnum)return false;
    return true;
}

void Pref::LoadHandler(Instruction* inst, int precount, int prenum, int vindex){
    int addflag = 0;
    //初始化统计信息
    if(vindex == -1){
        missinfoitem tmp;
        tmp.issuccess = 200;
        tmp.accesscnt = accesscnt;
        tmp.misscnt = misscnt;
        tmp.insttypes[0] = 0;
        tmp.insttypes[1] = 0;
        tmp.insttypes[2] = 0;
        tmp.insttypes[3] = 0;
        tmp.insttypes[4] = 0;
        tmp.insttypes[5] = 0;
        tmp.insttypes[6] = 0;
        tmp.insttypes[7] = 0;
        tmp.insttypes[8] = 0;
        tmp.insttypes[9] = 0;
        missinfo_v.push_back(tmp);
        vindex = missinfo_v.size() - 1;
        addflag = 1;
    }
    issuccess = 0;
    instaddnum = 0;
    numinsert = 0;
    typeinsert = 0;//0初始状态，1index递增，2指针递增，3a[b[i]]
    if(type == 0)
        all++;
    else
        notinaloop++;
    //初始化插入指令的builder
    //IRBuilder<> IRB(Instruction*); 在某个Instruction 前方连续插入语句
    IRBuilder<> builder(inst);
    builder.SetInsertPoint(inst);
    LoadInst* LI = dyn_cast<LoadInst>(inst);
    errs() << "inserting...\n";
    Value *addr = LI -> getPointerOperand();
    //初始化指令依赖序列preinsts和指令对应序列premap
    vector<Instruction*> preinsts;
    map<Value*, Value*> premap;
    int precountnow = precount * prenum;
    int loopindex = -1;
    //查找指令所在循环
    for(unsigned int i = 0; i < loopset.size(); i++){
        if(loopset[i].count(inst->getParent()) == 1){
            loopindex = i;
            break;
        }
    }
    if(loopindex == -1){
        errs()<<"not in a loop\n";
        typenum = 0;
        return;
    }
//    if(loopindex > 10)return;
    //查找指令的依赖序列和premap，并返回循环的indexi
    Instruction* indexi = findpreinsts(preinsts, inst, loopindex, premap);
    int flag = 0;
    int loadnum = 0;
    //无法获取indexi则返回
    if(indexi == NULL){
        errs()<<"can not insert1\n";
        cannotinsert++;
        typenum = 1;
        return;
    }
    else{
        //是否是a[b[i]]情形的场景判断
        errs()<<"indexi:  "<<*indexi<<"\n";
        for(unsigned int i = 0; i < preinsts.size(); i++){
            errs()<<i<<":  "<<*preinsts[i]<<"\n";
            if(LoadInst* LI = dyn_cast<LoadInst>(preinsts[i])){
                if(i != 0){
                    if(dyn_cast<AllocaInst>(LI->getPointerOperand()) == NULL && prenum == 1){
                        abi++;
                        if(typeinsert == 0)typeinsert = 3;
//                        typenum = 10;
//                        return;
//                        loadnum++;
//                        LoadHandler(preinsts[i], precount, loadnum + 1);
                    }
                }
            }
        }
        errs()<<"loadnum = "<<loadnum<<"\n";
    }
    //indexi是phi节点的情况
    if(PHINode* phii = dyn_cast<PHINode>(indexi)){
        errs()<<"if\n";
        //寻找循环的phi节点
        Value* v = findloopphivalue(phii, loopindex);
        if(v == NULL){
            errs()<<"can not insert 6\n";
            cannotinsert++;
            typenum = 6;
            return;
        }
        errs()<<"phi value: "<<*v<<"\n";
        if(CastInst* castinst = dyn_cast<CastInst>(v)){
            v = castinst->getOperand(0);
            errs()<<"phi value2: "<<*v<<"\n";
        }
        //递增关系为gep时：
        if(GetElementPtrInst* gepinst = dyn_cast<GetElementPtrInst>(v)){
            if(gepinst->getOperand(0) == indexi){
                errs()<<"ok\n";
                Value* stepv = gepinst->getOperand(1);
                //判断是否值得预取
                if(isValueable(1.5, preinsts, missinfo_v[vindex].accesscnt, missinfo_v[vindex].misscnt)){
                    cannotinsert++;
                    typenum = 12;
                    return;
                }
                //传入递增值变量
                builder.SetInsertPoint(indexi);
                PHINode* phinew = builder.CreatePHI(stepv->getType(), 2);
                numinsert++;
                missinfo_v[vindex].insttypes[5]++;
                Value* rsvdv = ConstantInt::get(Type::getInt64Ty(*context), 0);
                for(unsigned int i = 0; i < phii->getNumIncomingValues(); i++){
                    if(phii->getIncomingValue(i) == v){
                        phinew->addIncoming(stepv, phii->getIncomingBlock(i));
                    }
                    else{
                        phinew->addIncoming(rsvdv, phii->getIncomingBlock(i));
                    }
                }
                builder.SetInsertPoint(inst);
                //递增值乘K
                Value* Step = builder.CreateMul(phinew, ConstantInt::get(Type::getInt64Ty(*context), precountnow));
                missinfo_v[vindex].insttypes[2]++;
                numinsert++;
                //通过gep获取K次循环之后的indexi的值
                Value* addv = builder.CreateGEP(gepinst->getSourceElementType(), indexi, Step);
                missinfo_v[vindex].insttypes[6]++;
                numinsert++;
                //将计算得到的K次循环之后的indexi的值替换之前的indexi
                premap[(Value*)indexi] = addv;
                flag = 1;
                if(typeinsert == 0)typeinsert = 2;
            }
        }
        //递增方式为add的情况
        else if(Instruction* addinst = dyn_cast<Instruction>(v)){
            errs()<<"test1\n";
            if(addinst->getOpcode() == Instruction::Add){
                errs()<<"test2\n";
                if(addinst->getOperand(0) == indexi){
                    errs()<<"ok2\n";
                    //获取递增值
                    Value* stepv = addinst->getOperand(1);
                    builder.SetInsertPoint(indexi);
                    //判断是否值得预取
                if(isValueable(1.5, preinsts, missinfo_v[vindex].accesscnt, missinfo_v[vindex].misscnt)){
                    cannotinsert++;
                    typenum = 12;
                    return;
                }
                    //传入递增值
                    PHINode* phinew = builder.CreatePHI(stepv->getType(), 2);
                missinfo_v[vindex].insttypes[5]++;
                numinsert++;
                    Value* Step;
                    Value* rsvdv;
                    if(stepv->getType()->isIntegerTy() && stepv->getType()->getIntegerBitWidth() == 32){
                        Step = ConstantInt::get(Type::getInt32Ty(*context), precountnow);
                        rsvdv = ConstantInt::get(Type::getInt32Ty(*context), 0);
                    }
                    else if(stepv->getType()->isIntegerTy() && stepv->getType()->getIntegerBitWidth() == 64){
                        Step = ConstantInt::get(Type::getInt64Ty(*context), precountnow);
                        rsvdv = ConstantInt::get(Type::getInt64Ty(*context), 0);
                    }
                    //传入失败则返回
                    else{
                        phinew->eraseFromParent();
                        errs()<<"can not insert 4\n";
                        cannotinsert++;
                        typenum = 4;
                        return;
                    }
                    for(unsigned int i = 0; i < phii->getNumIncomingValues(); i++){
                        if(phii->getIncomingValue(i) == v){
                            phinew->addIncoming(stepv, phii->getIncomingBlock(i));
                        }
                        else{
                            phinew->addIncoming(rsvdv, phii->getIncomingBlock(i));
                        }
                    }
                    builder.SetInsertPoint(inst);

                    //递增值乘K
                    Value* Step2 = builder.CreateMul(phinew, Step);
                missinfo_v[vindex].insttypes[2]++;
                    numinsert++;
                    errs()<<"step2::"<<*Step2<<"\n";
                    //递增值加indexi得到K次循环之后的indexi
                    Value* addv = builder.CreateAdd(indexi, Step2);
                missinfo_v[vindex].insttypes[1]++;
                    numinsert++;
                    errs()<<"addv::"<<*addv<<"\n";
                    //将计算得到的新的值替换原来的indexi
                    premap[(Value*)indexi] = addv;
                    flag = 1;
                    if(typeinsert == 0)typeinsert = 1;
                }
            }
        }
    }
    //如果indexi是栈变量
    else if(AllocaInst* allocai = dyn_cast<AllocaInst>(indexi)){
        Instruction* loadi = NULL;
        //寻找preinsts中indexi的load指令
        for(auto it = preinsts.begin(); it != preinsts.end(); it++){
            LoadInst* tmpi = dyn_cast<LoadInst>(*it);
            if(tmpi == NULL)continue;
            if(tmpi->getPointerOperand() == indexi){
                loadi = tmpi;
                break;
            }
        }
        if(loadi == NULL){
            for(auto it = preinsts.begin(); it != preinsts.end(); it++){
                LoadInst* tmpi = dyn_cast<LoadInst>(*it);
                if(tmpi == NULL)continue;
                if(!dyn_cast<AllocaInst>(tmpi->getPointerOperand()))continue;
                indexi = (Instruction*)tmpi->getPointerOperand();
                loadi = tmpi;
                break;
            }
        }
        //找不到load则返回
        if(loadi == NULL){
            errs()<<"can not insert 2\n";
            cannotinsert++;
            typenum = 2;
            return;
        }
        errs()<<"loadi:"<<*loadi<<"\n";
        errs()<<"indexi:"<<*indexi<<"\n";
        //寻找循环中indexi的store指令
        Instruction* storei = NULL;
        for(auto it = indexi->users().begin(); it != indexi->users().end(); it++){
            StoreInst* tmpi = dyn_cast<StoreInst>(*it);
            if(tmpi == NULL)continue;
            if(loopset[loopindex].count(tmpi->getParent())){
                storei = tmpi;
                break;
            }
        }

        //找不到store则返回
        if(loadi == NULL || storei == NULL){
            errs()<<"can not insert 3\n";
            cannotinsert++;
            typenum = 3;
            return;
        }
        errs()<<"storei:"<<*storei<<"\n";
        int step = precountnow;
        //对indexi进行判断
        Instruction* stepinst = (Instruction*)(storei->getOperand(0));
        //indexi递增为add的情况
        if(stepinst->getOpcode() == Instruction::Add){
            errs()<<"if\n";
            if(ConstantInt* ci = dyn_cast<ConstantInt>(stepinst->getOperand(1))){
                errs()<<"if2\n";
                if(LoadInst* tmpli = dyn_cast<LoadInst>(stepinst->getOperand(0))){
                    errs()<<"if3\n";
                    if(tmpli->getPointerOperand() == indexi){
                        errs()<<"if4\n";
                        //获取indexi的递增
                        step *= ci->getSExtValue();
                        Value* Step;
                        if(loadi->getType()->isIntegerTy() && loadi->getType()->getIntegerBitWidth() == 32)
                            Step = ConstantInt::get(Type::getInt32Ty(*context), step);
                        else if(loadi->getType()->isIntegerTy() && loadi->getType()->getIntegerBitWidth() == 64)
                            Step = ConstantInt::get(Type::getInt64Ty(*context), step);
                        else{
                            errs()<<"can not insert 4\n";
                            cannotinsert++;
                            typenum = 4;
                            return;
                        }
                        Value* loadnew;
                        LoadInst* LI = dyn_cast<LoadInst>(loadi);
                        //判断预取是否有价值
                if(isValueable(1.25, preinsts, missinfo_v[vindex].accesscnt, missinfo_v[vindex].misscnt)){
                    cannotinsert++;
                    typenum = 12;
                    return;
                }
                        //插入indexi的load
                        loadnew = builder.CreateLoad(LI->getType(), LI->getPointerOperand());
                        errs()<<*loadnew<<"\n";
                        //计算K次循环之后indexi的值
                        Value* addv = builder.CreateAdd(loadnew, Step);
                missinfo_v[vindex].insttypes[1]++;
                        numinsert++;
                        errs()<<*addv<<"\n";
                        //将计算得到的indexi替换原来的indexi
                        premap[(Value*)loadi] = addv;
                        flag = 1;
                        if(typeinsert == 0)typeinsert = 1;
                    }
                }
            }
        }
        //递增为gep的情况
        else if(GetElementPtrInst *gepinst = dyn_cast<GetElementPtrInst>(stepinst)){
            errs()<<"elseif\n";
            //递增值为常数
            if(ConstantInt* ci = dyn_cast<ConstantInt>(stepinst->getOperand(1))){
                if(LoadInst* tmpli = dyn_cast<LoadInst>(stepinst->getOperand(0))){
                    if(tmpli->getPointerOperand() == indexi){
                        //获取递增值
                        step *= ci->getSExtValue();
                        Value* Step;
                        Step = ConstantInt::get(Type::getInt64Ty(*context), step);
                        Value* loadnew;
                        LoadInst* LI = dyn_cast<LoadInst>(loadi);
                if(isValueable(1.25, preinsts, missinfo_v[vindex].accesscnt, missinfo_v[vindex].misscnt)){
                    cannotinsert++;
                    typenum = 12;
                    return;
                }
                        //获取indexi
                        loadnew = builder.CreateLoad(LI->getType(), LI->getPointerOperand());
                        errs()<<*loadnew<<"\n";
                        //计算idnexiK次循环之后的值
                        Value* addv = builder.CreateGEP(gepinst->getSourceElementType(), loadnew, Step);
                missinfo_v[vindex].insttypes[6]++;
                        numinsert++;
                        errs()<<*addv<<"\n";
                        //使用计算得到的indexi替换原来的indexi
                        premap[(Value*)loadi] = addv;
                        flag = 1;
                        if(typeinsert == 0)typeinsert = 2;

                    }
                }
            }
            //递增值为变量
            else if(LoadInst* staticli = dyn_cast<LoadInst>(stepinst->getOperand(1))){
                errs()<<"else if2\n";
                if(LoadInst* tmpli = dyn_cast<LoadInst>(stepinst->getOperand(0))){
                    errs()<<"else if3\n";
                    if(tmpli->getPointerOperand() == indexi){
                        errs()<<"else if4\n";
                if(isValueable(3.25, preinsts, missinfo_v[vindex].accesscnt, missinfo_v[vindex].misscnt)){
                    cannotinsert++;
                    typenum = 12;
                    return;
                }
                        //获取递增值
                        Value* loadstatic = builder.CreateLoad(staticli->getType(), staticli->getPointerOperand());
                missinfo_v[vindex].insttypes[7]++;
                        numinsert++;
                        errs()<<*loadstatic<<"\n";
                        //获取K次递增的总量
                        Value* Step = builder.CreateMul(loadstatic, ConstantInt::get(Type::getInt64Ty(*context), step));
                missinfo_v[vindex].insttypes[2]++;
                        numinsert++;
                        //获取indexi
                        errs()<<*Step<<"\n";
                        Value* loadnew = builder.CreateLoad(tmpli->getType(), tmpli->getPointerOperand());
                missinfo_v[vindex].insttypes[7]++;
                        numinsert++;
                        errs()<<*loadnew<<"\n";
                        //计算K次循环之后的值
                        Value* addv = builder.CreateGEP(gepinst->getSourceElementType(), loadnew, Step);
                missinfo_v[vindex].insttypes[2]++;
                        numinsert++;
                        errs()<<*addv<<"\n";
                        //将计算得到的indexi替换原来的indexi
                        premap[(Value*)loadi] = addv;
                        flag = 1;
                        if(typeinsert == 0)typeinsert = 2;
                    }
                }
            }
        }
    }
    //不属于其中任何场景则返回
    if(flag == 0){
        errs()<<"can not insert 5\n";
        cannotinsert++;
        typenum = 5;
        return;
    }


    //根据preinsts序列和新的indexi，计算需要预取的地址
    for(int it = preinsts.size() - 1; it >= 0; it--){
        Instruction* iinst = preinsts[it];
        if(premap.count(iinst) > 0){
            Value* v = premap[iinst];
            if(premap.count(v) > 0){
                premap[iinst] = premap[v];
            }
            continue;
        }
//        errs()<<*iinst<<"\n";

        numinsert++;
        //根据原指令和premap替换关系，插入新的指令
        int tmp = createinst(iinst, inst, premap);
        missinfo_v[vindex].insttypes[insttype]++;
        if(tmp){
            missinfo_v[vindex].insttypes[4]++;
            numinsert++;
            break;
        }

    }


    //输出预取结果
    //createIRInsertPrefetch(inst)
    errs() << "insert prefetch success...\n";
    if(type == 0)
        success++;
    else
        notinaloopsuccess++;
    errs()<<*inst<<"\n";
    errs()<<"numinsert:"<<numinsert<<"\n";
    issuccess = 1;
    instaddnum = numinsert;
    typenum = typeinsert;

    inserttype[typeinsert]++;
    inserttype[0] += numinsert;
    DILocation* loc = inst->getDebugLoc();
    if(loc){
	    errs()<<"filename:"<<loc->getFilename()<<"\n";
	    errs()<<"line:"<<loc->getLine()<<"\n";
	    errs()<<"name: "<<inst->getName()<<"\n";
    }
}
//void Pref::bbindexinsert(BasicBlock* bb, unsigned int bbindex){
////    errs()<<bb->getName()<<"    "<<bbindex<<"\n";
//    bb2index_m[bb] = bbv.size();
//    index2bb_m[bbv.size()] = bb;
//    bbset.insert(bb);
//    bbv.push_back(bb);
//    for(unsigned int i = bbv.size() - 1; i > bbindex; i--){
//        BasicBlock* bbtmp = index2bb_m[i - 1];
////        errs()<<bbtmp->getName()<<"===="<<i<<"\n";
//        bb2index_m[bbtmp] = i;
//        index2bb_m[i] = bbtmp;
//        bbv[i] = bbtmp;
//    }
//    bb2index_m[bb] = bbindex;
//    index2bb_m[bbindex] = bb;
//    bbv[bbindex] = bb;
//}

//void Pref::loopanalysis2(Function &F){
//    index_bb_vv.clear();
//    bb_index1_m.clear();
//    bb_index2_m.clear();
//
//    bbset.clear();
//
//    if(F.getBasicBlockList().empty())return;
//    BasicBlock* bbnow = &F.getEntryBlock();
//
//    vector<BasicBlock*> tmpv;
//    tmpv.push_back(bbnow);
//    index_bb_vv.push_back(tmpv);
//    bb_index1_m[bbnow] = 0;
//    bb_index2_m[bbnow] = 0;
//    bbset.insert(bbnow);
//
//    int index1 = 0;
//    errs()<<"fsize: "<<F.size()<<"\n";
//    while(1){
//        errs()<<bbset.size()<<" "<<F.size()<<"\n";
//        if(bbset.size() == F.size()){
//            break;
//        }
//        if(index_bb_vv[index1].size() == 0){
//            break;
//        }
//        tmpv.clear();
//        for(unsigned int i = 0; i < index_bb_vv[index1].size(); i++){
//            bbnow = index_bb_vv[index1][i];
//            Instruction *inst = bbnow->getTerminator();
//            if(inst == NULL){
//                continue;
//            }
//            int sucnum = inst->getNumSuccessors();
//            if(sucnum == 0){
//                continue;
//            }
//            for(int j = 0; j < sucnum; j++){
//                BasicBlock* tmpbbnow = inst->getSuccessor(j);
//                if(bbset.count(tmpbbnow) == 0){
//                    tmpv.push_back(tmpbbnow);
//                    bb_index1_m[tmpbbnow] = index1 + 1;
//                    bb_index2_m[tmpbbnow] = tmpv.size() - 1;
//                    bbset.insert(tmpbbnow);
//                }
//            }
//        }
//        index_bb_vv.push_back(tmpv);
//        index1++;
//    }
//    for(unsigned int i = 0; i < index_bb_vv.size(); i++){
//        for(unsigned int j = 0; j < index_bb_vv[i].size(); j++){
//            BasicBlock* tmpbb = index_bb_vv[i][j];
//            errs()<<tmpbb->getName()<<" "<<bb_index1_m[tmpbb]<<" "<<bb_index2_m[tmpbb]<<"   ";
//        }
//        errs()<<"\n";
//    }
//    bbset.clear();
//    bbv.clear();
//    bbnow = &F.getEntryBlock();
//    bbv.push_back(bbnow);
//    while(1){
//        if(bbset.size() == F.size()){
//            break;
//        }
//        int flag = 0;
//        bbnow = bbv[bbv.size() - 1];
//        errs()<<"bbnow name :"<<bbnow->getName()<<"\n";
//        Instruction *inst = bbnow->getTerminator();
//        if(inst == NULL){
//            bbv.pop_back();
//            errs()<<" action: pop\n";
//            bbset.insert(bbnow);
//            continue;
//        }
//        int sucnum = inst->getNumSuccessors();
//        if(sucnum == 0){
//            bbv.pop_back();
//            errs()<<" action: pop\n";
//            bbset.insert(bbnow);
//            continue;
//        }
//        int j;
//        for(j = 0; j < sucnum; j++){
//            BasicBlock* tmpbbnow = inst->getSuccessor(j);
//            if(bbset.count(tmpbbnow) != 0){
//                continue;
//            }
//            if(find(bbv.begin(), bbv.end(), tmpbbnow) != bbv.end()){
//                vector<BasicBlock*> loopinfoitem;
//                for(auto it = find(bbv.begin(), bbv.end(), tmpbbnow); it != bbv.end(); it++){
//                    loopinfoitem.push_back(*it);
//                }
//                loopinfov.push_back(loopinfoitem);
//                continue;
//            }
//            bbv.push_back(tmpbbnow);
//            errs()<<" action: push  "<<tmpbbnow->getName()<<"\n";
//            flag = 1;
//            break;
//        }
//        if(flag == 0){
//            bbv.pop_back();
//            errs()<<" action: pop\n";
//            bbset.insert(bbnow);
//            continue;
//        }
//    }
//    for(unsigned int i = 0; i < loopinfov.size(); i++){
//        for(unsigned int j = 0; j < loopinfov[i].size(); j++){
//            BasicBlock* tmpbb = loopinfov[i][j];
//            errs()<<tmpbb->getName()<<" -> ";
//        }
//        errs()<<"\n";
//    }
//}

void Pref::countloop(Loop* L, unsigned nest){
    set<BasicBlock*> tmpbbset;
    for(auto it = L->block_begin();it != L->block_end(); it++){
        BasicBlock* bb = *it;
        tmpbbset.insert(bb);
    }
    vector<Loop*> subLoops = L->getSubLoops();
    for(auto it = subLoops.begin(); it != subLoops.end(); it++) countloop(*it, nest+1);
    loopset.push_back(tmpbbset);
}

void Pref::loopanalysis(Function &F){
    LoopInfo* LI = &getAnalysis<LoopInfoWrapperPass>(F).getLoopInfo();
    for(Loop* L : *LI){
        countloop(L, 0);
    }
}

void Pref::readpreflist(){
    FILE* fp;
    if((fp = fopen(MissInfoFileName.c_str(), "r")) == NULL){
        errs()<<"can not read missinfo.txt\n";
        return;
    }
    char modulename[1024];
    char funcname[1024];
    int bbindex;
    int insindex;
    float missrate;

//    while(fscanf(fp, "%s,%s,%d,%d,%d,%d,%f\n", modulename, funcname, &bbindex, &insindex, &accesscnt, &misscnt, &missrate) != EOF){
    while(fscanf(fp, "%s %s %d %d %d %d %f\n", modulename, funcname, &bbindex, &insindex, &accesscnt, &misscnt, &missrate) != EOF){
        missinfoitem tmp;
        for(unsigned int i = 0; i < 1024; i++){
            tmp.modulename[i] = modulename[i];
            tmp.funcname[i] = funcname[i];
        }
        tmp.bbindex = bbindex;
        tmp.insindex = insindex;
        tmp.accesscnt = accesscnt;
        tmp.misscnt = misscnt;
        tmp.inst = NULL;
        tmp.insttypes[0] = 0;
        tmp.insttypes[1] = 0;
        tmp.insttypes[2] = 0;
        tmp.insttypes[3] = 0;
        tmp.insttypes[4] = 0;
        tmp.insttypes[5] = 0;
        tmp.insttypes[6] = 0;
        tmp.insttypes[7] = 0;
        tmp.insttypes[8] = 0;
        tmp.insttypes[9] = 0;
        missinfo_v.push_back(tmp);
    }

    fclose(fp);
}

//bool Pref::findfuncname(StringRef funcname){
//    for(unsigned int i = 0; i < missinfo_v.size(); i++){
//        missinfoitem tmp = missinfo_v[i];
//        errs()<<tmp.funcname<<"   "<<funcname<<"\n";
//        if(tmp.funcname == funcname)return true;
//    }
//    return false;
//}

Instruction* Pref::findmissinst(missinfoitem tmp, Function* f){
    BasicBlock* b = NULL;
    Instruction* ret = NULL;
    if(f == NULL)return NULL;

    int bbindex = 0;
    int insindex = 0;
//    errs()<<f->getBasicBlockList().size()<<"\n";
    if(bbindex >= (int)f->getBasicBlockList().size())return NULL;
    for(auto it = f->begin(); it != f->end(); it++){
        if(bbindex == tmp.bbindex){
            b = &(*it);
        }
        bbindex++;
    }
    if(b == NULL)return NULL;
    if(insindex >= (int)b->getInstList().size())return NULL;
    for(auto it = b->begin(); it != b->end(); it++){
        if(insindex == tmp.insindex){
            ret = &(*it);
        }
        insindex++;
    }
//    errs()<<*ret<<"\n";
    if(ret == NULL)return NULL;
    if(dyn_cast<LoadInst>(ret))return ret;
    return NULL;
}

int Pref::findprecount(Instruction* inst){
    int loopindex = 0;
    for(unsigned int i = 0; i < loopset.size(); i++){
        if(loopset[i].count(inst->getParent()) == 1){
            loopindex = i;
            break;
        }
    }
    if(loopindex == (int)loopset.size()){
        return PREF_LATENCY;
    }
    int instcount = 0;
    for(auto it = loopset[loopindex].begin(); it != loopset[loopindex].end(); it++){
        instcount += (*it)->size();
    }
    return PREF_LATENCY/instcount;
}

void Pref::dfs(BasicBlock* b,int curinstnum){
    curinstnum += b->getInstList().size();
    Instruction *inst = b->getTerminator();
    int sucnum = inst->getNumSuccessors();
    if(sucnum==0){
        errs()<<"has no successor\n";
        if(curinstnum<funcinscount){
            funcinscount = curinstnum;
            errs()<<"funcintcount is:"<<funcinscount<<"\n";
            return;
        }
    }
    int i;
    for(i=0;i<sucnum;i++){
        BasicBlock* suc = inst->getSuccessor(i);
        dfs(suc,curinstnum);
    }
    return;
}
void Pref::dfs(BasicBlock* b,int curinstnum,missinfoitem tmp){
    //检查当前bb是否包含missinst
    int insindex = 0;
    if(insindex < (int)b->getInstList().size()){
        for(auto it = b->begin(); it != b->end(); it++){
            if(insindex == tmp.insindex){
                errs()<<"find hotinst ok\n";
                curinstnum += insindex;
                if(curinstnum < funchotinscount) funchotinscount = curinstnum;
                errs()<<"funchotinscount is:"<<funchotinscount<<"\n";
                return;
            }
            insindex++;
        } 
    }
    curinstnum += b->getInstList().size();
    Instruction *inst = b->getTerminator();
    int sucnum = inst->getNumSuccessors();
    if(sucnum==0){
        return;
    }
    int i;
    for(i=0;i<sucnum;i++){
        BasicBlock* suc = inst->getSuccessor(i);
        dfs(suc,curinstnum,tmp);
    }
    return;
}

//void Pref::getfuncinscount(Module &M){
//    FILE* fp_funcinstinfo = fopen(FuncinstInfoFileName.c_str(), "a");
//    if(fp_funcinstinfo == NULL){
//        errs()<<"can not write funcinstinfo.txt\n";
//        return;
//    }
//
//    vector<int> funcinscounts;
//    vector<int> funchotinscounts;
//    for(unsigned int i = 0;i < missinfo_v.size(); i++){
//        funcinscount = 666666666;
//        funchotinscount = 666666666;
//        missinfoitem tmp = missinfo_v[i];
//        Instruction *missinst = tmp.inst;
//        if(missinst == NULL) {
//            funcinscounts.push_back(funcinscount);
//            funchotinscounts.push_back(funchotinscount);
////            errs()<<"inst null\n";
//            continue;
//        }
//        Function* F = missinst->getFunction();
//        if(F == NULL){
//            funcinscounts.push_back(funcinscount);
//            funchotinscounts.push_back(funchotinscount);
////            errs()<<"function null\n";
//            continue;
//        }
//        errs()<<"find missinst and function ok\n";
//
//        
//        //如果所在函数包含循环，则返回
//        loopanalysis(*F);
//        if(loopset.size()>0){
//            funcinscounts.push_back(funcinscount);
//            funchotinscounts.push_back(funchotinscount);
////            fprintf(fp_funcinstinfo, "%s %s %d %d %d %d %d\n", missinfo_v[i].modulename,missinfo_v[i].funcname,missinfo_v[i].bbindex,missinfo_v[i].insindex,funcinscount,funchotinscount,-1);
//            errs()<<"contains loop\n";
//            continue;
//        }
//        
//        //获取所在函数执行一次所需的instructions数
//        BasicBlock* b = &F->getEntryBlock();
//        errs()<<"get basicblock ok,starting getting funcinscount\n";
//        dfs(b,0);
//        errs()<<"get funcinscount ok\n";
//        funcinscounts.push_back(funcinscount);
//        //统计从函数开始到热点instruction的指令数
//        dfs(b,0,missinfo_v[i]);
//        errs()<<"get funchotinscount ok\n";
//        funchotinscounts.push_back(funchotinscount);
//
//        LoadInst* li = dyn_cast<LoadInst>(missinst);
//        if(li == NULL){
//            continue;
//        }
//        Value* addr = li->getPointerOperand();
//        vector<Value*> funcargvalues;
//        vector<Value*> gepoperands;
//        vector<int> gepoperandsi;//argindex或者是constantint
//        vector<int> gepoperandst;//constantint=1， argindex=2
//        vector<StringRef> gvvector;
//        Function* f = missinst->getFunction();
//        int argnum = f->arg_size();
//        for(unsigned int j = 0; j < argnum; j++){
////            errs()<<j<<":  "<<*(f->getArg(j))<<"\n";
//            funcargvalues.push_back(f->getArg(j));
//        }
//        if(-1 != valueindex(funcargvalues, addr)){
//            errs()<<"isdirect:"<<1<<"\n";
//            int indexi = valueindex(funcargvalues, addr);
//            fprintf(fp_funcinstinfo, "%s %s %d %d %d %d %d %d\n", missinfo_v[i].modulename,missinfo_v[i].funcname,missinfo_v[i].bbindex,missinfo_v[i].insindex,funcinscount,funchotinscount,1, indexi);
//            continue;
//        }
//        GetElementPtrInst *gepinst = dyn_cast<GetElementPtrInst>(addr);
//        if(gepinst == NULL){
//            continue;
//        }
//
//
//        int isdirect = -1;
//        char gvtmp[1024] = "rsvd";
//        char* gvs = gvtmp;
//        StringRef gvv[16];
//        for(unsigned int j = 0; j < gepinst->getNumOperands(); j++){
//            errs()<<j<<":  "<<*(gepinst->getOperand(j))<<"\n";
//            gepoperands.push_back(gepinst->getOperand(j));
//        }
//        int gepsize = gepoperands.size();
//        for(unsigned int j = 0; j < gepoperands.size(); j++){
//            Value* v = gepoperands[j];
//            if(CastInst* castinst = dyn_cast<CastInst>(v)){
//                v = castinst->getOperand(0);
//            }
//            if(ConstantInt* ci = dyn_cast<ConstantInt>(v)){
//                gvv[j] = "rsvd";
//                gepoperandsi.push_back(ci->getSExtValue());
//                gepoperandst.push_back(1);
//                continue;
//            }
//            if(-1 != valueindex(funcargvalues, v)){
//                gvv[j] = "rsvd";
//                gepoperandsi.push_back(valueindex(funcargvalues, v));
//                gepoperandst.push_back(2);
//                continue;
//            }
//            if(LoadInst* li = dyn_cast<LoadInst>(v)){
//                if(GlobalVariable* gv = dyn_cast<GlobalVariable>(li->getPointerOperand())){
//                    gvv[j] = gv->getName();
//                    errs()<<"globalv:"<<gvv[j]<<"\n";
//                    gepoperandsi.push_back(0);
//                    gepoperandst.push_back(3);
//                    isdirect = 3;
//                    continue;
//                }
//            }
//            isdirect = 0;
//            break;
//        }
//        if(isdirect == -1){
//            isdirect = 2;
//        }
//        errs()<<"isdirect:"<<isdirect<<"\n";
//        if(isdirect == 0){
//            continue;
//        }
//        fprintf(fp_funcinstinfo, "%s %s %d %d %d %d %d %d\n", missinfo_v[i].modulename,missinfo_v[i].funcname,missinfo_v[i].bbindex,missinfo_v[i].insindex,funcinscount,funchotinscount,isdirect, gepsize);
//        for(unsigned int j = 0; j < gepoperands.size(); j++){
//            fprintf(fp_funcinstinfo, "%d %d %s\n", gepoperandsi[j], gepoperandst[j], gvv[j].data());
//        }
//    }
//    fclose(fp_funcinstinfo);
//}

int Pref::valueindex(vector<Value*> &valuev, Value* v){
    for(unsigned int i = 0; i < valuev.size(); i++){
        if(v == valuev[i])
            return i;
    }
    return -1;
}

bool Pref::isnotinaloop(unsigned int i){
    missinfoitem tmp = missinfo_v[i];
    for(unsigned int j = 0; j < notloop_v.size(); j++){
        notloopinfoitem tmp2 = notloop_v[j];
        if(tmp2.bbindex != tmp.bbindex)continue;
        if(tmp2.insindex != tmp.insindex)continue;
        int flag = 0;
        for(int k = 0; k < 1024; k++){
            if(tmp2.modulename[k] == '\0' && tmp.modulename[k] == '\0'){
                flag = 2;
                break;
            }
            if(tmp2.modulename[k] != tmp.modulename[k]){
                flag = 1;
                break;
            }
            if(tmp2.funcname[k] != tmp.funcname[k]){
                flag = 1;
                break;
            }
        }
        if(flag != 2){
            continue;
        }
        else{
            return true;
        }
    }
    return false;
}

//B序列预取
void Pref::notloophandler(Module &M){
    //初始化
    FILE* fp;

    errs()<<"notloopstart\n";
    if((fp = fopen(FuncinstInfoFileName.c_str(), "r")) == NULL){
        errs()<<"can not read funcinstinfo.txt\n";
        return;
    }
    char modulename[1024];
    char funcname[1024];
    int bbindex;
    int insindex;
    int funcinstnum;
    int hotinstnum;
    int basictype;
    int vectorsize;

    int flag = 0;

//    vector<notloopinfoitem> notloop_v;

    //读取文件内容到内存中
    while(fscanf(fp, "%s %s %d %d %d %d %d %d %d %d\n", modulename, funcname, &bbindex, &insindex, &accesscnt, &misscnt, &funcinstnum, &hotinstnum, &basictype, &vectorsize) != EOF){
        notloopinfoitem tmp;
        for(unsigned int i = 0; i < 1024; i++){
            tmp.modulename[i] = modulename[i];
            tmp.funcname[i] = funcname[i];
        }
        tmp.bbindex = bbindex;
        tmp.insindex = insindex;
        tmp.funcinstnum = funcinstnum;
        tmp.hotinstnum = hotinstnum;
        tmp.basictype = basictype;
        tmp.vectorsize = vectorsize;
        tmp.accesscnt = accesscnt;
        tmp.misscnt = misscnt;
        tmp.sucnum = 0;
        tmp.failnum = 0;
        tmp.isinsert = 0;
        if(basictype == 2 || basictype == 3){
            for(int i = 0; i < vectorsize; i++){
                fscanf(fp, "%d %d %d %s\n", &(tmp.v[i][0]), &(tmp.v[i][1]), &(tmp.v[i][2]), tmp.gname[i]);
            }
        }
        notloop_v.push_back(tmp);
        vector<nlinfoitem> tmp2;
        nl_vv.push_back(tmp2);
    }
    //对A序列中进行标记
    for(unsigned int i = 0; i < missinfo_v.size(); i++){
        if(isnotinaloop(i)){
            missinfo_v[i].typenum = 11;
        }
    }

    //遍历B序列中的指令
    for(unsigned int i = 0; i < notloop_v.size(); i++){
        notloopinfoitem tmp = notloop_v[i];
        StringRef funcname = tmp.funcname;
        //获取B指令的函数
        Function* F = M.getFunction(funcname);
        if(F == NULL){
//            errs()<<"function null\n";
            continue;
        }
        for(auto it = F->users().begin(); it != F->users().end(); it++){
            //获取函数的call指令
            if(CallInst* ci = dyn_cast<CallInst>(*it)){
                if(ci->getCalledFunction() != F){
                    break;
                }
            }
            //对call指令进行尝试插入预取
            errs()<<"~~~~~~~========================================================================================~~~~~~~\n";
            errs()<<**it<<"\n";
            Value* v = *it;
            if(CallInst* ci = dyn_cast<CallInst>(v)){
                //初始化
                IRBuilder<> builder(ci);
                notloop_v[i].isinsert = 1;
                //直接以参数为地址进行laod
                if(tmp.basictype == 1){
                    //创建一个新的load
                    Value* addr = ci->getOperand(tmp.vectorsize);
                    Value* loadtmp = builder.CreateLoad(addr);
                    Instruction* loadinst = dyn_cast<Instruction>(loadtmp);
                    //尝试对新的load进行预取
                    loopanalysis(*(ci->getFunction()));
                    LoadHandler(loadinst, findprecount(loadinst), 1, -1);
                    //记录结果
                    if(issuccess != 1)issuccess = 0;
                    nlinfoitem tmp2;
                    missinfoitem tmp3 = missinfo_v[missinfo_v.size() - 1];
                    tmp2.issuccess = issuccess;
                    tmp2.instaddnum = instaddnum;
                    tmp2.typenum = typenum;
                    for(int j = 0; j < 10; j++){
                        tmp2.insttypes[j] = tmp3.insttypes[j];
                    }
                    nl_vv[i].push_back(tmp2);
                    missinfo_v.pop_back();
                    if(issuccess == 1)notloop_v[i].sucnum++;
                    else notloop_v[i].failnum++;
                    //删除增加的laod
                    loadinst->eraseFromParent();
                }
                //通过gep计算得到地址
                else if(tmp.basictype == 2){
                    vector<Value*> opv;
                    //获取所有的gep的参数
                    for(int j = 0; j < tmp.vectorsize; j++){
                        if(tmp.v[j][1] == 1){
                            opv.push_back(ConstantInt::get(Type::getIntNTy(*context, tmp.v[j][2]), tmp.v[j][0]));
                        }
                        else if(tmp.v[j][1] == 2){
                            Value* tmpv = ci->getOperand(tmp.v[j][0]);
                            if(tmpv->getType()->isIntegerTy() && (int)tmpv->getType()->getIntegerBitWidth() != tmp.v[j][2]) {
                                tmpv = builder.CreateZExtOrTrunc(tmpv, Type::getIntNTy(*context, tmp.v[j][2]));
                            }
                            opv.push_back(tmpv);
                        }
                    }
                    ArrayRef<Value*> opa = ArrayRef<Value*>(opv);
                    ArrayRef<Value*> opa2 = opa.drop_front();
                    //创建新的gep和load指令
                    Value* geptmp = builder.CreateInBoundsGEP(opv[0], opa2);
                    Value* loadtmp = builder.CreateLoad(geptmp);
                    //尝试对新的load指令进行预取
                    Instruction* loadinst = dyn_cast<Instruction>(loadtmp);
                    loopanalysis(*(ci->getFunction()));
                    LoadHandler(loadinst, findprecount(loadinst), 1, -1);
                    //记录预取结果
                    if(issuccess != 1)issuccess = 0;
                    nlinfoitem tmp2;
                    missinfoitem tmp3 = missinfo_v[missinfo_v.size() - 1];
                    tmp2.issuccess = issuccess;
                    tmp2.instaddnum = instaddnum;
                    tmp2.typenum = typenum;
                    for(int j = 0; j < 10; j++){
                        tmp2.insttypes[j] = tmp3.insttypes[j];
                    }
                    nl_vv[i].push_back(tmp2);
                    missinfo_v.pop_back();
                    if(issuccess == 1)notloop_v[i].sucnum++;
                    else notloop_v[i].failnum++;
                    //删除添加的load指令
                    loadinst->eraseFromParent();
                }
                //需要global变量的计算
                else if(tmp.basictype = 3){
                    vector<Value*> opv;
                    //获取所有的gep参数
                    for(int j = 0; j < tmp.vectorsize; j++){
                        if(tmp.v[j][1] == 1){
                            opv.push_back(ConstantInt::get(Type::getIntNTy(*context, tmp.v[j][2]), tmp.v[j][0]));
                        }
                        else if(tmp.v[j][1] == 2){
                            Value* tmpv = ci->getOperand(tmp.v[j][0]);
                            if(tmpv->getType()->isIntegerTy() && (int)tmpv->getType()->getIntegerBitWidth() != tmp.v[j][2]) {
                                tmpv = builder.CreateZExtOrTrunc(tmpv, Type::getIntNTy(*context, tmp.v[j][2]));
                            }
                            opv.push_back(tmpv);
                        }
                        //全局变量添加load和转换操作
                        else if(tmp.v[j][1] == 3){
                            StringRef tmpname = tmp.gname[j];
                            if(M.getGlobalVariable(tmpname) == NULL){
                                flag = 1;
                                break;
                            }
                            Value* tmpv = builder.CreateLoad(M.getGlobalVariable(tmpname));
                            if(tmpv->getType()->isIntegerTy() && (int)tmpv->getType()->getIntegerBitWidth() != tmp.v[j][2]) {
                                tmpv = builder.CreateZExtOrTrunc(tmpv, Type::getIntNTy(*context, tmp.v[j][2]));
                            }
                            opv.push_back(tmpv);
                        }
                    }
                    if(flag == 1){
                        break;
                    }
                    ArrayRef<Value*> opa = ArrayRef<Value*>(opv);
                    ArrayRef<Value*> opa2 = opa.drop_front();
                    //添加gep和load指令
                    Value* geptmp = builder.CreateGEP(opv[0], opa2);
                    Value* loadtmp = builder.CreateLoad(geptmp);
                    //尝试对新的load指令进行预取
                    Instruction* loadinst = dyn_cast<Instruction>(loadtmp);
                    loopanalysis(*(ci->getFunction()));
                    LoadHandler(loadinst, findprecount(loadinst), 1, -1);
                    //记录预取结果
                    if(issuccess != 1)issuccess = 0;
                    nlinfoitem tmp2;
                    missinfoitem tmp3 = missinfo_v[missinfo_v.size() - 1];
                    tmp2.issuccess = issuccess;
                    tmp2.instaddnum = instaddnum;
                    tmp2.typenum = typenum;
                    for(int j = 0; j < 10; j++){
                        tmp2.insttypes[j] = tmp3.insttypes[j];
                    }
                    nl_vv[i].push_back(tmp2);
                    missinfo_v.pop_back();
                    if(issuccess == 1)notloop_v[i].sucnum++;
                    else notloop_v[i].failnum++;
                    //删除新添加的laod指令
                    loadinst->eraseFromParent();
                }
            }
            errs()<<"~~~~~~~========================================================================================~~~~~~~\n";
        }

    }
    fclose(fp);
    //输出A序列结果
    printout();
    //输出B序列结果
    printout2();
    return;
}

void Pref::readtopfile(){
    FILE* fp;
    topstart = 0;
    topend = missinfo_v.size();
    minrate = 0.05;
    errs()<<"          "<<topstart<<"   "<<topend<<"   "<<minrate<<"\n";
    if((fp = fopen(TopInfoFileName.c_str(), "r")) == NULL){
        return;
    }
    int s;
    int e;
    double rate;
    if(fscanf(fp, "%d\n", &s) == EOF)return;
    if(fscanf(fp, "%d\n", &e) == EOF)return;
    if(fscanf(fp, "%lf\n", &rate) == EOF)return;
    errs()<<"          "<<topstart<<"   "<<topend<<"   "<<minrate<<"\n";
    if(rate >= 1)return;
    if(rate < 0.05)return;
    if(s != -1)topstart = s;
    if(e != -1)topend = e;
    minrate = rate;
    errs()<<"          "<<topstart<<"   "<<topend<<"   "<<minrate<<"\n";
    return;
}

//void Pref::printtype(Module &M){
//    char cgFileName[1000];
//    StringRef MName = M.getModuleIdentifier();
//    unsigned int pos = 0;
//    string MNamestr = MName.data();
//    while((pos = MNamestr.find("/")) < MNamestr.length()){
//         MNamestr.erase(pos, 1);
//    }
//    strcpy(cgFileName, "./tmpout/");
//    strcat(cgFileName, "tmpout_");
//    strcat(cgFileName, MNamestr.c_str());
//    strcat(cgFileName, ".txt");
//
//    FILE* fp_funcinstinfo = fopen(cgFileName, "w");
//    if(fp_funcinstinfo == NULL){
//        errs()<<"can not write "<<cgFileName<<"\n";
//        return;
//    }
//    fprintf(fp_funcinstinfo, "%d\n", all);
//    fprintf(fp_funcinstinfo, "%d\n", success);
//    fprintf(fp_funcinstinfo, "%d\n", notinaloop);
//    fprintf(fp_funcinstinfo, "%d\n", notinaloopsuccess);
//    fprintf(fp_funcinstinfo, "%d\n%d\n%d\n%d\n", inserttype[0], inserttype[1], inserttype[2], inserttype[3]);
//
//}

void Pref::printout(){
    FILE *fp = fopen("out.txt", "a");
    if(fp == NULL){
        errs()<<"cannot write out.txt\n";
        return;
    }
    for(int i = 0; i < (int)missinfo_v.size(); i++){
        if(i < topstart)continue;
        if(i > topend)continue;
        missinfoitem tmp = missinfo_v[i];
        if(tmp.accesscnt * minrate > tmp.misscnt)continue;
        Instruction *missinst = tmp.inst;
        if(missinst == NULL)continue;
        if(tmp.issuccess == 200)continue;
        fprintf(fp, "%s,%s,%d,%d,%d,%d,%d,%d,%d,", tmp.modulename, tmp.funcname, tmp.bbindex, tmp.insindex, tmp.accesscnt, tmp.misscnt, tmp.issuccess, tmp.instaddnum, tmp.typenum);
        if(missinst->getDebugLoc())
            fprintf(fp, "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n", tmp.insttypes[0], tmp.insttypes[1], tmp.insttypes[2], tmp.insttypes[3], tmp.insttypes[4], tmp.insttypes[5], tmp.insttypes[6], tmp.insttypes[7], missinst->getDebugLoc()->getLine(), missinst->getDebugLoc()->getColumn());
        else
            fprintf(fp, "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n", tmp.insttypes[0], tmp.insttypes[1], tmp.insttypes[2], tmp.insttypes[3], tmp.insttypes[4], tmp.insttypes[5], tmp.insttypes[6], tmp.insttypes[7],0,0);
    }
    fclose(fp);
}

void Pref::printout2(){
    FILE *fp = fopen("out2.txt", "a");
    if(fp == NULL){
        errs()<<"cannot write out2.txt\n";
        return;
    }
    for(unsigned int i = 0; i < notloop_v.size(); i++){
        if(notloop_v[i].isinsert == 0){
            continue;
        }
        notloopinfoitem tmp = notloop_v[i];
        for(unsigned int j = 0; j < nl_vv[i].size(); j++){
            nlinfoitem tmp2 = nl_vv[i][j];
            fprintf(fp, "%s,%s,%d,%d,%d,%d,", tmp.modulename, tmp.funcname, tmp.bbindex, tmp.insindex, tmp.sucnum, tmp.failnum);
            fprintf(fp, "%d,", j);
            fprintf(fp, "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,\n", tmp2.issuccess, tmp2.instaddnum, tmp2.typenum, tmp2.insttypes[0], tmp2.insttypes[1], tmp2.insttypes[2], tmp2.insttypes[3], tmp2.insttypes[4], tmp2.insttypes[5], tmp2.insttypes[6], tmp2.insttypes[7]);
        }
    }
    fclose(fp);
}


//-pref插件主程序
bool Pref::runOnModule (Module &M)
{
    //errs()<<MissInfoFileName<<"           ========\n";
    context = &M.getContext();
    //A序列预取
    //读需要预取的指令从文件读取到内存中。
    readpreflist();
    //设置预取的最低miss阈值，需要预取的指令最低miss率为0.05，默认为0.05，即全分析。
    readtopfile();
    //将需要预取的指令由index信息对应到指令信息。
    for(unsigned int i = 0; i < missinfo_v.size(); i++){
        missinfoitem tmp = missinfo_v[i];
        StringRef strtmp = tmp.funcname;
//        errs()<<"funcname: "<<strtmp<<"*\n";
        Function* F = M.getFunction(strtmp);
        if(F == NULL){
//            errs()<<"function null\n";
            continue;
        }
//        errs()<<"find miss inst"<<F->getName()<<tmp.bbindex<<tmp.insindex<<"\n";
        missinfo_v[i].inst = findmissinst(tmp, F);
//        errs()<<"find miss inst"<<F->getName()<<tmp.bbindex<<tmp.insindex<<"\n";
        if(missinfo_v[i].inst == NULL){
//            errs()<<"inst null\n";
            continue;
        }
//        errs()<<"find missinst ok\n";
    }
//    int n0 = 0;
//    int n1 = 0;
//    int n2 = 0;
//    int n3 = 0;
    all = 0;
    success = 0;
    notinaloop = 0;
    notinaloopsuccess = 0;
    type = 0;
    //遍历指令序列尝试预取
    for(int i = 0; i < (int)missinfo_v.size(); i++){
        if(i < topstart)continue;
        if(i > topend)continue;
        missinfoitem tmp = missinfo_v[i];
//        if(tmp.accesscnt * 0.05 < tmp.misscnt)n0++;
//        if(tmp.accesscnt * 0.2 < tmp.misscnt)n1++;
//        if(tmp.accesscnt * 0.4 < tmp.misscnt)n2++;
//        if(tmp.accesscnt * 0.6 < tmp.misscnt)n3++;
        if(tmp.accesscnt * minrate > tmp.misscnt)continue;
        Instruction *missinst = tmp.inst;
        if(missinst == NULL)continue;
        //开始预取
        errs()<<"==================================================================================================================\n";
        errs()<<"starting insert inst:"<< *missinst<<"\n";
//        errs()<<*(missinst->getFunction())<<"\n"; 
        //输出文件行号信息等
        DILocation* loc = missinst->getDebugLoc();
        if(loc){
            errs()<<"filename:"<<loc->getFilename()<<"\n";
            errs()<<"line:"<<loc->getLine()<<"\n";
            errs()<<"col:"<<loc->getColumn()<<"\n";
        }
        Function* F = missinst->getFunction();
        errs()<<"loop Analysis: "<<F->getName()<<"\n";
        //分析指令所在函数的循环信息。
        loopanalysis(*F);
        errs()<<"start insert prefetch\n";
        //尝试对指令进行预取，预取的提前量由findprecount计算得到。
        LoadHandler(missinst, findprecount(missinst), 1, i);
        if(issuccess != 1)issuccess = 0;
        missinfo_v[i].issuccess = issuccess;
        missinfo_v[i].instaddnum = instaddnum;
        missinfo_v[i].typenum = typenum;

//        LoadHandler(missinst, 16, 1);
        errs()<<"isnert prefetch finish\n";
        errs()<<"==================================================================================================================\n";
    }
    errs()<<"start not in a loop prefetch\n";
    type = 1;
    //B序列预取
    notloophandler(M);
    errs()<<"not in a loop finish\n";
//    errs()<<"miss rate histogram:\n";
//    errs()<<"0.05:"<<n0<<"\n";
//    errs()<<"0.2:"<<n1<<"\n";
//    errs()<<"0.4:"<<n2<<"\n";
//    errs()<<"0.6:"<<n3<<"\n";
//    errs()<<"out module:\n";
//    errs()<<M<<"\n";
//    errs()<<"==========\n";

    //输出统计结果
    errs()<<"type:\n";
    errs()<<"all:"<<all<<"\n";
    errs()<<"suc:"<<success<<"\n";
    errs()<<"nal:"<<notinaloop<<"\n";
    errs()<<"nalsuc:"<<notinaloopsuccess<<"\n";
//    printtype(M);
    return true;
}//end of myHello::runOnFunction

char Pref::ID = 0;
//static RegisterPass<Pref> X("pref", "My perf Pass, version:3");

INITIALIZE_PASS_BEGIN(Pref, "Pref", "my pref pass", false, false)
INITIALIZE_PASS_END(Pref, "Pref", "my pref pass", false, false)

namespace llvm{
    ModulePass* createPref(){
        return new Pref();
    }
}
