#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/CallGraph.h"

#include "llvm/Support/Casting.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/Transforms/Instrumentation/MyTrace.h"
#include "llvm/Support/CommandLine.h"

#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <cstring>
#include <set>
#include <string>
#include <vector>
#include <mutex>

using namespace llvm;
using namespace std;

namespace llvm{
   void initializeMyTracePass(PassRegistry &);
}

static cl::opt<std::string> WhiteListFileName(
    "whitelist-filename",
    cl::desc("whitelist filename full path"),cl::Hidden,
    cl::init("whitelist.txt"));

static cl::opt<std::string> CGTmpFilePWD(
    "callgraph-tmpfilepwd",
    cl::desc("PWD to store tmp callgraph file for each module"),cl::Hidden,
    cl::init("/tmp/"));

static cl::opt<std::string> CGFileListPWD(
    "callgraph-filelistpwd",
    cl::desc("PWD to store CallGraphFileList.txt"),cl::Hidden,
    cl::init("./"));

enum INSTYPE
{
    OTHERS = 0,
    LOADINS,
    STOREINS,
    ALLOCAINS,
    CALLINS,
    RETURNINS,
    PREFINS
};

namespace
{
    struct MyTrace : public ModulePass 
    {
        static char ID;
        MyTrace () : ModulePass (ID) {
            initializeMyTracePass(*PassRegistry::getPassRegistry());
        }
        bool runOnModule (Module& M) override;

        void getAnalysisUsage(AnalysisUsage& AU) const {
            AU.addRequired<CallGraphWrapperPass>();
        }

private:
        LLVMContext* context;
        const DataLayout *DL;
        void LoadorStoreHandler (BasicBlock* const BBptr, BasicBlock::iterator& ins);
        void TypeInfoHandler (Module &M);
	bool iswhitelist(StringRef s);
        void whitelistinit();

        Function *LoadInstrumentation;
        Function *StoreInstrumentation;
	Function *PrefetchInstrumentation;
        Function *InitInstrumentation;
        Function *FinatInstrumentation;
        std::map<StringRef, int> skipFunctions;
        char str[128][128];
        int strnum;
    };//endof struct myHello
}//end of namespase

void MyTrace::TypeInfoHandler(Module &M){
    ofstream typefile;
    typefile.open("typefile.txt");
    //typefile<<test<<endl;
    typefile.close();
    return;
}

void MyTrace::LoadorStoreHandler (BasicBlock* const BBptr, BasicBlock::iterator& ins)
{
    BasicBlock::iterator nextIns = ins;
    nextIns++;
    
    Value* addr = NULL;
    int insType = OTHERS;
    if (LoadInst* LI = dyn_cast<LoadInst> (&(*ins)))
    {
        addr = LI -> getPointerOperand ();
        insType = LOADINS;
    }
    else if (StoreInst* SI = dyn_cast<StoreInst> (&(*ins)))
    {
        addr = SI -> getPointerOperand ();
        insType = STOREINS;
    }
    else if (CallInst* PI = dyn_cast<CallInst> (&(*ins)))
        if(PI -> getCalledFunction() && PI -> getCalledFunction() -> getName() == "llvm.prefetch")
    {
	auto arg = PI -> arg_begin();
        addr = *arg;
        insType = PREFINS;
    }
    else
    {
        errs () << "call LoadorStoreHandler() with a non-LoadorStore instruction\n";
        exit (0);
    }

    Value* actualAddr = NULL;
    Value* size_IR;

    Type *OrigPtrTy = addr -> getType ();
    Type *OrigTy = cast<PointerType> (OrigPtrTy) -> getElementType ();
    int memSize = DL -> getTypeStoreSizeInBits (OrigTy) / 8;
    size_IR = ConstantInt::get (Type::getInt32Ty (*context), memSize);

    IRBuilder<> IRBCall (&(*nextIns));
    actualAddr = IRBCall.CreatePointerCast (addr, Type::getInt64Ty (*context));

    Value* line = NULL;
    Value* FName = NULL, *MName = NULL, *instIndex_IR = NULL, *bbIndex_IR = NULL;
    unsigned lineraw = 0;
    StringRef FNameRaw="", MNameRaw="";
    if(DILocation* loc = ins -> getDebugLoc()){
        lineraw = loc -> getLine();
        //filenameraw = loc -> getFilename();
    }
    //if(!(ins -> getParent())->getName().empty() )BBNameRaw = (ins -> getParent()) -> getName();
    //else{
    //    string tmpForBBName;
    //    raw_string_ostream OS(tmpForBBName);
    //    ins->getParent()->printAsOperand(OS, false);
    //    BBNameRaw = OS.str(); 
    //}
    if(!ins -> getFunction()->getName().empty() )FNameRaw = (ins -> getFunction()) -> getName();
    if(!ins -> getModule()->getName().empty() )MNameRaw = (ins -> getModule()) -> getName();

    int bbIndex = 0, instIndex = 0;
    BasicBlock::iterator instBegin = ins -> getParent() -> begin();
    while(instBegin != ins){
        if(auto* cins = dyn_cast<CallInst> (&(*instBegin))){
            if(cins->getCalledFunction()){
                if(cins->getCalledFunction()->getName() == "LoadInstrumentation" || cins->getCalledFunction()->getName() == "StoreInstrumentation" || cins->getCalledFunction()->getName() == "PrefetchInstrumentation"){
                    instIndex -= 2;
                    BasicBlock::iterator preInst = instBegin;
                    preInst--;
                    if (!dyn_cast<PtrToIntInst> (&(*preInst))) instIndex += 1;
                }
                if(cins->getCalledFunction()->getName() == "InitInstrumentation") instIndex -= 1;
            }
        }
        instIndex++;
        instBegin++;
    }
    Function::iterator bbBegin = ins -> getFunction() -> begin();
    while(&(*bbBegin++) != BBptr)bbIndex++; 
 
    line = ConstantInt::get (Type::getInt32Ty (*context), lineraw);
    //BBName = IRBCall.CreateGlobalStringPtr(BBNameRaw, "_bb_name");
    FName = IRBCall.CreateGlobalStringPtr(FNameRaw, "_f_name");
    MName = IRBCall.CreateGlobalStringPtr(MNameRaw, "_m_name");
    instIndex_IR = ConstantInt::get (Type::getInt32Ty (*context), instIndex);
    bbIndex_IR = ConstantInt::get (Type::getInt32Ty (*context), bbIndex);

    DILocation* loc = ins->getDebugLoc();
    StringRef filename = "rsvd";
    int line2 = 0;
    int col = 0;
    if(loc){
        filename = loc->getFilename();
        line2 = loc->getLine();
        col = loc->getColumn();
    }
    if(filename.contains(",")){
        filename = "filename";
        errs()<<filename<<"\n";
    }
    Value* filenameIR = IRBCall.CreateGlobalStringPtr(filename, "_file_name");
    Value* lineIR = ConstantInt::get(Type::getInt32Ty(*context), line2);
    Value* colIR = ConstantInt::get(Type::getInt32Ty(*context), col);

    //CallGraph *cg = &getAnalysis<CallGraphWrapperPass>().getCallGraph();
    //StringRef cgFilename("callgraph.txt");
    //error_code EC;
    //raw_fd_stream cgos(cgFilename, EC);
    //cg->print(cgos);

    if (insType == LOADINS)
    {
        IRBCall.CreateCall (LoadInstrumentation, {actualAddr, size_IR, FName, MName, instIndex_IR, bbIndex_IR, line, filenameIR, lineIR, colIR});
    }
    else if (insType == STOREINS)
    {
        IRBCall.CreateCall (StoreInstrumentation, {actualAddr, size_IR, FName, MName, instIndex_IR, bbIndex_IR, line, filenameIR, lineIR, colIR});
    }
    else 
    {
        IRBCall.CreateCall (PrefetchInstrumentation, {actualAddr, size_IR, FName, MName, instIndex_IR, bbIndex_IR, line, filenameIR, lineIR, colIR});
    }

}

void MyTrace::whitelistinit()
{
    FILE* fp;
    if((fp = fopen(WhiteListFileName.c_str(), "r")) == NULL){
        errs()<<"no whitelist.txt\n";
        return;
    }
    int i = 0;
    while(fscanf(fp, "%s", str[i]) != EOF){
        errs()<<str[i]<<"\n";
        i++;
        if(i >= 128){
            break;
        }
    }
    strnum = i;
}

bool MyTrace::iswhitelist(StringRef s)
{
    for(int i = 0; i < strnum; i++){
        StringRef tmp = str[i];
        if(s.contains(str[i])){
            return true;
        }
    }
    return false;
}

void myprint(CallGraph& cg){
    Module &M = cg.getModule();
    
    StringRef MName = M.getModuleIdentifier();//need to delete all '\' in MName.
    int pos = 0;
    string MNamestr = MName.data();
    //strcpy(MNamestr, MName.data());
    while((pos = MNamestr.find("/")) < MNamestr.length()){
         MNamestr.erase(pos, 1);
    }
    char cgFileName[1000];// CGTmpFilePWD + "callgraph_" + MName.data() + ".txt";
    strcpy(cgFileName, CGTmpFilePWD.c_str());
    strcat(cgFileName, "CallGraph_");
    strcat(cgFileName, MNamestr.c_str());
    strcat(cgFileName, ".txt");
    FILE* fp = fopen(cgFileName, "w");
    if(fp == NULL) errs() << "open " << cgFileName << " failed\n";

    char cgFileNameList[200];
    strcpy(cgFileNameList, CGFileListPWD.c_str());
    strcat(cgFileNameList, "CallGraphFileList.txt");

    mutex mut;
    mut.lock();
    FILE* fpList = fopen(cgFileNameList, "a+");
    if(fpList == NULL) errs() << "open" << cgFileNameList << "failed\n";
    fprintf(fpList, "%s\n", cgFileName);
    fclose(fpList);
    mut.unlock();

    for(Function &F : M){
//        CallGraphNode* cgn = cg[&F];
        CallGraphNode* cgn = cg.getOrInsertFunction(&F);
        if(cgn == cg.getExternalCallingNode())continue;
        if(cgn == cg.getCallsExternalNode())continue;

	set<Function*> calledfunclist;	
        fprintf(fp, "%s:", cgn->getFunction()->getName().data());
	for(auto cgn_it : *cgn){
            CallGraphNode* calledFuncNode = cgn_it.second;
            if(auto tmp = calledFuncNode->getFunction()){
                if(calledfunclist.find(tmp) == calledfunclist.end()){
                    calledfunclist.insert(tmp);
                    fprintf(fp, "%s,", tmp->getName().data());
                }
            }
        }
        fprintf(fp, "\n");
    }
    fclose(fp);
}

bool MyTrace::runOnModule (Module &M)
{

//    errs() << "outputing typeinfo\n";
//    TypeInfoHandler(M);
    whitelistinit();
    errs() << "performing myHello::runOnModule () on Module " << M.getName () << "\n";
    DL = &M.getDataLayout();
    context = &M.getContext();
    skipFunctions.clear();
    StringRef tmpSR;
    tmpSR = "LoadInstrumentation";
    skipFunctions[tmpSR] = 0;
    M.getOrInsertFunction (tmpSR.str (),
                FunctionType::get (Type::getVoidTy (*context),
                    {
                    Type::getInt64Ty (*context),
                    Type::getInt32Ty (*context),
                    Type::getInt8PtrTy (*context),
                    Type::getInt8PtrTy (*context),
                    Type::getInt32Ty (*context),
                    Type::getInt32Ty (*context),
                    Type::getInt32Ty (*context),
                    Type::getInt8PtrTy (*context),
                    Type::getInt32Ty (*context),
                    Type::getInt32Ty (*context)
                    },
                    false));
    LoadInstrumentation = M.getFunction(tmpSR.str());
    tmpSR = "StoreInstrumentation";
    skipFunctions[tmpSR] = 0;
    M.getOrInsertFunction (tmpSR.str (),
                FunctionType::get (Type::getVoidTy (*context),
                    {
                    Type::getInt64Ty (*context),
                    Type::getInt32Ty (*context),
                    Type::getInt8PtrTy (*context),
                    Type::getInt8PtrTy (*context),
                    Type::getInt32Ty (*context),
                    Type::getInt32Ty (*context),
                    Type::getInt32Ty (*context),
                    Type::getInt8PtrTy (*context),
                    Type::getInt32Ty (*context),
                    Type::getInt32Ty (*context)
                    },
                    false));
    StoreInstrumentation = M.getFunction(tmpSR.str());
    tmpSR = "PrefetchInstrumentation";
    skipFunctions[tmpSR] = 0;
    M.getOrInsertFunction (tmpSR.str (),
                FunctionType::get (Type::getVoidTy (*context),
                    {
                    Type::getInt64Ty (*context),
                    Type::getInt32Ty (*context),
                    Type::getInt8PtrTy (*context),
                    Type::getInt8PtrTy (*context),
                    Type::getInt32Ty (*context),
                    Type::getInt32Ty (*context),
                    Type::getInt32Ty (*context),
                    Type::getInt8PtrTy (*context),
                    Type::getInt32Ty (*context),
                    Type::getInt32Ty (*context)
                    },
                    false));
    PrefetchInstrumentation = M.getFunction(tmpSR.str());
    tmpSR = "InitInstrumentation";
    skipFunctions[tmpSR] = 0;
    M.getOrInsertFunction (tmpSR.str (),
                FunctionType::get (Type::getVoidTy (*context),
                    {
                    },
                    false));
    InitInstrumentation = M.getFunction(tmpSR.str());
    tmpSR = "FinatInstrumentation";
    skipFunctions[tmpSR] = 0;
    M.getOrInsertFunction (tmpSR.str (),
                FunctionType::get (Type::getVoidTy (*context),
                    {
                    },
                    false));
    FinatInstrumentation = M.getFunction(tmpSR.str());

    for(auto &F : M){
        StringRef fn = F.getName ();
        if(fn == "main"){
            IRBuilder<> IRB (&(*(F.begin()->begin())));
            IRB.CreateCall(InitInstrumentation, {});
        }
        if(skipFunctions.find(fn) != skipFunctions.end()){
            continue;
        }
        if(strnum != 0){
            if(!iswhitelist(fn)){
                continue;
            }
        }
        errs() << "performing myHello::runOnFunction () on Function " << fn << "\n";
        for (auto &BB : F)
        {
            for (BasicBlock::iterator ins = BB.begin (), ins_end = BB.end (); ins != ins_end; ins++)
            {
                //ins -> print (errs ());
                //errs () << "\n";
                if (dyn_cast<LoadInst> (&(*ins)) || dyn_cast<StoreInst> (&(*ins)))
                {
                    LoadorStoreHandler (&BB, ins);
                }
                if (CallInst* PI = dyn_cast<CallInst> (&(*ins)))
                    if(PI -> getCalledFunction() && PI -> getCalledFunction() -> getName() == "llvm.prefetch")
                {
                    LoadorStoreHandler (&BB, ins);
                }
                if(dyn_cast<ReturnInst> (&(*ins)) && fn == "main"){
                    IRBuilder<> IRB (&(*ins));
                    IRB.CreateCall(FinatInstrumentation, {});
                }
                if (CallInst* exit_call = dyn_cast<CallInst> (&(*ins)))
                    if(exit_call -> getCalledFunction() && exit_call -> getCalledFunction() -> getName() == "exit")
                {
                    IRBuilder<> IRB (&(*ins));
                    IRB.CreateCall(FinatInstrumentation, {});
                }
            }
        }
    }

    CallGraph &cg = getAnalysis<CallGraphWrapperPass>().getCallGraph();
    //StringRef cgFilename("callgraph_"+M.getSourceFileName()+".txt");
    //error_code EC;
    //raw_fd_stream cgos(cgFilename, EC);
    //cg.print(cgos);
    myprint(cg);

    return true;
}//end of myHello::runOnFunction

char MyTrace::ID = 0;
//static RegisterPass<MyTrace> X("MyTrace", "My trace Pass, version:5");
INITIALIZE_PASS_BEGIN(MyTrace, "MyTrace", "My trace pass", false, false)
INITIALIZE_PASS_END(MyTrace, "MyTrace", "My trace pass", false, false)

namespace llvm{
    ModulePass* createMyTrace(){
        return new MyTrace();
    }
}
