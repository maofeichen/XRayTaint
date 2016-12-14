#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include "xt_constant.h"
#include "xt_data.h"
#include "xt_file.h"
#include "xt_liveness.h"
#include "xt_preprocess.h"
#include "xt_propagate.h"
#include "xt_searchavalanche.h"

using namespace std;

bool compare_res_node(const Node &a, const Node &b){
    return a.i_addr < b.i_addr;
}

void testCase5();
void testCase(string logPath, bool isForceAdd);
void testCaseDup(string logPath, bool isForceAdd);

int main(int argc, char const *argv[])
{
    vector<string> xt_log_aes, xt_log_fake, log_refine, logAesTaintKeystroke;
    vector<string> aes_alive_buf;
    vector<Func_Call_Cont_Buf_t> v_func_call_cont_buf;
    vector<Rec> logAESRec;
    vector<AvalancheResBetweenInAndOut> vAvalRes;

    // ----------------------------------------
    // Test Case 1: fake data xtaint log
    // ----------------------------------------
    // XT_File xt_file_fake(XT_FILE_PATH + XT_FILE_FAKE_DATA + XT_FILE_EXT);
    // xt_log_fake = xt_file_fake.read();
    // XT_Liveness::analyze_alive_buffer(xt_log_fake);

    // ----------------------------------------
    // Test Case 2: aes xtaint log
    // ----------------------------------------
    // XT_File xt_file_aes(XT_FILE_PATH + XT_FILE_AES + XT_FILE_EXT);
    // xt_log_aes = xt_file_aes.read();

    // preprocess xtaint log
    // XT_PreProcess xt_preprocess;
    // xt_log_aes = xt_preprocess.clean_size_mark(xt_log_aes);
    // xt_log_aes = xt_preprocess.clean_empty_function_mark(xt_log_aes);
    // xt_log_aes = xt_preprocess.clean_nonempty_function_mark(xt_log_aes);
    // xt_file_aes.write(XT_RESULT_PATH + XT_FILE_AES + XT_PREPROCESS + XT_FILE_EXT, xt_log_aes); 

    // xt_log_aes = XT_PreProcess::add_mem_size_info(xt_log_aes);
    // xt_file_aes.write(XT_RESULT_PATH + XT_FILE_AES + XT_ADD_SIZE_INFO + XT_FILE_EXT, xt_log_aes);


    // buffer liveness analysis
    // aes_alive_buf = XT_Liveness::analyze_alive_buffer(xt_log_aes);
    // xt_file_aes.write(XT_RESULT_PATH + XT_FILE_AES + XT_ALIVE_BUF + XT_FILE_EXT, aes_alive_buf);

    // Convert string format to Rec format
    // logAESRec = xt_preprocess.convertToRec(xt_log_aes); 

    // merge continues buffers
    // XT_Liveness xtLiveness;
    // v_func_call_cont_buf = XT_Liveness::merge_continue_buffer(aes_alive_buf);
    // v_func_call_cont_buf = XT_Liveness::filter_continue_buffer(v_func_call_cont_buf);
    // xtLiveness.forceAddTaintBuffer(v_func_call_cont_buf, TAINT_BUF_BEGIN_ADDR, TAINT_BUF_SIZE); 
    // xt_file_aes.write_continue_buffer(XT_RESULT_PATH + XT_FILE_AES + CONT_BUF + XT_FILE_EXT, v_func_call_cont_buf);

    // Searches avalanche based on continuous buffer of liveness analysis
    // SearchAvalanche sa(v_func_call_cont_buf, logAESRec);
    // vAvalRes = sa.searchAvalanche();
    // xt_file_aes.writeAvalancheResult(XT_RESULT_PATH + XT_FILE_AES + AVAL_RES + XT_FILE_EXT, vAvalRes);

    // Print avalanche results
    // if(!vAvalRes.empty() ){
    //     vector<AvalancheResBetweenInAndOut>::iterator it = vAvalRes.begin();
    //     for(; it != vAvalRes.end(); ++it){
    //         sa.printAvalResBetweenInAndOut(*it);
    //     }
    // }

    // DEBUG: bffff744 propagate result
    // sa.searchAvalancheDebug();

    // Propagate propa;
    // std::unordered_set<Node, NodeHash> propagate_res;
    // propagate_res = propa.searchAvalanche(xt_log_aes);

    // vector<Node> v_propagate_res;
    // for(auto s : propagate_res)
    //     v_propagate_res.push_back(s);
    // sort(v_propagate_res.begin(), v_propagate_res.end(), compare_res_node);

    // ----------------------------------------
    // Test Case 3: aes 1B with size mark refine
    // ----------------------------------------
    // XT_File file_refine(XT_FILE_PATH + FILE_REFINE + XT_FILE_EXT);
    // log_refine = file_refine.read();
    // log_refine = XT_PreProcess::add_mem_size_info(log_refine);

    // Propagate propa;
    // std::unordered_set<Node, NodeHash> propagate_res;
    // vector<NodePropagate> allPropagateRes;
    // propagate_res = propa.searchAvalanche(log_refine, allPropagateRes);
    // file_refine.write_all_propagate_result(XT_RESULT_PATH + FILE_REFINE + ALL_PROPAGATE_RES + XT_FILE_EXT, allPropagateRes);

    // vector<Node> v_propagate_res;
    // for(auto s : propagate_res)
    //     v_propagate_res.push_back(s);
    // sort(v_propagate_res.begin(), v_propagate_res.end(), compare_res_node);

    // ----------------------------------------
    // Test Case 4: aes xtaint log tainted keystroke as input
    // ----------------------------------------
    // XT_File fileAesTaintKeystroke(XT_FILE_PATH + FILE_AES_KEYSTOKE + XT_FILE_EXT);
    // logAesTaintKeystroke = fileAesTaintKeystroke.read();

    // preprocess xtaint log
    // XT_PreProcess xtPreProc;
    // logAesTaintKeystroke = xtPreProc.clean_size_mark(logAesTaintKeystroke);
    // logAesTaintKeystroke = xtPreProc.clean_empty_function_mark(logAesTaintKeystroke);
    // logAesTaintKeystroke = xtPreProc.clean_nonempty_function_mark(logAesTaintKeystroke);
    // fileAesTaintKeystroke.write(XT_RESULT_PATH + FILE_AES_KEYSTOKE + XT_PREPROCESS + XT_FILE_EXT, logAesTaintKeystroke); 

    // logAesTaintKeystroke = XT_PreProcess::add_mem_size_info(logAesTaintKeystroke);
    // fileAesTaintKeystroke.write(XT_RESULT_PATH + FILE_AES_KEYSTOKE + XT_ADD_SIZE_INFO + XT_FILE_EXT, logAesTaintKeystroke);


    // buffer liveness analysis
    // aes_alive_buf = XT_Liveness::analyze_alive_buffer(logAesTaintKeystroke);
    // fileAesTaintKeystroke.write(XT_RESULT_PATH + FILE_AES_KEYSTOKE + XT_ALIVE_BUF + XT_FILE_EXT, aes_alive_buf);

    // Convert string format to Rec format
    // logAESRec = xtPreProc.convertToRec(logAesTaintKeystroke); 

    // merge continues buffers
    // XT_Liveness xtLiveness;
    // v_func_call_cont_buf = XT_Liveness::merge_continue_buffer(aes_alive_buf);
    // v_func_call_cont_buf = XT_Liveness::filter_continue_buffer(v_func_call_cont_buf);

    // NO Need to add force buffer for this case
    // xtLiveness.forceAddTaintBuffer(v_func_call_cont_buf, TAINT_BUF_BEGIN_ADDR, TAINT_BUF_SIZE); 
    
    // fileAesTaintKeystroke.write_continue_buffer(XT_RESULT_PATH + FILE_AES_KEYSTOKE + CONT_BUF + XT_FILE_EXT, v_func_call_cont_buf);

    // Searches avalanche based on continuous buffer of liveness analysis
    // SearchAvalanche sa(v_func_call_cont_buf, logAESRec);
    // vAvalRes = sa.searchAvalanche();
    // fileAesTaintKeystroke.writeAvalancheResult(XT_RESULT_PATH + FILE_AES_KEYSTOKE + AVAL_RES + XT_FILE_EXT, vAvalRes);

    // testCase5();

    // analyze aes 128 1b cbc taint input with keystrokes
    // testCase(AES_128_CBC_1B_Taint_INPUT_KEYSTROKE, false);

    // analyze aes 128 1b local compile taint input with memory
    testCaseDup(AES_128_1B_LC_TAINT_INPUT, false);
    return 0;
}

// test case 5
// repeates the aes 128 cbc 1B taint input memory log
void testCase5()
{
    vector<string> xtLog;
    vector<string> aliveBuf;
    vector<Rec> xtLogRec;
    vector<Func_Call_Cont_Buf_t> vFuncCallContBuf;
    vector<AvalancheResBetweenInAndOut> vAvalResult;

    XT_File xtFile =(XT_FILE_PATH+AES_128_CBC_1B_TAINT_INPUT_MEMORY+XT_FILE_EXT);
    xtLog = xtFile.read();

    // preprocess
    XT_PreProcess xtPreProc;
    xtLog = xtPreProc.clean_size_mark(xtLog);
    xtLog = xtPreProc.clean_empty_function_mark(xtLog);
    xtLog = xtPreProc.clean_nonempty_function_mark(xtLog);
    // xtFile.write(XT_RESULT_PATH+AES_128_CBC_1B_TAINT_INPUT_MEMORY+XT_PREPROCESS + XT_FILE_EXT, xtLog);

    // add memory size infomation
    xtLog = XT_PreProcess::add_mem_size_info(xtLog);
    // xtFile.write(XT_RESULT_PATH + AES_128_CBC_1B_TAINT_INPUT_MEMORY + XT_ADD_SIZE_INFO + XT_FILE_EXT, xtLog);

    // buffer liveness analysis
    aliveBuf = XT_Liveness::analyze_alive_buffer(xtLog);
    // xtFile.write(XT_RESULT_PATH + AES_128_CBC_1B_TAINT_INPUT_MEMORY + XT_ALIVE_BUF + XT_FILE_EXT, aliveBuf);

    // Merges continuous buffers
    XT_Liveness xtLiveness;
    vFuncCallContBuf = XT_Liveness::merge_continue_buffer(aliveBuf);
    vFuncCallContBuf = XT_Liveness::filter_continue_buffer(vFuncCallContBuf);
    xtLiveness.forceAddTaintBuffer(vFuncCallContBuf, TAINT_BUF_BEGIN_ADDR, TAINT_BUF_SIZE);
    // xtFile.write_continue_buffer(XT_RESULT_PATH + AES_128_CBC_1B_TAINT_INPUT_MEMORY + CONT_BUF + XT_FILE_EXT, vFuncCallContBuf);

    // Converts string format to Rec format
    xtLogRec = xtPreProc.convertToRec(xtLog);

    // Searches avalanche effect
    SearchAvalanche sa(vFuncCallContBuf, xtLogRec);
    vAvalResult = sa.searchAvalanche();
    xtFile.writeAvalancheResult(XT_RESULT_PATH + AES_128_CBC_1B_TAINT_INPUT_MEMORY + AVAL_RES + XT_FILE_EXT, vAvalResult);
}

void testCase(string logPath, bool isForceAdd)
{
    vector<string> xtLog;
    vector<string> aliveBuf;
    vector<Rec> xtLogRec;
    vector<Func_Call_Cont_Buf_t> vFuncCallContBuf;
    vector<AvalancheResBetweenInAndOut> vAvalResult;

    XT_File xtFile =(XT_FILE_PATH + logPath + XT_FILE_EXT);
    xtLog = xtFile.read();

    // preprocess
    XT_PreProcess xtPreProc;
    xtLog = xtPreProc.clean_size_mark(xtLog);
    xtLog = xtPreProc.clean_empty_function_mark(xtLog);
    xtLog = xtPreProc.clean_nonempty_function_mark(xtLog);
    // xtFile.write(XT_RESULT_PATH + logPath + XT_PREPROCESS + XT_FILE_EXT, xtLog);

    // add memory size infomation
    xtLog = XT_PreProcess::add_mem_size_info(xtLog);
    // xtFile.write(XT_RESULT_PATH + logPath + XT_ADD_SIZE_INFO + XT_FILE_EXT, xtLog);

    // buffer liveness analysis
    aliveBuf = XT_Liveness::analyze_alive_buffer(xtLog);
    // xtFile.write(XT_RESULT_PATH + logPath + XT_ALIVE_BUF + XT_FILE_EXT, aliveBuf);

    // Merges continuous buffers
    XT_Liveness xtLiveness;
    vFuncCallContBuf = XT_Liveness::merge_continue_buffer(aliveBuf);
    vFuncCallContBuf = XT_Liveness::filter_continue_buffer(vFuncCallContBuf);
    if(isForceAdd)
        xtLiveness.forceAddTaintBuffer(vFuncCallContBuf, TAINT_BUF_BEGIN_ADDR, TAINT_BUF_SIZE);
    // xtFile.write_continue_buffer(XT_RESULT_PATH + logPath + CONT_BUF + XT_FILE_EXT, vFuncCallContBuf);

    // Converts string format to Rec format
    xtLogRec = xtPreProc.convertToRec(xtLog);

    // Searches avalanche effect
    SearchAvalanche sa(vFuncCallContBuf, xtLogRec);
    vAvalResult = sa.searchAvalanche();
    xtFile.writeAvalancheResult(XT_RESULT_PATH + logPath + AVAL_RES + XT_FILE_EXT, vAvalResult);
}

// Duplicate testCase() for latest test
void testCaseDup(string logPath, bool isForceAdd)
{
    vector<string> xtLog;
    vector<string> aliveBuf;
    vector<Rec> xtLogRec;
    vector<Func_Call_Cont_Buf_t> vFuncCallContBuf;
    vector<AvalancheResBetweenInAndOut> vAvalResult;

    XT_File xtFile =(XT_FILE_PATH + logPath + XT_FILE_EXT);
    xtLog = xtFile.read();

    // preprocess
    XT_PreProcess xtPreProc;
    // xtLog = xtPreProc.clean_size_mark(xtLog); Not needed any more

    // There is a bug
    // xtLog = xtPreProc.clean_empty_function_mark(xtLog);
    xtLog = xtPreProc.clean_nonempty_function_mark(xtLog);
    // xtFile.write(XT_RESULT_PATH + logPath + XT_PREPROCESS + XT_FILE_EXT, xtLog);

    // add memory size infomation

    // xtLog = XT_PreProcess::add_mem_size_info(xtLog); Not needed
    xtLog = xtPreProc.parseMemSizeInfo(xtLog);
    // xtFile.write(XT_RESULT_PATH + logPath + XT_ADD_SIZE_INFO + XT_FILE_EXT, xtLog);

    // buffer liveness analysis
    // aliveBuf = XT_Liveness::analyze_alive_buffer(xtLog);
    // xtFile.write(XT_RESULT_PATH + logPath + XT_ALIVE_BUF + XT_FILE_EXT, aliveBuf);

    // Merges continuous buffers

    XT_Liveness xtLiveness;
    // vFuncCallContBuf = XT_Liveness::merge_continue_buffer(aliveBuf);
    // vFuncCallContBuf = XT_Liveness::filter_continue_buffer(vFuncCallContBuf);
    // if(isForceAdd)
        // xtLiveness.forceAddTaintBuffer(vFuncCallContBuf, TAINT_BUF_BEGIN_ADDR, TAINT_BUF_SIZE);
    // xtFile.write_continue_buffer(XT_RESULT_PATH + logPath + CONT_BUF + XT_FILE_EXT, vFuncCallContBuf);

    // Converts string format to Rec format
    // xtLogRec = xtPreProc.convertToRec(xtLog);

    // Searches avalanche effect

    // SearchAvalanche sa(vFuncCallContBuf, xtLogRec);
    // vAvalResult = sa.searchAvalanche();
    // xtFile.writeAvalancheResult(XT_RESULT_PATH + logPath + AVAL_RES + XT_FILE_EXT, vAvalResult);
}
