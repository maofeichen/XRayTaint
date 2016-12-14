#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

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

int main(int argc, char const *argv[])
{
    vector<string> xt_log_aes, xt_log_fake, log_refine;
    vector<string> aes_alive_buf;
    vector<Func_Call_Cont_Buf_t> v_func_call_cont_buf;
    vector<Rec> logAESRec;

    // ----------------------------------------
    // Test Case 1: fake data xtaint log
    // ----------------------------------------
    // XT_File xt_file_fake(XT_FILE_PATH + XT_FILE_FAKE_DATA + XT_FILE_EXT);
    // xt_log_fake = xt_file_fake.read();
    // XT_Liveness::analyze_alive_buffer(xt_log_fake);

    // ----------------------------------------
    // Test Case 2: aes xtaint log
    // ----------------------------------------
    XT_File xt_file_aes(XT_FILE_PATH + XT_FILE_AES + XT_FILE_EXT);
    xt_log_aes = xt_file_aes.read();

    // preprocess xtaint log
    XT_PreProcess xt_preprocess;
    xt_log_aes = xt_preprocess.clean_size_mark(xt_log_aes);
    xt_log_aes = xt_preprocess.clean_empty_function_mark(xt_log_aes);
    xt_log_aes = xt_preprocess.clean_nonempty_function_mark(xt_log_aes);
    // xt_file_aes.write(XT_RESULT_PATH + XT_FILE_AES + XT_PREPROCESS + XT_FILE_EXT, xt_log_aes); 

    xt_log_aes = XT_PreProcess::add_mem_size_info(xt_log_aes);
    // xt_file_aes.write(XT_RESULT_PATH + XT_FILE_AES + XT_ADD_SIZE_INFO + XT_FILE_EXT, xt_log_aes);


    // buffer liveness analysis
    aes_alive_buf = XT_Liveness::analyze_alive_buffer(xt_log_aes);
    // xt_file_aes.write(XT_RESULT_PATH + XT_FILE_AES + XT_ALIVE_BUF + XT_FILE_EXT, aes_alive_buf);

    // Convert string format to Rec format
    logAESRec = xt_preprocess.convertToRec(xt_log_aes); 

    // merge continues buffers
    v_func_call_cont_buf = XT_Liveness::merge_continue_buffer(aes_alive_buf);
    v_func_call_cont_buf = XT_Liveness::filter_continue_buffer(v_func_call_cont_buf);
    // xt_file_aes.write_continue_buffer(XT_RESULT_PATH + XT_FILE_AES + CONT_BUF + XT_FILE_EXT, v_func_call_cont_buf);

    // Searches avalanche based on continuous buffer of liveness analysis
    SearchAvalanche sa(v_func_call_cont_buf, logAESRec);
    sa.searchAvalanche();
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

    return 0;
}
