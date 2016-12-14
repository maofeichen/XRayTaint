#include <algorithm>
#include <cassert>
#include <iostream>
#include <stack>
#include <string>
#include "xt_flag.h"
#include "xt_liveness.h"
#include "xt_util.h"

XT_Liveness::XT_Liveness(){}

// analyzes alive buffers for each function call given a xtlog.
// For those buffers are alive for multiple nested function call,
// they are ONLY considerred alive in the innermost function call.
// args:
//      - xtlog: a vector of strings that contains all xtaint records
// return:
//      - alive_buffer: a vector contaiins all alive buffers of each function
//          call. And function calls are sorted with ended first order.
vector<string> XT_Liveness::analyze_alive_buffer(vector<string> &v)
{
    int idx, idx_call, idx_ret;
    string ret, call;
    vector<string> alive_buffer, tmp;
    vector<string>::iterator it_call, it_ret;

    for(vector<string>::iterator it = v.begin(); it != v.end(); ++it){
        // If a function call END mark hit
        if(XT_Util::equal_mark(*it, flag::XT_RET_INSN_SEC) ){
            ret = *(it - 1);    // ret is previous of 2nd ret mark
            idx = v.end() - it;
            // cout << "Index of ret mark to end is: " << idx << endl;

            // scan backward to the begin
            vector<string>::reverse_iterator rit = v.rbegin() + idx - 1;
            for(; rit != v.rend(); ++rit){
                // if a CALL mark hits
                if(XT_Util::equal_mark(*rit, flag::XT_CALL_INSN) || 
                    XT_Util::equal_mark(*rit, flag::XT_CALL_INSN_FF2) ){
                    call = *rit;
                    // if a matched CALL & RET marks
                    if(XT_Util::is_pair_function_mark(call, ret) ){
                        idx_call = v.rend() - rit;
                        idx_ret = it - v.begin();

                        it_call = v.begin() + idx_call - 1;
                        it_ret = v.begin() + idx_ret + 1;
                        vector<string> v_function_call(it_call, it_ret);
                        // tmp = XT_Liveness::analyze_function_alive_buffer(v_function_call);
                        tmp = XT_Liveness::analyze_alive_buffer_per_function(v_function_call);

                        if(tmp.size() > 4){
                            for(vector<string>::iterator tmp_it = tmp.begin(); tmp_it != tmp.end(); ++tmp_it)
                                alive_buffer.push_back(*tmp_it);
                        }
                        break;  // break search backward
                    }
                }
            }
        }
    }
    return alive_buffer;
}

// !!! IGNORE
// analyzes alive buffers for a particular function call.
vector<string> XT_Liveness::analyze_function_alive_buffer(vector<string> &v)
{
    vector<string> v_new;
    stack<string> nest_function;
    bool is_in_nest_function = false;
    int idx;
    vector<string>::iterator it_call, it_ret;

    // push outermost CALL marks
    v_new.push_back(v[0]);
    v_new.push_back(v[1]);

    for(vector<string>::iterator it = v.begin() + 2; it != v.end() - 2; ++it){
        // If a nested CALL mark hits
        if(XT_Util::equal_mark(*it, flag::XT_CALL_INSN) || 
            XT_Util::equal_mark(*it, flag::XT_CALL_INSN_FF2) ){
            // if already in nested function, no need to check
            if(!is_in_nest_function){
                idx = it - v.begin();
                it_call = it;
                // finds its matched RET mark
                for(it_ret = v.begin() + idx; it_ret != v.end() - 2; ++it_ret){
                    // if a RET mark hits
                    if(XT_Util::equal_mark(*it_ret, flag::XT_RET_INSN))
                        if(XT_Util::is_pair_function_mark(*it_call, *it_ret) ){
                            is_in_nest_function = true;
                            nest_function.push(*it_call);
                            break;
                        }
                }
            }
        }
        // if a nested RET mark hit
        else if(XT_Util::equal_mark(*it, flag::XT_RET_INSN)){
            if(!nest_function.empty() && XT_Util::is_pair_function_mark(nest_function.top(), *it) ){
                nest_function.pop();
                is_in_nest_function = false;
            }
        }
        // if a mem buffer mark hits
        else if(XT_Util::equal_mark(*it, flag::TCG_QEMU_LD) || 
            XT_Util::equal_mark(*it, flag::TCG_QEMU_ST))
            if(!is_in_nest_function)
                v_new.push_back(*it);
    }

    // push outer most RET marks
    v_new.push_back(v[v.size() - 2]);
    v_new.push_back(v[v.size() - 1]);

    return v_new;
}

// analyzes alive buffers for a particular function call
vector<string> XT_Liveness::analyze_alive_buffer_per_function(vector<string> &v)
{
    vector<string> v_new, v_call_mark, v_ld, v_st;
    string call_mark, s_func_esp, s_mem_addr;
    unsigned long i_func_esp, i_mem_addr;

    call_mark = v[0];
    v_call_mark = XT_Util::split(call_mark.c_str(), '\t');
    s_func_esp = v_call_mark[1];
    // std::cout << "size of esp string: " << s_func_esp.size() << std::endl;
    i_func_esp = std::stoul(s_func_esp, nullptr, 16);

    // push outermost CALL marks
    v_new.push_back(v[0]);
    v_new.push_back(v[1]);

    for(vector<string>::iterator it = v.begin() + 2; it != v.end() - 2; ++it){
        // if(XT_Util::equal_mark(*it, flag::TCG_QEMU_LD)){
        //     v_ld = XT_Util::split((*it).c_str(), '\t');
        //     s_mem_addr = v_ld[1];
        //     i_mem_addr = std::stoul(s_mem_addr, nullptr, 16);

        //     if(is_mem_alive(i_func_esp, i_mem_addr))
        //         v_new.push_back(*it);
        // }
        // else if(XT_Util::equal_mark(*it, flag::TCG_QEMU_ST)){
        //     v_st = XT_Util::split((*it).c_str(), '\t');
        //     s_mem_addr = v_st[4];
        //     i_mem_addr = std::stoul(s_mem_addr, nullptr, 16);
        //     if(is_mem_alive(i_func_esp, i_mem_addr))
        //         v_new.push_back(*it);
        // }
        
        // Based on the paper, the buffers should: 
        // 1) alive
        // 2) be updated in the function call; that is, is the destination
        //    instead of source
        if(XT_Util::equal_mark(*it, flag::TCG_QEMU_ST)){
            v_st = XT_Util::split((*it).c_str(), '\t');
            s_mem_addr = v_st[4];
            i_mem_addr = std::stoul(s_mem_addr, nullptr, 16);
            if(is_mem_alive(i_func_esp, i_mem_addr))
                v_new.push_back(*it);
        }
    }

    // push outer most RET marks
    v_new.push_back(v[v.size() - 2]);
    v_new.push_back(v[v.size() - 1]);

    return v_new;
}

inline bool XT_Liveness::is_mem_alive(unsigned long &func_esp, unsigned long &mem_addr)
{
    if(mem_addr > STACK_BEGIN_ADDR)
        is_stack_mem_alive(func_esp, mem_addr);
    else
        is_heap_mem_alive();
}

inline bool XT_Liveness::is_stack_mem_alive(unsigned long &func_esp, unsigned long &stack_addr)
{
    if(stack_addr > func_esp)
        return true;
    else
        return false;
}

// heap addr always consider alive
inline bool XT_Liveness::is_heap_mem_alive()
{
    return true;
}

// merge continue buffers for all function calls in xtaint log
vector<Func_Call_Cont_Buf_t> XT_Liveness::merge_continue_buffer(vector<string> &v)
{
    vector<string>::iterator it_call, it_ret;
    Func_Call_Cont_Buf_t func_call_cont_buf;
    vector<Func_Call_Cont_Buf_t> v_func_call_cont_buf;

    for(vector<string>::iterator it = v.begin(); it != v.end(); ++it){
        if(XT_Util::equal_mark(*it, flag::XT_CALL_INSN) ||
            XT_Util::equal_mark(*it, flag::XT_CALL_INSN_FF2) ){
            it_call = it;
            for(it_ret = it_call + 1; it_ret != v.end(); ++it_ret){
                // find call mark coresponding ret mark
                if(XT_Util::equal_mark(*it_ret, flag::XT_RET_INSN_SEC)){
                    vector<string> v_function_call(it_call, it_ret + 1);
                    func_call_cont_buf = XT_Liveness::analyze_continue_buffer_per_function(v_function_call);
                    v_func_call_cont_buf.push_back(func_call_cont_buf);
                    break;
                }
            }
        }

    }

    return v_func_call_cont_buf;
}

// merge continues buffer if any for a particular function call
Func_Call_Cont_Buf_t XT_Liveness::analyze_continue_buffer_per_function(vector<string> &v)
{
    Func_Call_Cont_Buf_t func_call_cont_buf;
    vector<Cont_Buf_t> v_cont_buf;
    Buf_Rec_t buf_rec;
    vector<Buf_Rec_t> v_buf_rec;

    func_call_cont_buf.call_mark = v[0];
    func_call_cont_buf.sec_call_mark = v[1];

    for(vector<string>::iterator it = v.begin() + 2; it != v.end() - 2; ++it){
        if(XT_Util::equal_mark(*it, flag::TCG_QEMU_LD) ){
            buf_rec = XT_Liveness::analyze_load_buf(*it);
            v_buf_rec.push_back(buf_rec);
        }
        else if(XT_Util::equal_mark(*it, flag::TCG_QEMU_ST) ){
            buf_rec = XT_Liveness::analyze_store_buf(*it);
            v_buf_rec.push_back(buf_rec);
        }
    }
    std::sort(v_buf_rec.begin(), v_buf_rec.end(), XT_Liveness::compare_buf_rec);
    v_cont_buf = XT_Liveness::create_continue_buffer(v_buf_rec);
    func_call_cont_buf.cont_buf = v_cont_buf;

    func_call_cont_buf.ret_mark = v[v.size() - 2];
    func_call_cont_buf.sec_ret_mark = v[v.size() - 1];

    return func_call_cont_buf;
}

inline Buf_Rec_t XT_Liveness::analyze_load_buf(string &s)
{
    Buf_Rec_t buf_rec;
    vector<string> v_ld_rec;

    v_ld_rec = XT_Util::split(s.c_str(), '\t');
    buf_rec.src_flag = v_ld_rec[0];
    buf_rec.src_addr = v_ld_rec[1];
    buf_rec.src_val = v_ld_rec[2];

    buf_rec.dst_flag = v_ld_rec[3];
    buf_rec.dst_addr = v_ld_rec[4];
    buf_rec.dst_val = v_ld_rec[5];

    buf_rec.s_size = v_ld_rec[6];
    buf_rec.this_rec = s;

    buf_rec.addr = std::stoul(buf_rec.src_addr, nullptr, 16);
    buf_rec.size = std::stoul(buf_rec.s_size, nullptr, 10);

    return buf_rec;
}

inline Buf_Rec_t XT_Liveness::analyze_store_buf(string &s)
{
    Buf_Rec_t buf_rec;
    vector<string> v_st_rec;

    v_st_rec = XT_Util::split(s.c_str(), '\t');
    buf_rec.src_flag = v_st_rec[0];
    buf_rec.src_addr = v_st_rec[1];
    buf_rec.src_val = v_st_rec[2];

    buf_rec.dst_flag = v_st_rec[3];
    buf_rec.dst_addr = v_st_rec[4];
    buf_rec.dst_val = v_st_rec[5];

    buf_rec.s_size = v_st_rec[6];
    buf_rec.this_rec = s;

    buf_rec.addr = std::stoul(buf_rec.dst_addr, nullptr, 16);
    buf_rec.size = std::stoul(buf_rec.s_size, nullptr, 10);

    return buf_rec;
}

bool XT_Liveness::compare_buf_rec(Buf_Rec_t &b1, Buf_Rec_t &b2)
{
    return b1.addr < b2.addr;
}

vector<Cont_Buf_t> XT_Liveness::create_continue_buffer(vector<Buf_Rec_t> &v_buf_rec)
{
    vector<Cont_Buf_t> v_cont_buf;
    Cont_Buf_t cont_buf;

    cont_buf.begin_addr = v_buf_rec[0].addr;
    cont_buf.size = v_buf_rec[0].size;
    for(vector<Buf_Rec_t>::iterator it = v_buf_rec.begin() + 1; it != v_buf_rec.end(); ++it){
        // if addr already contain
        if((cont_buf.begin_addr + cont_buf.size / 8) > (*it).addr)
            continue;
        // if continue
        else if((cont_buf.begin_addr + cont_buf.size / 8) == (*it).addr )
            cont_buf.size += (*it).size;
        // if discontinue
        else if((cont_buf.begin_addr + cont_buf.size / 8) < (*it).addr){
            v_cont_buf.push_back(cont_buf);
            cont_buf.begin_addr = (*it).addr;
            cont_buf.size = (*it).size;
        }
    }

    return v_cont_buf;
}

// fliter continue buffers that size larger than 4 bytes
vector<Func_Call_Cont_Buf_t> XT_Liveness::filter_continue_buffer(vector<Func_Call_Cont_Buf_t> &v)
{
    Func_Call_Cont_Buf_t func_call_cont_buf;
    vector<Func_Call_Cont_Buf_t> v_new;

    for(vector<Func_Call_Cont_Buf_t>::iterator it_func = v.begin(); it_func != v.end(); ++it_func){
        func_call_cont_buf.call_mark = (*it_func).call_mark;
        func_call_cont_buf.sec_call_mark = (*it_func).sec_call_mark;
        func_call_cont_buf.ret_mark = (*it_func).ret_mark;
        func_call_cont_buf.sec_ret_mark = (*it_func).sec_ret_mark;

        for(vector<Cont_Buf_t>::iterator it_cont_buf = (*it_func).cont_buf.begin();
            it_cont_buf != (*it_func).cont_buf.end(); ++it_cont_buf){
            if((*it_cont_buf).size > 32)
                func_call_cont_buf.cont_buf.push_back(*it_cont_buf);
        }
        v_new.push_back(func_call_cont_buf);
        func_call_cont_buf.cont_buf.clear();
    }

    return v_new;
}

// Force add taint buffer as alive buffer into the liveness analysis result
// Currently add it to the 1st buffer set
void XT_Liveness::forceAddTaintBuffer(vector<Func_Call_Cont_Buf_t> &vFCallContBuf, 
                                      unsigned long beginAddr, unsigned long size)
{
    // Func_Call_Cont_Buf_t fCallContBuf;
    // vector<Func_Call_Cont_Buf_t> vRes;

    Cont_Buf_t contBuf;
    contBuf.begin_addr = beginAddr;
    contBuf.size = size;

    vFCallContBuf[0].cont_buf.push_back(contBuf);

    // return vRes;
}
