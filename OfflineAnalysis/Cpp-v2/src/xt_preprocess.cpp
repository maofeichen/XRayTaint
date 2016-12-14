#include <cassert>
#include <string>
#include <vector>
#include "xt_flag.h"
#include "xt_preprocess.h"
#include "xt_util.h"

using namespace std;

XT_PreProcess::XT_PreProcess(){}

vector<string> XT_PreProcess::clean_size_mark(vector<string> &v)
{
    vector<string> v_new;
    string begin, end;
    
    for(vector<string>::iterator it = v.begin(); it != v.end(); ++it){
        // if a size end mark
        if( (*it).substr(0,2).compare(flag::XT_SIZE_END) == 0){
            end = *it;
            begin = v_new.back();
            // if a begin mark
            if(begin.substr(0,2).compare(flag::XT_SIZE_BEGIN) == 0)
                // if match size
                if(begin.substr(3, string::npos).compare(end.substr(3,string::npos) ) == 0 ){
                    v_new.pop_back();
                    continue;
                }
        }
        v_new.push_back(*it);
    }
    // std::cout << "after clean size mark: " << std::endl;
    // for(vector<string>::iterator it = v_new.begin(); it != v_new.end(); ++it)
    //     std::cout << *it << std::endl; 
    return v_new;
}

// v - contain xtaint record line by line
// if a pair of function call mark, there is no records between, delete it
// for example,
//      14   c0795f08    c015baa5    
//      4b  c01ace50    0   
//      18  c0795f04    c015baa5    
//      4c  c01ace80    0  
// first two lines indicate a CALL instruction:
// - 14 is CALL mark
// - come with esp value, top of stack value,
// - 4b is 2nd mark of CALL
// - comes with callee addr
//
// last two lines indicate RET insn
// - 18 is RET mark
// - comes with esp value, top of stack
// - 4c is 2nd mark of RET
// - comes with function end addr
//
// they are match due to the top of stack values are same, and
// since no valid records between, delete them 
// return - new vector
vector<string> XT_PreProcess::clean_empty_function_mark(vector<string> &v)
{
    vector<string> v_new, v_call, v_ret;
    string call, ret;
    int sz, idx;

    for(vector<string>::iterator it = v.begin(); it != v.end(); ++it){
        // if a 2nd ret insn mark
        if( (*it).substr(0,2).compare(flag::XT_RET_INSN_SEC) == 0){
            ret = v_new.back();
            sz = v_new.size();
            call = v_new.at(sz - 3);
            // if an CALL insn mark
            if(call.substr(0,2).compare(flag::XT_CALL_INSN) == 0 || \
                call.substr(0,2).compare(flag::XT_CALL_INSN_FF2) == 0 ){
                // if matches
                v_call = XT_Util::split(call.c_str(), '\t');
                v_ret = XT_Util::split(ret.c_str(), '\t');
                assert(v_call.size() == v_ret.size() );
                sz = v_call.size();
                if(v_call.at(sz - 2).compare(v_ret.at(sz - 2) ) == 0){
                    // pop last three
                    for(idx = 0; idx < 3; idx++)
                        v_new.pop_back();
                    continue;
                }
            }
        }
        v_new.push_back(*it);
    }
    return v_new;
}

inline bool XT_PreProcess::is_invalid_record(string &s)
{
     if(s.substr(0,2).compare(flag::XT_INSN_ADDR) != 0 && \
        s.substr(0,2).compare(flag::XT_TCG_DEPOSIT) != 0 && \
        s.substr(0,2).compare(flag::XT_SIZE_BEGIN) != 0 && \
        s.substr(0,2).compare(flag::XT_SIZE_END) != 0 && \
        s.substr(0,2).compare(flag::XT_CALL_INSN_SEC) != 0 && \
        s.substr(0,2).compare(flag::XT_RET_INSN) != 0)
        return true;
    else
        return false;   
}
// clear pair function call marks that contain no valid records between
vector<string> XT_PreProcess::clean_nonempty_function_mark(vector<string> &v)
{
    vector<string> v_new, v_call, v_ret;
    string call, ret;
    int sz, num_item;
    bool is_invalid_rec, is_del_marks;
    
    for(std::vector<string>::iterator it = v.begin(); it != v.end(); ++it){
        // if a 2nd RET insn mark
        if( (*it).substr(0,2).compare(flag::XT_RET_INSN_SEC) == 0){
            is_del_marks = false; // alway assume do not del the pair marks 
            is_invalid_rec = true; // always assume no valid records between 
            num_item = 1;
            ret = v_new.back();

            // scan reverse to find most recent CALL mark
            // ??? why begins from rbegin() ???
            vector<string>::reverse_iterator rit = v_new.rbegin();
            for(; rit != v_new.rend(); ++rit){
                call = *rit;
                // found a CALL mark
                if(call.substr(0,2).compare(flag::XT_CALL_INSN) == 0 || \
                    call.substr(0,2).compare(flag::XT_CALL_INSN_FF2) == 0){
                    v_call = XT_Util::split(call.c_str(), '\t');
                    v_ret = XT_Util::split(ret.c_str(), '\t');
                    assert(v_call.size() == v_ret.size() );
                    sz = v_call.size();

                    // is CALL & RET marks matched & no valid records between
                    if(v_call.at(sz - 2).compare(v_ret.at(sz - 2) ) == 0 && is_invalid_rec){
                        // del the pair markds and records between
                        v_new.resize(v_new.size() - num_item);
                        is_del_marks = true;
                    } 

                    break; // break inner for loop if a CALL found
                }
                // else if a valid record, set the valid flag to false
                if(is_invalid_record(call) && is_invalid_rec)
                    is_invalid_rec = false;

                num_item++;
            }
            if(!is_del_marks)
                v_new.push_back(*it); // if not del, push the RET mark as well
        }
        else
            v_new.push_back(*it);  // push non RET mark records
    }

    return v_new;
}


// Convert string xt log format to Rec format
std::vector<Rec> XT_PreProcess::convertToRec(std::vector<std::string> &log)
{
    vector<Rec> v_rec;
    vector<string> v_log, v_single_rec;

    Rec rec;
    Node src, dst;
    int i;

    for(vector<string>::iterator it = log.begin(); it != log.end(); ++it){
        v_single_rec = XT_Util::split( (*it).c_str(), '\t');
        if(XT_Util::isMarkRecord(v_single_rec[0]) ){
            rec.isMark = true;
            rec.regular = initMarkRecord(v_single_rec);
        }else{
            rec.isMark = false;
            rec.regular = initRegularRecord(v_single_rec);
        }
        v_rec.push_back(rec);
        i++;
    }
    return v_rec;
} 

// Parse size info for qemu_ld/st record
std::vector<string> XT_PreProcess::parseMemSizeInfo(std::vector<std::string> &v)
{
	string recFlag;
	for(vector<string>::iterator it = v.begin(); it != v.end(); ++it){
		recFlag = (*it).substr(0,2);
	}
}

// for each qemu ld/st record, add size info to the end of each
vector<string> XT_PreProcess::add_mem_size_info(vector<string> &v)
{
    int idx;
    string size_mark;
    vector<string> v_new, v_size_mark;

    for(vector<string>::iterator it = v.begin(); it != v.end(); ++it){
        if(XT_Util::equal_mark(*it, flag::TCG_QEMU_LD) ||
            XT_Util::equal_mark(*it, flag::TCG_QEMU_ST)){
            idx = v.end() - it;

            vector<string>::reverse_iterator rit = v.rbegin() + idx;
            for(; rit != v.rend(); ++rit){
                // if most recent size mark is BEGIN, indicating it is 
                // enclosed by a pair of size marks
                if(XT_Util::equal_mark(*rit, flag::XT_SIZE_BEGIN)){
                    v_size_mark = XT_Util::split((*rit).c_str(), '\t');
                    *it = *it + v_size_mark[1];
                    break;
                }
                // if most recent size mark is an END, indicating there is NO
                // size mark of this record, 32 bit default
                else if(XT_Util::equal_mark(*rit, flag::XT_SIZE_END)){
                    *it = *it + "32";
                    break;
                }
            }
        }
        v_new.push_back(*it);
    }
    return v_new;
}

inline RegularRec XT_PreProcess::initMarkRecord(vector<string> &singleRec)
{
    RegularRec mark;

    mark.src.flag = singleRec[0];
    mark.src.addr = singleRec[1];
    mark. src.val = singleRec[2];
    mark.src.i_addr = 0;
    mark.src.sz = 0;

    return mark;
}

inline RegularRec XT_PreProcess::initRegularRecord(vector<string> &singleRec)
{
    RegularRec reg;

    reg.src.flag = singleRec[0];
    reg.src.addr = singleRec[1];
    reg.src.val = singleRec[2];
    reg.src.i_addr = 0;
    reg.src.sz = 0;

    reg.dst.flag = singleRec[3];
    reg.dst.addr = singleRec[4];
    reg.dst.val = singleRec[5];
    reg.dst.i_addr = 0;
    reg.dst.sz = 0;

    if(XT_Util::equal_mark(singleRec[0], flag::TCG_QEMU_LD) ){
        reg.src.i_addr = std::stoul(singleRec[1], nullptr, 16);
        reg.src.sz = std::stoul(singleRec[6], nullptr, 10);
    } else if(XT_Util::equal_mark(singleRec[0], flag::TCG_QEMU_ST) ) {
        reg.dst.i_addr = std::stoul(singleRec[4], nullptr, 16);
        reg.dst.sz = std::stoul(singleRec[6], nullptr, 10);
    }

    return reg;
}
