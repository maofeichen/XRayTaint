#include <cassert>
#include "xt_flag.h"
#include "xt_util.h"

vector<string> XT_Util::split(const char *s, char c)
{
    vector<string> v;

    do {
        const char *b = s;
        while(*s != c && *s)
            s++;

        v.push_back(string(b, s) );
    } while (*s++ != 0);
    
    // cout << "parse string to: " << v.size() << " tokens" << endl;
    // for(vector<string>::iterator i = v.begin(); i != v.end(); ++i){
    //     cout << *i << endl;
    // }

    return v;
}

bool XT_Util::is_pair_function_mark(string &s_call, string &s_ret)
{
    vector<string> v_call, v_ret;
    int sz;

    v_call = XT_Util::split(s_call.c_str(), '\t');
    v_ret = XT_Util::split(s_ret.c_str(), '\t');
    assert(v_call.size() == v_ret.size() );
    sz = v_call.size();
                    
    // matched CALL and RET mark
    if(v_call.at(sz - 2).compare(v_ret.at(sz - 2) ) == 0)
        return true;
    else
        return false;
}

bool XT_Util::equal_mark(string &s1, const string &s2)
{
    if(s1.substr(0,2).compare(s2) == 0)
        return true;
    else
        return false;
}

bool XT_Util::isMarkRecord(string &flag)
{
    if(XT_Util::equal_mark(flag, flag::XT_SIZE_BEGIN) || 
        XT_Util::equal_mark(flag, flag::XT_SIZE_END) || 
        XT_Util::equal_mark(flag, flag::XT_INSN_ADDR) || 
        XT_Util::equal_mark(flag, flag::XT_TCG_DEPOSIT) ||
        XT_Util::equal_mark(flag, flag::XT_CALL_INSN) || 
        XT_Util::equal_mark(flag, flag::XT_CALL_INSN_FF2) ||
        XT_Util::equal_mark(flag, flag::XT_CALL_INSN_SEC) ||
        XT_Util::equal_mark(flag, flag::XT_CALL_INSN_FF2_SEC) ||
        XT_Util::equal_mark(flag, flag::XT_RET_INSN) ||
        XT_Util::equal_mark(flag, flag::XT_RET_INSN_SEC) )
        return true;
    else
        return false;
}
