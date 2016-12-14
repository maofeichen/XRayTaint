#include <fstream>
#include <iostream>
#include <vector>
#include "xt_file.h"

XT_File::XT_File(std::string path)
{
    path_r = path;
}

std::vector<std::string> XT_File::read()
{
    std::ifstream xt_file(path_r.c_str() );
    std::vector<std::string> v;
    std::string line;
    int i;

//    i = 0;
    if(xt_file.is_open() ){
        while(getline(xt_file, line) ){
            if(i == 453)
                std::cout << "Index: " << i << std::endl;
            v.push_back(line);
//            i++;
        }
    }
    else
        std::cout << "error open file: " << path_r << std::endl;
    xt_file.close();

    // std::cout << "read file: " << path_r << std::endl;
    // for(std::vector<std::string>::iterator it = v.begin(); it != v.end(); ++it)
    //     std::cout << *it << std::endl;

    return v;
}

void XT_File::write(string p, vector<string> &v)
{
    ofstream f(p.c_str());

    if(f.is_open()){
        for(vector<string>::iterator it = v.begin(); it != v.end(); ++it)
            f << *it <<'\n';

        f.close();
    }
    else
        cout << "error open file: " << p << endl;
}

void XT_File::write_continue_buffer(string p, vector<Func_Call_Cont_Buf_t> &v)
{
    ofstream f(p.c_str());

    if(f.is_open()){
        for(vector<Func_Call_Cont_Buf_t>::iterator it_func = v.begin();
            it_func != v.end(); ++it_func){
            f << "Function Call: " << '\n';
            f << (*it_func).call_mark << '\n';
            f << (*it_func).sec_call_mark << '\n';

            for(vector<Cont_Buf_t>::iterator it_cont_buf = (*it_func).cont_buf.begin();
                it_cont_buf != (*it_func).cont_buf.end(); ++it_cont_buf){
                f << "Begin_Addr: " << hex << (*it_cont_buf).begin_addr << '\n';
                f << "Size: " << dec << (*it_cont_buf).size / 8  << " bytes" << '\n';
            }

            f << (*it_func).ret_mark << '\n';
            f << (*it_func).sec_ret_mark << '\n';
        }
        f.close();
    }
    else
        cout << "error open file: " << p << std::endl;
}

void XT_File::write_all_propagate_result(string path, vector<NodePropagate> &allPropagateRes)
{
    int layer = 0;
    string insnAddr = "";
    ofstream file(path.c_str() );
    if(file.is_open() ){
        file << "Total Propagates: " << allPropagateRes.size() << endl;
        file << "------------------------------" << endl;

        for (auto s : allPropagateRes){
            if(layer != s.layer){
                layer = s.layer;
                file << "------------------------------" << endl;
            }
            if(insnAddr != s.insnAddr){
                insnAddr = s.insnAddr;
                file << "==============================" << endl;
                file << "guest insn addr: " << insnAddr << endl;
                file << "==============================" << endl;
            }
            file << "layer: " << s.layer;
            file << "\tid: " << s.id;
            file << "\tparent id: " << s.parentId;
            if(s.isSrc)
                file << "\tsrc" << endl;
            else
                file << "\tdst" << endl;

            file << "flag: " << s.n.flag;
            file << "\taddr: " << s.n.addr;
            file << "\tval: " << s.n.val << '\n' << endl;
        }
        file.close();
    } else
        cout << "error open file: " << path << endl;
}

void XT_File::writeAvalancheResult(std::string p, std::vector<AvalancheResBetweenInAndOut> &vAvalRes)
{
    SearchAvalanche sa;

    freopen(p.c_str(), "w", stdout);
    if(!vAvalRes.empty() ){
        vector<AvalancheResBetweenInAndOut>::iterator it = vAvalRes.begin();
        for(; it != vAvalRes.end(); ++it){
            cout << "---------- ---------- ---------- ----------" << endl;
            sa.printAvalResBetweenInAndOut(*it);
        }
    }
    fclose(stdout);

    // ofstream file(p.c_str(), "w",stdout);
    // if(file.is_open() ){
    //     if(!vAvalRes.empty() ){
    //         sa.printAvalResBetweenInAndOut(vAvalRes);
    //     }
    //     file.close();
    // } else
    //     cout << "error open file: " << p << endl;
}