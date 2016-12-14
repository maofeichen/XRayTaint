#include "xt_flag.h"
#include "xt_propagate.h"
#include "xt_util.h"

#include <algorithm>
#include <cassert>
#include <queue>
#include <iostream>
#include <string>
#include <unordered_set>
#include <vector>

#define DEBUG 1

using namespace std;

Propagate::Propagate(){}

unordered_set<Node, NodeHash> Propagate::searchAvalanche(vector<string> &log,
                                                         vector<NodePropagate> &allPropgateRes)
{
    unordered_set<Node, NodeHash> propagate_res;
    vector<Rec> v_rec;
    NodePropagate s;
    bool isFound = false;

    v_rec = initRec(log);

    s.isSrc = true;
    s.parentId = 0;
    s.layer = 0;

    s.n.flag = "34";
    s.n.addr = "bffff753";
    s.n.val = "34";
    s.n.i_addr = std::stoul(s.n.addr, nullptr, 16);
    s.n.sz = 8;

    unsigned int i = 0;
    for(vector<Rec>::iterator it = v_rec.begin(); it != v_rec.end(); ++it){
        if(!(*it).isMark){
            if(s.n.flag == (*it).regular.src.flag &&
               s.n.addr == (*it).regular.src.addr &&
               s.n.val == (*it).regular.src.val){
                isFound = true;
                break;
            }
        }
        i++;
    } // end for

    if(isFound){
        s.id = i * 2;
        s.pos = i;
        s.insnAddr = getInsnAddr(i, v_rec);
        propagate_res = bfs_old_debug(s, v_rec, allPropgateRes);
    }
    return propagate_res;
}

unordered_set<Node, NodeHash> Propagate::getPropagateResult(NodePropagate &s, 
                                                            std::vector<Rec> &vRec)
{
    return bfs_old(s, vRec);
}

vector<Rec> Propagate::initRec(vector<string> &log)
{
    vector<Rec> v_rec;
    vector<string> v_log, v_single_rec;

    Rec rec;
    Node src, dst;
    int i;

//    i = 0;
    for(vector<string>::iterator it = log.begin(); it != log.end(); ++it){
//        if(i == 450)
//            std::cout << "Index: " << i << endl;
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

//    i = 0;
//    for(auto s : v_rec){
//        std::cout << "Index: " << i << endl;
//        if(s.isMark){
//            std::cout << "mark flag: " << s.regular.src.flag << std::endl;
//            std::cout << "mark addr: " << s.regular.src.addr << std::endl;
//            std::cout << "mark val: " << s.regular.src.val << std::endl;
//        } else {
//            std::cout << "src flag: " << s.regular.src.flag << std::endl;
//            std::cout << "src addr: " << s.regular.src.addr << std::endl;
//            std::cout << "src val: " << s.regular.src.val << std::endl;
//
//            std::cout << "dst flag: " << s.regular.src.flag << std::endl;
//            std::cout << "dst addr: " << s.regular.src.addr << std::endl;
//            std::cout << "dst val: " << s.regular.src.val << std::endl;
//        }
//        i++;
//    }
    return v_rec;
} 

// UNFINISHED !!!
unordered_set<Node, NodeHash> Propagate::bfs(NodePropagate &s, vector<Rec> &r)
{
    queue<NodePropagate> q_propagate;
    unordered_set<Node, NodeHash> res;

    NodePropagate currNode, nextNode;
    struct Rec currRec;
    int numHit;
    bool isValidPropagate, isSameInsn;

    q_propagate.push(s);
    while(!q_propagate.empty() ){
        currNode = q_propagate.front();
        q_propagate.pop();

        // if a source node
        if(currNode.isSrc){
            unsigned int i = currNode.pos;
            // can't be a mark
            assert( r[i].isMark == false);
            nextNode = propagate_dst(currNode, r);
            q_propagate.push(nextNode);

            // if it is store to buffer operation, save to propagate result
            Node node = nextNode.n;
            if(XT_Util::equal_mark(node.flag, flag::TCG_QEMU_ST) )
                insert_propagate_result(node, res);
        } else { // if a dst node
            // find valid propagation from dst -> src for afterwards records
            numHit = 0;
            isSameInsn = true;  // assume belongs to same insn at first
            vector<Rec>::size_type i = currNode.pos + 1;
            for(; i != r.size(); i++) {
                isValidPropagate = false;
                currRec = r[i];

                // if cross insn boundary
                if(isSameInsn)
                    if(currRec.isMark && 
                        XT_Util::equal_mark(currRec.regular.src.flag, flag::XT_INSN_ADDR) )
                        isSameInsn = false;

                if(!currRec.isMark){
                    isValidPropagate = is_valid_propagate(currNode, currRec, r);

                    if(isValidPropagate){
                        nextNode = propagte_src(currNode, r, i);
                        // is it a load opreration? If so, then it is a memory buffer

                    } // end isValidPropagate
                }
            } // end of for loop
        }
    } // end of while loop
    return res;
}

unordered_set<Node, NodeHash> Propagate::bfs_old(NodePropagate &s, vector<Rec> &v_rec)
{
    unordered_set<Node, NodeHash> res_buffer;
    vector<NodePropagate> v_propagate_buffer;
    queue<NodePropagate> q_propagate;

    NodePropagate currNode, nextNode;
    struct Rec currRec;
    int numHit;
    bool isValidPropagate, isSameInsn;

    // If the start node is a dst node, should push to q_propagate instead 
    // of v_propagate_buffer?
    // Because there is rule below that any node in the v_propagate_buffer
    // should be a src (even if it is memory buffer)
    // v_propagate_buffer.push_back(s);

    if(s.isSrc)
        v_propagate_buffer.push_back(s);
    else{
        v_propagate_buffer.push_back(s);
        q_propagate.push(s);
    }
    while(!v_propagate_buffer.empty() ){
    L_Q_PROPAGATE:
        // non buffer propagation
        while(!q_propagate.empty() ){
            numHit = 0;
            isSameInsn = true;

            currNode = q_propagate.front();

            // if a source node
            if(currNode.isSrc){
                unsigned int i = currNode.pos;
                // can't be a mark
                assert( v_rec[i].isMark == false);
                nextNode = propagate_dst(currNode, v_rec);
                q_propagate.push(nextNode);
                numHit++;

                // if it is store to buffer operation, save to propagate buffer result
                Node node = nextNode.n;
                if(XT_Util::equal_mark(node.flag, flag::TCG_QEMU_ST) )
                    insert_propagate_result(node, res_buffer);
            }
            // if a dst node
            // find valid propagation from dst -> src for afterwards records
            else{
                numHit = 0;
                isSameInsn = true;  // assume belongs to same insn at first
                vector<Rec>::size_type i = currNode.pos + 1;
                for(; i != v_rec.size(); i++) {
                    isValidPropagate = false;
                    currRec = v_rec[i];

                    // if cross insn boundary
                    if(isSameInsn)
                        if(currRec.isMark && 
                            XT_Util::equal_mark(currRec.regular.src.flag, flag::XT_INSN_ADDR) )
                            isSameInsn = false;

                    if(!currRec.isMark){
                        isValidPropagate = is_valid_propagate(currNode, currRec, v_rec);

                        if(isValidPropagate){
                            nextNode = propagte_src(currNode, v_rec, i);
                            // is it a load opreration? If so, then it is a memory buffer
                            if(XT_Util::equal_mark(nextNode.n.flag, flag::TCG_QEMU_LD) ){
                                insert_buffer_node(nextNode, v_propagate_buffer, numHit);

                                // also save to propagate result!!!
                                Node node = nextNode.n;
                                insert_propagate_result(node, res_buffer);
                            } else{ // if not a buffer node
                                if(is_save_to_q_propagate(isSameInsn, numHit) ){
                                    q_propagate.push(nextNode);
                                    numHit++;
                                }
                            }
                        } // end isValidPropagate
                    } // end isMark

                    // if not belong to same instruction and
                    // already have hit, and
                    // not a memory buffer
                    // can break the loop
                    if(!isSameInsn && 
                        numHit >= 1 && 
                        !XT_Util::equal_mark(currNode.n.flag, flag::TCG_QEMU_ST) )
                            break;
                } // end of for loop
            } // end dst node case
            q_propagate.pop();  
        } // end while q_propagate

        if(!v_propagate_buffer.empty() ){
            currNode = v_propagate_buffer[0];
            v_propagate_buffer.erase(v_propagate_buffer.begin() );

            // memory buffer only contains buffer nodes are as src
            if(currNode.isSrc){
                nextNode = propagate_dst(currNode, v_rec);
                q_propagate.push(nextNode);
                numHit++;
            }
        }

        if(!q_propagate.empty() )
            goto L_Q_PROPAGATE;
    } // end while v_propagate_buffer

    return res_buffer;
} 

unordered_set<Node, NodeHash> Propagate::bfs_old_debug(NodePropagate &s,
                                                       vector<Rec> &v_rec,
                                                       vector<NodePropagate> &allPropgateRes)
{
    unordered_set<Node, NodeHash> res_buffer;
    vector<NodePropagate> v_propagate_buffer;
    queue<NodePropagate> q_propagate;

    NodePropagate currNode, nextNode;
    struct Rec currRec;
    int numHit;
    bool isValidPropagate, isSameInsn;

    v_propagate_buffer.push_back(s);
    while(!v_propagate_buffer.empty() ){
    L_Q_PROPAGATE:
        // non buffer propagation
        while(!q_propagate.empty() ){
            numHit = 0;
            isSameInsn = true;

            currNode = q_propagate.front();
            allPropgateRes.push_back(currNode); // record all propagate result for debug
#ifdef DEBUG
            // if(currNode.insnAddr == "804945d")
            //     cout << "DEBUG: set breakpoint Insn Addr: 804945d" << endl;
            if(currNode.id == 10595)
                cout << "DEBUG: set breakpoint ID: 10595" << endl;
#endif

            // if a source node
            if(currNode.isSrc){
                unsigned int i = currNode.pos;
                // can't be a mark
                assert( v_rec[i].isMark == false);
                nextNode = propagate_dst(currNode, v_rec);
                q_propagate.push(nextNode);
                numHit++;

                // if it is store to buffer operation, save to propagate buffer result
                Node node = nextNode.n;
                if(XT_Util::equal_mark(node.flag, flag::TCG_QEMU_ST) )
                    insert_propagate_result(node, res_buffer);
            }
            // if a dst node
            // find valid propagation from dst -> src for afterwards records
            else{
                numHit = 0;
                isSameInsn = true;  // assume belongs to same insn at first
                vector<Rec>::size_type i = currNode.pos + 1;
                for(; i != v_rec.size(); i++) {
                    isValidPropagate = false;
                    currRec = v_rec[i];

                    // if cross insn boundary
                    if(isSameInsn)
                        if(currRec.isMark && 
                            XT_Util::equal_mark(currRec.regular.src.flag, flag::XT_INSN_ADDR) )
                            isSameInsn = false;

                    if(!currRec.isMark){
                        isValidPropagate = is_valid_propagate(currNode, currRec, v_rec);

                        if(isValidPropagate){
                            nextNode = propagte_src(currNode, v_rec, i);
                            // is it a load opreration? If so, then it is a memory buffer
                            if(XT_Util::equal_mark(nextNode.n.flag, flag::TCG_QEMU_LD) ){
                                insert_buffer_node(nextNode, v_propagate_buffer, numHit);

                                // also save to propagate result!!!
                                Node node = nextNode.n;
                                insert_propagate_result(node, res_buffer);
                            } else{ // if not a buffer node
                                if(is_save_to_q_propagate(isSameInsn, numHit) ){
                                    q_propagate.push(nextNode);
                                    numHit++;
                                }
                            }
                        } // end isValidPropagate
                    } // end isMark

                    // if not belong to same instruction and
                    // already have hit, and
                    // not a memory buffer
                    // can break the loop
                    if(!isSameInsn && 
                        numHit >= 1 && 
                        !XT_Util::equal_mark(currNode.n.flag, flag::TCG_QEMU_ST) )
                            break;
                } // end of for loop
            } // end dst node case
            q_propagate.pop();  
        } // end while q_propagate

        if(!v_propagate_buffer.empty() ){
            currNode = v_propagate_buffer[0];
            allPropgateRes.push_back(currNode);
            v_propagate_buffer.erase(v_propagate_buffer.begin() );
#ifdef DEBUG
            // if(currNode.insnAddr == "804945d")
            //     cout << "DEBUG: set breakpoint Insn Addr: 804945d" << endl;
            if(currNode.id == 10595)
                cout << "DEBUG: set breakpoint ID: 10595" << endl;
#endif

            // memory buffer only contains buffer nodes are as src
            if(currNode.isSrc){
                nextNode = propagate_dst(currNode, v_rec);
                q_propagate.push(nextNode);
                numHit++;
            }
        }

        if(!q_propagate.empty() )
            goto L_Q_PROPAGATE;
    } // end while v_propagate_buffer

    return res_buffer;
}

inline string Propagate::getInsnAddr(unsigned int &idx, vector<Rec> &v_rec)
{
   unsigned int i = idx;
   while(i > 0){
       if(v_rec[i].isMark &&
          XT_Util::equal_mark(v_rec[i].regular.src.flag, flag::XT_INSN_ADDR) )
           return v_rec[i].regular.src.addr;
       i--;
   }
   return "";
}


inline NodePropagate Propagate::propagate_dst(NodePropagate &s, vector<Rec> &r)
{
    NodePropagate d;
    unsigned int i = s.pos;

    d.isSrc = false;
    d.pos = s.pos;
    d.parentId = s.id;
    d.id = s.id + 1;
    d.layer = s.layer + 1;
    d.insnAddr = getInsnAddr(d.pos, r);

    d.n.flag = r[i].regular.dst.flag;
    d.n.addr = r[i].regular.dst.addr;
    d.n.val = r[i].regular.dst.val;
    d.n.i_addr = r[i].regular.dst.i_addr;
    d.n.sz = r[i].regular.dst.sz;

    return d;
}

inline NodePropagate Propagate::propagte_src(NodePropagate &d, std::vector<Rec> &v_rec, int i)
{
    NodePropagate s;

    s.isSrc = true;
    s.pos = i;
    s.parentId = d.id;
    s.id = i * 2;
    s.layer = d.layer + 1;
    s.insnAddr = getInsnAddr(s.pos, v_rec);

    s.n.flag = v_rec[i].regular.src.flag;
    s.n.addr = v_rec[i].regular.src.addr;
    s.n.val = v_rec[i].regular.src.val;
    s.n.i_addr = v_rec[i].regular.src.i_addr;
    s.n.sz = v_rec[i].regular.src.sz;

    return s;
}

inline void Propagate::insert_propagate_result(Node &n, std::unordered_set<Node, NodeHash> &res)
{
    unordered_set<Node, NodeHash>::const_iterator got = res.find(n);
    // if not in the propagate result
    if(got == res.end() )
        res.insert(n);
}

// dst -> src propagation rules:
//      1. records belong to same insn, can have multiple hits
//      2. records beyond insn, can only have one hit
// if the dst node is a store operation, then if
//      dst.addr == current record src.addr
//      consider valid
// else otherwise
//      case 1 - dst.addr == current record src.addr
inline bool Propagate::is_valid_propagate(NodePropagate &currNode, 
                                          Rec &currRec,
                                          vector<Rec> &v_rec)
{
    bool isValidPropagate, isStore; 

    isValidPropagate = false;
    if(XT_Util::equal_mark(currNode.n.flag, flag::TCG_QEMU_ST) )
        isStore = true;
    else
        isStore = false;

    // is the dst node a store operation, indicating node is a memory buffer
    // then only the addresses are same is valid?
    if(isStore){
        if(currNode.n.addr == currRec.regular.src.addr /*&& currNode.n.val == currRec.regular.src.val*/)
            isValidPropagate = true;
    }else{
        // case 1
        // dst node.addr == current node src.addr
        if(currNode.n.addr == currRec.regular.src.addr){
            // if vals are also same
            if(currNode.n.val == currRec.regular.src.val)
                isValidPropagate = true;
            else if(currNode.n.val.find(currRec.regular.src.val) != string::npos || 
                        currRec.regular.src.val.find(currNode.n.val) != string::npos)
                isValidPropagate = true;
            // specail case: tcg add
            else if(XT_Util::equal_mark(currRec.regular.src.flag, flag::TCG_ADD) )
                isValidPropagate = true;
            // special case: if current node next node is a tcg xor
            else if(XT_Util::equal_mark(v_rec[currNode.pos + 1].regular.src.flag, flag::TCG_XOR) )
                isValidPropagate = true;
        }
        // case 2
        // load pointer: current node val is same with current record's addr
        // else if(currNode.n.val == currRec.regular.src.addr &&
        //     XT_Util::equal_mark(currNode.n.flag, flag::TCG_QEMU_LD) )
        // No need to equal Qemu Load
        else if(currNode.n.val == currRec.regular.src.addr && currNode.n.val.length() >= 7)
            isValidPropagate = true;
    }

    return isValidPropagate;
}

bool Propagate::compare_buffer_node(const NodePropagate &a, const NodePropagate &b)
{
    return a.id < b.id;
}

void Propagate::insert_buffer_node(NodePropagate &node, 
                                                          vector<NodePropagate> &v_propagate_buf, 
                                                          int &numHit)
{
    bool hasNode = false;
    for(vector<NodePropagate>::iterator it = v_propagate_buf.begin(); 
          it != v_propagate_buf.end(); ++it){
        if((*it).id == node.id)
            hasNode = true;
    }

    if(!hasNode){
        v_propagate_buf.push_back(node);
        sort(v_propagate_buf.begin(), v_propagate_buf.end(), compare_buffer_node);
        numHit++;
    }
}

// determines if it needs to save to the q_propagate given 
//      1). flag of is in same instruction 
//      2). number of valid propagations hits
inline bool Propagate::is_save_to_q_propagate(bool isSameInsn, int &numHit)
{
    bool isSave = false;

    if(isSameInsn)
        isSave = true;
    else{
        if(numHit < 1)
            isSave = true;
    }
    return isSave;
}

inline RegularRec Propagate::initMarkRecord(vector<string> &singleRec)
{
    RegularRec mark;

    mark.src.flag = singleRec[0];
    mark.src.addr = singleRec[1];
    mark. src.val = singleRec[2];
    mark.src.i_addr = 0;
    mark.src.sz = 0;

    return mark;
}

inline RegularRec Propagate::initRegularRecord(vector<string> &singleRec)
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
