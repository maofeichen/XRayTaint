#ifndef XT_DATA_H
#define XT_DATA_H

#include <string>
#include <vector>

// Buffer Record
struct Buf_Rec_t{
    std::string src_flag;
    std::string src_addr;
    std::string src_val;

    std::string dst_flag;
    std::string dst_addr;
    std::string dst_val;

    std::string s_size;
    std::string this_rec;

    unsigned long addr;
    unsigned int size;
};

// Continue Buffer
struct Cont_Buf_t
{
    unsigned long begin_addr;
    unsigned long size;
};

// Continues Buffers per function call
struct Func_Call_Cont_Buf_t
{
    std::string call_mark;
    std::string sec_call_mark;
    std::string ret_mark;
    std::string sec_ret_mark;
    std::vector<Cont_Buf_t> cont_buf;
};

struct Node{
    std::string flag;
    std::string addr;
    std::string val;

    unsigned long i_addr;
    unsigned int sz;
};

inline bool operator==(Node a, Node b)
{
    return a.flag == b.flag &&
               a.addr == b.addr &&
               a.val == b.val &&
               a.sz == b.sz;
}

struct NodeHash
{
    std::size_t operator()(const Node &a) const {
        size_t h1 ( std::hash<int>()(a.i_addr) );
        size_t h2 ( std::hash<int>()(a.sz) );
        return h1 ^ (h2 << 1);    
    }
};

struct RegularRec
{
    struct Node src;
    struct Node dst;
};

struct MarkRec
{
    struct Node mark;
};

// if a mark, then src becomes the mark
struct Rec
{
    bool isMark;
    struct RegularRec regular;
    // union{
    //     struct RegularRec regular;
    //     struct MarkRec mark;
    // };
};

struct NodePropagate
{
    unsigned long id;
    unsigned long parentId;
    unsigned long layer;
    std::string insnAddr;
    bool isSrc;
    unsigned int pos;
    struct Node n; 
};

#endif
