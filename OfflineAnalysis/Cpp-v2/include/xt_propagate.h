#ifndef XT_PROPAGATE_H
#define XT_PROPAGATE_H 

#include "xt_data.h"

#include <string>
#include <unordered_set>
#include <vector>

class Propagate
{
private:
    inline std::string getInsnAddr(unsigned int &idx, std::vector<Rec> &v_rec);
    inline NodePropagate propagate_dst(NodePropagate &s, std::vector<Rec> &r);
    inline NodePropagate propagte_src(NodePropagate &d, std::vector<Rec> &v_rec, int i);
    inline void insert_propagate_result(Node &n, std::unordered_set<Node, NodeHash> &res);
    inline bool is_valid_propagate(NodePropagate &currNode, Rec &currRec, std::vector<Rec> &v_rec);
    inline bool is_save_to_q_propagate(bool isSameInsn, int &numHit);

    inline RegularRec initMarkRecord(std::vector<std::string> &singleRec);      // Move to preprocess
    inline RegularRec initRegularRecord(std::vector<std::string> &singleRec);   // Move to preprocess

    static bool compare_buffer_node(const NodePropagate &a, const NodePropagate &b);
    void insert_buffer_node(NodePropagate &node, std::vector<NodePropagate> &v_propagate_buf, int &numHit);

    std::vector<Rec> initRec(std::vector<std::string> &log); // IGNORE!!! 

    std::unordered_set<Node, NodeHash> bfs(NodePropagate &s, std::vector<Rec> &r);
    std::unordered_set<Node, NodeHash> bfs_old(NodePropagate &s, 
                                               std::vector<Rec> &v_rec);   
    std::unordered_set<Node, NodeHash> bfs_old_debug(NodePropagate &s, 
                                                     std::vector<Rec> &v_rec, 
                                                     std::vector<NodePropagate> &allPropgateRes);
public:
    Propagate();

    // INGORE!!!
    std::unordered_set<Node, NodeHash> searchAvalanche(std::vector<std::string> &log, 
                                                       std::vector<NodePropagate> &allPropgateRes);
    std::unordered_set<Node, NodeHash> getPropagateResult(NodePropagate &s, 
                                                          std::vector<Rec> &vRec);
};
#endif
