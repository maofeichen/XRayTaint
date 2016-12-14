#ifndef XT_UTIL_H
#define XT_UTIL_H

#include <string>
#include <vector>

using namespace std;

class XT_Util{
public:
    static vector<string> split(const char*, char);
    static bool equal_mark(string &, const string &);
    static bool is_pair_function_mark(string &, string &);
    static bool isMarkRecord(string &flag);
}; 
#endif