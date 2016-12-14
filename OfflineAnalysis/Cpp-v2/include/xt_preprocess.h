#ifndef XT_PREPROCESS_H
#define XT_PREPROCESS_H

#include "xt_data.h"
#include <vector>
#include <string>

using namespace std;

class XT_PreProcess
{
private:
    inline bool is_invalid_record(string &);
    inline RegularRec initMarkRecord(std::vector<std::string> &singleRec);
    inline RegularRec initRegularRecord(std::vector<std::string> &singleRec);
public:
    XT_PreProcess();

    vector<string> clean_size_mark(vector<string> &);
    vector<string> clean_empty_function_mark(vector<string> &);
    vector<string> clean_nonempty_function_mark(vector<string> &);
	std::vector<Rec> convertToRec(std::vector<std::string> &log); 
	std::vector<string> parseMemSizeInfo(std::vector<std::string> &v);

	// !!!IGNORE
    static vector<string> add_mem_size_info(vector<string> &);
};
#endif
