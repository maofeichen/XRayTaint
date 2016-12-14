#include "xt_flag.h"
#include "xt_propagate.h"
#include "xt_searchavalanche.h"
#include "xt_util.h"

#include <cassert>
#include <iostream>

#define DEBUG 1

using namespace std;

SearchAvalanche::SearchAvalanche(){}
SearchAvalanche::SearchAvalanche(vector<Func_Call_Cont_Buf_t> v_funcCallContBuf,
								 vector<Rec> logAesRec)
{
	m_vFuncCallContBuf = v_funcCallContBuf;
	m_logAesRec = logAesRec;
}

vector<AvalancheResBetweenInAndOut> SearchAvalanche::searchAvalanche()
{
	vector<FunctionCallBuffer> v_functionCallBuffer;
	AvalancheResBetweenInAndOut avalResInOut;
	vector<AvalancheResBetweenInAndOut> vAvalRes;

	BufferInOut bufInOut;
	vector<BufferInOut> vBufInOut;	// Duplicate In Out buffers check

	int numSearch;
	v_functionCallBuffer = getFunctionCallBuffer(m_vFuncCallContBuf);

	// print all continue buffers
	// printFuncCallContBuf(m_vFuncCallContBuf);

	cout << "Begin to search avalanche between buffers:" << endl;
	numSearch = 0;
	vector<FunctionCallBuffer>::iterator in = v_functionCallBuffer.begin();
	for(; in != v_functionCallBuffer.end(); ++in){
		// if NOT kernel address and larger than 8 bytes
		if(in->buffer.size >= BUFFER_LEN && 
		   !isKernelAddress(in->buffer.beginAddr) ){

			vector<FunctionCallBuffer>::iterator out = in + 1;
			for(; out != v_functionCallBuffer.end(); ++out){
				if(!isSameFunctionCall(*in, *out) && 
				   out->buffer.size >= BUFFER_LEN && 
				   !isKernelAddress(out->buffer.beginAddr) && 
				   in->buffer.beginAddr != out->buffer.beginAddr){

				   	bufInOut = assignBufInOut(*in, *out);
				   	if(!isDuplBufInOut(bufInOut, vBufInOut) ){
				   		vBufInOut.push_back(bufInOut);

				   		cout << numSearch << " times search avalanche..." << endl;
						// Print in & out 
						cout << "----------------------------------------" << endl;
						cout << "Input buffer:" << endl;
					   	printFunctionCallBuffer(*in);
					   	cout << "Output buffer: " << endl;
					   	printFunctionCallBuffer(*out);

					   	avalResInOut = searchAvalancheBetweenInAndOut(*in, *out);
					   	// printAvalResBetweenInAndOut(avalResInOut);
					   	vAvalRes.push_back(avalResInOut);

					   	numSearch++;
				   	}
	
					// DEBUG
					// if(in->buffer.beginAddr == 0xbffff764 && 
					// 	out->buffer.beginAddr == 0xbffff77c){
					// 	avalResInOut = searchAvalancheBetweenInAndOut(*in, *out);
					// 	printAvalResBetweenInAndOut(avalResInOut);
					// 	goto LABEL_OUTTER_LOOP;
					// }

					// search avalanche effect between in and out continuous buffer
					// searchAvalancheBetweenInAndOut(*in, *out);
				}
			} // end inner for
		}
	} // end outter for
LABEL_OUTTER_LOOP:
	cout << "Total numbfer of seaching: " << numSearch << endl;
	cout << "search finish" << endl;

	return vAvalRes;
}

void SearchAvalanche::searchAvalancheDebug()
{
	vector<FunctionCallBuffer> vFunctionCallBuffer;
	vFunctionCallBuffer = getFunctionCallBuffer(m_vFuncCallContBuf);
	
	vector<FunctionCallBuffer>::iterator in = vFunctionCallBuffer.begin();
	for(; in != vFunctionCallBuffer.end(); ++in){
		if(in->buffer.size >= BUFFER_LEN && 
		   !isKernelAddress(in->buffer.beginAddr) && 
		   in->buffer.beginAddr == 0xbffff744){
		   	vector<FunctionCallBuffer>::iterator out = in + 1;
		   	searchAvalancheBetweenInAndOutDebug(*in, *out);
		   	break;
		}
	}
}

// Given function call buffer in and out, assigns them to a struct <in, out>
// for duplicate in and out buffer checking
inline BufferInOut SearchAvalanche::assignBufInOut(FunctionCallBuffer &in, FunctionCallBuffer &out)
{
	BufferInOut bufInOut;

	bufInOut.in.beginAddr = in.buffer.beginAddr;
	bufInOut.in.size = in.buffer.size;

	bufInOut.out.beginAddr = out.buffer.beginAddr;
	bufInOut.out.size = out.buffer.size;

	return bufInOut;
}

inline void SearchAvalanche::clearAvalacheResult(AvalancheRes &avalRes, 
												 Buffer &avalIn, std::vector<Buffer> &vAvalOut)
{
	avalRes.avalIn.beginAddr = 0;
	avalRes.avalIn.size = 0;
	avalRes.vAvalOut.clear();

	avalIn.beginAddr = 0;
	avalIn.size = 0;
	
	vAvalOut.clear();
}

inline bool SearchAvalanche::isDuplBufInOut(BufferInOut &bufInOut, vector<BufferInOut> &vBufInOut)
{
	if(vBufInOut.empty())
		return false;

	for(vector<BufferInOut>::iterator it = vBufInOut.begin(); it != vBufInOut.end(); ++it){
		if(it->in.beginAddr == bufInOut.in.beginAddr && 
		   it->in.size == bufInOut.in.size && 
		   it->out.beginAddr == bufInOut.out.beginAddr &&
		   it->out.size == bufInOut.out.size)
			return true;
	}

	return false;
}

inline string SearchAvalanche::getInsnAddr(unsigned int &idx, vector<Rec> &vRec)
{
	unsigned int i = idx;
	while(i > 0){
		if(vRec[i].isMark &&
           XT_Util::equal_mark(vRec[i].regular.src.flag, flag::XT_INSN_ADDR) )
			return vRec[i].regular.src.addr;
		i--;
   }
   return "";
}

// Is the hardcode correct?
inline bool SearchAvalanche::isKernelAddress(unsigned int addr)
{
	if(addr > KERNEL_ADDR)
		return true;
	else
		return false;
}

inline bool SearchAvalanche::isMarkMatch(string &mark, Rec &r)
{
	vector<string> vMark;

	vMark = XT_Util::split(mark.c_str(), '\t');
	if(vMark[0] == r.regular.src.flag && 
	   vMark[1] == r.regular.src.addr && 
	   vMark[2] == r.regular.src.val)
		return true;
	else return false;
}

// Determines if the given address is in the range of given node
// !!! Notice it MUST be < (NOT <= ) 
inline bool SearchAvalanche::isInRange(unsigned long &addr, Node &node)
{
	if(addr >= node.i_addr && addr < node.i_addr + node.sz / BIT_TO_BYTE)
		return true;
	else return false;
}

inline bool SearchAvalanche::isSameBuffer(FunctionCallBuffer &a, FunctionCallBuffer &b)
{
	if(a.buffer.beginAddr == b.buffer.beginAddr &&
		a.buffer.size == b.buffer.size)
		return true;
	else
		return false;
}

inline bool SearchAvalanche::isSameFunctionCall(FunctionCallBuffer &a, FunctionCallBuffer &b)
{
	if(a.callMark == b.callMark && 
	   a.callSecMark == b.callSecMark && 
	   a.retMark == b.retMark && 
	   a.retSecMark == b.retSecMark)
		return true;
	else return false;
}

inline bool SearchAvalanche::isSameNode(NodePropagate &a, NodePropagate &b)
{
	if(a.isSrc 		== b.isSrc && 
	   a.id 		== b.id && 
	   a.parentId 	== b.parentId && 
	   a.layer		== b.layer && 
	   a.pos 		== b.pos && 
	   a.insnAddr 	== b.insnAddr && 
	   a.n.flag 	== b.n.flag && 
	   a.n.addr 	== b.n.addr && 
	   a.n.val 		== b.n.val && 
	   a.n.i_addr 	== b.n.i_addr && 
	   a.n.sz 		== b.n.sz)
		return true;
	else return false;
}

inline void SearchAvalanche::saveAvalancheResult(AvalancheRes &avalRes, Buffer &avalIn, std::vector<Buffer> &vAvalOut)
{
	avalRes.avalIn.beginAddr = avalIn.beginAddr;
	avalRes.avalIn.size = avalIn.size;

	for(auto s : vAvalOut){
		avalRes.vAvalOut.push_back(s);
	}
}

void SearchAvalanche::assignFunctionCallBuffer(FunctionCallBuffer &a, FunctionCallBuffer &b)
{
	a.callMark = b.callMark;
	a.callSecMark = b.callSecMark;
	a.retMark = b.retMark;
	a.retSecMark = b.retSecMark;
	a.buffer.beginAddr = b.buffer.beginAddr;
	a.buffer.size = b.buffer.size;
}

NodePropagate SearchAvalanche::initialBeginNode(FunctionCallBuffer &buf, 
												unsigned long &addr,
												vector<Rec> &logRec)
{
	NodePropagate s;
	Node node;
	bool isFound;
	int functionCallIdx = 0;
	unsigned int recordIdx = 0;

	// locate the function call position
	vector<Rec>::iterator it = logRec.begin();
	for(; it != logRec.end(); ++it){
		if(it->isMark){
			if(isMarkMatch(buf.callMark, *it) && 
			   isMarkMatch(buf.callSecMark, *(it + 1) ) ){
				functionCallIdx = it - logRec.begin();
				break;
			}
		}
	}

#ifdef DEBUG
	// functionCallIdx is the index of callMark in logRec vector
	// if(functionCallIdx != 0)
	// 	cout << "Function Call Idx: " << functionCallIdx << endl;
#endif

	if(functionCallIdx != 0){
		vector<Rec>::iterator it = logRec.begin() + functionCallIdx;
		for(; it != logRec.end(); ++it){
			if(!it->isMark){
				if(XT_Util::equal_mark(it->regular.src.flag, flag::TCG_QEMU_LD) ){
					if(isInRange(addr, it->regular.src) ){
						isFound = true;
						recordIdx = it - logRec.begin();
						break;
					}
				} else if(XT_Util::equal_mark(it->regular.src.flag, flag::TCG_QEMU_ST) ){
					if(isInRange(addr, it->regular.dst) ){
						isFound = true;
						recordIdx = it - logRec.begin();
						break;
					}
				}
			} // end if !it->isMark
		}
	}

	assert(isFound == true);
	if(isFound){
		if(XT_Util::equal_mark(logRec[recordIdx].regular.src.flag, flag::TCG_QEMU_LD) ){
			node = logRec[recordIdx].regular.src;
			s.isSrc = true;
			s.id = recordIdx * 2;
		} else if(XT_Util::equal_mark(logRec[recordIdx].regular.src.flag, flag::TCG_QEMU_ST) ){
			node = logRec[recordIdx].regular.dst;
			s.isSrc = false;
			s.id = recordIdx * 2 + 1;
		}
		s.parentId	= 0;
		s.layer		= 0;
		s.pos 		= recordIdx;
		s.insnAddr 	= getInsnAddr(recordIdx, logRec);
		s.n.flag 	= node.flag;
		s.n.addr 	= node.addr;
		s.n.val 	= node.val;
		s.n.i_addr 	= node.i_addr;
		s.n.sz 		= node.sz;
	}

	return s;
}

// Given the propagate result of in, and continuous out buffer,
// returns the intersection of the two (essentially the avalanche effect)
vector<FunctionCallBuffer> SearchAvalanche::getAvalancheInNewSearch(unordered_set<Node, NodeHash> &propagateResult, 
											  				   	    FunctionCallBuffer &out)
{
	vector<FunctionCallBuffer> vFuncCallBuffer;
	FunctionCallBuffer funcCallBuffer;
	unsigned long addr;
	unsigned int size, numPropagateByte;
	bool isHit;

	funcCallBuffer.callMark 	= out.callMark;
	funcCallBuffer.callSecMark 	= out.callSecMark;
	funcCallBuffer.retMark 		= out.retMark;
	funcCallBuffer.retSecMark 	= out.retSecMark;	
	// funcCallBuffer.buffer.beginAddr = out.buffer.beginAddr;
	funcCallBuffer.buffer.size 	= 0;

	addr = out.buffer.beginAddr;
	size = out.buffer.size / BIT_TO_BYTE;
	numPropagateByte = 0;

	for(int byteIdx = 0; byteIdx < size; byteIdx++){
		isHit = false;
		for(auto s : propagateResult){
			if(addr >= s.i_addr && addr < s.i_addr + s.sz / BIT_TO_BYTE){
				isHit = true;
				numPropagateByte++;
				break;
			}
		}
		if(isHit){
			if(numPropagateByte == 1)
				funcCallBuffer.buffer.beginAddr = addr;
			funcCallBuffer.buffer.size += 1 * BIT_TO_BYTE;
		} else{
			if(numPropagateByte >= VALID_AVALANCHE_LEN)
				vFuncCallBuffer.push_back(funcCallBuffer);
			else{
				numPropagateByte = 0;
			}
		}
		addr++;
	}

	// push the last avalache buffer if it is valid
	if(funcCallBuffer.buffer.size / BIT_TO_BYTE >= VALID_AVALANCHE_LEN)
		vFuncCallBuffer.push_back(funcCallBuffer);

	return vFuncCallBuffer;
}

vector<Buffer> SearchAvalanche::getAvalancheInFirstByte(std::unordered_set<Node, NodeHash> &propagateRes, 
														FunctionCallBuffer &out)
{

}

vector<Buffer> SearchAvalanche::getAvalancheInRestByte(unordered_set<Node, NodeHash> &propagateRes, 
									  				   vector<Buffer> &vAvalOut)
{
	Buffer buf;
	vector<Buffer> vAvalOutNew;

	for(vector<Buffer>::iterator it = vAvalOut.begin(); it != vAvalOut.end(); ++it){
		buf = getAvalancheInRestByteOneBuffer(propagateRes, *it);
		if(buf.beginAddr != 0 && 
		   buf.size / BIT_TO_BYTE >= VALID_AVALANCHE_LEN)
			vAvalOutNew.push_back(buf);
	}

	return vAvalOutNew; 
}

Buffer SearchAvalanche::getAvalancheInRestByteOneBuffer(unordered_set<Node, NodeHash> &propagateRes, 
														Buffer &avalOut)
{
	Buffer buf;

	unsigned int byteIndex, numPropagateByte;
	unsigned long addr;
	bool isHit;

	buf.beginAddr = 0;
	buf.size = 0;

	numPropagateByte = 0;
	addr = avalOut.beginAddr;
	for(byteIndex = 0; byteIndex < (avalOut.size / BIT_TO_BYTE); byteIndex++){
		isHit = false;
		for(auto s : propagateRes){
			if(addr >= s.i_addr && addr < s.i_addr + s.sz / BIT_TO_BYTE){
				isHit = true;
				numPropagateByte++;
				break;
			}
		}
		if(isHit){
			if(numPropagateByte == 1)
				buf.beginAddr = addr;
			buf.size += 1 * BIT_TO_BYTE;
		} else{
			if(numPropagateByte >= VALID_AVALANCHE_LEN)
				break;
			else{
				// No valid propagate result
				buf.beginAddr = 0;
				buf.size = 0;
				break;
			}
		}
		addr++;
	}
	return buf;
}

// Transfers Func_Call_Cont_Buf_t to FunctionCallBuffer.
// In Func_Call_Cont_Buf_t, each pair of call and ret mark may have multiple
// continuous buffers.
// But in FunctionCallBuffer, each pair of call and ret mark only have one
// continous buffer, even there might be repeated marks in the results.
vector<FunctionCallBuffer> SearchAvalanche::getFunctionCallBuffer(vector<Func_Call_Cont_Buf_t> &v)
{
	vector<FunctionCallBuffer> v_new;
	FunctionCallBuffer f;

	for(auto s : v){
		for(auto t : s.cont_buf){
			f.callMark = s.call_mark;
			f.callSecMark = s.sec_call_mark;
			f.retMark = s.ret_mark;
			f.retSecMark = s.sec_ret_mark;
			f.buffer.beginAddr = t.begin_addr;
			f.buffer.size = t.size;

			v_new.push_back(f);
		}
	}
	return v_new;
}

void SearchAvalanche::searchAvalancheBetweenInAndOut_IGNORE(FunctionCallBuffer &in, FunctionCallBuffer &out)
{
	NodePropagate prev_s, curr_s,s;
	Propagate propagate;
	unordered_set<Node, NodeHash> propagateResult;
	
	vector<FunctionCallBuffer> vTempAvalancheRes, vAvalancheRes;
	AvalancheRes avalRes;
	AvalancheResBetweenInAndOut avalResInOut;


	unsigned int inBytes, numInByteSearch, byteIndex;
	unsigned long inBeginAddr;
	bool isNewSearch;

#ifdef DEBUG
	cout << "Input buffer: "	<< endl;
	cout << "Call Mark: "		<< in.callMark << '\t';
	cout << "Sec Call Mark: "	<< in.callSecMark << endl;
	cout << "Ret Mark: "		<< in.retMark << '\t';
	cout << "Sec Ret Mark: "	<< in.retSecMark << endl;
	cout << "Input Addr: "		<< hex << in.buffer.beginAddr << '\t';
	cout << "Input Size: "		<< in.buffer.size << endl;

	cout << "Output buffer: "	<< endl;
	cout << "Call Mark: "		<< out.callMark << '\t';
	cout << "Sec Call Mark: "	<< out.callSecMark << endl;
	cout << "Ret Mark: "		<< out.retMark << '\t';
	cout << "Sec Ret Mark: "	<< out.retSecMark << endl;
	cout << "Output Addr: "		<< hex << out.buffer.beginAddr << '\t';
	cout << "Output Size: "		<< out.buffer.size << endl;
#endif

	inBytes = in.buffer.size / BIT_TO_BYTE;
	inBeginAddr = in.buffer.beginAddr;
	numInByteSearch = 0;
	isNewSearch = true;
	byteIndex = 0;

// Process 1st byte of each ponential avalanche buffer
LABEL_STAGE_ONE:
	while(byteIndex < inBytes){


		prev_s = curr_s;
		curr_s = initialBeginNode(in, inBeginAddr, m_logAesRec);

		// Temporary Optimize
		// No need to search propagte result for duplicate begin node
		if(!isSameNode(prev_s, curr_s) ){
			propagateResult = propagate.getPropagateResult(curr_s,m_logAesRec);
#ifdef DEBUG
			// cout << "Number of propagate result: " << propagateResult.size() << endl;
			// for(auto s : propagateResult){
			// 	cout << "Addr: " << hex << s.i_addr << endl;
			// 	cout << "Size: " << s.sz / BIT_TO_BYTE << " bytes" << endl;
			// }
#endif
			vTempAvalancheRes = getAvalancheInNewSearch(propagateResult, out);

			if(!vTempAvalancheRes.empty() ){
				avalRes.avalIn.beginAddr = inBeginAddr;
				avalRes.avalIn.size = 1 * BIT_TO_BYTE;
				goto LABEL_STAGE_TWO;	
			}
		}

		inBeginAddr++;
		byteIndex++;
		numInByteSearch++;
	}

// Process rest bytes of each ponential avalanche buffer
LABEL_STAGE_TWO:
	while(byteIndex < inBytes){
		byteIndex++;
	}
}


AvalancheResBetweenInAndOut SearchAvalanche::searchAvalancheBetweenInAndOut(FunctionCallBuffer &in, FunctionCallBuffer &out)
{
	NodePropagate s, curr_s, prev_s;
	Propagate propagate;
	unordered_set<Node, NodeHash> propagateRes;

	unsigned long inBeginAddr;
	unsigned int numInByteAccumulate, byteIndex;

	Buffer avalIn;
	vector<Buffer> vAvalOut;
	vector<FunctionCallBuffer> vFuncAvalOut;

	AvalancheRes avalRes;
	AvalancheResBetweenInAndOut avalResInOut;

	avalIn.beginAddr = 0;
	avalIn.size = 0;
	vAvalOut.clear();

	avalRes.avalIn.beginAddr = 0;
	avalRes.avalIn.size = 0;
	avalRes.vAvalOut.clear();

	assignFunctionCallBuffer(avalResInOut.in, in);
	assignFunctionCallBuffer(avalResInOut.out, out);
	avalResInOut.vAvalacheRes.clear();

	byteIndex = 0;
	numInByteAccumulate = 0;
	inBeginAddr = in.buffer.beginAddr;

// Process first stage
LABEL_S_ONE:
	while(byteIndex < in.buffer.size / BIT_TO_BYTE){
		s = initialBeginNode(in, inBeginAddr, m_logAesRec);
		propagateRes = propagate.getPropagateResult(s, m_logAesRec);
		vFuncAvalOut = getAvalancheInNewSearch(propagateRes, out);

		// if 1st byte can propagate to any valid subset of out?
		if(!vFuncAvalOut.empty() ){
			// we don't need vFuncAvalOut, only need vAvalOut
			// need to transfer
			for(vector<FunctionCallBuffer>::iterator it = vFuncAvalOut.begin(); 
				it != vFuncAvalOut.end(); ++it){
				Buffer buf;
				buf.beginAddr = it->buffer.beginAddr;
				buf.size = it->buffer.size;
				vAvalOut.push_back(buf);
			}
			// 1st byte has propagate result, init avalIn
			avalIn.beginAddr = inBeginAddr;
			avalIn.size = 1 * BIT_TO_BYTE;

			byteIndex++;
			numInByteAccumulate++;
			inBeginAddr++;
			goto LABEL_S_TWO;		
		} else{
			byteIndex++;
			inBeginAddr++;
		}
	}

LABEL_S_TWO:
	while(byteIndex < in.buffer.size / BIT_TO_BYTE){
		prev_s = curr_s;
		curr_s = initialBeginNode(in, inBeginAddr, m_logAesRec);
		if(!isSameNode(prev_s, curr_s)){
			propagateRes = propagate.getPropagateResult(s, m_logAesRec);
			vAvalOut = getAvalancheInRestByte(propagateRes, vAvalOut);
		}

		if(!vAvalOut.empty() ){
			// can propagate, accumulate size
			avalIn.size += 1 * BIT_TO_BYTE;

			byteIndex++;
			numInByteAccumulate++;
			inBeginAddr++;
		} else{
			// clear avalIn, vAvalOut
			if(numInByteAccumulate >= VALID_AVALANCHE_LEN){
				// save avalIn, vAvalOut to AvalancheRes
				saveAvalancheResult(avalRes, avalIn, vAvalOut);
				avalResInOut.vAvalacheRes.push_back(avalRes);
			}
			clearAvalacheResult(avalRes, avalIn, vAvalOut);
			byteIndex++;
			numInByteAccumulate = 0;
			inBeginAddr++;
			goto LABEL_S_ONE;
		}
	}

	// if all bytes of in can propagate to all of out
	if(avalIn.beginAddr != 0 && 
	   avalIn.size / BIT_TO_BYTE >= VALID_AVALANCHE_LEN && 
	   !vAvalOut.empty() ){
		saveAvalancheResult(avalRes, avalIn, vAvalOut);
		avalResInOut.vAvalacheRes.push_back(avalRes);
	}

	return avalResInOut;
}

void SearchAvalanche::searchAvalancheBetweenInAndOutDebug(FunctionCallBuffer &in, FunctionCallBuffer &out)
{
	NodePropagate s;
	unordered_set<Node, NodeHash> propagateResult;
	Propagate propagate;

	s = initialBeginNode(in, in.buffer.beginAddr, m_logAesRec);
	propagateResult = propagate.getPropagateResult(s, m_logAesRec);
#ifdef DEBUG
	cout << "Number of propagate result: " << propagateResult.size() << endl;
	for(auto s : propagateResult){
		cout << "Addr: " << hex << s.i_addr << endl;
		cout << "Size: " << s.sz / BIT_TO_BYTE << " bytes" << endl;
	}
#endif
}

void SearchAvalanche::printAvalResBetweenInAndOut(AvalancheResBetweenInAndOut &avalResInOut)
{
	cout << "Search Avalache Input Buffer: " << endl;
	printFunctionCallBuffer(avalResInOut.in);
	cout << "Search Avalache Output Buffer: " << endl;
	printFunctionCallBuffer(avalResInOut.out);
	if(!avalResInOut.vAvalacheRes.empty() ){
		for(auto s : avalResInOut.vAvalacheRes){
			printAvalancheRes(s);
		}
	} else
		cout << "no avalanche found between the input and output buffer" << endl;
}

void SearchAvalanche::printFunctionCallBuffer(FunctionCallBuffer &a)
{
	cout << "Call Mark: " << a.callMark << endl;
	cout << "Sec Call Mark: " << a.callSecMark << endl;
	cout << "Ret Mark: " << a.retMark << endl;
	cout << "Sec Ret Mark: " << a.retSecMark << endl;
	cout << "Buffer Begin Addr: " << hex << a.buffer.beginAddr << endl;
	cout << "Buffer Size: " << dec << a.buffer.size / BIT_TO_BYTE << endl; 
}

void SearchAvalanche::printAvalancheRes(AvalancheRes &avalRes)
{
	cout << "avalache effect from buffer: " << endl;
	cout << "Buffer begin addr: " << hex << avalRes.avalIn.beginAddr << endl;
	cout << "Buffer size: " << dec << avalRes.avalIn.size / BIT_TO_BYTE << endl;

	cout << "avalache effect to buffers: " << endl;
	for(auto s : avalRes.vAvalOut)
		printBuffer(s);

}

void SearchAvalanche::printFuncCallContBuf(std::vector<Func_Call_Cont_Buf_t> &vFuncCallContBuf)
{
	int funcCallIndex;
	int contBufIndex;
	int numTotalContBuf;

	cout << "Number of funcation calls: " << vFuncCallContBuf.size() << endl;

	funcCallIndex = 0;
	numTotalContBuf = 0;
	for (auto s : vFuncCallContBuf){
		cout << "Function Call Index: " << funcCallIndex << endl;
		cout << "Call Mark: " << s.call_mark << endl;
		cout << "Sec Call Mark: " << s.sec_call_mark << endl;
		cout << "Ret Mark: " << s.ret_mark << endl;
		cout << "Sec Ret Mark: " << s.sec_ret_mark << endl;

		cout << "continuous buffers in this function call: " << endl;
		contBufIndex = 0;
		for(auto t : s.cont_buf){
			if(t.size / BIT_TO_BYTE > VALID_AVALANCHE_LEN && 
			   !isKernelAddress(t.begin_addr)){
				cout << "Begin Addr: " << hex << t.begin_addr << endl;
				cout << "Size: " << dec << t.size / BIT_TO_BYTE << endl;
				cout << "----------" << endl;
				contBufIndex++;
				numTotalContBuf++;
			}
		}
		cout << "number of valid continuous buffers: " << contBufIndex << endl;
		cout << "--------------------" << endl;
		funcCallIndex++;
	}
	cout << "number of total continuout buffers: " << numTotalContBuf << endl;
}

void SearchAvalanche::printBuffer(Buffer &a)
{
	cout << "Buffer Begin Addr: " << hex << a.beginAddr << endl;
	cout << "Buffer Size: " << dec << a.size / BIT_TO_BYTE << endl; 
}