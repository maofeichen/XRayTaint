#ifndef XT_FLAG_H
#define XT_FLAG_H

#include <string>

using namespace std;

namespace flag
{
    const string XT_SIZE_BEGIN      = "20";
    const string XT_SIZE_END        = "24";

    const string XT_INSN_ADDR       = "32";
    const string XT_TCG_DEPOSIT     = "4a";

    const string XT_CALL_INSN       = "14";
    const string XT_CALL_INSN_SEC   = "15";
    const string XT_CALL_INSN_FF2   = "1a";
    const string XT_CALL_INSN_FF2_SEC   = "1b";

    const string XT_RET_INSN        = "18";
    const string XT_RET_INSN_SEC    = "19";

    const string TCG_QEMU_LD        = "52";
    const string TCG_QEMU_LD_POINTER	= "56";
    const string TCG_QEMU_ST        = "5a";
    const string TCG_QEMU_ST_POINTER	= "5e";

    const int NUM_TCG_LD			= 0x52;
    const int NUM_TCG_LD_POINTER	= 0x56;
    const int NUM_TCG_ST			= 0x5a;
    const int NUM_TCG_ST_POINTER	= 0x5e;

    const string TCG_ADD            = "3b";
    const string TCG_XOR            = "47";
}
#endif
