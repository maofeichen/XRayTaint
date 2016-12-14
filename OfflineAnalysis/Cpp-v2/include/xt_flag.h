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
    const string XT_CALL_INSN_FF2   = "4e";
    const string XT_CALL_INSN_2nd   = "4b";
    const string XT_CALL_INSN_3nd   = "4d";

    const string XT_RET_INSN        = "18";
    const string XT_RET_INSN_2nd    = "4c";

    const string TCG_QEMU_LD        = "34";
    const string TCG_QEMU_ST        = "35";

    const string TCG_ADD            = "3b";
    const string TCG_XOR            = "40";
}
#endif
