#include <PR/os_internal.h>
#include "viint.h"

void *osViGetNextFramebuffer(void) {
    register u32 saveMask = __osDisableInt();
    void *framep = __osViNext->framep;
    
    __osRestoreInt(saveMask);
    return framep;
}
