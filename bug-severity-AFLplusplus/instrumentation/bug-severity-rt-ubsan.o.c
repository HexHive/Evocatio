#include "config.h"
#include "types.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* EXPERIMENTAL: LLVM 12.0.1 SPECIFED
https://github.com/llvm/llvm-project/blob/llvmorg-12.0.1/compiler-rt/test/ubsan/TestCases/Misc/monitor.cpp
*/

void __ubsan_get_current_report_data(
    const char **OutIssueKind,
    const char **OutMessage,
    const char **OutFilename,
    unsigned *OutLine, unsigned *OutCol,
    char **OutMemoryAddr
);

static u8  __afl_evo_already_init  = 0;
static u8  __afl_evo_using_capfuzz = 0;
static u8 *__afl_evo_cap_res_path;

static inline void __afl_evo_TryInit() {
    if (likely(!__afl_evo_already_init)) {
        if (getenv(EVOCATIO_ENV_CAPFUZZ)) 
            { __afl_evo_using_capfuzz = 1; }

        if (!(__afl_evo_cap_res_path = getenv(EVOCATIO_ENV_RESPATH)))
            { __afl_evo_cap_res_path = EVOCATIO_DEFAULT_RESPATH; }

        __afl_evo_already_init = 1;
    }
}

static inline u32 __afl_evo_GetHash(char *str, u32 len) {
//Use DJBHash (Daniel J. Bernstein). May switch to xxhash.h in future.
    u32 hash = 5381;
    for(u32 i = 0; i < len; ++i)
      { hash = ((hash << 5) + hash) + (*str); str++;}
    return hash;
}

static inline void __afl_evo_SaveCap(char *cap_text, u8 hashed) {
    if (unlikely(!__afl_evo_cap_res_path)) return;
    //Use ANSI-C style
    FILE *fp = fopen(__afl_evo_cap_res_path, "w");
    if (likely(fp)) {
        if (unlikely(!hashed)) {
            fprintf(fp, "%s", cap_text);
            //fprintf(stderr, "CAP TEXT: %s", cap_text); //for debug
        } else {
            u32 cap_hash = __afl_evo_GetHash(cap_text, strlen(cap_text));
            fwrite(&cap_hash, sizeof(u32), 1, fp);
            //fprintf(stderr, "CAP HASH: %u", cap_hash); //for debug
        }
        fclose(fp);
    } else {
        fprintf(stderr, "%s: Unable to create '%s'", __func__, __afl_evo_cap_res_path);
    }
}

static inline void __afl_evo_GetCapability() {
    char * cap_text_buf = NULL;

    const char *IssueKind = NULL;
    const char *Message   = NULL;
    const char *Filename  = NULL;
    unsigned Line=0, Col=0;
    char *Addr;
    __ubsan_get_current_report_data(
        &IssueKind,
        &Message, &Filename, &Line, &Col,
        &Addr
    );

    size_t buf_ofs = 0;
    if (IssueKind) buf_ofs += strlen(IssueKind);
    if (Message)   buf_ofs += strlen(Message);
    if (Filename)  buf_ofs += strlen(Filename);
    buf_ofs += 12; //max: "4294967295\0"
    buf_ofs += 12; //max: "4294967295\0"

    cap_text_buf = (char *) calloc(buf_ofs, sizeof(char));

    if(unlikely(!cap_text_buf)) {
        fprintf(stderr, "%s: calloc failed", __func__);
        return;
    }

    snprintf(cap_text_buf, buf_ofs, 
        "%s%s%s%u%u",
        IssueKind ? IssueKind : "",
        Message   ? Message   : "",
        Filename  ? Filename  : "",
        Line, Col
    );

    __afl_evo_SaveCap(cap_text_buf, 1);
    free(cap_text_buf);
    return;
}

/**
 * https://github.com/llvm/llvm-project/blob/ef32c611aa214dea855364efd7ba451ec5ec3f74/compiler-rt/lib/ubsan/ubsan_monitor.cpp#L38-L39
 * SANITIZER_WEAK_DEFAULT_IMPL
 * void __ubsan::__ubsan_on_report(void) {}
 * 
 * https://github.com/llvm/llvm-project/blob/ef32c611aa214dea855364efd7ba451ec5ec3f74/compiler-rt/lib/ubsan/ubsan_monitor.h#L33-L35
 * extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __ubsan_on_report(void);
*/
void __ubsan_on_report(void) {
    __afl_evo_TryInit();
    __afl_evo_GetCapability();
}