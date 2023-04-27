#include "config.h"
#include "types.h"
#include "sanitizer/asan_interface.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static inline const char *__afl_evo_ChkBugType() { 
    return __asan_get_report_description(); 
}

static inline const char *__afl_evo_ChkOpsType() {
    return __asan_get_report_access_type() ? "write": "read";
}

static inline const char *__afl_evo_ChkObjType() {
/* DEADLOCK RISK - DO NOT USE UNLESS SOLVED THIS ISSUE
    https://github.com/llvm/llvm-project/issues/61860 */
    void *obj_addr = __asan_get_report_address();
    //Use like those in llvm-project/compiler-rt/test/asan/TestCases/debug_locate.cpp
    return __asan_locate_address(obj_addr, NULL, 0, NULL, NULL);
}

static inline u64 __afl_evo_ChkInvalidAddr() {
    return (u64) __asan_get_report_address();
}

static inline u64 __afl_evo_ChkAccessLen() {
    return (u64) __asan_get_report_access_size();
}

static inline u32 __afl_evo_ChkStackHash() {
    u32 stack_hash = 0;

    void **frame_ptrs = malloc(EVOCATIO_STACK_FRAME_MAXNUM * sizeof(void*));
    if (unlikely(!frame_ptrs)) {
        fprintf(stderr, "%s: malloc failed", __func__);
        return stack_hash;
    }
    
    void *assume_heap_addr = __asan_get_report_address();
    size_t i;
    size_t n_frames = __asan_get_alloc_stack(assume_heap_addr,
                frame_ptrs, (size_t)EVOCATIO_STACK_FRAME_MAXNUM, NULL);

    if (n_frames > 0) {
        // 1 pointer is N bytes in mem so need 2+(N<<1) hex numbers (max) in string "0xFF...". Don't forget '\0'.
        u32   stack_len = 0;
        char *stack_str = (char *) calloc(1 + n_frames * (2 + (sizeof(void*) << 1)), sizeof(char));
        if (unlikely(!stack_str)) {
            fprintf(stderr, "%s: calloc failed", __func__);
            return stack_hash;
        }
        //make snprintf believe that it can write 0xFF...FF\0
        size_t write_most = 1 + 2 + (sizeof(void*) << 1);
        int    write_some = 0;
        for (size_t i = 0; i < n_frames; ++i) {
            write_some = snprintf((stack_str + stack_len), write_most, "%p", frame_ptrs[i]);
            if (unlikely(write_some < 0 || write_some >= write_most)) break; //should never happen
            stack_len += write_some;
        }
        stack_hash = __afl_evo_GetHash(stack_str, stack_len);
        free(stack_str);
    }
    free(frame_ptrs);
    return stack_hash;
}

static inline void __afl_evo_GetCapability() {
    char * cap_text_buf = NULL;

    const char * bugT   = __afl_evo_ChkBugType();
    const char * operaT = __afl_evo_ChkOpsType();

    u64  invalidAddr = __afl_evo_ChkInvalidAddr();
    char invalidAddr_buf[1 + 20]; //max: "18446744073709551615\0"
    snprintf(invalidAddr_buf, sizeof(invalidAddr_buf), "%llu", invalidAddr);

    u64  accessLen = __afl_evo_ChkAccessLen();
    char accessLen_buf[1 + 20]; //max: "18446744073709551615\0"
    snprintf(accessLen_buf, sizeof(accessLen_buf), "%llu", accessLen);

    if (unlikely(!__afl_evo_using_capfuzz)) {
        cap_text_buf = (char *) calloc((
                strlen(bugT)            + sizeof(EVOCATIO_IDENTIFIER)-1 + \
                strlen(operaT)          + sizeof(EVOCATIO_IDENTIFIER)-1 + \
                strlen(invalidAddr_buf) + sizeof(EVOCATIO_IDENTIFIER)-1 + \
                strlen(accessLen_buf)   + sizeof(EVOCATIO_IDENTIFIER)
            ), sizeof(char));

        if(unlikely(!cap_text_buf)) {
            fprintf(stderr, "%s: calloc failed", __func__);
            return;
        }

        strcat(cap_text_buf, bugT);            strcat(cap_text_buf, EVOCATIO_IDENTIFIER);
        strcat(cap_text_buf, operaT);          strcat(cap_text_buf, EVOCATIO_IDENTIFIER);
        strcat(cap_text_buf, accessLen_buf);   strcat(cap_text_buf, EVOCATIO_IDENTIFIER);
        strcat(cap_text_buf, invalidAddr_buf); strcat(cap_text_buf, EVOCATIO_IDENTIFIER);

        __afl_evo_SaveCap(cap_text_buf, 0);
        free(cap_text_buf);
        return;
    }

    u64  allocStackHash = __afl_evo_ChkStackHash();
    char allocStackHash_buf[1 + 20]; //max: "18446744073709551615\0"
    snprintf(allocStackHash_buf, sizeof(allocStackHash_buf), "%llu", allocStackHash);

    cap_text_buf = (char *) calloc((
                strlen(bugT)            + strlen(operaT) + \
                strlen(invalidAddr_buf) + strlen(accessLen_buf) + \
                strlen(allocStackHash_buf) + 1
            ), sizeof(char));

    if(unlikely(!cap_text_buf)) {
        fprintf(stderr, "%s: calloc failed", __func__);
        return;
    }

    strcat(cap_text_buf, bugT);
    strcat(cap_text_buf, operaT);
    //strcat(cap_text_buf, invalidAddr_buf);//currently disabled for suitable sensitivity
    strcat(cap_text_buf, accessLen_buf);
    strcat(cap_text_buf, allocStackHash_buf);

    __afl_evo_SaveCap(cap_text_buf, 1);
    free(cap_text_buf);
    return;
}

/**
 * https://github.com/llvm/llvm-project/blob/main/compiler-rt/include/sanitizer/asan_interface.h
 * void __asan_on_error(void);
 * 
 * https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/asan/asan_report.cpp
 * SANITIZER_INTERFACE_WEAK_DEF(void, __asan_on_error, void) {}
*/
void __asan_on_error(void) {
    __afl_evo_TryInit();
    __afl_evo_GetCapability();
}