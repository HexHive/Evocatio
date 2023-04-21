#include "config.h"
#include "sanitizer/asan_interface.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t __afl_evocatio_already_init = 0;
static uint8_t __afl_using_capfuzz = 0;
static uint8_t* __afl_cap_res_path;

static unsigned int __afl_evocatio_GetHash(char* str, unsigned int len)
{
    unsigned int hash = 5381;
    unsigned int i    = 0;

    for(i = 0; i < len; str++, i++)
    {
        hash = ((hash << 5) + hash) + (*str);
    }

    return hash;
}

static inline void __afl_evocatio_WriteCapText(char *path, char *cap_text) {

    uint8_t ret;

    ret = open(path, O_RDWR | O_CREAT | O_EXCL, EVOCATIO_DEFAULT_PERMISSION);

    if (ret < 0) {
	    fprintf(stderr, "%s: Unable to create '%s'", __func__, path);
    } else {
	    FILE *fp = fopen(path,"w");
	    fprintf(fp, "%s", cap_text);
	    fclose(fp);
    }

    return;
}

static inline void __afl_evocatio_WriteCapHash(char *path, uint64_t *cap_hash) {

    uint8_t ret;

    ret = open(path, O_RDWR | O_CREAT | O_EXCL, EVOCATIO_DEFAULT_PERMISSION);

    if (ret < 0) {
	    fprintf(stderr, "%s: Unable to create '%s'", __func__, path);
    } else {
	    FILE *fp = fopen(path,"w");
	    fwrite(&cap_hash, sizeof(cap_hash)/2, 1, fp);
	    fclose(fp);
    }

    return;
}

static inline void __afl_evocatio_TryInit() {
    if (!__afl_evocatio_already_init) {
        if (getenv(EVOCATIO_ENV_CAPFUZZ)) __afl_using_capfuzz = 1;
        __afl_cap_res_path = getenv(EVOCATIO_ENV_RESPATH);
        if (!__afl_cap_res_path) {
            __afl_cap_res_path = EVOCATIO_DEFAULT_RESPATH;
        }
        __afl_evocatio_already_init = 1;
    }
}

static inline void __afl_evocatio_GetCapability() {
    const char *bugT;
    char       *operaT;
    void       *invalidAddr;
    uint64_t   accessLen;

    //const char *objectType;
    uint64_t   allocStackHash;

    bugT        = __asan_get_report_description();
    operaT      = __asan_get_report_access_type() ? "write": "read";
    invalidAddr = __asan_get_report_address();
    accessLen   = __asan_get_report_access_size();
    
    char invalidAddr_buf[20];
    snprintf(invalidAddr_buf, sizeof(invalidAddr_buf)-1, "%llu", (unsigned long long)invalidAddr);
    char accessLen_buf[20];
    snprintf(accessLen_buf, sizeof(accessLen_buf)-1, "%llu", (unsigned long long)accessLen);

    char *hash_string_ori = (char *) malloc(100);

    if (!__afl_using_capfuzz) {
        strcpy(hash_string_ori, bugT);            strcat(hash_string_ori, EVOCATIO_IDENTIFIER);
        strcat(hash_string_ori, operaT);          strcat(hash_string_ori, EVOCATIO_IDENTIFIER);
        strcat(hash_string_ori, accessLen_buf);   strcat(hash_string_ori, EVOCATIO_IDENTIFIER);
        strcat(hash_string_ori, invalidAddr_buf); strcat(hash_string_ori, EVOCATIO_IDENTIFIER);
        __afl_evocatio_WriteCapText(__afl_cap_res_path, hash_string_ori);
        return;
    }

    /* DEADLOCK RISK - DO NOT USE! 
       https://github.com/llvm/llvm-project/issues/61860 */
    // Get object type
    //char varName[100];
    //objectType = __asan_locate_address(invalidAddr, varName, 100, NULL, NULL);

    // Get allocation stack trace
    size_t maxAllocFrames = 20;
    void **allocFrames = calloc(maxAllocFrames, sizeof(void*));
    size_t nFrames= __asan_get_alloc_stack(invalidAddr, allocFrames, maxAllocFrames, NULL);

    // Compute allocation stack trace hash
    allocStackHash = 0;
    char allocStackHash_buf[20] = "";
    if (nFrames > 0) {
        // Concatenate addresses
        size_t len = 14*maxAllocFrames + 1;
        char buff[len];
        for (int i = 0; i < nFrames; i++)
            snprintf(&(buff[14*i]), 15, "%p", allocFrames[i]);

        allocStackHash = __afl_evocatio_GetHash(buff, strlen(buff));
        snprintf(allocStackHash_buf, sizeof(allocStackHash_buf)-1, "%lu", allocStackHash);
    }

    // Free allocFrames
    free(allocFrames);

    strcpy(hash_string_ori, bugT);
    strcat(hash_string_ori, operaT);
    strcat(hash_string_ori, accessLen_buf);
    //strcat(hash_string_ori, objectType); //DEADLOCK RISK - DO NOT USE! https://github.com/llvm/llvm-project/issues/61860
    strcat(hash_string_ori, allocStackHash_buf);
    //strcat(hash_string_ori, invalidAddr_buf);

    uint64_t capability_hash = 0;
    capability_hash = __afl_evocatio_GetHash(hash_string_ori, strlen(hash_string_ori));

    //printf("capability hash is: %lu\n", capability_hash);
    __afl_evocatio_WriteCapHash(__afl_cap_res_path, capability_hash);
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
    __afl_evocatio_TryInit();
    __afl_evocatio_GetCapability();
}