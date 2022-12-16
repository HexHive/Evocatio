#include "sanitizer/asan_interface.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_PERMISSION 0600

/*
 * This is our custom implemantation of `__asan_on_error`.
 * This is called by ASan before crashing. Inside it we
 * have access to all fuctions defined in this header file:
 *
 * https://github.com/llvm/llvm-project/blob/main/compiler-rt/include/sanitizer/asan_interface.h
 */

unsigned int DJBHash(char* str, unsigned int len)
{
    unsigned int hash = 5381;
    unsigned int i    = 0;

    for(i = 0; i < len; str++, i++)
    {
        hash = ((hash << 5) + hash) + (*str);
    }

    return hash;
}

static void write_capability_hash_to_file(char *path, uint64_t capHash) {

    uint8_t ret;

    ret = open(path, O_RDWR | O_CREAT | O_EXCL, DEFAULT_PERMISSION);

    if (ret < 0) {
	fprintf(stderr, "Unable to create '%s'", path);
    } else {
	FILE *fp = fopen(path,"w");
	fwrite(&capHash, sizeof(capHash)/2, 1, fp);
	fclose(fp);
    }

    return;
}

void __my_asan_on_error() {
    const char *bugT;
    char *operaT;
    void *invalidAddr;
    uint64_t accessLen;
    const char *objectType;
    uint64_t allocStackHash;

    bugT = __asan_get_report_description();
    operaT = __asan_get_report_access_type() ? "write": "read";
    invalidAddr = __asan_get_report_address();
    accessLen = __asan_get_report_access_size();
    char invalidAddr_buf[20];
    snprintf(invalidAddr_buf, sizeof(invalidAddr_buf)-1, "%llu", (unsigned long long)invalidAddr);
    char accessLen_buf[20];
    snprintf(accessLen_buf, sizeof(accessLen_buf)-1, "%llu", (unsigned long long)accessLen);

    // Get object type
    char varName[100];
    objectType = __asan_locate_address(invalidAddr, varName, 100, NULL, NULL);

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

        allocStackHash = DJBHash(buff, strlen(buff));
        snprintf(allocStackHash_buf, sizeof(allocStackHash_buf)-1, "%lu", allocStackHash);
    }

    // Free allocFrames
    free(allocFrames);

    char *hash_string_ori = (char *) malloc(100);
    strcpy(hash_string_ori, bugT);
    strcat(hash_string_ori, operaT);
    strcat(hash_string_ori, accessLen_buf);
    strcat(hash_string_ori, objectType);
    strcat(hash_string_ori, allocStackHash_buf);
    //strcat(hash_string_ori, invalidAddr_buf);

    uint64_t capability_hash = 0;
    capability_hash = DJBHash(hash_string_ori, strlen(hash_string_ori));

    //printf("capability hash is: %lu\n", capability_hash);
    write_capability_hash_to_file("/tmp/cap_res_file", capability_hash);    // HACK! HardCode file path!

}
