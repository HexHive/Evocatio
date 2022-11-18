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

/*
 * We only monitor the same buffer
 * */
static uint8_t is_same_buffer(uint64_t allocStackHash_cur) {
    uint8_t is_same = 0;
    char *buffer_pc_prev_path = "/tmp/buffer_pc_prev";
    uint64_t allocStackHash_prev = 0;

    // STEP 1: check previous buffer alloc stack hash from temp file
    uint8_t ret;

    ret = open(buffer_pc_prev_path, O_RDWR | O_CREAT | O_EXCL, DEFAULT_PERMISSION);

    if (ret < 0) {
        fprintf(stderr, "Unable to create '%s'", buffer_pc_prev_path);
    } else {
        FILE *fp = fopen(buffer_pc_prev_path,"r");
        if (fp == NULL) {
            fprintf(stderr, "Unable to read '%s'", buffer_pc_prev_path);
            return 0;
        }

        fread(&allocStackHash_prev, 4, 1, fp);  // HACK! capability hash length is fixed now!
        fclose(fp);
    }

    // STEP 2: compare pc
    if (allocStackHash_cur == allocStackHash_prev) {
        is_same = 1;
    } else {
        is_same = 0;
    }

    // STEP 3: dump pc address when this is the first error report
    if (allocStackHash_prev == 0) {
        FILE *fp = fopen(buffer_pc_prev_path,"w");
        fwrite(&allocStackHash_cur, sizeof(allocStackHash_cur)/2, 1, fp);
        fclose(fp);

        return 1;
    }

    return is_same;
}

/* *****************************************************************************
 * Original version of Asan will stop execution at the first error, if
 * there is a loop, in which the invalid access length can be accumulated,
 * Asan will lost this information. In order to solve this problem, we keep
 * the program running until SEGV/Normal exit, so that we can record the invalid
 * access length in total.
 * ****************************************************************************/
static uint64_t check_repeat_access(uint64_t invalidAddr_cur, uint64_t buf_alloc_hash_cur) {
    char *access_addr_prev_path = "/tmp/acc_addr_prev";
    uint64_t addr_prev = 0;
    uint64_t access_len = 0;

    // STEP 0: we calculate the access length only when we are at the same pc
    if (is_same_buffer(buf_alloc_hash_cur)) {
        // Nice! let's calculate the access length
    } else {
        // This is not the same buffer, let's quit now!
        return (unsigned long long)-1;
    }
    // STEP 1: check previous accessing address from temp file
    uint8_t ret;

    ret = open(access_addr_prev_path, O_RDWR | O_CREAT | O_EXCL, DEFAULT_PERMISSION);

    if (ret < 0) {
        fprintf(stderr, "Unable to create '%s'", access_addr_prev_path);
    } else {
        FILE *fp = fopen(access_addr_prev_path,"r");
        if (fp == NULL) {
            fprintf(stderr, "Unable to read '%s'", access_addr_prev_path);
            return (unsigned long long)-1;
        }

        fread(&addr_prev, 8, 1, fp);  // HACK! capability hash length is fixed now!
        fclose(fp);
    }

    // STEP 2: calculate access length (access_addr_cur - access_addr_prev)
    if (addr_prev)
        access_len = invalidAddr_cur - addr_prev;

    // STEP 3: update previous address file with current access address
    FILE *fp = fopen(access_addr_prev_path,"w");
    fwrite(&invalidAddr_cur, sizeof(invalidAddr_cur), 1, fp);
    fclose(fp);

    return access_len;
}

void __my_asan_on_error() {
    const char *bugT;
    char *operaT;
    void *invalidAddr;
    uint64_t accessLen;
    // const char *objectType;
    uint64_t allocStackHash;
    uint64_t access_addr_cur;
    uint64_t accessLenAccumulate;      // access length accumulated by loop, new feature of CapSan than Asan
    uint64_t pc_current;

    bugT = __asan_get_report_description();
    operaT = __asan_get_report_access_type() ? "write": "read";
    invalidAddr = __asan_get_report_address();
    accessLen = __asan_get_report_access_size();
    char invalidAddr_buf[20];
    snprintf(invalidAddr_buf, sizeof(invalidAddr_buf)-1, "%llu", (unsigned long long)invalidAddr);
    char accessLen_buf[20];
    snprintf(accessLen_buf, sizeof(accessLen_buf)-1, "%llu", (unsigned long long)accessLen);

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

    // Calculate accumulate access length
    access_addr_cur = (unsigned long long)invalidAddr;
    accessLenAccumulate = check_repeat_access(access_addr_cur, allocStackHash);

    if (accessLenAccumulate == (unsigned long long)-1) {
        return;
    }

    char accessLenAccumulate_buf[20];
    snprintf(accessLenAccumulate_buf, sizeof(accessLenAccumulate_buf)-1, "%llu", (unsigned long long)accessLenAccumulate);


    // Prepare capability summary data
    char *hash_string_ori = (char *) malloc(100);
    strcpy(hash_string_ori, bugT);
    strcat(hash_string_ori, accessLen_buf);
    strcat(hash_string_ori, operaT);
    // strcat(hash_string_ori, objectType);
    // strcat(hash_string_ori, allocStackHash_buf);
    // strcat(hash_string_ori, invalidAddr_buf);
    strcat(hash_string_ori, accessLenAccumulate_buf);

    uint64_t capability_hash = 0;
    capability_hash = DJBHash(hash_string_ori, strlen(hash_string_ori));

    //printf("capability hash is: %lu\n", capability_hash);
    write_capability_hash_to_file("/tmp/cap_res_file", capability_hash);    // HACK! HardCode file path!

}
