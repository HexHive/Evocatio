/*
   american fuzzy lop++ - test case minimizer
   ------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com> and
                        Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   A simple test case minimizer that takes an input file and tries to remove
   as much data as possible while keeping the binary in a crashing state
   *or* producing consistent instrumentation output (the mode is auto-selected
   based on the initially observed behavior).

 */

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"
#include "forkserver.h"
#include "sharedmem.h"
#include "common.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>

#include <sys/wait.h>
#include <sys/time.h>
#ifndef USEMMAP
  #include <sys/shm.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>

#include "cJSON.h"
#include "khash.h"
KHASH_MAP_INIT_INT64(m64HashTable, unsigned int)   // instantiate structs and methods

khash_t(m64HashTable) *all_cap_hashTable;     /* all capabilities we have ever seen */

#ifdef WORD_SIZE_64
  u64 ori_hit_count = UINT64_MAX;
  u64 cur_hit_count;
  int8_t is_64 = 1;
#else
  u32 ori_hit_count = UINT32_MAX;
  u32 cur_hit_count;
  int8_t is_64 = 0;
#endif

static u8 *mask_bitmap;                /* Mask for trace bits (-B)          */

static u8 *in_file,                    /* Minimizer input test case         */
    *out_file, *output_file,           /* Minimizer output file             */
    *input_byte_cons_file,             /* Minimizer input byte constraints file*/
    *new_seeds_dir;                    /* Dump new PoCs into this directory */

static u8 *pCapResFilePath;            /* Specify env var EVOCATIO_RESPATH  */
static u8 remove_cap_res_f;            /* remove cap_res_file on exit?      */

static u8 *in_data;                    /* Input data for trimming           */

static u32 in_len,                     /* Input data length                 */
    missed_hangs,                      /* Misses due to hangs               */
    missed_crashes,                    /* Misses due to crashes             */
    missed_paths,                      /* Misses due to exec path diffs     */
    map_size = MAP_SIZE;

static u64 orig_cksum;                 /* Original checksum                 */

static u8 crash_mode,                  /* Crash-centric mode?               */
    hang_mode,                         /* Minimize as long as it hangs      */
    exit_crash,                        /* Treat non-zero exit as crash?     */
    edges_only,                        /* Ignore hit counts?                */
    exact_mode,                        /* Require path match for crashes?   */
    remove_out_file,                   /* remove out_file on exit?          */
    remove_shm = 1,                    /* remove shmem on exit?             */
    debug,                             /* debug mode                        */
    heavy_mode;                        /* won't early abort when detect C-D */


static volatile u8 stop_soon;          /* Ctrl-C pressed?                   */

static afl_forkserver_t *fsrv;
static sharedmem_t       shm;
static sharedmem_t *     shm_fuzz;

u32 brute_start_pos, brute_end_pos;  /* Brute force start/end address */

u32 *critical_bytes;                  /* Bytes can introduce new capability */
u32 all_critical_byte_num;            /* Number of critical_bytes */
u32 all_capability_num;               /* The number of capabilities we have seen */


#define DEBUG 0
#define DUMP_SUM 1                      /* Dump capability summary into file or not? */
#define MAX_CAPABILITY_NUM 1000        /* How many capability we will keep at most */
#define CAPABILITY_LEN 60              /* How many bytes we have for each capability details */

char ori_capability[CAPABILITY_LEN];                        /* Original capability detail  */
char all_capabilities[MAX_CAPABILITY_NUM][CAPABILITY_LEN];  /* Restore all capabilities we have ever seen*/
char cur_capabilities[MAX_CAPABILITY_NUM][CAPABILITY_LEN];  /* Restore all capabilities current byte introduced */

u32 capability_cnt = 0;                  /* How many capability we already seen */
u32 cur_capability_cnt = 1;              /* How many capability current byte introduce */

u8 *ori_trace_bits;                  /* bitmap of original PoC       */

typedef enum {
    /* 00 */ NOBODY,                         /* This byte is neither C-byte nor D-byte  */
    /* 01 */ C_Byte,                         /* This is a C-byte            */
    /* 02 */ D_Byte,                         /* This is a D-byte            */
    /* 03 */ C_D_Byte,                       /* This is a C-D-byte          */
    /* 04 */ Non_Byte,                       /* This is a Non-crashing-byte */
    /* 05 */ C_Non_Byte,                     /* This is a C-non-byte        */
    /* 06 */ D_Non_Byte,                     /* This is a D-non-byte        */
    /* 07 */ C_D_Non_Byte                    /* This is a C-D-Non-byte      */
} FUNCTION_LABEL;

typedef enum {
    /* 00 */ NO_POWER,                  /* This byte has NO attacking power */
    /* 01 */ OPERATION_TYPE,            /* Invalid memory operation type, read or write?  */
    /* 02 */ ACCESS_LEN,                /* Invalid memory access length                   */
    /* 03 */ ACCESS_RANGE,              /* Invalid memory access range                    */
    /* 04 */ CRASH_LOC                  /* Crash address                                  */
} ATTACKING_LABEL;

struct pair {
  long left_addr;
  long right_addr;
};

struct byte_cons {
    FUNCTION_LABEL  func_lab;
    u32 capability_num;   /* How many capability this byte can introduce? */
};

typedef enum {
  /* 00 */ READ,                  /* This is an invalid READ */
  /* 01 */ WRITE                  /* This is an invalid WRITE */
} T_OPERATION;

typedef enum {
  /* 00 */ NOP,                  /* Junk Type */
  /* 01 */ HOF,                  /* Heap Buffer Overflow */
  /* 02 */ SOF                   /* Stack Buffer Overflow */
} T_BUG;

// TODO: this data structure needs to check further!
struct capability {
  T_OPERATION operation_t;
  u32 access_len[256];
  T_BUG bug_t[10];
  long invalid_addr[256];
  u8 bug_num;
  u32 access_len_num;
  u32 invalid_addr_num;
};

/*
 * forkserver section
 */

/* Classify tuple counts. This is a slow & naive version, but good enough here.
 */

#define TIMES4(x) x, x, x, x
#define TIMES8(x) TIMES4(x), TIMES4(x)
#define TIMES16(x) TIMES8(x), TIMES8(x)
#define TIMES32(x) TIMES16(x), TIMES16(x)
#define TIMES64(x) TIMES32(x), TIMES32(x)
static const u8 count_class_lookup[256] = {

    [0] = 0,
    [1] = 1,
    [2] = 2,
    [3] = 4,
    [4] = TIMES4(8),
    [8] = TIMES8(16),
    [16] = TIMES16(32),
    [32] = TIMES32(64),
    [128] = TIMES64(128)

};

#undef TIMES64
#undef TIMES32
#undef TIMES16
#undef TIMES8
#undef TIMES4

static sharedmem_t *deinit_shmem(afl_forkserver_t *fsrv,
                                 sharedmem_t *     shm_fuzz) {

  afl_shm_deinit(shm_fuzz);
  fsrv->support_shmem_fuzz = 0;
  fsrv->shmem_fuzz_len = NULL;
  fsrv->shmem_fuzz = NULL;
  ck_free(shm_fuzz);
  return NULL;

}

/* Apply mask to classified bitmap (if set). */

static void apply_mask(u32 *mem, u32 *mask) {

  u32 i = (map_size >> 2);

  if (!mask) { return; }

  while (i--) {

    *mem &= ~*mask;
    mem++;
    mask++;

  }

}

static void classify_counts(afl_forkserver_t *fsrv) {

  u8 *mem = fsrv->trace_bits;
  u32 i = map_size;
  cur_hit_count = 0;

  if (edges_only) {

    while (i--) {

      if (*mem) { *mem = 1; }
      mem++;

    }

  } else {

    while (i--) {
      /* Update cur_hit_count */
      cur_hit_count += *mem;

      *mem = count_class_lookup[*mem];
      mem++;

    }

  }

}

/* See if any bytes are set in the bitmap. */

static inline u8 anything_set(afl_forkserver_t *fsrv) {

  u32 *ptr = (u32 *)fsrv->trace_bits;
  u32  i = (map_size >> 2);

  while (i--) {

    if (*(ptr++)) { return 1; }

  }

  return 0;

}

static void at_exit_handler(void) {

  if (remove_shm) {

    if (shm.map) afl_shm_deinit(&shm);
    if (fsrv->use_shmem_fuzz) deinit_shmem(fsrv, shm_fuzz);

  }

  afl_fsrv_killall();
  if (remove_out_file) unlink(out_file);
  if (remove_cap_res_f) unlink(pCapResFilePath);
}

/* Read initial file. */

static void read_initial_file(void) {

  struct stat st;
  s32         fd = open(in_file, O_RDONLY);

  if (fd < 0) { PFATAL("Unable to open '%s'", in_file); }

  if (fstat(fd, &st) || !st.st_size) { FATAL("Zero-sized input file."); }

  if (st.st_size >= TMIN_MAX_FILE) {

    FATAL("Input file is too large (%u MB max)", TMIN_MAX_FILE / 1024 / 1024);

  }

  in_len = st.st_size;
  in_data = ck_alloc_nozero(in_len);

  ck_read(fd, in_data, in_len, in_file);

  close(fd);

  OKF("Read %u byte%s from '%s'.", in_len, in_len == 1 ? "" : "s", in_file);

}

/* There is no split() in C-language, so I have to write one :( */
void split(char *src,const char *separator,char **dest,int *num) {
  char *pNext;
  int count = 0;
  if (src == NULL || strlen(src) == 0)
    return;
  if (separator == NULL || strlen(separator) == 0)
    return;
  pNext = strtok(src,separator);
  while(pNext != NULL) {
    *dest++ = pNext;
    ++count;
    pNext = strtok(NULL,separator);
  }
  *num = count;
}

/* Write output file. */

static s32 write_to_file(u8 *path, u8 *mem, u32 len) {

  s32 ret;

  unlink(path);                                            /* Ignore errors */

  ret = open(path, O_RDWR | O_CREAT | O_EXCL, DEFAULT_PERMISSION);

  if (ret < 0) { PFATAL("Unable to create '%s'", path); }

  ck_write(ret, mem, len, path);

  lseek(ret, 0, SEEK_SET);

  return ret;

}

/* Dump capability hashes into file. */

static s32 dump_capability_hash_to_file(u8 *path) {
  s32 ret;

  ret = open(path, O_RDWR | O_CREAT | O_EXCL, DEFAULT_PERMISSION);

  if (ret < 0) { PFATAL("Unable to create '%s'", path); }

  cJSON *json = cJSON_CreateObject();

  for (u32 i = 0; i < capability_cnt; i++) {

  }
  return 0;
}

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

unsigned int calculate_hash(char capability[]) {
  unsigned int capability_hash = 0;
  const char *separator = "@@";
  char *revbuf[8] = {0};
  int num = 0;      /* Number of sub-string after split */
  split(capability, separator, revbuf, &num);

  char *hash_string_ori = ck_alloc(100);
  strcpy(hash_string_ori, revbuf[0]);
  strcat(hash_string_ori, revbuf[1]);
  strcat(hash_string_ori, revbuf[3]);
  strcat(hash_string_ori, revbuf[2]);

  capability_hash = DJBHash(hash_string_ori, strlen(hash_string_ori));
  ck_free(hash_string_ori);

  return capability_hash;
}

void getAllCapHashes(unsigned int *all_cap_hashes) {
  char tmp_capability[CAPABILITY_LEN+10];

  for (u32 i = 0; i < capability_cnt; i++) {
    if (all_capabilities[i]) {
      strncpy(tmp_capability, all_capabilities[i], CAPABILITY_LEN);
      strcat(tmp_capability, "\0");
      all_cap_hashes[i] = calculate_hash(tmp_capability);
    }
  }
}

/* Write input bytes constraints into file. */

static s32 write_constraints_to_file(u8 *path, struct byte_cons *consRes, u32 len) {

    s32 ret;

    unlink(path);                                            /* Ignore errors */

    ret = open(path, O_RDWR | O_CREAT | O_EXCL, DEFAULT_PERMISSION);

    if (ret < 0) { PFATAL("Unable to create '%s'", path); }

    int arr_len = len / sizeof(struct byte_cons);

    cJSON *json = cJSON_CreateObject();

    for (int i = 0; i < arr_len; i++) {
        /* Prepare position */
        char buffer[16];
        snprintf(buffer, 16, "%d", i);
        cJSON *elem = cJSON_CreateObject();
        cJSON_AddItemToObject(json, buffer, elem );

        /* Prepare function label */
        cJSON_AddItemToObject(elem,"func_lab",cJSON_CreateNumber(consRes[i].func_lab));

        /* Prepare capability_num */
        cJSON_AddItemToObject(elem,"capability_num",cJSON_CreateNumber(consRes[i].capability_num));
    }

    /* Prepare capability hashes */
    unsigned int *all_cap_hashes = ck_alloc(sizeof(uint64_t) * capability_cnt);
    getAllCapHashes(all_cap_hashes);

    cJSON *ArrHash =  cJSON_CreateIntArray(all_cap_hashes, capability_cnt);
    ck_free(all_cap_hashes);

    cJSON_AddItemToObject(json, "capHashes", ArrHash);

    /* Prepare to dump */
    char *buf = cJSON_Print(json);
    FILE *fp = fopen(path,"w");
    fwrite(buf,strlen(buf),1,fp);
    free(buf);
    fclose(fp);

    cJSON_Delete(json);

    return 0;
}

/* check capability by reading capability hash from specific file */
void check_capability(char result[]) {

  FILE *fp = fopen(pCapResFilePath, "r");
  if (!fp) PFATAL("Unable to open '%s'", pCapResFilePath);

  fgets(result, 60, fp);

  fclose(fp);
}

/* return 0 ——> this is a new capability
 * return 1 ——> we have seen this capability before! */

u8 is_old_capability() {
  int ret;
  khiter_t iter = 0;
  unsigned int cap_hash = 0;

  /* STEP One: calculate map index */
  char cur_capability[CAPABILITY_LEN];
  check_capability(cur_capability);
  cap_hash = calculate_hash(cur_capability);

  /* STEP Two: update the value in heatMap according to index */
  /* Check whether we have this key in hash map */
  iter = kh_get(m64HashTable, all_cap_hashTable, cap_hash);
  if (iter == kh_end(all_cap_hashTable)) {
    /* This key doesn't exist */
    // Insert this key into hash table
    iter = kh_put(m64HashTable, all_cap_hashTable, cap_hash, &ret);
    if (!ret) kh_del(m64HashTable, all_cap_hashTable, iter);

    // Initialize the key with value 1
    kh_value(all_cap_hashTable, iter) = 1;

    all_capability_num += 1;

    return 0;

  } else {

    /* This key exist */
    return 1;

  }
}

void capability_init(u32 poc_len) {

  /* Initialize all_capabilities, which is a hash table */
  all_cap_hashTable = kh_init(m64HashTable);

  /* Initialize critical bytes */
  critical_bytes = ck_alloc(sizeof(u32) * poc_len);
  all_critical_byte_num = 0;

  all_capability_num = 0;

}

void capability_destroy() {

  /* Destroy hash table */
  kh_destroy(m64HashTable, all_cap_hashTable);

  /* Free alloced memory */
  ck_free(critical_bytes);
  ck_free(ori_trace_bits);

}

/* Identify whether ori_trace_bits(the map of original PoC) is subset of bitmap_cur */
u8 is_superset_bitmap(u8 *trace_bits_cur, u32 map_size) {

  for (u32 i = 0; i < map_size; i++) {
    if (ori_trace_bits[i] && !trace_bits_cur[i]) {
      /* There is at least one edge was hit by original,
       * but no longer hit by current! */
      return 0;
    }
  }

  return 1;

}

/* Whether we have seen this capability in all or current? */
void check_all_current(char capability_cur[CAPABILITY_LEN]) {
  u8 seen_in_all = 0;
  u8 seen_in_cur = 0;

  /* Check whether this is a new capability we first see! */
  for (u32 i = 0; i < capability_cnt + 1; i++) {
    if (!memcmp(capability_cur, all_capabilities[i], CAPABILITY_LEN)) {
      /* We have seen this capability in all_capabilities already! */
      seen_in_all = 1;
      break;
    }
  } // End of checking all

  for (u32 j = 0; j < cur_capability_cnt + 1; j++) {
    /* Check whether we have seen this capability in this byte */
    if (!memcmp(capability_cur, cur_capabilities[j], CAPABILITY_LEN)) {
      /* We have seen this capability in cur_capabilities already! */
      seen_in_cur = 1;
      break;
    }
  } // End of checking current

  if (!seen_in_all) {
    /* This is a new capability we have never seen in global! */

    /* Update all first */
    memcpy(all_capabilities[capability_cnt], capability_cur, CAPABILITY_LEN);
    capability_cnt++;

    /* Update current second */
    memcpy(cur_capabilities[cur_capability_cnt], capability_cur, CAPABILITY_LEN);
    cur_capability_cnt++;

  } else if (!seen_in_cur) {
    /* This capability has been seen in all, but not in current */

    /* Update current ONLY */
    memcpy(cur_capabilities[cur_capability_cnt], capability_cur, CAPABILITY_LEN);
    cur_capability_cnt++;

  } else {}

  if (DEBUG) {
    if (capability_cnt > MAX_CAPABILITY_NUM-1 || cur_capability_cnt > MAX_CAPABILITY_NUM-1) {
      printf("Oops! OVERFLOW IS COMING!!!\n");
    }
  }

}

/* Identify whether this is a C/D byte */
/* return 0 ——> nobody byte
 * return 1 ——> C-byte
 * return 2 ——> D-byte
 * return 3 ——> C&D byte
 * return 4 ——> Non-crashing byte
 *  */
static u8 check_cd_byte(afl_forkserver_t *fsrv, u8 is_crash) {
  u64 cksum = hash64(fsrv->trace_bits, fsrv->map_size, HASH_CONST);

  if (is_crash) {
    /* This is a crashing input */
    if (cksum != orig_cksum) {
      char cur_capability[CAPABILITY_LEN];
      check_capability(cur_capability);

      if (!strcmp(cur_capability, ori_capability)) {

        /* bitmap changed when crash, but no new capability! */
        /* we think this is caused by hitting bug-irrelevant paths */
        return 1;
      } else {
        /* We find new capability! */
        /* This byte can change bitmap and capability at same time! */
        /* we think this byte can affect capability-related branch! */
        check_all_current(cur_capability);

        return 3;  // C&D byte!
      } // End of different cap hash than ori_capability_hash

    }

    /* bitmap && hit_cnt_sum are same */
    /* We need invoke capability sanitizer to know whether it is a D-byte */
    /* Only when capability has changed, this is a D-byte */
    char cur_capability[CAPABILITY_LEN];
    check_capability(cur_capability);

    if (!strcmp(cur_capability, ori_capability)) {

      /* Capability has not changed */
      return 0;    // This is a nobody byte
    } else {
      /* Capability changed! */

      /* This is a new capability, we need to update all_capabilities! */
      check_all_current(cur_capability);

      return 2;    // This is a D-byte!
    }

  } else {
    /* This is a non-crashing input! */

    if (is_superset_bitmap(fsrv->trace_bits, fsrv->map_size)) {
      /* If the bitmap of this non-crashing input is superset of original,
       * we keep this non-crashing input, which will be used to compare! */
      return 4;   // non-crashing byte is 4!
    } else {
      /* The bitmap changed before crash, so this should be a C-byte! */
      return 1;
    }
  }

  return 0;

}

/* There is no sort() in C-language, so I have to write one :( */
void bubble_sort(long arr[], int len) {
  int i, j;
  long temp;
  for (i = 0; i < len - 1; i++)
    for (j = 0; j < len - 1 - i; j++)
      if (arr[j] > arr[j + 1]) {
        temp = arr[j];
        arr[j] = arr[j + 1];
        arr[j + 1] = temp;
      }
}


/* op_type:
 * 0 ——> read
 * 1 ——> write */
void update_capabilities(struct capability *cap, u8 op_type,
                         char *bug_type, char *access_len, char *invalid_addr) {
  u8 seen_bug_t = 0;
  u8 seen_access_len = 0;
  u8 seen_invalid_addr = 0;

  u8 is_HOF = 0;
  u8 is_SOF = 0;

  /* STEP 1: check bug type */
  if (!strcmp(bug_type, "heap-buffer-overflow")) {
    is_HOF = 1;

    for (uint8_t j = 0; j < 10; j++) {
      if (cap[op_type].bug_num == 0) {break;}

      if (cap[op_type].bug_t[j] == HOF) {
        /* We have seen HOF! */
        seen_bug_t = 1;
        break;
      }

    } // End-of bug_t iteration
  } else {
    // TODO: we need to support other bug types!
  }

  /* STEP 2: check access length */
  for (uint16_t j = 0; j < 256; j++) {
    if (cap[op_type].access_len_num == 0) {break;}

    if ((u32)atoi(access_len) == cap[op_type].access_len[j]) {
      /* We have seen this length before! */
      seen_access_len = 1;
      break;
    }
  } // End-of access length iteration

  /* STEP 3: check invalid access address */
  for (uint16_t j = 0; j < 256; j++) {
    if (cap[op_type].invalid_addr_num == 0) {break;}

    if (atol(invalid_addr) == cap[op_type].invalid_addr[j]) {
      /* We have seen this address before! */
      seen_invalid_addr = 1;
      break;
    }
  } // End-of access address iteration

  /* STEP 4: Update capability */
  if (!seen_bug_t) {

    if (is_HOF) {
      cap[op_type].bug_t[cap[op_type].bug_num] = HOF;
      cap[op_type].bug_num += 1;
    } else if (is_SOF) {
      cap[op_type].bug_t[cap[op_type].bug_num] = SOF;
      cap[op_type].bug_num += 1;
    } else {}
  }

  if (!seen_access_len) {

    cap[op_type].access_len[cap[op_type].access_len_num] = (u32)atoi(access_len);
    cap[op_type].access_len_num += 1;
  }

  if (!seen_invalid_addr) {

    cap[op_type].invalid_addr[cap[op_type].invalid_addr_num] = atol(invalid_addr);
    cap[op_type].invalid_addr_num += 1;
  }

}

/* Re-organize capability results */
void analyze_capabilities(struct capability *cap) {
  char *revbuf[4] = {0};
  int num = 0;      /* Number of sub-string after split */

  cap[0].operation_t = READ;
  cap[1].operation_t = WRITE;

  /* Syntex of capability file:
   * bug_T @@ operation_T @@ access_len @@ invalid_addr */

  for (u32 i = 0; i < capability_cnt; i++) {
    split(all_capabilities[i], EVOCATIO_IDENTIFIER, revbuf, &num);
    char *bug_type = revbuf[0];
    char *op_type = revbuf[1];
    char *access_len = revbuf[2];
    char *invalid_addr = revbuf[3];

    /* We organize final result according to the operation type!
     * so we parse it first! */
    if (!strcmp(op_type, "read")) {

      /* This is a read */
      update_capabilities(cap, 0, bug_type, access_len, invalid_addr);

    } else if (!strcmp(op_type, "write")) {

      /* This is a write */
      update_capabilities(cap, 1, bug_type, access_len, invalid_addr);

    } else {}

  }
}


u8 is_consecutive(long left_addr, long right_addr) {

}

struct pair find_pair(long left_addr, long right_addr) {

}

/* Merge everything that can be merged */
// TODO: we only merge invalid memory access address, should support more mode!
void merge_capability_run(struct capability *cap_sum, struct pair *result) {
  u32 pair_cnt = 0;

  /* Merge seperate memory addresses into memory region */
  // HACK! we only have 2 categories
  for(u8 i = 0; i < 2; i++) {
    long pair_left_tmp=0, pair_right_tmp=0;
    long pair_left_next = 0;
    struct pair one_pair_tmp;

    /* sort all invalid addresses first */
    bubble_sort(cap_sum[i].invalid_addr, 256);

    u32 start_pos = 0;
    for (u32 pos = 0; pos < 256; pos++) {
      if (cap_sum[i].invalid_addr[pos] == 0) {
        continue;
      } else {
        start_pos = pos;
        break;
      }
    }

    pair_left_next = cap_sum[i].invalid_addr[start_pos];
    
    for (u32 j = start_pos; j < 256; j++) {
      pair_left_tmp = pair_left_next;

      if (cap_sum[i].invalid_addr[j]+1 == cap_sum[i].invalid_addr[j+1]) {
        /* This is a consecutive address pair! */
        pair_right_tmp = cap_sum[i].invalid_addr[j+1];  // update right!
      } else {
        /* Break consecutive address here! */
        pair_right_tmp = cap_sum[i].invalid_addr[j];
        pair_left_next = cap_sum[i].invalid_addr[j+1];

        /* Update result */
        one_pair_tmp.left_addr = pair_left_tmp;
        one_pair_tmp.right_addr = pair_right_tmp;
        result[pair_cnt] = one_pair_tmp;

        pair_cnt++;
      }
    }
  }
}

/* Merge capabilies if they can be merged */
/* We only merge consecutive accessed memory addresses */
// TODO: Maybe we can merge more?
void merge_capability() {
  /* HACK! we only support READ and WRITE,
   * so there should be only 2 categories */
  struct capability* capability_sum;
  capability_sum = ck_alloc(sizeof(struct capability) * 2);

  analyze_capabilities(capability_sum);

  struct pair *merged_cap = ck_alloc(sizeof(struct pair) * 200);

  merge_capability_run(capability_sum, merged_cap);

  if (DUMP_SUM) {
    /* Dump capability_sum into file  */
  }
}

/* File name format:
 * AccessType_AccessLen_BugType_Address
 * */
void get_dump_file_name(char file_name[CAPABILITY_LEN]) {
  char cur_capability[CAPABILITY_LEN];
  check_capability(cur_capability);

  const char *separator = "@@";
  char *revbuf[4] = {0};
  int num = 0;      /* Number of sub-string after split */

  /* Syntex of capability file:
   * bug_T @@ operation_T @@ access_len @@ invalid_addr */
  split(cur_capability, separator, revbuf, &num);
  char *bug_type = revbuf[0];
  char *op_type = revbuf[1];
  char *access_len = revbuf[2];
  char *invalid_addr = revbuf[3];

  char *result_tmp = ck_alloc(100);
  char *spliter = "_";

  strcpy(result_tmp, op_type);
  strcat(result_tmp,spliter);

  strcat(result_tmp, access_len);
  strcat(result_tmp,spliter);

  strcat(result_tmp, bug_type);
  strcat(result_tmp,spliter);

  strcat(result_tmp, invalid_addr);

  memcpy(file_name, result_tmp, strlen(result_tmp));

  ck_free(result_tmp);
}

/* There are 4 kinds of seeds
 * 1. new byte, new capability ——> keep it
 * 2. new byte, old capability ——> keep it
 * 3. old byte, new capability ——> keep it
 * 4. old byte, old capability ——> drop it
 * */

void dump_valuable_seed(u32 pos, u8* buf) {
  u8 is_new_byte = 0;
  u8 is_new_cap = 0;
  u8 find_byte = 0;

  /* Analyze byte */
  for (u32 i = 0; i < all_critical_byte_num; i++) {
    if (pos == critical_bytes[i]) {
      /* This is not a new byte */
      find_byte = 1;
      break;
    }
  }

  if (!find_byte) {
    is_new_byte = 1;

    critical_bytes[all_critical_byte_num] = pos;
    all_critical_byte_num += 1;

  }

  /* Analyze capability */
  if (!is_old_capability()) { is_new_cap = 1; }

  if (!is_new_byte && !is_new_cap) {
    return;
  }

  /* This should be a valuable seed! */
  /* We are going to dump current input into file */

  char file_name[CAPABILITY_LEN];
  get_dump_file_name(file_name);

  u8 *dump_file_path = alloc_printf("%s/%s", new_seeds_dir, file_name);
  close(write_to_file(dump_file_path, buf, in_len));
  ck_free(dump_file_path);
}

/* Execute target application. Returns 0 if the changes are a dud, or
   1 if they should be kept. */

static u8 tmin_run_target(afl_forkserver_t *fsrv, u8 *mem, u32 len,
                          u8 first_run) {
  /* 0 ——> neither C nor D,
   * 1 ——>C,
   * 2 ——> D,
   * 3 ——> C&D
   * */
  u8 cd_result = 0;

  afl_fsrv_write_to_testcase(fsrv, mem, len);

  fsrv_run_result_t ret =
      afl_fsrv_run_target(fsrv, fsrv->exec_tmout, &stop_soon);

  if (ret == FSRV_RUN_ERROR) { FATAL("Couldn't run child"); }

  if (stop_soon) {

    SAYF(cRST cLRD "\n+++ Minimization aborted by user +++\n" cRST);
    close(write_to_file(output_file, in_data, in_len));
    exit(1);

  }

  /* Always discard inputs that time out, unless we are in hang mode */

  if (hang_mode) {

    switch (ret) {

      case FSRV_RUN_TMOUT:
        return 1;
      case FSRV_RUN_CRASH:
        missed_crashes++;
        return 0;
      default:
        missed_hangs++;
        return 0;

    }

  }

  classify_counts(fsrv);
  apply_mask((u32 *)fsrv->trace_bits, (u32 *)mask_bitmap);

  if (ret == FSRV_RUN_TMOUT) {

    missed_hangs++;
    return 0;

  }

  /* Handle crashing inputs depending on current mode. */

  if (ret == FSRV_RUN_CRASH) {

    if (first_run) {
      /* We don't need to check_cd_byte for the first run! */
    } else {
      cd_result = check_cd_byte(fsrv, 1);
    }

    if (first_run) { crash_mode = 1; }

    if (crash_mode) {

      if (!exact_mode) { return 1, cd_result; }

    } else {

      missed_crashes++;
      return 0, cd_result;

    }

  } else {

    cd_result = check_cd_byte(fsrv, 0);

    /* Handle non-crashing inputs appropriately. */

    if (crash_mode) {

      missed_paths++;
      return 0, cd_result;

    }

  }

  if (ret == FSRV_RUN_NOINST) { FATAL("Binary not instrumented?"); }

  u64 cksum = hash64(fsrv->trace_bits, fsrv->map_size, HASH_CONST);

  if (first_run) {
    orig_cksum = cksum;
    ori_hit_count = cur_hit_count;

    check_capability(ori_capability);
    ori_trace_bits = ck_alloc(fsrv->map_size);
    memcpy(ori_trace_bits, fsrv->trace_bits, fsrv->map_size);

    /* Create a buffer for all_capabilities! */
    memcpy(all_capabilities[capability_cnt], ori_capability, CAPABILITY_LEN);
    capability_cnt++;
  }

  if (orig_cksum == cksum && ori_hit_count == cur_hit_count) { return 1, cd_result; }

  missed_paths++;
  return 0, cd_result;

}

/* Actually minimize! */

static void minimize(afl_forkserver_t *fsrv) {

  static u32 alpha_map[256];

  u8 *tmp_buf = ck_alloc_nozero(in_len);
  u32 orig_len = in_len, stage_o_len;

  u32 del_len, set_len, del_pos, set_pos, i, alpha_size, cur_pass = 0;
  u32 syms_removed, alpha_del0 = 0, alpha_del1, alpha_del2, alpha_d_total = 0;
  u8  changed_any, prev_del;

  if (1) { goto bruteforce_all; }

bruteforce_all:
  /**************************
   * CHARACTER BRUTEFORCE *
  **************************/
  ACTF(cBRI "Stage #4: " cRST "Character brute force...");
  struct byte_cons input_byte_cons[in_len];   /* index represents byte offset in input */

  /* Capability brute force initialization */
  capability_init(in_len);

  memcpy(tmp_buf, in_data, in_len);

  /* alloc a buffer, return zeroed memory */
  struct byte_cons* constraintsRes = ck_alloc(sizeof(input_byte_cons));
  if (!brute_end_pos) {
    brute_end_pos = in_len;
  }
    for (i = brute_start_pos; i < brute_end_pos; i++) {

        printf("Analyzing byte %d / %d\n", i, in_len);

        /* Re-set cur_capability_cnt before staring next iteration! */
        cur_capability_cnt = 0;

        u8 res, orig = tmp_buf[i];

        /* C-byte       ——> 1
         * D-byte       ——> 2
         * C-D byte     ——> 3
         * non-byte     ——> 4
         * C-non byte   ——> 5
         * D-non byte   ——> 6
         * C-D-non byte ——> 7*/
        u8 cd_res, is_c_byte=0, is_d_byte=0, is_non_crashing_byte=0,
                   is_c_and_d_byte=0, is_c_non_byte=0, is_d_non_byte=0,
                   is_c_d_non_byte=0;

        uint16_t pass_val_cnt = 0;        // how many different value can pass
        for (int j = 0; j < 256; j++) {
          /* we try all 256 characters during the brute force */
          if (orig == j) {
              pass_val_cnt++;
              continue;                               // we don't need to try the original value again
          }

          tmp_buf[i] = j;

          res, cd_res = tmin_run_target(fsrv, tmp_buf, in_len, 0);

          /* Dump the input that can introduce new capability info file! */
          /* We won't dump the input when cd_res is (0, 1)*/
          if (cd_res != 0 && cd_res != 1) {

            dump_valuable_seed(i, tmp_buf);

          }

          /* Recover byte value before analysis further! */
          tmp_buf[i] = orig;

          if (cd_res == 0) {
            ;
          } else if (cd_res == 1) {
            /* This is a C byte at least */
            if (is_c_byte || is_c_and_d_byte || is_c_non_byte) {
              continue;
            } else if (is_d_byte) {
              /* This is a C-D byte! */
              constraintsRes[i].func_lab += 1;   // C-D byte should equal to 3!
              is_c_and_d_byte = 1;
              continue;
            } else if (is_non_crashing_byte){
              /* This is a C-non byte*/
              constraintsRes[i].func_lab += 1;  // C-non byte should equal to 5!
              is_c_non_byte = 1;
              continue;
            } else if (is_d_non_byte) {
              /* This is a c_d_non byte */
              constraintsRes[i].func_lab += 1;  // C-D-non byte should be equal to 7!
              is_c_d_non_byte = 1;
              break;      // we have find answer, don't need to test anymore!
            } else {}

            /* This is the first time we know it is a C byte! */
            constraintsRes[i].func_lab = 1;
            is_c_byte = 1;

            if (!heavy_mode) {
              /* early abort! */
              break; // we have find answer, don't need to test anymore!
            } else {
              /* heavy mode! we won't early abort! */
              /* if this is a C-byte, whether it can also be a D-byte? */
              /* we want to detect C-D byte further! Only exist in heavy mode! */

              // do nothing!
            }

          } else if (cd_res == 2) {
            /* This is a D byte at least */
            if (is_d_byte || is_c_and_d_byte || is_d_non_byte) {
              continue;
            } else if (is_c_byte) {
              /* This is a C-D byte! */
              constraintsRes[i].func_lab += 2;  // C-D byte should equal to 3!
              is_c_and_d_byte = 1;
              continue;
            } else if (is_non_crashing_byte) {
              /* A byte cannot be C-D byte and non-crashing byte at same time!
               * but it can be D byte and non-crashing byte at same time! */
              constraintsRes[i].func_lab += 2;  // D-non byte equal to 6!
              is_d_non_byte = 1;
              continue;
            } else if (is_c_non_byte) {
              /* This is a C-D-non byte */
              constraintsRes[i].func_lab += 2; // C-D-non byte should be equal to 7!
              is_c_d_non_byte = 1;
              break;      // we have find answer, don't need to test anymore!
            } else {}

            /* This is the first time we know it is a D byte! */
            constraintsRes[i].func_lab = 2;
            is_d_byte = 1;

            if (!heavy_mode) {
              /* early abort! */
              break; // we have find answer, don't need to test anymore!
            } else {
              /* heavy mode! we won't early abort! */
              /* if this is a D-byte, whether it can also be a C-byte? */
              /* we want to detect C-D byte further! Only exist in heavy mode! */

              // do nothing!
            }
          } // end of D byte
          else if (cd_res == 4) {
            /* This is a non-crashing byte at least,
             * If you change this byte, you can make the program from
             * crashing to non-crashing, or from non-crashing to crashing */
            if (is_non_crashing_byte || is_c_non_byte || is_d_non_byte) {
              continue;
            } else if (is_c_byte && !is_c_non_byte) {
              /* This is a c-non byte */
              constraintsRes[i].func_lab += 4;  // C-non byte should equal to 5!
              is_c_non_byte = 1;
              continue;
            }else if (is_d_byte && !is_d_non_byte) {
              /* This is a D-byte && non-crashing byte! */
              constraintsRes[i].func_lab += 4;    // D-non byte equal to 6!
              is_d_non_byte = 1;
              continue;
            } else if (is_c_and_d_byte && !is_c_d_non_byte) {
              /* This is C-D-non byte */
              constraintsRes[i].func_lab += 4; // C-D-non byte should be equal to 7!
              is_c_d_non_byte = 1;
              break;  // we have find answer, don't need to test anymore!
            } else {}

            /* This is the first time we know it is a non-crashing byte! */
            constraintsRes[i].func_lab = 4;
            is_non_crashing_byte = 1;

            if (!heavy_mode) {
              /* early abort! */
              break; // we have find answer, don't need to test anymore!
            } else {
              /* heavy mode! we won't early abort! */
              /* if this is a D-byte, whether it can also be a C-byte? */
              /* we want to detect C-D byte further! Only exist in heavy mode! */

              // do nothing!
            }

          } // end of non-crashing byte
          else if (cd_res == 3) {
            /* This is a C-D byte at least! */
            /* Very special byte! It can affect the capability-related branch! */
            if (is_c_and_d_byte || is_c_d_non_byte||is_c_non_byte) {
              continue;
            } else if (is_non_crashing_byte && !is_c_d_non_byte) {
              constraintsRes[i].func_lab += 4;  // C-D-non byte should be equal to 7!
              break;
            } else if (is_c_byte && !is_c_and_d_byte) {
              constraintsRes[i].func_lab += 2;
              is_c_and_d_byte = 1;
              continue;
            } else if (is_d_byte && !is_c_and_d_byte){
              constraintsRes[i].func_lab += 1;
              is_c_and_d_byte = 1;
              continue;
            } else if (is_c_non_byte) {
              constraintsRes[i].func_lab += 2;
              is_c_d_non_byte = 1;
              break;
            } else if (is_d_non_byte) {
              constraintsRes[i].func_lab += 1;
              is_c_d_non_byte = 1;
              break;
            } else {}

            /* This is the first time we know it is a C-D byte! */
            constraintsRes[i].func_lab = 3;
            is_c_and_d_byte = 1;

            if (!heavy_mode) {
              /* early abort! */
              break; // we have find answer, don't need to test anymore!
            } else {
              /* heavy mode! we won't early abort! */
              /* if this is a D-byte, whether it can also be a C-byte? */
              /* we want to detect C-D byte further! Only exist in heavy mode! */

              // do nothing!
            }
          } // end of C-D byte
          else {}

        } // end of iterate byte's value

        /* We have verified 256 values */
        if (!is_c_byte && !is_d_byte && is_non_crashing_byte &&
            !is_c_and_d_byte && !is_c_non_byte && !is_d_non_byte &&
            !is_c_d_non_byte) {
          constraintsRes[i].func_lab = 0;   // this must be a nobody byte!
        }

        /* Calculate how many capability this byte has introduced */
        constraintsRes[i].capability_num = cur_capability_cnt;

        /* Clean cur_capabilities buffer */
        memset(cur_capabilities, 0, sizeof(cur_capabilities));

    } // end of iterate byte


    if (1) { goto finalize_all; }

finalize_all:

  if (tmp_buf) { ck_free(tmp_buf); }

  /* Merge capability result */
  //merge_capability();

  if (hang_mode) {

    SAYF("\n" cGRA "     File size reduced by : " cRST
         "%0.02f%% (to %u byte%s)\n" cGRA "    Characters simplified : " cRST
         "%0.02f%%\n" cGRA "     Number of execs done : " cRST "%llu\n" cGRA
         "          Fruitless execs : " cRST "termination=%u crash=%u\n\n",
         100 - ((double)in_len) * 100 / orig_len, in_len,
         in_len == 1 ? "" : "s",
         ((double)(alpha_d_total)) * 100 / (in_len ? in_len : 1),
         fsrv->total_execs, missed_paths, missed_crashes);
    return;

  }

  SAYF("\n" cGRA "     File size reduced by : " cRST
       "%0.02f%% (to %u byte%s)\n" cGRA "    Characters simplified : " cRST
       "%0.02f%%\n" cGRA "     Number of execs done : " cRST "%llu\n" cGRA
       "          Fruitless execs : " cRST "path=%u crash=%u hang=%s%u\n\n",
       100 - ((double)in_len) * 100 / orig_len, in_len, in_len == 1 ? "" : "s",
       ((double)(alpha_d_total)) * 100 / (in_len ? in_len : 1),
       fsrv->total_execs, missed_paths, missed_crashes,
       missed_hangs ? cLRD : "", missed_hangs);

  if (fsrv->total_execs > 50 && missed_hangs * 10 > fsrv->total_execs &&
      !hang_mode) {

    WARNF(cLRD "Frequent timeouts - results may be skewed." cRST);

  }

  /* Dump input bytes constraints to file */
  close(write_constraints_to_file(input_byte_cons_file, constraintsRes, sizeof(input_byte_cons)));

  /* Free memory to avoid memory leak */
  ck_free(constraintsRes);
  capability_destroy();

}

/* Handle Ctrl-C and the like. */

static void handle_stop_sig(int sig) {

  (void)sig;
  stop_soon = 1;
  afl_fsrv_killall();

}

/* Do basic preparations - persistent fds, filenames, etc. */

static void set_up_environment(afl_forkserver_t *fsrv, char **argv) {

  u8 *  x;
  char *afl_preload;
  char *frida_afl_preload = NULL;

  fsrv->dev_null_fd = open("/dev/null", O_RDWR);
  if (fsrv->dev_null_fd < 0) { PFATAL("Unable to open /dev/null"); }

  if (!out_file) {

    u8 *use_dir = ".";

    if (access(use_dir, R_OK | W_OK | X_OK)) {

      use_dir = get_afl_env("TMPDIR");
      if (!use_dir) { use_dir = "/tmp"; }

    }

    out_file = alloc_printf("%s/.afl-tmin-temp-%u", use_dir, (u32)getpid());
    remove_out_file = 1;

  }

  unlink(out_file);

  fsrv->out_file = out_file;
  fsrv->out_fd = open(out_file, O_RDWR | O_CREAT | O_EXCL, DEFAULT_PERMISSION);

  if (fsrv->out_fd < 0) { PFATAL("Unable to create '%s'", out_file); }

  /* Set for Evocatio */

  unsetenv(EVOCATIO_ENV_CAPFUZZ);

  pCapResFilePath = get_afl_env(EVOCATIO_ENV_RESPATH);
  if (!pCapResFilePath) {

    u8 *use_dir = ".";
    if (access(use_dir, R_OK | W_OK | X_OK)) {
        use_dir = get_afl_env("TMPDIR");
        if (!use_dir) { use_dir = "/tmp"; }
    }

    pCapResFilePath = alloc_printf("%s/.afl-tmin-temp-CapResFile-%u", use_dir, (u32)getpid());
    setenv(EVOCATIO_ENV_RESPATH, pCapResFilePath, 0);
    remove_cap_res_f = 1;
  }

  unlink(pCapResFilePath);

  /* Set sane defaults... */

  x = get_afl_env("ASAN_OPTIONS");

  if (x) {

    if (!strstr(x, "abort_on_error=1")) {

      FATAL("Custom ASAN_OPTIONS set without abort_on_error=1 - please fix!");

    }

#ifndef ASAN_BUILD
    if (!getenv("AFL_DEBUG") && !strstr(x, "symbolize=0")) {

      FATAL("Custom ASAN_OPTIONS set without symbolize=0 - please fix!");

    }

#endif

  }

  x = get_afl_env("MSAN_OPTIONS");

  if (x) {

    if (!strstr(x, "exit_code=" STRINGIFY(MSAN_ERROR))) {

      FATAL("Custom MSAN_OPTIONS set without exit_code=" STRINGIFY(
          MSAN_ERROR) " - please fix!");

    }

    if (!strstr(x, "symbolize=0")) {

      FATAL("Custom MSAN_OPTIONS set without symbolize=0 - please fix!");

    }

  }

  x = get_afl_env("LSAN_OPTIONS");

  if (x) {

    if (!strstr(x, "symbolize=0")) {

      FATAL("Custom LSAN_OPTIONS set without symbolize=0 - please fix!");

    }

  }

  setenv("ASAN_OPTIONS",
         "abort_on_error=1:"
         "detect_leaks=0:"
         "allocator_may_return_null=1:"
         "symbolize=0:"
         "detect_odr_violation=0",
         0);

  setenv("UBSAN_OPTIONS",
         "halt_on_error=1:"
         "abort_on_error=1:"
         "malloc_context_size=0:"
         "allocator_may_return_null=1:"
         "symbolize=0",
         0);

  setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                         "abort_on_error=1:"
                         "msan_track_origins=0:"
                         "allocator_may_return_null=1:"
                         "symbolize=0", 0);

  setenv("LSAN_OPTIONS",
         "exitcode=" STRINGIFY(LSAN_ERROR) ":"
         "fast_unwind_on_malloc=0:"
         "symbolize=0:"
         "print_suppressions=0",
         0);

  if (get_afl_env("AFL_PRELOAD")) {

    if (fsrv->qemu_mode) {

      /* afl-qemu-trace takes care of converting AFL_PRELOAD. */

    } else if (fsrv->frida_mode) {

      afl_preload = getenv("AFL_PRELOAD");
      u8 *frida_binary = find_afl_binary(argv[0], "afl-frida-trace.so");
      if (afl_preload) {

        frida_afl_preload = alloc_printf("%s:%s", afl_preload, frida_binary);

      } else {

        frida_afl_preload = alloc_printf("%s", frida_binary);

      }

      ck_free(frida_binary);

      setenv("LD_PRELOAD", frida_afl_preload, 1);
      setenv("DYLD_INSERT_LIBRARIES", frida_afl_preload, 1);

    } else {

      setenv("LD_PRELOAD", getenv("AFL_PRELOAD"), 1);
      setenv("DYLD_INSERT_LIBRARIES", getenv("AFL_PRELOAD"), 1);

    }

  } else if (fsrv->frida_mode) {

    u8 *frida_binary = find_afl_binary(argv[0], "afl-frida-trace.so");
    setenv("LD_PRELOAD", frida_binary, 1);
    setenv("DYLD_INSERT_LIBRARIES", frida_binary, 1);
    ck_free(frida_binary);

  }

  if (frida_afl_preload) { ck_free(frida_afl_preload); }

}

/* Setup signal handlers, duh. */

static void setup_signal_handlers(void) {

  struct sigaction sa;

  sa.sa_handler = NULL;
  sa.sa_flags = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

}

/* Display usage hints. */

static void usage(u8 *argv0) {

  SAYF(
      "\n%s [ options ] -- /path/to/target_app [ ... ]\n\n"

      "Required parameters:\n"

      "  -i file       - input test case to be shrunk by the tool\n"
      "  -o file       - final output location for the minimized data\n\n"

      "Execution control settings:\n"

      "  -f file       - input file read by the tested program (stdin)\n"
      "  -t msec       - timeout for each run (%u ms)\n"
      "  -m megs       - memory limit for child process (%u MB)\n"
      "  -O            - use binary-only instrumentation (FRIDA mode)\n"
      "  -Q            - use binary-only instrumentation (QEMU mode)\n"
      "  -U            - use unicorn-based instrumentation (Unicorn mode)\n"
      "  -W            - use qemu-based instrumentation with Wine (Wine "
      "mode)\n"
      "                  (Not necessary, here for consistency with other afl-* "
      "tools)\n\n"

      "Minimization settings:\n"

      "  -e            - solve for edge coverage only, ignore hit counts\n"
      "  -x            - treat non-zero exit codes as crashes\n\n"
      "  -H            - minimize a hang (hang mode)\n"

      "For additional tips, please consult %s/README.md.\n\n"

      "Environment variables used:\n"
      "AFL_CRASH_EXITCODE: optional child exit code to be interpreted as crash\n"
      "AFL_FORKSRV_INIT_TMOUT: time spent waiting for forkserver during startup (in milliseconds)\n"
      "AFL_KILL_SIGNAL: Signal ID delivered to child processes on timeout, etc. (default: SIGKILL)\n"
      "AFL_MAP_SIZE: the shared memory size for that target. must be >= the size\n"
      "              the target was compiled for\n"
      "AFL_PRELOAD:  LD_PRELOAD / DYLD_INSERT_LIBRARIES settings for target\n"
      "AFL_TMIN_EXACT: require execution paths to match for crashing inputs\n"
      "AFL_NO_FORKSRV: run target via execve instead of using the forkserver\n"
      "ASAN_OPTIONS: custom settings for ASAN\n"
      "              (must contain abort_on_error=1 and symbolize=0)\n"
      "MSAN_OPTIONS: custom settings for MSAN\n"
      "              (must contain exitcode="STRINGIFY(MSAN_ERROR)" and symbolize=0)\n"
      "TMPDIR: directory to use for temporary input files\n",
      argv0, EXEC_TIMEOUT, MEM_LIMIT, doc_path);

  exit(1);

}

/* Main entry point */

int main(int argc, char **argv_orig, char **envp) {

  s32    opt;
  u8     mem_limit_given = 0, timeout_given = 0, unicorn_mode = 0, use_wine = 0;
  u8  brute_start_given = 0, brute_end_given = 0;
  char **use_argv;

  char **argv = argv_cpy_dup(argc, argv_orig);

  afl_forkserver_t fsrv_var = {0};
  if (getenv("AFL_DEBUG")) { debug = 1; }
  fsrv = &fsrv_var;
  afl_fsrv_init(fsrv);
  map_size = get_map_size();
  fsrv->map_size = map_size;

  doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;

  SAYF(cCYA "afl-tmin" VERSION cRST " by Michal Zalewski\n");

  while ((opt = getopt(argc, argv, "+i:o:c:k:s:d:f:m:t:BxeOQUWHhg")) > 0) {

    switch (opt) {

      case 'i':

        if (in_file) { FATAL("Multiple -i options not supported"); }
        in_file = optarg;
        break;

      case 'o':

        if (output_file) { FATAL("Multiple -o options not supported"); }
        output_file = optarg;
        break;

      case 'c':

        if (input_byte_cons_file) { FATAL("Multiple -c options not supported"); }
        input_byte_cons_file = optarg;
        break;

      case 'k':

        if (new_seeds_dir) { FATAL("Multiple -k options not supported"); }
        new_seeds_dir = optarg;
        break;

      case 's':
        if (brute_start_given) { FATAL("Multiple -s options not supported"); }
        brute_start_given = 1;

        if (!optarg) { FATAL("Wrong usage of -s"); }

        sscanf(optarg, "%u", &brute_start_pos);
        break;

      case 'd':
        if (brute_end_given) { FATAL("Multiple -d options not supported"); }
        brute_end_given = 1;

        if (!optarg) { FATAL("Wrong usage of -d"); }

        sscanf(optarg, "%u", &brute_end_pos);
        break;

      case 'f':

        if (out_file) { FATAL("Multiple -f options not supported"); }
        fsrv->use_stdin = 0;
        out_file = ck_strdup(optarg);
        break;

      case 'e':

        if (edges_only) { FATAL("Multiple -e options not supported"); }
        if (hang_mode) {

          FATAL("Edges only and hang mode are mutually exclusive.");

        }

        edges_only = 1;
        break;

      case 'x':

        if (exit_crash) { FATAL("Multiple -x options not supported"); }
        exit_crash = 1;
        break;

      case 'm': {

        u8 suffix = 'M';

        if (mem_limit_given) { FATAL("Multiple -m options not supported"); }
        mem_limit_given = 1;

        if (!optarg) { FATAL("Wrong usage of -m"); }

        if (!strcmp(optarg, "none")) {

          fsrv->mem_limit = 0;
          break;

        }

        if (sscanf(optarg, "%llu%c", &fsrv->mem_limit, &suffix) < 1 ||
            optarg[0] == '-') {

          FATAL("Bad syntax used for -m");

        }

        switch (suffix) {

          case 'T':
            fsrv->mem_limit *= 1024 * 1024;
            break;
          case 'G':
            fsrv->mem_limit *= 1024;
            break;
          case 'k':
            fsrv->mem_limit /= 1024;
            break;
          case 'M':
            break;

          default:
            FATAL("Unsupported suffix or bad syntax for -m");

        }

        if (fsrv->mem_limit < 5) { FATAL("Dangerously low value of -m"); }

        if (sizeof(rlim_t) == 4 && fsrv->mem_limit > 2000) {

          FATAL("Value of -m out of range on 32-bit systems");

        }

      }

      break;

      case 't':

        if (timeout_given) { FATAL("Multiple -t options not supported"); }
        timeout_given = 1;

        if (!optarg) { FATAL("Wrong usage of -t"); }

        fsrv->exec_tmout = atoi(optarg);

        if (fsrv->exec_tmout < 10 || optarg[0] == '-') {

          FATAL("Dangerously low value of -t");

        }

        break;

      case 'O':                                               /* FRIDA mode */

        if (fsrv->frida_mode) { FATAL("Multiple -O options not supported"); }

        fsrv->frida_mode = 1;
        setenv("AFL_FRIDA_INST_SEED", "0x0", 1);

        break;

      case 'Q':

        if (fsrv->qemu_mode) { FATAL("Multiple -Q options not supported"); }
        if (!mem_limit_given) { fsrv->mem_limit = MEM_LIMIT_QEMU; }

        fsrv->qemu_mode = 1;
        break;

      case 'U':

        if (unicorn_mode) { FATAL("Multiple -Q options not supported"); }
        if (!mem_limit_given) { fsrv->mem_limit = MEM_LIMIT_UNICORN; }

        unicorn_mode = 1;
        break;

      case 'W':                                           /* Wine+QEMU mode */

        if (use_wine) { FATAL("Multiple -W options not supported"); }
        fsrv->qemu_mode = 1;
        use_wine = 1;

        if (!mem_limit_given) { fsrv->mem_limit = 0; }

        break;

      case 'H':                                                /* Hang Mode */

        /* Minimizes a testcase to the minimum that still times out */

        if (hang_mode) { FATAL("Multipe -H options not supported"); }
        if (edges_only) {

          FATAL("Edges only and hang mode are mutually exclusive.");

        }

        hang_mode = 1;
        break;

      case 'g':                                              /* heavy mode */
        /* complete brute force, won't early abort */
        if (heavy_mode) { FATAL("Multipe -g options not supported"); }

        heavy_mode = 1;
        break;

      case 'B':                                              /* load bitmap */

        /* This is a secret undocumented option! It is speculated to be useful
           if you have a baseline "boring" input file and another "interesting"
           file you want to minimize.

           You can dump a binary bitmap for the boring file using
           afl-showmap -b, and then load it into afl-tmin via -B. The minimizer
           will then minimize to preserve only the edges that are unique to
           the interesting input file, but ignoring everything from the
           original map.

           The option may be extended and made more official if it proves
           to be useful. */

        if (mask_bitmap) { FATAL("Multiple -B options not supported"); }
        mask_bitmap = ck_alloc(map_size);
        read_bitmap(optarg, mask_bitmap, map_size);
        break;

      case 'h':
        usage(argv[0]);
        return -1;
        break;

      default:
        usage(argv[0]);

    }

  }

  if (optind == argc || !in_file || !output_file || !new_seeds_dir) { usage(argv[0]); }

  check_environment_vars(envp);

  if (getenv("AFL_NO_FORKSRV")) {             /* if set, use the fauxserver */
    fsrv->use_fauxsrv = true;

  }

  setenv("AFL_NO_AUTODICT", "1", 1);

  /* initialize cmplog_mode */
  shm.cmplog_mode = 0;

  atexit(at_exit_handler);
  setup_signal_handlers();

  set_up_environment(fsrv, argv);

  fsrv->target_path = find_binary(argv[optind]);
  fsrv->trace_bits = afl_shm_init(&shm, map_size, 0);
  detect_file_args(argv + optind, out_file, &fsrv->use_stdin);

  if (fsrv->qemu_mode) {

    if (use_wine) {

      use_argv = get_wine_argv(argv[0], &fsrv->target_path, argc - optind,
                               argv + optind);

    } else {

      use_argv = get_qemu_argv(argv[0], &fsrv->target_path, argc - optind,
                               argv + optind);

    }

  } else {

    use_argv = argv + optind;

  }

  exact_mode = !!get_afl_env("AFL_TMIN_EXACT");
  if (!exact_mode) {
    WARNF("Critical Bytes Inference requires AFL_TMIN_EXACT=1. It will be set to 1 for default.");
    exact_mode = 1;
  }
  if (hang_mode && exact_mode) {
    FATAL("AFL_TMIN_EXACT won't work for loops in hang mode, ignoring.");
  }

  SAYF("\n");

  if (getenv("AFL_FORKSRV_INIT_TMOUT")) {

    s32 forksrv_init_tmout = atoi(getenv("AFL_FORKSRV_INIT_TMOUT"));
    if (forksrv_init_tmout < 1) {

      FATAL("Bad value specified for AFL_FORKSRV_INIT_TMOUT");

    }

    fsrv->init_tmout = (u32)forksrv_init_tmout;

  }

  fsrv->kill_signal =
      parse_afl_kill_signal_env(getenv("AFL_KILL_SIGNAL"), SIGKILL);

  if (getenv("AFL_CRASH_EXITCODE")) {

    long exitcode = strtol(getenv("AFL_CRASH_EXITCODE"), NULL, 10);
    if ((!exitcode && (errno == EINVAL || errno == ERANGE)) ||
        exitcode < -127 || exitcode > 128) {

      FATAL("Invalid crash exitcode, expected -127 to 128, but got %s",
            getenv("AFL_CRASH_EXITCODE"));

    }

    fsrv->uses_crash_exitcode = true;
    // WEXITSTATUS is 8 bit unsigned
    fsrv->crash_exitcode = (u8)exitcode;

  }

  shm_fuzz = ck_alloc(sizeof(sharedmem_t));

  /* initialize cmplog_mode */
  shm_fuzz->cmplog_mode = 0;
  u8 *map = afl_shm_init(shm_fuzz, MAX_FILE + sizeof(u32), 1);
  shm_fuzz->shmemfuzz_mode = 1;
  if (!map) { FATAL("BUG: Zero return from afl_shm_init."); }
#ifdef USEMMAP
  setenv(SHM_FUZZ_ENV_VAR, shm_fuzz->g_shm_file_path, 1);
#else
  u8 *shm_str = alloc_printf("%d", shm_fuzz->shm_id);
  setenv(SHM_FUZZ_ENV_VAR, shm_str, 1);
  ck_free(shm_str);
#endif
  fsrv->support_shmem_fuzz = 1;
  fsrv->shmem_fuzz_len = (u32 *)map;
  fsrv->shmem_fuzz = map + sizeof(u32);

  read_initial_file();

  if (!fsrv->qemu_mode && !unicorn_mode) {

    fsrv->map_size = 4194304;  // dummy temporary value
    u32 new_map_size =
        afl_fsrv_get_mapsize(fsrv, use_argv, &stop_soon,
                             (get_afl_env("AFL_DEBUG_CHILD") ||
                              get_afl_env("AFL_DEBUG_CHILD_OUTPUT"))
                                 ? 1
                                 : 0);

    if (new_map_size) {

      if (map_size < new_map_size ||
          (new_map_size > map_size && new_map_size - map_size > MAP_SIZE)) {

        if (!be_quiet)
          ACTF("Aquired new map size for target: %u bytes\n", new_map_size);

        afl_shm_deinit(&shm);
        afl_fsrv_kill(fsrv);
        fsrv->map_size = new_map_size;
        fsrv->trace_bits = afl_shm_init(&shm, new_map_size, 0);
        afl_fsrv_start(fsrv, use_argv, &stop_soon,
                       (get_afl_env("AFL_DEBUG_CHILD") ||
                        get_afl_env("AFL_DEBUG_CHILD_OUTPUT"))
                           ? 1
                           : 0);

      }

      map_size = new_map_size;

    }

    fsrv->map_size = map_size;

  } else {

    afl_fsrv_start(fsrv, use_argv, &stop_soon,
                   (get_afl_env("AFL_DEBUG_CHILD") ||
                    get_afl_env("AFL_DEBUG_CHILD_OUTPUT"))
                       ? 1
                       : 0);

  }

  if (fsrv->support_shmem_fuzz && !fsrv->use_shmem_fuzz)
    shm_fuzz = deinit_shmem(fsrv, shm_fuzz);

  ACTF("Performing dry run (mem limit = %llu MB, timeout = %u ms%s)...",
       fsrv->mem_limit, fsrv->exec_tmout, edges_only ? ", edges only" : "");

  tmin_run_target(fsrv, in_data, in_len, 1);

  if (hang_mode && !fsrv->last_run_timed_out) {

    FATAL(
        "Target binary did not time out but hang minimization mode "
        "(-H) was set (-t %u).",
        fsrv->exec_tmout);

  }

  if (fsrv->last_run_timed_out && !hang_mode) {

    FATAL(
        "Target binary times out (adjusting -t may help). Use -H to minimize a "
        "hang.");

  }

  if (hang_mode) {

    OKF("Program hangs as expected, minimizing in " cCYA "hang" cRST " mode.");

  } else if (!crash_mode) {

    OKF("Program terminates normally, minimizing in " cCYA "instrumented" cRST
        " mode.");

    if (!anything_set(fsrv)) { FATAL("No instrumentation detected."); }

  } else {

    OKF("Program exits with a signal, minimizing in " cMGN "%scrash" cRST
        " mode.",
        exact_mode ? "EXACT " : "");

  }

  minimize(fsrv);

  ACTF("Writing output to '%s'...", output_file);

  unlink(out_file);
  if (out_file) { ck_free(out_file); }
  out_file = NULL;

  close(write_to_file(output_file, in_data, in_len));

  if (remove_cap_res_f) unlink(pCapResFilePath);
  if (pCapResFilePath) { ck_free(pCapResFilePath); }
  pCapResFilePath = NULL;

  OKF("We're done here. Have a nice day!\n");

  remove_shm = 0;
  afl_shm_deinit(&shm);
  if (fsrv->use_shmem_fuzz) shm_fuzz = deinit_shmem(fsrv, shm_fuzz);
  afl_fsrv_deinit(fsrv);
  if (fsrv->target_path) { ck_free(fsrv->target_path); }
  if (mask_bitmap) { ck_free(mask_bitmap); }
  if (in_data) { ck_free(in_data); }

  argv_cpy_free(argv);

  exit(0);

}

