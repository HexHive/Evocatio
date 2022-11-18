/*
   american fuzzy lop++ - bitmap related routines
   ----------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"
#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#if !defined NAME_MAX
  #define NAME_MAX _XOPEN_NAME_MAX
#endif

khash_t(m64HashTable) *heatMapUnion;           /* capability union heat map */
int union_cnt = 0;                             /* number of union we have */
khash_t(m64HashTable) *all_cap_hashTable;     /* all capabilities we have ever seen */

/* Write bitmap to file. The bitmap is useful mostly for the secret
   -B option, to focus a separate fuzzing session on a particular
   interesting input without rediscovering all the others. */

void write_bitmap(afl_state_t *afl) {

  u8  fname[PATH_MAX];
  s32 fd;

  if (!afl->bitmap_changed) { return; }
  afl->bitmap_changed = 0;

  snprintf(fname, PATH_MAX, "%s/fuzz_bitmap", afl->out_dir);
  fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);

  if (fd < 0) { PFATAL("Unable to open '%s'", fname); }

  ck_write(fd, afl->virgin_bits, afl->fsrv.map_size, fname);

  close(fd);

}

/* Count the number of bits set in the provided bitmap. Used for the status
   screen several times every second, does not have to be fast. */

u32 count_bits(afl_state_t *afl, u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = (afl->fsrv.map_size >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This gets called on the inverse, virgin bitmap; optimize for sparse
       data. */

    if (v == 0xffffffff) {

      ret += 32;
      continue;

    }

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;

  }

  return ret;

}

/* Count the number of bytes set in the bitmap. Called fairly sporadically,
   mostly to update the status screen or calibrate and examine confirmed
   new paths. */

u32 count_bytes(afl_state_t *afl, u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = (afl->fsrv.map_size >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (!v) { continue; }
    if (v & 0x000000ffU) { ++ret; }
    if (v & 0x0000ff00U) { ++ret; }
    if (v & 0x00ff0000U) { ++ret; }
    if (v & 0xff000000U) { ++ret; }

  }

  return ret;

}

/* Count the number of non-255 bytes set in the bitmap. Used strictly for the
   status screen, several calls per second or so. */

u32 count_non_255_bytes(afl_state_t *afl, u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = (afl->fsrv.map_size >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (v == 0xffffffffU) { continue; }
    if ((v & 0x000000ffU) != 0x000000ffU) { ++ret; }
    if ((v & 0x0000ff00U) != 0x0000ff00U) { ++ret; }
    if ((v & 0x00ff0000U) != 0x00ff0000U) { ++ret; }
    if ((v & 0xff000000U) != 0xff000000U) { ++ret; }

  }

  return ret;

}

/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or timeout, should be
   reasonably fast. */
#define TIMES4(x) x, x, x, x
#define TIMES8(x) TIMES4(x), TIMES4(x)
#define TIMES16(x) TIMES8(x), TIMES8(x)
#define TIMES32(x) TIMES16(x), TIMES16(x)
#define TIMES64(x) TIMES32(x), TIMES32(x)
#define TIMES255(x)                                                      \
  TIMES64(x), TIMES64(x), TIMES64(x), TIMES32(x), TIMES16(x), TIMES8(x), \
      TIMES4(x), x, x, x
const u8 simplify_lookup[256] = {

    [0] = 1, [1] = TIMES255(128)

};

/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */

const u8 count_class_lookup8[256] = {

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

#undef TIMES255
#undef TIMES64
#undef TIMES32
#undef TIMES16
#undef TIMES8
#undef TIMES4

u16 count_class_lookup16[65536];

void init_count_class16(void) {

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++) {

    for (b2 = 0; b2 < 256; b2++) {

      count_class_lookup16[(b1 << 8) + b2] =
          (count_class_lookup8[b1] << 8) | count_class_lookup8[b2];

    }

  }

}

/* Import coverage processing routines. */

#ifdef WORD_SIZE_64
  #include "coverage-64.h"
#else
  #include "coverage-32.h"
#endif

/* check capability by reading capability hash from specific file */
uint64_t check_capability() {
  /* capability hash file path is fixed! */
  char *cap_hash_file = "/tmp/cap_res_file";
  uint64_t result = 0;

  FILE *fp = fopen(cap_hash_file,"r");
  if (fp == NULL) {
    PFATAL("Unable to open '%s'", cap_hash_file);
    return -1;
  }

  fread(&result, 4, 1, fp);  // HACK! capability hash length is fixed now!
  fclose(fp);

  /* remove the prev_addr file, so that we can know whether we are running a new poc */
  if(access("/tmp/acc_addr_prev", F_OK) == 0) {
    remove("/tmp/acc_addr_prev");
  } else {
    // file doesn't exist
  }

  /* remove the buffer_pc_prev file, so that we can know whether we are running a new poc */
  if(access("/tmp/buffer_pc_prev", F_OK) == 0) {
    remove("/tmp/buffer_pc_prev");
  } else {
    // file doesn't exist
  }

  return result;
}

void check_mutate_pos(struct queue_entry *q, void *mem) {
  int diff_pos_cnt = 0;

  /* Check whether the two strings to be compared have the same length */
  if (original_poc_len != q->len) {
    /* Warning! The should be same, if you arrive this branch, there must
     * be some problem! */
    return;
  }

  u8 *orig_buf, *cur_buf;
  int orig_byte, cur_byte;

  orig_buf = original_poc_buf;
  cur_buf = mem;

  for (u32 i = 0; i < q->len; i++) {
    orig_byte = *(orig_buf + i);
    cur_byte  = *(cur_buf + i);

    if (orig_byte != cur_byte) {
      /* This position was mutated! */
      q->cur_mutated_pos[diff_pos_cnt] = (int) i;
      diff_pos_cnt++;
    }
  }

  /* Update cur_mutate_pos_num */
  q->cur_mutate_pos_num = diff_pos_cnt;

  return;
}

/* Hash the mutated positions
 * This hash value will be used to be the key of heatMap
 * Our heatMap is a hash table */
unsigned int calculate_pos_hash(struct queue_entry *q) {
  unsigned int result = 0;
  char *hash_string_ori;
  char buffer[16];
  char *spliter = "_";
  u32 union_len = 0;     // how many positions in this union?

  // TODO: how to identify meaningless mutation union?
  if (q->cur_mutate_pos_num > q->len * 0.8) {
    /* HACK!
     * This is a meaningless union, because its mutation length is
     * larger than the length of the poc, it mutated too many bytes,
     * so we just drop it!
     * */
    return 0;
  }

  hash_string_ori = malloc(q->cur_mutate_pos_num * 16);
  for (int i = 0; i < q->cur_mutate_pos_num; i++) {

    snprintf(buffer, 16, "%d", q->cur_mutated_pos[i]);

    if (i == 0) {
      strcpy(hash_string_ori, buffer);
      strcat(hash_string_ori, spliter);
    } else {
      strcat(hash_string_ori, buffer);
      strcat(hash_string_ori, spliter);
    }

    union_len += 1;

  }

  /* Update union related status */
  q->union_len = union_len;

  result = DJBHash(hash_string_ori, strlen(hash_string_ori));

  free(hash_string_ori);
  return result;
}

void change_position_value(u8 *data_to_change, u8 *orig_data,
                            int position[], int pos_to_change_num) {
  char orig_ch;
  int changing_pos;

  for (int i = 0; i < pos_to_change_num; i++) {
    changing_pos = position[i];
    orig_ch = *(orig_data + changing_pos);
    memset(data_to_change+changing_pos, orig_ch, 1);
  }

}

/* Execute target application. Returns 0 if the capability is not
 * changed, or 1 if the capability is different. */

static u8 trim_run_target(afl_forkserver_t *fsrv, u8 *mem, u32 len,
                          u32 cap_hash_orig) {

  static volatile u8 stop_soon;          /* Ctrl-C pressed? */

  afl_fsrv_write_to_testcase(fsrv, mem, len);

  fsrv_run_result_t ret =
      afl_fsrv_run_target(fsrv, fsrv->exec_tmout, &stop_soon);

  if (ret == FSRV_RUN_ERROR) { FATAL("Couldn't run child"); }

  if (stop_soon) {

    SAYF(cRST cLRD "\n+++ Minimization aborted by user +++\n" cRST);
    exit(1);

  }

  /* Handle crashing inputs depending on current mode. */

  if (ret == FSRV_RUN_CRASH) {
    /* Handle crashing inputs. */

    // Check whether the capability is still same after recover
    u32 cap_hash_cur = check_capability();
    if (cap_hash_cur != cap_hash_orig) {
      /* capability changed! */
      return 1;
    } else {
      return 0;
    }

  } else {

    /* Handle non-crashing inputs appropriately. */
    /* capability changed! */
    return 1;

  }

}

/* We locate necessary mutate byte by applying delta debugging
 * if the capability is not changed after we recover the value of byte_a,
 * we will regard byte_a as a meaningless mutation, and remove it from necessary
 * mutation byte.
 *
 * In order to speed up the trimming process, we will recover bytes with different
 * step length, which is similar to afl-tmin's minimize strategy */
void minimize(afl_state_t *afl, struct queue_entry *q, void *mem) {
  u32 del_len, del_pos, cur_pass = 0;
  u32 in_len;
  u8 *test_data;
  u32 cap_hash_before_trim;

   if (q->cur_mutate_pos_num <= 1) {
     /* No need for trimming! */
     return;
   }

  // Initialize cap_hash before trim
  cap_hash_before_trim = check_capability();

  // in_len stands for the length of union
  in_len = q->cur_mutate_pos_num;
  
  /* tmp_buf is the buffer for union bytes */
  int tmp_buf[MAX_MUTATE_NUM] = {-1};

  /* test_data is the buffer we will use to test */
  test_data = ck_alloc_nozero(q->len);

  /**************************
   * UNION BLOCK DELETION   *
   **************************/
   /* If one position in union is deleted, we will recover the value
    * of this position */
  del_len = next_pow2(in_len / UNION_TRIM_START_STEPS);


next_del_blksize:

  if (!del_len) { del_len = 1; }
  del_pos = 0;

  while (del_pos < in_len) {
    /* Initialize test_data */
    memcpy(test_data, original_poc_buf, original_poc_len);

    u8  res;
    s32 tail_len;

    tail_len = in_len - del_pos - del_len;
    if (tail_len < 0) { tail_len = 0; }

    u32 tmp_buf_len = 0;

    /* Head */
    for (u32 i = 0; i < del_pos; i++) {
      tmp_buf[i] = q->cur_mutated_pos[i];
      tmp_buf_len++;
    }

    /* Tail */
    for (u32 j = del_pos + del_len; j < in_len; j++) {
      tmp_buf[tmp_buf_len] = q->cur_mutated_pos[j];
      tmp_buf_len++;
    }

    /* Recover positions, generate new input to test */
    change_position_value(test_data, mem, tmp_buf, in_len - del_len);

    res = trim_run_target(&afl->fsrv, test_data, q->len,
                          cap_hash_before_trim);

    if (res) {
      /* Capability changed after trimming */
      // Current positions cannot be trimmed!

      del_pos += del_len;

    } else {
      /* Capability didn't change after trimming */
      // Trim success, let's try to trim more positions from union

      /* Update union */
      for (u32 k = 0; k < del_pos + tail_len; k++) {
        q->cur_mutated_pos[k] = tmp_buf[k];
      }
      q->cur_mutate_pos_num = del_pos + tail_len;

      in_len = del_pos + tail_len;

    }

  }

  if (del_len > 1 && in_len >= 1) {

    del_len /= 2;
    goto next_del_blksize;

  }

  /* Prepare minimum mutated testcase according to cur_mutated_pos */
  memcpy(test_data, original_poc_buf, original_poc_len);
  change_position_value(test_data, mem, q->cur_mutated_pos, q->cur_mutate_pos_num);

  /* replace mem with test_data, so that we will only store the minimum
   * capability introducing seed into the queue */
  memcpy(mem, test_data, q->len);
  
  ck_free(test_data);

}

// TODO: add trim for union support here!
/*every time we find new capability, we should:
* Step One:    Locate mutated positions (we call it union)
* Step Two:    Not every position is the union is necessary for the new capability,
*              we should trim the union, only keep the minimum union
* */
void trim_union(afl_state_t *afl, struct queue_entry *q, void *mem) {

  /* Step One: Compare current input with original input, so that we can
  *            know which bytes were mutated!
  **/
  check_mutate_pos(q, mem);

  /* Step Two: remove meaningless mutation from union */
  minimize(afl, q, mem);

  /* Update union_len */
  q->union_len = q->cur_mutate_pos_num;

}

/* return 0 ——> this is a new capability
 * return 1 ——> we have seen this capability before! */

u8 is_old_capability() {
  int ret;
  khiter_t iter = 0;

  /* STEP One: calculate map index */
  unsigned int cap_hash = check_capability();

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

void update_heat_map(struct queue_entry *q) {

  int is_missing, ret;
  khiter_t iter = 0;

  /* STEP One: calculate map index */
  unsigned int pos_hash = calculate_pos_hash(q);
  q->union_hash = pos_hash;

  if (pos_hash == 0) {
    /* This is a meaningless union, because its mutation length is
     * larger than the length of the poc, it mutated too many bytes,
     * so we just drop it!
     * */
    return;
  }

  if (!q->union_len) {
    /* this is our original PoC */
    return;
  }

  /* STEP Two: update the value in heatMap according to index */

  /* Check whether we have this key in hash map */
  iter = kh_get(m64HashTable, heatMapUnion, pos_hash);
  if (iter == kh_end(heatMapUnion)) {
    /* This key doesn't exist */

    // check whether we have found more than MAX_UNION_NUM
    if (all_union_num > MAX_UNION_NUM) {
      /* We just initialize the heat of this seed as 1 */
      q->union_heat = 1;
      return;
    }
    // Insert this key into hash table
    iter = kh_put(m64HashTable, heatMapUnion, pos_hash, &ret);
    if (!ret) kh_del(m64HashTable, heatMapUnion, iter);

    // Initialize the key with value 1
    kh_value(heatMapUnion, iter) = 1;
    union_cnt += 1;

    /* insert this union into all_union */
    all_union[all_union_num].union_hash = pos_hash;
    all_union[all_union_num].union_len = q->union_len;
    all_union[all_union_num].pos_num = 0;

    for (int i = 0; i < q->cur_mutate_pos_num; i++) {
      all_union[all_union_num].mutate_pos[i] = (u32)q->cur_mutated_pos[i];
      all_union[all_union_num].pos_num += 1;
    }

    all_union_num += 1;

    new_union = 1;

  } else {
    /* This key exist */
    // Update the value of this key
    kh_value(heatMapUnion, iter) += 1;

    new_union = 0;
  }

  /* Update union related status */
  q->union_heat = kh_val(heatMapUnion, iter);

}

/*****************************************************
 * *********** HEAT MAP UNION HASH TABLE *************
 *
 * We use hash table to speed up the heatmap update
 * key is the mutation position hash
 * value is the heat
******************************************************/

/********* heatMapUnion Hash Table Related  *****************/

/********* End of heatMapUnion Hash Table Related  *****************/

/* Should only be used at the first run */
void capability_init(afl_state_t *afl) {
  u32 cap_hash_cur = check_capability();

  afl->virgin_capability = cap_hash_cur;

  struct stat st;
  s32 fd = open(afl->initial_poc_path, O_RDONLY);

  if (fd < 0) { PFATAL("Unable to open '%s'", afl->initial_poc_path); }
  if (fstat(fd, &st) || !st.st_size) { FATAL("Zero-sized initial_poc."); }
  u32 in_len = st.st_size;
  close(fd);

  /* Initialize original input bytes */
  original_poc_buf = ck_alloc(in_len);
  int fd_ori = open(afl->initial_poc_path, O_RDONLY);
  if (unlikely(fd_ori < 0)) { PFATAL("Unable to open '%s'", afl->initial_poc_path); }

  ck_read(fd_ori, original_poc_buf, in_len, afl->initial_poc_path);
  close(fd_ori);

  original_poc_len = in_len;

  /* Initialize all_capabilities, which is a hash table */
  all_cap_hashTable = kh_init(m64HashTable);

  /* Initialize heatMapUnion, which is a hash table */
  //init_heatMapUnion(afl);
  heatMapUnion = kh_init(m64HashTable);

  /* Initialize all_union, which will be used in mutation stage */
  all_union = ck_alloc(sizeof(cap_union_t) * MAX_UNION_NUM);

  new_union = 0;

  all_union_num = 0;
  all_capability_num = 0;

}
/* return 0 if we do not need update
 * return 1 if we update the fuzzed_union with new item */
inline u8 update_union_fuzzed(u32 union_hash) {
  u8 union_is_found = 0;

  for (u32 i = 0; i < fuzzed_union_cnt; i++) {
    if (union_hash == fuzzed_union[i]) {
      /* We have fuzzed this union, do not need update! */
      union_is_found = 1;

      break;
    }
  } // end of fuzzed_union iteration

  if (!union_is_found) {
    /* This is the first time we see this union! */
    /* Update the fuzzed_union with it ! */
    fuzzed_union[fuzzed_union_cnt] = union_hash;
    fuzzed_union_cnt += 1;

    return 1;
  }

  return 0;
}

inline void scan_seed_capability(afl_state_t *afl, struct queue_entry *q, u8 *use_mem) {

  /* Initialize virgin when this is first run */
  if (!afl->virgin_capability) {
    /* This is first run!
     * we need to initialize it!*/
    capability_init(afl);
    fuzzed_union_cnt = 0;
  }

  /* Check whether current capability exist in virgin*/
  is_old_capability();

  /* Update union */
  trim_union(afl, q, use_mem);

  q->union_len = q->cur_mutate_pos_num;

  /* Update mutation heat map with minimum union */
  update_heat_map(q);

}

/* Check if the current seed brings any new capability */
inline u8 has_new_capability(afl_state_t *afl, struct queue_entry *q, void *mem) {

  u32 cap_hash_cur = check_capability();

  /* Initialize virgin when this is first run */
  if (!afl->virgin_capability) {
    /* This is first run!
     * we need to initialize it!*/
    capability_init(afl);
    fuzzed_union_cnt = 0;

    is_old_capability();

    return 1;
  }

  /* Check whether current capability exist in virgin*/
  if (is_old_capability()) {
    /* We have seen this capability already! */
    return 0;
  }

  return 1;

}

/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen.
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

inline u8 has_new_bits(afl_state_t *afl, u8 *virgin_map) {

#ifdef WORD_SIZE_64

  u64 *current = (u64 *)afl->fsrv.trace_bits;
  u64 *virgin = (u64 *)virgin_map;

  u32 i = (afl->fsrv.map_size >> 3);

#else

  u32 *current = (u32 *)afl->fsrv.trace_bits;
  u32 *virgin = (u32 *)virgin_map;

  u32 i = (afl->fsrv.map_size >> 2);

#endif                                                     /* ^WORD_SIZE_64 */

  u8 ret = 0;
  while (i--) {

    if (unlikely(*current)) discover_word(&ret, current, virgin);

    current++;
    virgin++;

  }

  if (unlikely(ret) && likely(virgin_map == afl->virgin_bits))
    afl->bitmap_changed = 1;

  return ret;

}

/* A combination of classify_counts and has_new_bits. If 0 is returned, then the
 * trace bits are kept as-is. Otherwise, the trace bits are overwritten with
 * classified values.
 *
 * This accelerates the processing: in most cases, no interesting behavior
 * happen, and the trace bits will be discarded soon. This function optimizes
 * for such cases: one-pass scan on trace bits without modifying anything. Only
 * on rare cases it fall backs to the slow path: classify_counts() first, then
 * return has_new_bits(). */

inline u8 has_new_bits_unclassified(afl_state_t *afl, u8 *virgin_map) {

  /* Handle the hot path first: no new coverage */
  u8 *end = afl->fsrv.trace_bits + afl->fsrv.map_size;

#ifdef WORD_SIZE_64

  if (!skim((u64 *)virgin_map, (u64 *)afl->fsrv.trace_bits, (u64 *)end))
    return 0;

#else

  if (!skim((u32 *)virgin_map, (u32 *)afl->fsrv.trace_bits, (u32 *)end))
    return 0;

#endif                                                     /* ^WORD_SIZE_64 */
  classify_counts(&afl->fsrv);
  return has_new_bits(afl, virgin_map);

}

/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. */

void minimize_bits(afl_state_t *afl, u8 *dst, u8 *src) {

  u32 i = 0;

  while (i < afl->fsrv.map_size) {

    if (*(src++)) { dst[i >> 3] |= 1 << (i & 7); }
    ++i;

  }

}

#ifndef SIMPLE_FILES

/* Construct a file name for a new test case, capturing the operation
   that led to its discovery. Returns a ptr to afl->describe_op_buf_256. */

u8 *describe_op(afl_state_t *afl, u8 new_bits, size_t max_description_len) {

  /* Check whether we should switch to exploit! */
  if (get_cur_time() + afl->prev_run_time - afl->start_time >= EXPLORE_TIME) {
    if (all_union_num != 0) {
      start_exploitation = 1;
    } else {
      /* If no union was found, we continue to exploration,
       * Because we cannot focus on any union */
    }
  }

  size_t real_max_len =
      MIN(max_description_len, sizeof(afl->describe_op_buf_256));
  u8 *ret = afl->describe_op_buf_256;

  if (unlikely(afl->syncing_party)) {

    sprintf(ret, "sync:%s,src:%06u", afl->syncing_party, afl->syncing_case);

  } else {

    sprintf(ret, "src:%06u", afl->current_entry);

    if (afl->splicing_with >= 0) {

      sprintf(ret + strlen(ret), "+%06d", afl->splicing_with);

    }

    sprintf(ret + strlen(ret), ",time:%llu",
            get_cur_time() + afl->prev_run_time - afl->start_time);

    if (afl->current_custom_fuzz &&
        afl->current_custom_fuzz->afl_custom_describe) {

      /* We are currently in a custom mutator that supports afl_custom_describe,
       * use it! */

      size_t len_current = strlen(ret);
      ret[len_current++] = ',';
      ret[len_current] = '\0';

      ssize_t size_left = real_max_len - len_current - strlen(",+cov") - 2;
      if (unlikely(size_left <= 0)) FATAL("filename got too long");

      const char *custom_description =
          afl->current_custom_fuzz->afl_custom_describe(
              afl->current_custom_fuzz->data, size_left);
      if (!custom_description || !custom_description[0]) {

        DEBUGF("Error getting a description from afl_custom_describe");
        /* Take the stage name as description fallback */
        sprintf(ret + len_current, "op:%s", afl->stage_short);

      } else {

        /* We got a proper custom description, use it */
        strncat(ret + len_current, custom_description, size_left);

      }

    } else {

      /* Normal testcase descriptions start here */
      sprintf(ret + strlen(ret), ",op:%s", afl->stage_short);

      if (afl->stage_cur_byte >= 0) {

        sprintf(ret + strlen(ret), ",pos:%d", afl->stage_cur_byte);

        if (afl->stage_val_type != STAGE_VAL_NONE) {

          sprintf(ret + strlen(ret), ",val:%s%+d",
                  (afl->stage_val_type == STAGE_VAL_BE) ? "be:" : "",
                  afl->stage_cur_val);

        }

      } else {

        sprintf(ret + strlen(ret), ",rep:%d", afl->stage_cur_val);

      }

    }

  }

  if (new_bits == 2) { strcat(ret, ",+cov"); }

  if (new_union) { strcat(ret, ",+union"); }

  if (unlikely(strlen(ret) >= max_description_len))
    FATAL("describe string is too long");

  return ret;

}

#endif                                                     /* !SIMPLE_FILES */

/* Write a message accompanying the crash directory :-) */

void write_crash_readme(afl_state_t *afl) {

  u8    fn[PATH_MAX];
  s32   fd;
  FILE *f;

  u8 val_buf[STRINGIFY_VAL_SIZE_MAX];

  sprintf(fn, "%s/crashes/README.txt", afl->out_dir);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);

  /* Do not die on errors here - that would be impolite. */

  if (unlikely(fd < 0)) { return; }

  f = fdopen(fd, "w");

  if (unlikely(!f)) {

    close(fd);
    return;

  }

  fprintf(
      f,
      "Command line used to find this crash:\n\n"

      "%s\n\n"

      "If you can't reproduce a bug outside of afl-fuzz, be sure to set the "
      "same\n"
      "memory limit. The limit used for this fuzzing session was %s.\n\n"

      "Need a tool to minimize test cases before investigating the crashes or "
      "sending\n"
      "them to a vendor? Check out the afl-tmin that comes with the fuzzer!\n\n"

      "Found any cool bugs in open-source tools using afl-fuzz? If yes, please "
      "drop\n"
      "an mail at <afl-users@googlegroups.com> once the issues are fixed\n\n"

      "  https://github.com/AFLplusplus/AFLplusplus\n\n",

      afl->orig_cmdline,
      stringify_mem_size(val_buf, sizeof(val_buf),
                         afl->fsrv.mem_limit << 20));      /* ignore errors */

  fclose(f);

}

/* Check if the result of an execve() during routine fuzzing is interesting,
   save or queue the input test case for further analysis if so. Returns 1 if
   entry is saved, 0 otherwise. */

u8 __attribute__((hot))
save_if_interesting(afl_state_t *afl, void *mem, u32 len, u8 fault) {

  if (unlikely(len == 0)) { return 0; }

  u8 *queue_fn = "";
  u8  new_bits = '\0';
  s32 fd;
  u8  keeping = 0, res, classified = 0;
  u64 cksum = 0;

  u8 fn[PATH_MAX];

  u8 new_capability = 0;

  /* Update path frequency. */

  /* Generating a hash on every input is super expensive. Bad idea and should
     only be used for special schedules */
  if (unlikely(afl->schedule >= FAST && afl->schedule <= RARE)) {

    cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

    /* Saturated increment */
    if (afl->n_fuzz[cksum % N_FUZZ_SIZE] < 0xFFFFFFFF)
      afl->n_fuzz[cksum % N_FUZZ_SIZE]++;

  }

  if (likely(fault == afl->crash_mode)) {

    /* Keep only if there is new capability, add to queue for
       future fuzzing, etc. */

    //new_bits = has_new_bits_unclassified(afl, afl->virgin_bits);
    new_capability = has_new_capability(afl, afl->queue_cur, mem);

    if (likely(!new_capability)) {

      //if (unlikely(afl->crash_mode)) { ++afl->total_crashes; }
      return 0;

    }

    /*
    if (likely(!new_bits)) {

      if (unlikely(afl->crash_mode)) { ++afl->total_crashes; }
      return 0;

    } */

    classified = new_bits;

#ifndef SIMPLE_FILES

    queue_fn = alloc_printf(
        "%s/queue/id:%06u,%s", afl->out_dir, afl->queued_paths,
        describe_op(afl, new_bits, NAME_MAX - strlen("id:000000,")));

#else

    queue_fn =
        alloc_printf("%s/queue/id_%06u", afl->out_dir, afl->queued_paths);

#endif                                                    /* ^!SIMPLE_FILES */
    fd = open(queue_fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", queue_fn); }
    ck_write(fd, mem, len, queue_fn);
    close(fd);
    add_to_queue(afl, queue_fn, len, 0);

    struct queue_entry *q_cur = afl->queue_buf[afl->queued_paths - 1];
    trim_union(afl, q_cur, mem);

    /* Update mutation heat map with minimum union */
    update_heat_map(q_cur);

#ifdef INTROSPECTION
    if (afl->custom_mutators_count && afl->current_custom_fuzz) {

      LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

        if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

          const char *ptr = el->afl_custom_introspection(el->data);

          if (ptr != NULL && *ptr != 0) {

            fprintf(afl->introspection_file, "QUEUE CUSTOM %s = %s\n", ptr,
                    afl->queue_top->fname);

          }

        }

      });

    } else if (afl->mutation[0] != 0) {

      fprintf(afl->introspection_file, "QUEUE %s = %s\n", afl->mutation,
              afl->queue_top->fname);

    }

#endif


    /* Try to calibrate inline; this also calls update_bitmap_score() when
       successful. */

    res = calibrate_case(afl, afl->queue_top, mem, afl->queue_cycle - 1, 0);

    if (unlikely(res == FSRV_RUN_ERROR)) {

      FATAL("Unable to execute target application");

    }

    if (likely(afl->q_testcase_max_cache_size)) {

      queue_testcase_store_mem(afl, afl->queue_top, mem);

    }

    keeping = 1;

  }

  switch (fault) {

    case FSRV_RUN_TMOUT:

      /* Timeouts are not very interesting, but we're still obliged to keep
         a handful of samples. We use the presence of new bits in the
         hang-specific bitmap as a signal of uniqueness. In "non-instrumented"
         mode, we just keep everything. */

      ++afl->total_tmouts;

      if (afl->unique_hangs >= KEEP_UNIQUE_HANG) { return keeping; }

      if (likely(!afl->non_instrumented_mode)) {

        if (!classified) {

          classify_counts(&afl->fsrv);
          classified = 1;

        }

        simplify_trace(afl, afl->fsrv.trace_bits);

        if (!has_new_bits(afl, afl->virgin_tmout)) { return keeping; }

      }

      ++afl->unique_tmouts;
#ifdef INTROSPECTION
      if (afl->custom_mutators_count && afl->current_custom_fuzz) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

            const char *ptr = el->afl_custom_introspection(el->data);

            if (ptr != NULL && *ptr != 0) {

              fprintf(afl->introspection_file,
                      "UNIQUE_TIMEOUT CUSTOM %s = %s\n", ptr,
                      afl->queue_top->fname);

            }

          }

        });

      } else if (afl->mutation[0] != 0) {

        fprintf(afl->introspection_file, "UNIQUE_TIMEOUT %s\n", afl->mutation);

      }

#endif

      /* Before saving, we make sure that it's a genuine hang by re-running
         the target with a more generous timeout (unless the default timeout
         is already generous). */

      if (afl->fsrv.exec_tmout < afl->hang_tmout) {

        u8 new_fault;
        write_to_testcase(afl, mem, len);
        new_fault = fuzz_run_target(afl, &afl->fsrv, afl->hang_tmout);

        /* A corner case that one user reported bumping into: increasing the
           timeout actually uncovers a crash. Make sure we don't discard it if
           so. */

        if (!afl->stop_soon && new_fault == FSRV_RUN_CRASH) {

          goto keep_as_crash;

        }

        if (afl->stop_soon || new_fault != FSRV_RUN_TMOUT) { return keeping; }

      }

#ifndef SIMPLE_FILES

      snprintf(fn, PATH_MAX, "%s/hangs/id:%06llu,%s", afl->out_dir,
               afl->unique_hangs,
               describe_op(afl, 0, NAME_MAX - strlen("id:000000,")));

#else

      snprintf(fn, PATH_MAX, "%s/hangs/id_%06llu", afl->out_dir,
               afl->unique_hangs);

#endif                                                    /* ^!SIMPLE_FILES */

      ++afl->unique_hangs;

      afl->last_hang_time = get_cur_time();

      break;

    case FSRV_RUN_CRASH:

    keep_as_crash:

      /* This is handled in a manner roughly similar to timeouts,
         except for slightly different limits and no need to re-run test
         cases. */

      ++afl->total_crashes;

      if (afl->unique_crashes >= KEEP_UNIQUE_CRASH) { return keeping; }

      if (likely(!afl->non_instrumented_mode)) {

        //if (!has_new_bits(afl, afl->virgin_crash)) { return keeping; }
        if (!has_new_capability(afl, afl->queue_cur, mem)) { return keeping; }

      }

      if (unlikely(!afl->unique_crashes)) { write_crash_readme(afl); }

#ifndef SIMPLE_FILES

      snprintf(fn, PATH_MAX, "%s/crashes/id:%06llu,sig:%02u,%s", afl->out_dir,
               afl->unique_crashes, afl->fsrv.last_kill_signal,
               describe_op(afl, 0, NAME_MAX - strlen("id:000000,sig:00,")));

#else

      snprintf(fn, PATH_MAX, "%s/crashes/id_%06llu_%02u", afl->out_dir,
               afl->unique_crashes, afl->last_kill_signal);

#endif                                                    /* ^!SIMPLE_FILES */

      ++afl->unique_crashes;
#ifdef INTROSPECTION
      if (afl->custom_mutators_count && afl->current_custom_fuzz) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

            const char *ptr = el->afl_custom_introspection(el->data);

            if (ptr != NULL && *ptr != 0) {

              fprintf(afl->introspection_file, "UNIQUE_CRASH CUSTOM %s = %s\n",
                      ptr, afl->queue_top->fname);

            }

          }

        });

      } else if (afl->mutation[0] != 0) {

        fprintf(afl->introspection_file, "UNIQUE_CRASH %s\n", afl->mutation);

      }

#endif
      if (unlikely(afl->infoexec)) {

        // if the user wants to be informed on new crashes - do that
#if !TARGET_OS_IPHONE
        // we dont care if system errors, but we dont want a
        // compiler warning either
        // See
        // https://stackoverflow.com/questions/11888594/ignoring-return-values-in-c
        (void)(system(afl->infoexec) + 1);
#else
        WARNF("command execution unsupported");
#endif

      }

      afl->last_crash_time = get_cur_time();
      afl->last_crash_execs = afl->fsrv.total_execs;

      break;

    case FSRV_RUN_ERROR:
      FATAL("Unable to execute target application");

    default:
      return keeping;

  }

  /* If we're here, we apparently want to save the crash or hang
     test case, too. */

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
  if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", fn); }
  ck_write(fd, mem, len, fn);
  close(fd);

  return keeping;

}

