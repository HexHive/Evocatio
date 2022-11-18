#!/bin/python3

import sys
import os
import argparse
import json
import math


"""
Script to calculate bug severity score.

Input: capability details for each CVE

Output: severity score of the CVE

"""

NEED_PRINT = 1

total_bug_type = 10
VALUE_2 = 5
VALUE_3 = 5
VALUE_4 = 5
VALUE_5 = 5
VALUE_6 = 5

class SeverityScore:

    def __init__(self, cap_json_file):
        """Constructor"""
        self._cap_json = cap_json_file
        self._cap_details = dict()

    def _load_cap_from_json(self):
        with open(self._cap_json, "r") as f:
            self._cap_details = json.load(f)

        return self._cap_details

    @staticmethod
    def _print_cap_details(content):
        print("min_read_len: {}\n".format(content["min_read_len"]))
        print("max_read_len: {}\n".format(content["max_read_len"]))
        print("read_len_num: {}\n".format(content["read_len_num"]))
        print("min_write_len: {}\n".format(content["min_write_len"]))
        print("max_write_len: {}\n".format(content["max_write_len"]))
        print("write_len_num: {}\n".format(content["write_len_num"]))

        print("min_read_addr: {}\n".format(content["min_read_addr"]))
        print("max_read_addr: {}\n".format(content["max_read_addr"]))
        print("read_addr_num: {}\n".format(content["read_addr_num"]))
        print("min_write_addr: {}\n".format(content["min_write_addr"]))
        print("max_write_addr: {}\n".format(content["max_write_addr"]))
        print("write_addr_num: {}\n".format(content["write_addr_num"]))

        print("orig_stack_num: {}\n".format(content["orig_stack_num"]))
        print("orig_heap_num: {}\n".format(content["orig_heap_num"]))

        print("min_orig_size_read: {}\n".format(content["min_orig_size_read"]))
        print("max_orig_size_read: {}\n".format(content["max_orig_size_read"]))
        print("orig_size_read_num: {}\n".format(content["orig_size_read_num"]))
        print("min_orig_size_write: {}\n".format(content["min_orig_size_write"]))
        print("max_orig_size_write: {}\n".format(content["max_orig_size_write"]))
        print("orig_size_write_num: {}\n".format(content["orig_size_write_num"]))

        print("orig_offset_min_read: {}\n".format(content["orig_offset_min_read"]))
        print("orig_offset_max_read: {}\n".format(content["orig_offset_max_read"]))
        print("orig_offset_read_num: {}\n".format(content["orig_offset_read_num"]))
        print("orig_offset_min_write: {}\n".format(content["orig_offset_min_write"]))
        print("orig_offset_max_write: {}\n".format(content["orig_offset_max_write"]))
        print("orig_offset_write_num: {}\n".format(content["orig_offset_write_num"]))

    def _calculate_score(self):
        score = 0
        y1 = y2 = y3 = y4 = y5 = y6 = 0

        # =============================================================
        #       Factor 1: bug type
        # =============================================================
        y1_base_score = 0
        if "stack-buffer-overflow" in self._bug_type or "stack-overflow" in self._bug_type or "global-buffer-overflow" in self._bug_type:
            y1_base_score = 4
        elif "heap-buffer-overflow" in self._bug_type or "heap-use-after-free" in self._bug_type:
            y1_base_score = 3
        elif "null" in self._bug_type:
            y1_base_score = 2
        else:
            y1_base_score = 1

        y1 = y1_base_score + len(self._bug_type)/total_bug_type

        # =============================================================
        #       Factor 2: Access length
        # =============================================================
        max_len_read = int(self._max_read_len)
        max_len_write = int(self._max_write_len)

        y2_read = 1/(1 + math.exp(-max_len_read * VALUE_2))
        y2_write = 1/(1 + math.exp(-max_len_write * VALUE_2))

        # =============================================================
        #       Factor 3: Access memory address
        # =============================================================
        access_range_read = int(self._max_read_addr) - int(self._min_read_addr)
        access_range_write = int(self._max_write_addr) - int(self._min_write_addr)

        y3_read = 1 / (1 + math.exp(-access_range_read * VALUE_3))
        y3_write = 1 / (1 + math.exp(-access_range_write * VALUE_3))

        # =============================================================
        #       Factor 4: Origin Object number
        # =============================================================
        stack_obj_num = int(self._orig_stack_num)
        heap_obj_num = int(self._orig_heap_num)

        all_obj_num = stack_obj_num + heap_obj_num
        y4 = 1 / (1 + math.exp(-all_obj_num * VALUE_4))

        # =============================================================
        #       Factor 5: Origin Object size
        # =============================================================
        max_obj_size_read = int(self._max_orig_size_read)
        max_obj_size_write = int(self._max_orig_size_write)

        y5_read = 1 / (1 + math.exp(-max_obj_size_read * VALUE_5))
        y5_write = 1 / (1 + math.exp(-max_obj_size_write * VALUE_5))

        # =============================================================
        #       Factor 6: Offset
        # =============================================================
        offset_num_read = int(self._orig_offset_read_num)
        offset_num_write = int(self._orig_offset_write_num)

        y6_read = 1 / (1 + math.exp(-offset_num_read * VALUE_6))
        y6_write = 1 / (1 + math.exp(-offset_num_write * VALUE_6))

        score_read = y1 + y2_read + y3_read + y4 + y5_read + y6_read
        score_write = y1 + y2_write + y3_write + y4 + y5_write + y6_write

        return score_read, score_write

    def _init_value(self, content):
        self._bug_type = content["bug_type"]

        self._min_read_len = content["min_read_len"]
        self._max_read_len = content["max_read_len"]
        self._read_len_num = content["read_len_num"]
        self._min_write_len = content["min_write_len"]
        self._max_write_len = content["max_write_len"]
        self._write_len_num = content["write_len_num"]

        self._min_read_addr = content["min_read_addr"]
        self._max_read_addr = content["max_read_addr"]
        self._read_addr_num = content["read_addr_num"]
        self._min_write_addr = content["min_write_addr"]
        self._max_write_addr = content["max_write_addr"]
        self._write_addr_num = content["write_addr_num"]

        self._orig_stack_num = content["orig_stack_num"]
        self._orig_heap_num = content["orig_heap_num"]

        self._min_orig_size_read = content["min_orig_size_read"]
        self._max_orig_size_read = content["max_orig_size_read"]
        self._orig_size_read_num = content["orig_size_read_num"]
        self._min_orig_size_write = content["min_orig_size_write"]
        self._max_orig_size_write = content["max_orig_size_write"]
        self._orig_size_write_num = content["orig_size_write_num"]

        self._orig_offset_min_read = content["orig_offset_min_read"]
        self._orig_offset_max_read = content["orig_offset_max_read"]
        self._orig_offset_read_num = content["orig_offset_read_num"]
        self._orig_offset_min_write = content["orig_offset_min_write"]
        self._orig_offset_max_write = content["orig_offset_max_write"]
        self._orig_offset_write_num = content["orig_offset_write_num"]

    def start_work(self):
        content = self._load_cap_from_json()

        if NEED_PRINT:
            SeverityScore._print_cap_details(content)

        self._init_value(content)

        score_read, score_write = self._calculate_score()
        print("Severity Score READ is: {}\n".format(score_read))
        print("Severity Score WRITE is: {}\n".format(score_write))


def main():
    """"""

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", help="capability json file")

    args = parser.parse_args()

    Calculator = SeverityScore(args.i)
    Calculator.start_work()


if __name__ == "__main__":
    main()