#!/bin/python3

import subprocess
import sys
import os
import argparse
import json
import re

"""
Script to scan crashes to know whether we find new capabilities.

Do a quick statical analyze on them

"""

capability_res_file = "/tmp/cap_res_file"
asan_output_file = "/tmp/asan.out"
eval_time_file = "/tmp/eval_time.res"
cap_detail_json = "/tmp/cap_details.json"

IS_RAW_DATA = 1


class RawDataGenetator:

    def __init__(self, binary_path, crash_source_dir, crash_target_dir, binary_args):
        """Constructor"""
        self.binary = binary_path
        self.crash_dict = dict()
        self.inputs_path = set()
        self.crash_source_dir = crash_source_dir
        self._crash_target_dir = crash_target_dir
        self.binary_args = binary_args
        self._crash_pos_all = dict()

        self._invalid_read_len = set()
        self._invalid_write_len = set()

        self.capability_res_sta = dict()
        self.invalid_access_cap = dict()

        self._human_read_merged_res = dict()

        self._err_file = asan_output_file
        self._asan_out = None

        self.all_cap_info = dict()
        self.all_heap_alloc_hash = set()
        self.all_acc_offset = set()
        self.all_direction = set()
        self.all_obj_size = set()
        self.all_stack_obj = set()
        self.all_bug_type = set()

        self.unique_bug_type_time = []
        self.unique_acc_len_time = []
        self.unique_obj_time = []

        self.bug_type = []

        self.min_read_len = 0
        self.max_read_len = 0
        self.read_len_num = 0
        self.min_write_len = 0
        self.max_write_len = 0
        self.write_len_num = 0

        self.min_read_addr = 0
        self.max_read_addr = 0
        self.read_addr_num = 0
        self.min_write_addr = 0
        self.max_write_addr = 0
        self.write_addr_num = 0

        self.orig_stack_num = 0
        self.orig_heap_num = 0

        self.min_orig_size_read = 0
        self.max_orig_size_read = 0
        self.orig_size_read_num = 0
        self.min_orig_size_write = 0
        self.max_orig_size_write = 0
        self.orig_size_write_num = 0

        self.orig_offset_min_read = 0
        self.orig_offset_max_read = 0
        self.orig_offset_read_num = 0
        self.orig_offset_min_write = 0
        self.orig_offset_max_write = 0
        self.orig_offset_write_num = 0

        self.orig_size_read = set()
        self.orig_size_write = set()
        self.orig_offset_read = set()
        self.orig_offset_write = set()

    def dump_cap_details_json(self):
        with open(cap_detail_json, "w") as f:
            content = dict()

            content["bug_type"] = self.bug_type

            content["min_read_len"] = self.min_read_len
            content["max_read_len"] = self.max_read_len
            content["read_len_num"] = self.read_len_num
            content["min_write_len"] = self.min_write_len
            content["max_write_len"] = self.max_write_len
            content["write_len_num"] = self.write_len_num

            content["min_read_addr"] = self.min_read_addr
            content["max_read_addr"] = self.max_read_addr
            content["read_addr_num"] = self.read_addr_num
            content["min_write_addr"] = self.min_write_addr
            content["max_write_addr"] = self.max_write_addr
            content["write_addr_num"] = self.write_addr_num

            content["orig_stack_num"] = self.orig_stack_num
            content["orig_heap_num"] = self.orig_heap_num

            content["min_orig_size_read"] = self.min_orig_size_read
            content["max_orig_size_read"] = self.max_orig_size_read
            content["orig_size_read_num"] = self.orig_size_read_num
            content["min_orig_size_write"] = self.min_orig_size_write
            content["max_orig_size_write"] = self.max_orig_size_write
            content["orig_size_write_num"] = self.orig_size_write_num

            content["orig_offset_min_read"] = self.orig_offset_min_read
            content["orig_offset_max_read"] = self.orig_offset_max_read
            content["orig_offset_read_num"] = self.orig_offset_read_num
            content["orig_offset_min_write"] = self.orig_offset_min_write
            content["orig_offset_max_write"] = self.orig_offset_max_write
            content["orig_offset_write_num"] = self.orig_offset_write_num

            str_to_dump = json.dumps(content)
            f.write(str_to_dump)

    def start_work(self):
        """"""
        self._get_crashes()
        self._handle_crashes()

        if IS_RAW_DATA:
            self._merge_capabilities()

            if "read" in self.invalid_access_cap.keys():
                self._merge_consecutive_addr("read")
            if "write" in self.invalid_access_cap.keys():
                self._merge_consecutive_addr("write")

            self.eval_update_all_object_and_offset()
            self.get_cap_res()
            self.dump_cap_details_json()
        else:
            self._merge_capabilities()

            if "read" in self.invalid_access_cap.keys():
                self._merge_consecutive_addr("read")
            if "write" in self.invalid_access_cap.keys():
                self._merge_consecutive_addr("write")

    def _get_crashes(self):
        """"""
        for crash in os.listdir(self.crash_source_dir):
            crash_path = os.path.join(self.crash_source_dir, crash)
            self.inputs_path.add(crash_path)

    def _handle_crashes(self):
        """"""
        for crash_path in self.inputs_path:
            self._scan_capability(crash_path)

    def _get_capability_details(self, capability_string):
        # bug_type @@ operation_type @@ access_len @@ access_addr @@
        content_list = capability_string[0].split("@@")
        bug_type = content_list[0]
        op_type = content_list[1]
        access_len = content_list[2]
        access_addr = content_list[3]

        return bug_type, op_type, access_len, access_addr

    def _parse_asan_alloc_stack(self):
        infer_bug_type_str = "ERROR: AddressSanitizer:"
        infer_stack_str = "stack-buffer-overflow"
        alloc_stack_hash = 0

        # Bug type, is stack or heap?
        is_bug_on_heap = -1

        frame_addr_all = []

        for line in self._asan_out:
            if "SUMMARY" in line:
                # we have scan enough info
                break

            # Find bug type
            if infer_bug_type_str in line:
                if infer_stack_str in line:
                    is_bug_on_heap = 0
                    break
                else:
                    is_bug_on_heap = 1
                    continue

            # Parse heap related info
            if is_bug_on_heap:
                # Parse alloc hash
                if "#" in line and "0x" in line:
                    frame_addr = line.split(" in ")[0].split("0x")[1]
                    frame_addr_all.append(frame_addr)

        # Calculate alloc stack hash
        if is_bug_on_heap:
            alloc_stack_hash = hash(str(frame_addr_all))

        return is_bug_on_heap, alloc_stack_hash

    """
        Example: 0x6020000002f8 is located 0 bytes to the right of 8-byte region [0x6020000002f0,0x6020000002f8)
                 acc_start_addr             --> 0x6020000002f8
                 invalid_acc_start_offset   --> 0
                 offset_direction           --> right
                 corrupted_obj_size         --> 8        
    """
    def _parse_asan_object_access_offset(self, is_bug_on_heap):
        infer_alloc_str = "allocated by thread"
        infer_alloc_str = "is located"
        infer_stack_overflow_obj = "overflows this variable"

        start_off_found = 0
        stack_corrupt_obj_found = 0

        offset_result = dict()

        # Overflow is located x bytes to the left or right?
        offset_direction = None

        # The size of corrupted object
        corrupted_obj_size = 0

        # Invalid access start offset
        invalid_acc_start_offset = 0

        # corrputed object name, only for stack bug
        stack_overflowed_obj = ""

        for line in self._asan_out:
            if "SUMMARY" in line:
                # we have scan enough info
                break

            if is_bug_on_heap == -1:
                # this is a bad input
                break

            if is_bug_on_heap:
                if infer_alloc_str in line:

                    numbers = re.findall(r"\b\d+\b", line)  # parse all numbers in this line
                    if len(numbers) == 0:
                        print('Weird! there is no size of access!\n')
                        break

                    invalid_acc_start_offset = numbers[0]
                    corrupted_obj_size = numbers[1]

                    if "to the " in line:
                        offset_direction = line.split("to the ")[1].split(" ")[0]
                    elif "inside of" in line:
                        offset_direction = "inside"
                    else:
                        pass

                    offset_result["acc_start_off"] = invalid_acc_start_offset
                    offset_result["off_direction"] = offset_direction
                    offset_result["obj_size"] = corrupted_obj_size

                    offset_result["stack_corrupt_obj"] = -1

                    return offset_result

            else:
                # Parse stack related info
                if infer_alloc_str in line:

                    numbers = re.findall(r"\b\d+\b", line)  # parse all numbers in this line
                    if len(numbers) == 0:
                        print('Weird! there is no size of access!\n')
                        break

                    invalid_acc_start_offset = numbers[0]
                    offset_result["acc_start_off"] = invalid_acc_start_offset
                    start_off_found = 1

                elif infer_stack_overflow_obj in line:
                    stack_overflowed_obj = line.split(" '")[1].split("' ")[0]
                    offset_result["stack_corrupt_obj"] = stack_overflowed_obj
                    stack_corrupt_obj_found = 1
                else:
                    pass

                if start_off_found and stack_corrupt_obj_found:
                    offset_result["off_direction"] = -1
                    offset_result["obj_size"] = -1
                    return offset_result

        return 0

    def _parse_asan_out(self):
        with open(self._err_file, 'r', errors='ignore') as f:
            self._asan_out = f.readlines()

        # parse allocation stack trace
        is_bug_on_heap, alloc_stack_hash = self._parse_asan_alloc_stack()

        # parse offset from that object to which we wrote/read
        offset_res = self._parse_asan_object_access_offset(is_bug_on_heap)

        with open(capability_res_file, "r") as f:
            capability_res = f.readlines()

            if "read" in capability_res[0]:
                if offset_res != 0:
                    obj_size = int(offset_res["obj_size"])
                    offset = int(offset_res["acc_start_off"])

                    if self.min_orig_size_read == 0 and obj_size != -1:
                        self.min_orig_size_read = obj_size
                    if obj_size != -1 and obj_size < self.min_orig_size_read:
                        self.min_orig_size_read = obj_size

                    if self.max_orig_size_read == 0 and obj_size != -1:
                        self.max_orig_size_read = obj_size
                    if obj_size > self.max_orig_size_read:
                        self.max_orig_size_read = obj_size

                    if obj_size not in self.orig_size_read:
                        self.orig_size_read.add(obj_size)

                    if self.orig_offset_min_read == 0:
                        self.orig_offset_min_read = offset
                    if offset < self.orig_offset_min_read:
                        self.orig_offset_min_read = offset

                    if self.orig_offset_max_read == 0:
                        self.orig_offset_max_read = offset
                    if offset > self.orig_offset_max_read:
                        self.orig_offset_max_read = offset

                    if offset not in self.orig_offset_read:
                        self.orig_offset_read.add(offset)

            if "write" in capability_res[0]:
                if offset_res != 0:
                    obj_size = int(offset_res["obj_size"])
                    offset = int(offset_res["acc_start_off"])

                    if self.min_orig_size_write == 0 and obj_size != -1:
                        self.min_orig_size_write = obj_size
                    if obj_size != -1 and obj_size < self.min_orig_size_write:
                        self.min_orig_size_write = obj_size

                    if self.max_orig_size_write == 0 and obj_size != -1:
                        self.max_orig_size_write = obj_size
                    if obj_size > self.max_orig_size_write:
                        self.max_orig_size_write = obj_size

                    if obj_size not in self.orig_size_write:
                        self.orig_size_write.add(obj_size)

                    if self.orig_offset_min_write == 0:
                        self.orig_offset_min_write = offset
                    if offset < self.orig_offset_min_write:
                        self.orig_offset_min_write = offset

                    if self.orig_offset_max_write == 0:
                        self.orig_offset_max_write = offset
                    if offset > self.orig_offset_max_write:
                        self.orig_offset_max_write = offset

                    if offset not in self.orig_offset_write:
                        self.orig_offset_write.add(offset)

        return alloc_stack_hash, offset_res

    """
    Parsing CapSan's output, count how many unique corrupted objects
    & offset & direction were found
    """
    def eval_update_all_object_and_offset(self):
        for seed_name, info in self.all_cap_info.items():
            heap_alloc_hash = info[0]
            offset_info = info[1]

            if offset_info == 0:
                continue

            acc_offset = offset_info["acc_start_off"]
            direction = offset_info["off_direction"]
            obj_size = offset_info["obj_size"]
            stack_obj = offset_info["stack_corrupt_obj"]

            if heap_alloc_hash != -1:
                if heap_alloc_hash not in self.all_heap_alloc_hash:
                    self.all_heap_alloc_hash.add(heap_alloc_hash)

                    pattern = re.compile(r'(?<=time:)\d+')
                    time_in_file = pattern.findall(seed_name)
                    seed_time = time_in_file[0]

                    self.unique_obj_time.append(seed_time)

            if acc_offset != -1:
                if acc_offset not in self.all_acc_offset:
                    self.all_acc_offset.add(acc_offset)

            if direction != -1:
                if direction not in self.all_direction:
                    self.all_direction.add(direction)

            if obj_size != -1:
                if obj_size not in self.all_obj_size:
                    self.all_obj_size.add(obj_size)

            if stack_obj != -1:
                if stack_obj not in self.all_stack_obj:
                    self.all_stack_obj.add(stack_obj)

    def dump_time_into_file(self):
        with open(eval_time_file, "w") as f:
            content = dict()

            content["bug_type"] = self.unique_bug_type_time
            content["acc_len"] = self.unique_acc_len_time
            content["obj"] = self.unique_obj_time

            str_to_dump = json.dumps(content)
            f.write(str_to_dump)

    def _scan_capability(self, crash_path):
        self.run_crash(crash_path)

        # Parse cd_res
        with open(capability_res_file, "r") as f:
            capability_res = f.readlines()

        # Parse ASan output
        heap_alloc_hash, offset_info = self._parse_asan_out()
        self.all_cap_info[crash_path] = [heap_alloc_hash, offset_info]

        bug_type, op_type, access_len, access_addr = self._get_capability_details(capability_res)
        self.capability_res_sta[crash_path] = [bug_type, op_type, access_len, access_addr]

    def _parse_binary_args(self, arg_file):
        content = ""
        with open(arg_file, 'r') as f:
            content = f.readline()

            return content

    def run_crash(self, crash_path):
        args = [self.binary]
        # args.append(crash_path)
        if self.binary_args is None:
            args.append(crash_path)
        else:
            bin_args = self._parse_binary_args(self.binary_args)
            if '@@' in bin_args:
                arg_before_poc = bin_args.split("@@")[0]
                arg_behind_poc = bin_args.split("@@")[1].strip()

                if len(arg_before_poc) != 0:
                    args.extend(arg_before_poc.split(" ")[:-1])

                args.append(crash_path)
                args.extend(arg_behind_poc.split(" "))
            else:
                args.append(crash_path)
                args.extend(self.binary_args.split(" "))


        cmd = " ".join(args)

        er = open(self._err_file, 'w')
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=er)

        er.flush()
        er.close()

    """
    Merge the access addresses if they are consecutive
    """
    def _merge_consecutive_addr(self, access_type):

        for key, value in self.invalid_access_cap[access_type].items():
            addr_left = 0
            addr_right = 0

            cur_len = key
            cur_len_all_addr = value

            for x in sorted(set(cur_len_all_addr)):

                if addr_left == 0:
                    addr_left = x
                    addr_right = x

                if x + 1 not in cur_len_all_addr:
                    if access_type not in self._human_read_merged_res.keys():
                        self._human_read_merged_res[access_type] = {cur_len: [(addr_left, addr_right)]}
                        # reset addr_left and addr_right
                        addr_left = addr_right = 0
                        continue

                    if cur_len in self._human_read_merged_res[access_type].keys():
                        if addr_left in self._human_read_merged_res[access_type][cur_len]:
                            pass
                        else:
                            self._human_read_merged_res[access_type][cur_len].append((addr_left, addr_right))
                    else:
                        self._human_read_merged_res[access_type][cur_len] = [(addr_left, addr_right)]

                    # reset addr_left and addr_right
                    addr_left = addr_right = 0

                else:
                    addr_right = x + 1

    def _merge_capabilities(self):
        for seed_name, value in self.capability_res_sta.items():
            bug_type = value[0]
            access_type = value[1]
            access_len = value[2]
            access_addr = int(value[3])

            if bug_type not in self.all_bug_type:
                self.all_bug_type.add(bug_type)

                pattern = re.compile(r'(?<=time:)\d+')
                time_in_file = pattern.findall(seed_name)
                seed_time = time_in_file[0]

                self.unique_bug_type_time.append(seed_time)

            if access_type in self.invalid_access_cap.keys():
                if access_len in self.invalid_access_cap[access_type].keys():
                    if access_addr in self.invalid_access_cap[access_type][access_len]:
                        continue
                    else:
                        self.invalid_access_cap[access_type][access_len].add(access_addr)
                        continue
                else:
                    # insert new access_addr
                    self.invalid_access_cap[access_type][access_len] = set()
                    self.invalid_access_cap[access_type][access_len].add(access_addr)

                    pattern = re.compile(r'(?<=time:)\d+')
                    time_in_file = pattern.findall(seed_name)
                    seed_time = time_in_file[0]

                    self.unique_acc_len_time.append(seed_time)

                    continue

            else:
                self.invalid_access_cap[access_type] = {access_len: set()}
                self.invalid_access_cap[access_type][access_len].add(access_addr)
                continue

    def dump_human_read_res(self):
        with open(self._crash_target_dir, "w") as f:
            json_str = json.dumps(self._human_read_merged_res)
            f.writelines(json_str)

    def get_cap_res(self):

        self.bug_type = list(self.all_bug_type)
        self.orig_heap_num = len(self.all_heap_alloc_hash)
        self.orig_stack_num = len(self.all_stack_obj)

        for key in self.invalid_access_cap.keys():
            if "read" in key:
                self.read_len_num = len(self.invalid_access_cap["read"])
            if "write" in key:
                self.write_len_num = len(self.invalid_access_cap["write"])

        if self.read_len_num:
            for read_len, addresses in self.invalid_access_cap["read"].items():
                if self.min_read_len == 0:
                    self.min_read_len = read_len
                if read_len <= self.min_read_len:
                    self.min_read_len = read_len

                if self.max_read_len == 0:
                    self.max_read_len = read_len
                if read_len >= self.max_read_len:
                    self.max_read_len = read_len

                left_addr = min(list(addresses))
                rigth_addr = max(list(addresses))

                if self.min_read_addr == 0:
                    self.min_read_addr = left_addr

                if left_addr <= self.min_read_addr:
                    self.min_read_addr = left_addr

                if self.max_read_addr == 0:
                    self.max_read_addr = rigth_addr

                if rigth_addr >= self.max_read_addr:
                    self.max_read_addr = rigth_addr

            all_read_range = 0
            for acc_len, acc_address in self._human_read_merged_res["read"].items():
                all_read_range += len(acc_address)

            self.read_addr_num = all_read_range

            self.orig_size_read_num = len(self.orig_size_read)
            self.orig_offset_read_num = len(self.orig_offset_read)

        if self.write_len_num:
            for write_len, addresses in self.invalid_access_cap["write"].items():
                if self.min_write_len == 0:
                    self.min_write_len = write_len
                if write_len <= self.min_write_len:
                    self.min_write_len = write_len

                if self.max_write_len == 0:
                    self.max_write_len = write_len
                if write_len >= self.max_write_len:
                    self.max_write_len = write_len

                left_addr = min(list(addresses))
                rigth_addr = max(list(addresses))

                if self.min_write_addr == 0:
                    self.min_write_addr = left_addr

                if left_addr <= self.min_write_addr:
                    self.min_write_addr = left_addr

                if self.max_write_addr == 0:
                    self.max_write_addr = rigth_addr

                if rigth_addr >= self.max_write_addr:
                    self.max_write_addr = rigth_addr

            all_write_range = 0
            for acc_len, acc_address in self._human_read_merged_res["write"].items():
                all_write_range += len(acc_address)

            self.write_addr_num = all_write_range

            self.orig_size_write_num = len(self.orig_size_write)
            self.orig_offset_write_num = len(self.orig_offset_write)


def main():
    """"""

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", help="crashes dir")
    parser.add_argument("-o", help="statical result file")
    parser.add_argument("-b", help="cb path")
    parser.add_argument("-a", help="the path of argument file", default=None)

    args = parser.parse_args()
    Worker = RawDataGenetator(args.b, args.i, args.o, args.a)
    Worker.start_work()

    if IS_RAW_DATA:
        pass

    print('Finished!')


if __name__ == "__main__":
    main()

