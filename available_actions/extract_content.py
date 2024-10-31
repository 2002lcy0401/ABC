import lief
import numpy as np 
import struct
import math
from secml.array import CArray
from copy import copy, deepcopy
import time
import shutil
import os
#1. PE section injection 添加一个新节
def section_count(exe_pth,adv_pth,content):
    return content,len(content)

#2. PE padding 末尾注入字节
def padding_count(exe_path,exe_path2,content):
   return content,len(content)
      
#3. dos_header 修改dos头,MZ和PE之间的数据（除了64个固定的字节）
def header_extract(exe_path,adv_pth,new_data):
    if new_data==[]:
        # 复制文件并保留权限和元数据
        shutil.copy2(exe_path, adv_pth)
        return 0
    with open(exe_path, "rb") as file_handle:
        code = file_handle.read()
    x=CArray(np.frombuffer(code, dtype=np.uint8)).atleast_2d()
    exe_object=CArray(x)
    pe_position = exe_object[0x3C:0x40].tondarray().astype(np.uint16)[0]
    pe_position = struct.unpack("<I", bytes(pe_position.astype(np.uint8)))[0]
    if pe_position > 127:
        indexes_to_perturb = list(range(2, 60))+list(range(128,pe_position)) # (MZ——PE_poisition之间的位置)+(PE_position+64字节——PE)
    else:
        indexes_to_perturb = list(range(2, 60))
    t1=len(indexes_to_perturb)
    return new_data[0:t1],t1
   
#4. slack  修改PE文件的松弛区域
def slack(exe_path,adv_pth,new_data):
    if new_data==[]:
        # 复制文件并保留权限和元数据
        shutil.copy2(exe_path, adv_pth)
        return 0
    # 获取松弛索引
    exe_object=lief.PE.parse(exe_path)
    all_slack_space = []
    for s in exe_object.sections:
        if s.size > s.virtual_size:
            all_slack_space.extend(list(range(s.offset + s.virtual_size,
					            s.offset + s.size)))
    t=len(new_data)
    t1=len(all_slack_space)
    with open(exe_path, "rb") as file_handle:
        code = file_handle.read()
    x=CArray(np.frombuffer(code, dtype=np.uint8)).atleast_2d()
    exe_data=CArray(x)
    x_adv = deepcopy(exe_data)
    if t<t1:
        # 用 0 扩充 A 到与 B 相同的长度
        new_data = new_data + [0] * (t1-t)
        return new_data[0:t1],t1
    else:
        return new_data[0:t1],t1

#5. code cave 代码洞穴注入
def code_cave(exe_path,adv_pth,new_data):
    exe_object: lief.PE = lief.parse(exe_path)
    section_num=len(exe_object.sections)
    t=len(new_data)
    t1=t//section_num
    section_file_alignment = exe_object.optional_header.file_alignment
    t2 = int(math.floor(t1/section_file_alignment)) * section_file_alignment
    return new_data[0:t2*section_num],t2*section_num

#5. code cave 代码洞穴注入
def code_cave2(exe_path,adv_pth,new_data):
    exe_object: lief.PE = lief.parse(exe_path)
    section_num=len(exe_object.sections)
    t=len(new_data)
    t1=t
    section_file_alignment = exe_object.optional_header.file_alignment
    t2 = int(math.floor(t1/section_file_alignment)) * section_file_alignment
    return new_data[0:t2],t2

# 6.header_extend
def extend(exe_path,adv_pth,new_data):

    # 更新位置
    exe_object: lief.PE = lief.parse(exe_path)
    file_alignment = exe_object.optional_header.file_alignment
    t=len(new_data)
    t1 = int(math.floor(t/file_alignment)) * file_alignment
    return new_data[0:t1],t1    


