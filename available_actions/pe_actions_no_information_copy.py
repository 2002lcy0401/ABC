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
def section_add(exe_pth,adv_pth,content):
    if content==[]:
        # 复制文件并保留权限和元数据

        shutil.copy2(exe_pth, adv_pth)
        return 0

    exe_object=lief.PE.parse(exe_pth)
    new_section = lief.PE.Section()
    new_section.name = '.lcy'
    new_section.content = content
    # new_section.content = [ord(i) for i in "This is lcy's section"]
    new_section.characteristics = lief.PE.SECTION_CHARACTERISTICS.MEM_DISCARDABLE 
    exe_object.add_section(new_section)
    builder = lief.PE.Builder(exe_object)#使用LIEF库来构建PE（Portable Executable）文件。
    builder.build()
    # print('new Sections：')
    # for s in exe_object.sections:
    #     print(s.name, s.characteristics_lists)
    exe_object = lief.PE.parse(builder.get_build())
    builder.write(adv_pth) #保存为新的可执行性文件


#2. PE padding 末尾注入字节
def padding(exe_path,exe_path2,new_data):
    if new_data==[]:
        # 复制文件并保留权限和元数据

        shutil.copy2(exe_path, exe_path2)
        return 0
    data_len=len(new_data)        

    t=CArray(new_data)
    # new_data = (t * 255).astype(np.uint8) # 创建你想要添加的字节数据
    new_data = t.astype(np.uint8) # 创建你想要添加的字节数据
    with open(exe_path, "rb") as file_handle:
        code = file_handle.read()
    x=CArray(np.frombuffer(code, dtype=np.uint8)).atleast_2d()
    # x = End2EndModel.bytes_to_numpy(code, 2 ** 20, 256, False)
    exe_object=CArray(x)
    # print(exe_object)
    exe_object_adv = exe_object.append(new_data)
    # print('Padding：')
    # print(exe_object_adv)
    exe_real = exe_object_adv.tolist()
    x_real_adv = b''.join([bytes([int(i)]) for i in exe_real])
    with open(exe_path2, 'wb') as f:
        f.write(x_real_adv)

        
#3. dos_header 修改dos头,MZ和PE之间的数据（除了64个固定的字节）
def header_modify(exe_path,adv_pth,new_data):
    if new_data==[]:
        # 复制文件并保留权限和元数据
        shutil.copy2(exe_path, adv_pth)
        return 0
    with open(exe_path, "rb") as file_handle:
        code = file_handle.read()
    x=CArray(np.frombuffer(code, dtype=np.uint8)).atleast_2d()
    exe_object=CArray(x)
    x_adv = deepcopy(exe_object)
    pe_position = exe_object[0x3C:0x40].tondarray().astype(np.uint16)[0]
    pe_position = struct.unpack("<I", bytes(pe_position.astype(np.uint8)))[0]
    if pe_position > 127:
        indexes_to_perturb = list(range(2, 60))+list(range(128,pe_position)) # (MZ——PE_poisition之间的位置)+(PE_position+64字节——PE)
    else:
        indexes_to_perturb = list(range(2, 60))
    # print('header perturb indexs：')
    # print(indexes_to_perturb)
    t=len(new_data)
    # print('Add_data length:',t)
    t1=len(indexes_to_perturb)
    # print('DOS modify size:',t1)
    if t<t1:
        # 扩充的部分是 B 中超出 A 长度的部分
        extension = indexes_to_perturb[t:]
        # 创建一个新的列表，将 A 和扩充部分拼接在一起
        new_data = new_data + extension

        x_adv[0, indexes_to_perturb] = CArray(new_data[0:t1])
        exe_real = x_adv.tolist()[0]
        x_real_adv = b''.join([bytes([int(i)]) for i in exe_real])
        with open(adv_pth, 'wb') as f:
            f.write(x_real_adv)

    else:
        x_adv[0, indexes_to_perturb] = CArray(new_data[0:t1])
        exe_real = x_adv.tolist()[0]
        x_real_adv = b''.join([bytes([int(i)]) for i in exe_real])
        with open(adv_pth, 'wb') as f:
            f.write(x_real_adv) 

# 4.扩充dos头部分
def header_shift(exe_path,adv_pth,new_data):
    if new_data==[]:
        # 复制文件并保留权限和元数据
        shutil.copy2(exe_path, adv_pth)
        return 0        
    # 更新位置
    exe_object: lief.PE = lief.parse(exe_path)
    file_alignment = exe_object.optional_header.file_alignment
    t=len(new_data)
    t1 = int(math.floor(t/file_alignment)) * file_alignment    
    ori_pe_position = exe_object.dos_header.addressof_new_exeheader
    exe_object.dos_header.addressof_new_exeheader=ori_pe_position+t1
    adv_pe_position = exe_object.dos_header.addressof_new_exeheader
    # 修改每个节的偏移
    for section in exe_object.sections:
        section.pointerto_raw_data += t1
    exe_object.write(adv_pth)

    # 更新内容

    with open(adv_pth, "rb") as file_handle:
        code = file_handle.read()
    x2=CArray(np.frombuffer(code, dtype=np.uint8)).atleast_2d()
    exe_data2=CArray(x2)
    x_adv = deepcopy(exe_data2)
    indexes_to_perturb = list(range(ori_pe_position, adv_pe_position))
    t=len(indexes_to_perturb)
    # print(f'Header shift size：{t}')
    x_adv[0, indexes_to_perturb] = CArray(new_data[0:t])
    exe_real = x_adv.tolist()[0]
    x_real_adv = b''.join([bytes([int(i)]) for i in exe_real])
    with open(adv_pth, 'wb') as f:
        f.write(x_real_adv) 


#5. slack  修改PE文件的松弛区域

def slack(exe_path,adv_pth,new_data):
    if new_data==[]:

        # 复制文件并保留权限和元数据
        shutil.copy2(exe_path, adv_pth)
        return 0

    # 获取松弛索引
    exe_object=lief.PE.parse(exe_path)
    all_slack_space = []
    for s in exe_object.sections:
        # print(s.name)
        # print("s.size,s.virtual_size,s.offset")
        # print(s.size,s.virtual_size,s.offset)
        if s.size > s.virtual_size:
            all_slack_space.extend(list(range(s.offset + s.virtual_size,
					            s.offset + s.size)))
    # print('all slack indexs：')
    # print(all_slack_space)
    t=len(new_data)
    # print('Add_data size:',t)
    t1=len(all_slack_space)
    # print('Slack size:',t1)
    # 更新内容
    with open(exe_path, "rb") as file_handle:
        code = file_handle.read()
    x=CArray(np.frombuffer(code, dtype=np.uint8)).atleast_2d()
    exe_data=CArray(x)
    x_adv = deepcopy(exe_data)
    if t<t1:
        # 用 0 扩充 A 到与 B 相同的长度
        new_data = new_data + [0] * (t1-t)

        x_adv[0, all_slack_space] = CArray(new_data[0:t1])
        exe_real = x_adv.tolist()[0]
        x_real_adv = b''.join([bytes([int(i)]) for i in exe_real])
        with open(adv_pth, 'wb') as f:
            f.write(x_real_adv) 

    else:

        x_adv[0, all_slack_space] = CArray(new_data[0:t1])
        exe_real = x_adv.tolist()[0]
        x_real_adv = b''.join([bytes([int(i)]) for i in exe_real])
        with open(adv_pth, 'wb') as f:
            f.write(x_real_adv) 


#6. code cave 代码洞穴注入
def code_cave(exe_path,adv_pth,new_data):
    if new_data==[]:
        # 复制文件并保留权限和元数据

        shutil.copy2(exe_path, adv_pth)
        return 0
    # 索引获取，offset修改

    exe_object: lief.PE = lief.parse(exe_path)
    section_num=len(exe_object.sections)
    t=len(new_data)
    # print('添加数据的总字节数:',t)
    # print("样本的总节数：",section_num)
    t1=t//section_num
    # print("每节平均注入的字节数：",t1)
    ## 填充的字节数量需要是文件对齐方式的倍数
    section_file_alignment = exe_object.optional_header.file_alignment
    # print("文件对齐长度:",section_file_alignment)

    if section_file_alignment == 0:
        return exe_object, []
    
    ## real_size通过计算保证是文件对齐方式的倍数
    t2 = int(math.floor(t1/section_file_alignment)) * section_file_alignment
    # print("实际每节填充长度：",t2)
    # print("总共填充长度：",t2*section_num)
    index_all=[]
    for i in range(1,section_num+1):
        section_offset = exe_object.sections[i-1].offset
        ## 计算在该节前面填充的字节索引
        index_section = list(range(section_offset, section_offset + t2))
        index_all.extend(index_section)
        ## 增大i和i后面节的偏移量offset
        for j in range(i,section_num+1):
            exe_object.sections[j-1].offset += t2
    builder = lief.PE.Builder(exe_object)
    builder.build()
    builder.write(adv_pth) 
    
    # 内容填充
    with open(exe_path, "rb") as file_handle:
        code = file_handle.read()
    x1=CArray(np.frombuffer(code, dtype=np.uint8)).atleast_2d()
    exe_list1=x1
    # print("原始大小",exe_list1.size)

    with open(adv_pth, "rb") as file_handle:
        code = file_handle.read()
    x2=CArray(np.frombuffer(code, dtype=np.uint8)).atleast_2d()
    exe_list2=x2
    x_adv = deepcopy(exe_list2)
    # print("填充后大小:",exe_list2.size)

    x_adv[0, index_all] = CArray(new_data[0:t2*section_num])
    exe_real = x_adv.tolist()[0]
    x_real_adv = b''.join([bytes([int(i)]) for i in exe_real])
    with open(adv_pth, 'wb') as f:
        f.write(x_real_adv) 



def split_array(arr):
    n = len(arr)
    if n < 1300:
        raise ValueError("The length of the array must be at least 1300.")
    part1 = arr[:300]
    # 使用列表解析来删除负数
    part1 = [num for num in part1 if num >= 0]
    part2 = arr[300:1300]
    part2 = [num for num in part2 if num >= 0]
    remaining_length = n - 1300
    base_length = remaining_length // 4
    extra = remaining_length % 4
    start = 1300
    parts = [part1, part2]
    for i in range(4):
        end = start + base_length + (1 if i < extra else 0)
        part=arr[start:end]
        part=[num for num in part if num >= 0]
        parts.append(part)
        start = end
    return parts

def adv_name(exe_path):
    base_name, ext = os.path.splitext(exe_path)
    new_filename = f"{base_name}_adv{ext}"
    return new_filename    

def seed_to_add(exe_path,adv_pth,seed):
    parts=split_array(seed)
    header_modify(exe_path,adv_pth,parts[0])
    adv_pth1=adv_name(adv_pth)
    slack(adv_pth, adv_pth1,parts[1])
    os.remove(adv_pth)
    adv_pth2=adv_name(adv_pth1)
    section_add(adv_pth1, adv_pth2,parts[2])
    os.remove(adv_pth1)
    adv_pth3=adv_name(adv_pth2)
    padding(adv_pth2, adv_pth3,parts[3])
    os.remove(adv_pth2)
    adv_pth4=adv_name(adv_pth3)
    header_shift(adv_pth3,adv_pth4,parts[4])
    os.remove(adv_pth3)
    adv_pth5=adv_name(adv_pth4)
    code_cave(adv_pth4,adv_pth5,parts[5])
    os.remove(adv_pth4)
    os.rename(adv_pth5, adv_pth)
    time.sleep(0.1)


def seed_to_add2(exe_path,adv_pth,seed):
    parts=split_array(seed)
    header_modify(exe_path,adv_pth,parts[0])
    adv_pth1=adv_name(adv_pth)
    slack(adv_pth, adv_pth1,parts[1])
    adv_pth2=adv_name(adv_pth1)
    section_add(adv_pth1, adv_pth2,parts[2])
    adv_pth3=adv_name(adv_pth2)
    padding(adv_pth2, adv_pth3,parts[3])
    adv_pth4=adv_name(adv_pth3)
    code_cave(adv_pth3,adv_pth4,parts[4])
    adv_pth5=adv_name(adv_pth4)
    header_shift(adv_pth4,adv_pth5,parts[5])
    os.remove(adv_pth)
    os.remove(adv_pth1)
    os.remove(adv_pth2)
    os.remove(adv_pth3)
    os.remove(adv_pth4)
    os.rename(adv_pth5, adv_pth)


def seed_to_add3(exe_path,adv_pth,seed):
    parts=split_array(seed)
    header_modify(exe_path,adv_pth,parts[0])
    adv_pth1=adv_name(adv_pth)
    slack(adv_pth, adv_pth1,parts[1])
    os.remove(adv_pth)
    adv_pth2=adv_name(adv_pth1)
    section_add(adv_pth1, adv_pth2,parts[2])
    os.remove(adv_pth1)
    adv_pth3=adv_name(adv_pth2)
    padding(adv_pth2, adv_pth3,parts[3])
    os.remove(adv_pth2)
    adv_pth4=adv_name(adv_pth3)
    code_cave(adv_pth3,adv_pth4,parts[4])
    os.remove(adv_pth3)
    os.rename(adv_pth4, adv_pth)
    time.sleep(0.1)