import lief
import numpy as np 
import struct
import math
from secml.array import CArray
from copy import copy, deepcopy
from secml_malware.models.malconv import MalConv
from secml_malware.models.c_classifier_end2end_malware import CClassifierEnd2EndMalware, End2EndModel

exe_path = 'benign_sample/winmine.exe'
exe_object: lief.PE = lief.parse(exe_path)
exe_path2='benign_sample/winmine3.exe'

#1. PE section injection 添加一个新节
def new_section(exe_object):
    new_section = lief.PE.Section()
    new_section.name = '.lcy'
    new_section.content = [ord(i) for i in "This is lcy's section"]
    new_section.characteristics = lief.PE.Section.CHARACTERISTICS.MEM_DISCARDABLE
    exe_object.add_section(new_section)
    builder = lief.PE.Builder(exe_object)#使用LIEF库来构建PE（Portable Executable）文件。
    builder.build()
    new_sample=new_section(exe_object)
    print('Sections：')
    for s in new_sample.sections:
        print(s.name, s.characteristics_lists)
    exe_object = lief.PE.parse(builder.get_build())
    # builder.write('winmine2.exe') #保存为新的可执行性文件
    
    return exe_object

#2. PE padding 末尾注入字节
def padding(exe_path,exe_path2,new_data):
    t=CArray(new_data)
    # new_data = (t * 255).astype(np.uint8) # 创建你想要添加的字节数据
    new_data = t.astype(np.uint8) # 创建你想要添加的字节数据
    with open(exe_path, "rb") as file_handle:
        code = file_handle.read()

    x=CArray(np.frombuffer(code, dtype=np.uint8)).atleast_2d()
    # x = End2EndModel.bytes_to_numpy(code, 2 ** 20, 256, False)

    exe_object=CArray(x)
    print(exe_object)
    exe_object_adv = exe_object.append(new_data)
    print('Padding：')
    print(exe_object_adv)

    exe_real = exe_object_adv.tolist()

    x_real_adv = b''.join([bytes([int(i)]) for i in exe_real])
    with open(exe_path2, 'wb') as f:
        f.write(x_real_adv)
        
#3. dos_header 修改dos头,MZ和PE之间的数据（除了64个固定的字节）以及扩充dos头部分
def dos_header(exe_path):

    with open(exe_path, "rb") as file_handle:
        code = file_handle.read()
    x=CArray(np.frombuffer(code, dtype=np.uint8)).atleast_2d()
    # x = End2EndModel.bytes_to_numpy(code, 2 ** 20, 256, False)

    exe_object=CArray(x)
    # print(exe_object)
    x_adv = deepcopy(exe_object)

    pe_position = exe_object[0x3C:0x40].tondarray().astype(np.uint16)[0]
    pe_position = struct.unpack("<I", bytes(pe_position.astype(np.uint8)))[0]

    if pe_position > 127:
        indexes_to_perturb = list(range(2, 60))+list(range(128,pe_position)) # (MZ——PE_poisition之间的位置)+(PE_position+64字节——PE)
    else:
        indexes_to_perturb = list(range(2, 60))
    print('header perturb indexs：')
    print(indexes_to_perturb)
    # real_size = len(indexes_to_perturb)
    # t=CArray([[0]*real_size])
    # new_data = (t * 255).astype(np.uint8) # 创建你想要添加的字节数据
    # x_adv[0, indexes_to_perturb] = CArray(new_data)
    # print(x_adv)
    # exe_real = x_adv.tolist()[0]
    # x_real_adv = b''.join([bytes([int(i)]) for i in exe_real])
    # with open(exe_path2, 'wb') as f:
    #     f.write(x_real_adv)
    return indexes_to_perturb

# dos_header(exe_path)


#4. slack space 修改PE文件的松弛区域索引

def slack_idx(exe_path):
    exe_object=lief.PE.parse(exe_path)
    all_slack_space = []
    for s in exe_object.sections:
        print(s.name)
        print("s.size,s.virtual_size,s.offset")
        print(s.size,s.virtual_size,s.offset)
        if s.size > s.virtual_size:
            
            all_slack_space.extend(list(range(s.offset + s.virtual_size,
					            s.offset + s.size)))
    print('all slack indexs：')
    print(all_slack_space)
    return all_slack_space

# a=slack_idx(exe_path)
# print(a)


#5. code cave 代码洞穴注入,want_size代表想要每节注入多少的字节
def code_cave(exe_path,want_size,out_path):
    exe_object: lief.PE = lief.parse(exe_path)
    section_num=len(exe_object.sections)
    print("总节数：",section_num)

    with open(exe_path, "rb") as file_handle:
        code = file_handle.read()

    # print(code)

    x=CArray(np.frombuffer(code, dtype=np.uint8)).atleast_2d()
    exe_list=x
    print("注入前，原始样子：")
    print(exe_list)
    print("原始大小",exe_list.size)
    ## 填充的字节数量需要是文件对齐方式的倍数
    section_file_alignment = exe_object.optional_header.file_alignment
    print("文件对齐长度:",section_file_alignment)
    if section_file_alignment == 0:
        return exe_object, []
    ## real_size通过计算保证是文件对齐方式的倍数
    real_size = int(math.ceil(want_size / section_file_alignment)) * section_file_alignment
    print("想要填充长度：",want_size)
    print("实际填充长度：",real_size)
    index_all=[]

    print("注入前，各节的偏移量:")

    for i in range(1,section_num+1):
        print("节",i,"的偏移量:",exe_object.sections[i-1].offset)
    print("---------------------------------")
    offset=[]
    for i in range(1,section_num+1):
        section_offset = exe_object.sections[i-1].offset
        ## 计算在该节前面填充的字节索引
        index_section = list(range(section_offset, section_offset + real_size))
        index_all.extend(index_section)
        ## 增大i和i后面节的偏移量offset
        for j in range(i,section_num+1):
            exe_object.sections[j-1].offset += real_size

    print("索引：")
    print(index_all)


    builder = lief.PE.Builder(exe_object)
    builder.build()
    builder.write(out_path) 


    return out_path,index_all

# out_path='benign_sample/winmine5.exe'
# index=code_cave(exe_path,50,out_path)

## carray格式转exe
def carraytoexe(carray,outpath):
    x_real = carray.tolist()[0]
    x_real_adv = b''.join([bytes([i]) for i in x_real])
    with open(outpath, 'wb') as f:
        f.write(x_real_adv)

## exe转carray  
def exetocarray(exe_path):
    with open(exe_path, "rb") as file_handle:
        code = file_handle.read()
    x=CArray(np.frombuffer(code, dtype=np.uint8)).atleast_2d()
    exe_object = CArray(x)
    x_adv = deepcopy(exe_object)
    return x_adv



## 对exe文件进行扰动,生成exe_adv
def exe_perturb(exe_path,perturb_index,out_path,perturb_data):
    x_adv=exetocarray(exe_path)
    t=CArray([perturb_data])

    new_data = (t * 255).astype(np.uint8) 
    print("扰动数据：")
    print(new_data)
    x_adv[0, perturb_index] = CArray(new_data)
    carraytoexe(x_adv,out_path)

perturb_index=slack_idx(exe_path)
size=len(perturb_index)
perturb_data=[0.1]* size   ## 想要添加的字节数据
exe_perturb(exe_path,perturb_index,'benign_sample/winmine6.exe',perturb_data)


# path,perturb_index=code_cave(exe_path,50,'benign_sample/winmine5.exe')
# size=len(perturb_index)
# perturb_data=[0.1]* size   ## 想要添加的字节数据
# exe_perturb(path,perturb_index,'benign_sample/winmine6.exe',perturb_data)
