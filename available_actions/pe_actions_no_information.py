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
def section_add(mal_pth,adv_pth,content):
    if content==[]:
        shutil.copy2(mal_pth, adv_pth)
    else:
        exe_object=lief.PE.parse(mal_pth)
        new_section = lief.PE.Section()
        new_section.name = '.lcy'
        new_section.content = content
        new_section.characteristics = lief.PE.SECTION_CHARACTERISTICS.MEM_DISCARDABLE 
        exe_object.add_section(new_section)
        builder = lief.PE.Builder(exe_object)#使用LIEF库来构建PE（Portable Executable）文件。
        builder.build()
        builder.write(adv_pth) #保存为新的可执行性文件

#2. PE padding 末尾注入字节
def padding(exe_path,exe_path2,new_data):
    if new_data==[]:
        # 复制文件并保留权限和元数据
        shutil.copy2(exe_path, exe_path2)
    else:
        t=CArray(new_data)
        new_data = t.astype(np.uint8)
        with open(exe_path, "rb") as file_handle:
            code = file_handle.read()
        x=CArray(np.frombuffer(code, dtype=np.uint8)).atleast_2d()
        exe_object=CArray(x)
        exe_object_adv = exe_object.append(new_data)
        exe_real = exe_object_adv.tolist()
        x_real_adv = b''.join([bytes([int(i)]) for i in exe_real])
        with open(exe_path2, 'wb') as f:
            f.write(x_real_adv)

        
#3. dos_header 修改dos头,MZ和PE之间的数据（除了64个固定的字节）
def header_modify(exe_path,adv_pth,new_data):
    if new_data==[]:
        # 复制文件并保留权限和元数据
        shutil.copy2(exe_path, adv_pth)
    else:
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
        t=len(new_data)
        t1=len(indexes_to_perturb)
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
def header_extend(exe_path,adv_pth,new_data):
    if new_data==[]:
        # 复制文件并保留权限和元数据
        shutil.copy2(exe_path, adv_pth)
    else:      
        # 更新位置
        exe_object: lief.PE = lief.parse(exe_path)
        file_alignment = exe_object.optional_header.file_alignment
        # print(file_alignment)
        t=len(new_data)
        t1 = int(math.floor(t/file_alignment)) * file_alignment    

        ori_position = exe_object.sections[0].pointerto_raw_data
        # print(ori_position)
        # exe_object.dos_header.addressof_new_exeheader=ori_pe_position+t1
        adv_position = exe_object.sections[0].pointerto_raw_data+t1
        # print(adv_position)       

        # 修改每个节的偏移
        for section in exe_object.sections:
            section.pointerto_raw_data += t1

        builder = lief.PE.Builder(exe_object)#使用LIEF库来构建PE（Portable Executable）文件。
        builder.build()
        builder.write(adv_pth) #保存为新的可执行性文件
        # exe_object.write(adv_pth)

        # 更新内容

        with open(adv_pth, "rb") as file_handle:
            code = file_handle.read()
        x2=CArray(np.frombuffer(code, dtype=np.uint8)).atleast_2d()
        exe_data2=CArray(x2)
        x_adv = deepcopy(exe_data2)
        indexes_to_perturb = list(range(ori_position, adv_position))
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
    else:
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

# with open('winmine1.exe', "rb") as f:
# 	data = f.read()
    
# slack('winmine.exe','winmine2.exe',data)

#6. code cave 代码洞穴注入
def code_cave(exe_path,adv_pth,new_data):
    if new_data==[]:
        # 复制文件并保留权限和元数据
        shutil.copy2(exe_path, adv_pth)
    # 索引获取，offset修改
    else:
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


#6. code cave2 只在第一个节下面填充数据
def code_cave2(exe_path,adv_pth,new_data):
    if new_data==[]:
        shutil.copy2(exe_path, adv_pth)
    else:
        exe_object: lief.PE = lief.parse(exe_path)
        section_num=len(exe_object.sections)
        
        t=len(new_data)
        t1=t
        section_file_alignment = exe_object.optional_header.file_alignment
        if section_file_alignment == 0:
            return exe_object, []
        t2 = int(math.floor(t1/section_file_alignment)) * section_file_alignment
        index_all=[]
        section_offset = exe_object.sections[0].offset
        index_section = list(range(section_offset, section_offset + t2))
        index_all.extend(index_section)
        for j in range(1,section_num+1):
            exe_object.sections[j-1].offset += t2
        builder = lief.PE.Builder(exe_object)
        builder.build()
        builder.write(adv_pth) 
        with open(exe_path, "rb") as file_handle:
            code = file_handle.read()
        x1=CArray(np.frombuffer(code, dtype=np.uint8)).atleast_2d()
        exe_list1=x1
        with open(adv_pth, "rb") as file_handle:
            code = file_handle.read()
        x2=CArray(np.frombuffer(code, dtype=np.uint8)).atleast_2d()
        exe_list2=x2
        x_adv = deepcopy(exe_list2)
        x_adv[0, index_all] = CArray(new_data[0:t2])
        exe_real = x_adv.tolist()[0]
        x_real_adv = b''.join([bytes([int(i)]) for i in exe_real])
        with open(adv_pth, 'wb') as f:
            f.write(x_real_adv) 



# 测试每一种操作的正确完整性
def test():
    mal_dir='../mal_small'
    ben_path='../top_10_success_rate/185984.exe'
    with open(ben_path, "rb") as file:
        byte_data = file.read()
    all_data = [byte for byte in byte_data]
    len=102400
    seed=all_data[0:len]
    mal_list=os.listdir(mal_dir)
    k=0
    for mal in mal_list:
        k=k+1
        mal_path=os.path.join(mal_dir,mal)
        mal_path=os.path.normpath(mal_path)
        mal_adv=mal.split('.')[0]+'_adv.exe'
        adv_path=os.path.join(mal_dir,mal_adv)
        adv_path=os.path.normpath(adv_path)
        print(f'当前是第{k}个:',mal)
        for i in range(5):
            print('第',i+1,'次测试')
            slack(mal_path,adv_path,seed)
            os.remove(mal_path)
            os.rename(adv_path,mal_path)

def test2():
    mal_path='winmine.exe'
    ben_path='DriverEasy.exe'
    with open(ben_path, "rb") as file:
        byte_data = file.read()
    all_data = [byte for byte in byte_data]
    len=3024000
    seed1=all_data[0:len]
    # seed2=all_data[0:len]
    adv_path='winmine_adv.exe'
    code_cave2(mal_path,adv_path,seed1)
    # header_extend(adv_path,adv_path,seed2)


def test3():
    mal_dir='../mal_small_copy'
    ben_path='../benign_section_content/0a464a3765ffc0c23cf47345bf1185426af8e6b5711e015ca18027afcac2f2e0.exe_.text_241152'
    with open(ben_path, "rb") as file:
        byte_data = file.read()
    all_data = [byte for byte in byte_data]
    seed=all_data
    mal_list=os.listdir(mal_dir)
    k=0
    for mal in mal_list:
        k=k+1
        mal_path=os.path.join(mal_dir,mal)
        mal_path=os.path.normpath(mal_path)
        mal_adv=mal.split('.')[0]+'_adv.exe'
        adv_path=os.path.join(mal_dir,mal_adv)
        adv_path=os.path.normpath(adv_path)
        print(f'当前是第{k}个:',mal)
        # exe_object: lief.PE = lief.parse(mal_path)
        header_extend(mal_path,adv_path,seed)

# test2()

        