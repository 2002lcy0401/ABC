import pefile
import lief
import sys
import os
import get_cfg
import networkx as nx
import shutil

def pefile_check(file_path):
    """
    使用pefile库检查PE文件是否为可执行文件。

    参数:
    - file_path: PE文件的路径。

    返回:
    - Tuple (bool, str): 是否可执行以及相关信息。
    """
    try:
        # 检查文件是否存在
        if not os.path.isfile(file_path):
            return False, f"文件不存在: {file_path}"
        # 加载PE文件
        pe = pefile.PE(file_path)
        # 检查PE特征标志中的可执行标志
        # IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
        executable_flag = pe.FILE_HEADER.Characteristics & 0x0002
        is_executable = bool(executable_flag)
        # print(f"[pefile] IMAGE_FILE_EXECUTABLE_IMAGE 标志: {'设置' if is_executable else '未设置'}")

        # 另一种判断方法是查看入口点是否存在且非零
        has_entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint != 0
        # print(f"[pefile] 入口点存在且非零: {'是' if has_entry_point else '否'}")

        # 综合判断
        if is_executable and has_entry_point:
            pe.close()
            return True, "pefile判断为可执行文件。"

        
        else:
            pe.close()
            return False, "pefile判断为不可执行文件。"

    except pefile.PEFormatError as e:
        return False, f"pefile格式错误: {e}"
    except Exception as e:
        return False, f"pefile发生错误: {e}"

def lief_check(file_path):
    """
    使用LIEF库检查PE文件是否为可执行文件。

    参数:
    - file_path: PE文件的路径。

    返回:
    - Tuple (bool, str): 是否可执行以及相关信息。
    """
    try:
        # Also try parsing the file with lief
        binary = lief.PE.parse(file_path)
        # print(f"[lief] 文件格式: {binary.header.machine}")
        # print(f"Magic: {binary.dos_header.magic}")
        return True, "LIEF判断为可执行文件。"
    except lief.exception as e:
        return  False, f"LIEF无法解析为PE文件"

def file_format_check(file_path):
    """
    结合pefilF库检查PE文件是否为可执行文件。

    参数:
    - file_path: PE文件的路径。

    返回:
    - bool: 是否为可执行文件。
    """
    pefile_result, pefile_info = pefile_check(file_path)
    # print(pefile_info)

    lief_result, lief_info = lief_check(file_path)
    # print(lief_info)

    # 如果两者都认为是可执行文件，则返回True
    if pefile_result and lief_result:
        # print("该PE文件是一个可执行文件。")
        return True
    else:
        # print("该PE文件不是一个可执行文件。")
        return False





def get_file_cfg(file_path):
    get_cfg.main(file_path)
    directory_path = os.path.dirname(file_path)
    base_name1 = os.path.splitext(os.path.basename(file_path))[0]
    output_file = os.path.join(directory_path, f"{base_name1}_cfg.dot")
    return output_file


def read_cfg_from_dot(dot_file):
    """ 从DOT文件读取CFG,返回NetworkX图对象 """
    G = nx.DiGraph()
    with open(dot_file, 'r') as f:
        lines = f.readlines()
        for line in lines:
            if '->' in line:
                # 提取边的起始和结束节点
                src, dst = line.split('->')
                src = src.strip().replace('"', '')
                dst = dst.strip().replace('"', '').replace(';', '')
                G.add_edge(src, dst)
            elif '[label=' in line:
                # 提取节点
                node = line.split()[0].replace('"', '')
                G.add_node(node)
    return G


def cfg_check(cfgfile_path1,cfgfile_path2,threshold=0.8):
    """ 比较两个CFG图,返回它们的相似度,超过threshold则认为它们大致相同 """
    # cfg1_path=get_file_cfg(file_path1)
    # cfg2_path=get_file_cfg(file_path2)
    cfg1=read_cfg_from_dot(cfgfile_path1)
    cfg2=read_cfg_from_dot(cfgfile_path2)
    # 计算两个图的相似度
    nodesA = set(cfg1.nodes())
    nodesB = set(cfg2.nodes())
    edgesA = set(cfg1.edges())
    edgesB = set(cfg2.edges())

    if len(nodesA | nodesB)==0:
        print("两个CFG图都为空")
        return True
    if len(edgesA | edgesB)==0:
        print("两个CFG图都没有边")
        return True
    # 计算节点和边的Jaccard相似度
    node_similarity = len(nodesA & nodesB) / len(nodesA | nodesB)

    edge_similarity = len(edgesA & edgesB) / len(edgesA | edgesB)

    print(f"Node Similarity: {node_similarity:.2f}")
    print(f"Edge Similarity: {edge_similarity:.2f}")

    # 如果节点和边的相似度都超过阈值，则认为CFG相似
    if node_similarity >= threshold and edge_similarity >= threshold:
        print("CFG大致相同")
        return True
    return False
    
# cfg_check('winmine.exe','winmine2.exe')


# ori_cfg_dir='cfg/ori'
# mal_dir='malware_dataset'
# mal_path='malware_dataset//0a2c072d42b25e7110393d7f95bd63b0c5482722.exe'
# dot_path=get_file_cfg(mal_path)
# mal='0a2c072d42b25e7110393d7f95bd63b0c5482722.exe'

# shutil.copy(dot_path,os.path.join(ori_cfg_dir,mal.split('.')[0]+'.dot'))
# os.remove(dot_path)
# os.remove(os.path.join(mal_dir,mal+'.idb'))

# if __name__ == "__main__":
#     mal_dir='minimal_malconv_adv'
#     mal_list=os.listdir(mal_dir)
#     success=0
#     for mal in mal_list:
#         mal_path=os.path.join(mal_dir,mal)
#         mal_path=os.path.abspath(mal_path)
#         print(mal_path)
#         if(file_format_check(mal_path))=='False':
#             print('该PE文件不是一个可执行文件')
#         else:
#             success+=1
#     print('success:',success,'all',len(mal_list))




# mal_dir='dataset/malware_padding'
# # mal_adv_dir="D:\\malware_design\\minimal_result\\malconv\\step2_adv"
# # mal_adv_dir="D:\\malware_design\\gamma_adv\\ember"
# # mal_adv_dir="D:\\malware_design\\mab_adv\\ember\\minimal"
# mal_adv_dir="D:\malware_design\cfg_compare\mab\malgct"
# mal_list=os.listdir(mal_adv_dir)

# ori_cfg_dir='cfg/malgct/ori'
# adv_cfg_dir='cfg/malgct/adv'

# success=0
# all=len(mal_list)
# i=1
# for mal in mal_list:
#     print(f'process {i}')
#     i+=1
#     maladv_path=os.path.join(mal_adv_dir,mal)
#     maladv_path=os.path.normpath(maladv_path)
#     mal_path=mal.split('_adv')[0]+'.exe'
#     mal2=mal_path
#     mal_path=os.path.join(mal_dir,mal_path)
#     mal_path=os.path.normpath(mal_path)



#     dot_path=get_file_cfg(mal_path)
#     mal_dot_path=os.path.join(ori_cfg_dir,mal.split('.')[0]+'.dot')
#     if os.path.exists(dot_path):
#         shutil.copy(dot_path,mal_dot_path)
#         os.remove(dot_path)
#         os.remove(os.path.join(mal_dir,mal2+'.idb'))


#         dot_path=get_file_cfg(maladv_path)
#         adv_dot_path=os.path.join(adv_cfg_dir,mal.split('.')[0]+'.dot')
#         shutil.copy(dot_path,adv_dot_path)
#         os.remove(dot_path)
#         os.remove(os.path.join(mal_adv_dir,mal+'.idb'))
#         fun_flag=cfg_check(mal_dot_path,adv_dot_path,threshold=0.8)
#         if fun_flag:
#             success+=1
#             print('funtionality_verification结果为:',fun_flag)
#     else:
#         print("不能提取CFG,直接略过")
#         all=all-1
#         continue

# print('success:',success,'all',all,'success rate:',success/all)


