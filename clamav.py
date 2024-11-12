import pyclamd
import os

def scan_with_pyclamd(file_path):
    # 使用 TCP 连接方式
    cd = pyclamd.ClamdNetworkSocket('127.0.0.1', 3310)
    if cd.ping():  # 检查 ClamAV 服务是否正常
        result = cd.scan_file(file_path)
        # print(result)
        if result is None:
            return 0  # 干净文件
        else:
            return 1  # 恶意文件
    else:
        print("ClamAV service is not running.")
        return -1







def get_absolute_paths(directory):
    # 获取目录中所有文件的文件名
    file_names = os.listdir(directory)
    
    # 生成每个文件的绝对路径
    absolute_paths = [os.path.abspath(os.path.join(directory, file_name)) for file_name in file_names]
    
    return absolute_paths



# 示例用法
# directory = "C:\\Users\\21433\\Desktop\\miniMal\\dataset\\malware_clamav"  # 替换为你的文件夹路径
# absolute_paths = get_absolute_paths(directory)

# # 打印所有文件的绝对路径
# for file_path in absolute_paths:
#     print(file_path)
#     # 示例用法
#     # file_path = 'D:\\malware_design\\dataset\\benign\\0a8deb24eef193e13c691190758c349776eab1cd65fba7b5dae77c7ee9fcc906.exe'
#     result = scan_with_pyclamd(file_path)
#     if result == 1:
#         print("The file is malicious.")
#     elif result == 0:
#         os.remove(file_path)
#         print("The file is clean.")
#     else:
#         print("An error occurred.")



# import os
# import random

# def keep_random_files(folder_path, keep_count):
#     # 获取文件夹中所有的.exe文件
#     exe_files = [f for f in os.listdir(folder_path) if f.endswith('.exe')]
    
#     # 如果文件数量少于200个，则全部保留
#     if len(exe_files) <= keep_count:
#         print("文件数量少于200个，将全部保留。")
#         return
    
#     # 随机选择200个文件
#     selected_files = random.sample(exe_files, keep_count)
    
#     # 删除未被选中的文件
#     for file in exe_files:
#         if file not in selected_files:
#             file_path = os.path.join(folder_path, file)
#             try:
#                 os.remove(file_path)
#                 print(f"已删除文件: {file_path}")
#             except Exception as e:
#                 print(f"删除文件{file_path}时出错: {e}")

# # 使用示例
# folder_path = 'dataset/malware_200'  # 替换为你的文件夹路径
# keep_count = 200
# keep_random_files(folder_path, keep_count)