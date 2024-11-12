import os

def scan_with_avast(file_path):
    avast_path="D:\\Avast\\ashCmd.exe "
    scanCmd = avast_path + file_path + " /d /p"
    scanResults = str(os.system(scanCmd))

    print(scanResults)
    if scanResults == '0':
        print("The file is benign.")
        return 0
    else:
        return 1
    

# import subprocess
# import os

# def scan_with_avast(file_path):
#     avast_path = "D:\\Avast\\ashCmd.exe "
#     scanCmd = avast_path + file_path + " /d /p"

#     print(scanCmd)

#     try:
#         # Run the command and capture the output
#         result = subprocess.run(scanCmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

#         # Analyze stdout for specific indications of success or threat
#         scan_output = result.stdout
#         print(scan_output)
#         if "no threat" in scan_output or "clean" in scan_output:
#             print("The file is benign.")
#             return 0
#         else:
#             print("Potential threat detected.")
#             return 1
#     except Exception as e:
#         print(f"Error running Avast scan: {e}")
#         return 1

def get_absolute_paths(directory):
    # 获取目录中所有文件的文件名
    file_names = os.listdir(directory)
    
    # 生成每个文件的绝对路径
    absolute_paths = [os.path.abspath(os.path.join(directory, file_name)) for file_name in file_names]
    
    return absolute_paths






# print(scan_with_avast("C:\\Users\\21433\\Desktop\\miniMal\\dataset\\malware_clamav\\ef6d8840259560ff117a52f4fead2aeca708cb17.exe"))
# print(scan_with_avast("C:\\Users\\21433\\Desktop\\miniMal\\dataset\\benign\\192034.exe"))




# 示例用法
# directory = "C:\\Users\\21433\\Desktop\\miniMal\\dataset\\malware_avast"  # 替换为你的文件夹路径
# absolute_paths = get_absolute_paths(directory)

# # 打印所有文件的绝对路径
# for file_path in absolute_paths:
#     print(file_path)
#     # 示例用法
#     # file_path = 'D:\\malware_design\\dataset\\benign\\0a8deb24eef193e13c691190758c349776eab1cd65fba7b5dae77c7ee9fcc906.exe'
#     result = scan_with_avast(file_path)
#     if result == 1:
#         print("The file is malicious.")
#     elif result == 0:
#         os.remove(file_path)
#         print("The file is clean.")
#     else:
#         print("An error occurred.")

