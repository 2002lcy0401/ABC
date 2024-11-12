import sys
import subprocess
import os

def run_idapython(ida_path, script_path, pe_file_path):
    """
    使用 subprocess 模块调用 IDA Pro 来运行指定的 IDAPython 脚本。

    :param ida_path: ida.exe 的绝对路径
    :param script_path: extract_cfg.py 的绝对路径
    :param pe_file_path: 需要分析的 PE 文件路径
    """
    # 确保路径中没有空格或特殊字符的问题
    cmd = [
        ida_path,
        "-A",
        f"-S\"{script_path}\"",
        f"\"{pe_file_path}\""
    ]

    # 将命令列表转换为字符串，适用于 Windows CMD
    cmd_str = ' '.join(cmd)

    print(f"Executing command: {cmd_str}")

    try:
        # 执行命令，并等待其完成
        subprocess.run(cmd_str, check=True, shell=True)
        print("IDA Pro 脚本执行成功, CFG 已保存到文件。")
    except subprocess.CalledProcessError as e:
        print(f"运行 IDA Pro 时出错: {e}")
        # sys.exit(1)

def main(pe_file_path):

    # 验证 PE 文件路径是否存在
    if not os.path.isfile(pe_file_path):
        print(f"错误: PE 文件 '{pe_file_path}' 不存在。")
        sys.exit(1)
    
    # 配置 IDA Pro 和脚本的路径
    ida_path = r"C:\\Users\\21433\\Desktop\\IDA_Pro_v8.3_Portable\\ida.exe"  # 请根据实际情况修改
    script_path = r"C:\\Users\\21433\\Desktop\\IDA_Pro_v8.3_Portable\\cfg.py"  # 请根据实际情况修改

    # 验证 ida.exe 是否存在
    if not os.path.isfile(ida_path):
        print(f"错误: IDA Pro 可执行文件 '{ida_path}' 不存在。")
        sys.exit(1)
    
    # 验证 extract_cfg.py 是否存在
    if not os.path.isfile(script_path):
        print(f"错误: 脚本文件 '{script_path}' 不存在。")
        sys.exit(1)
    
    # 调用 IDA Pro 运行脚本
    run_idapython(ida_path, script_path, pe_file_path)

if __name__ == "__main__":
    pe_file_path = "C:\\Users\\21433\\Desktop\\IDA_Pro_v8.3_Portable\\winmine2.exe" # 请根据实际情况修改
    main(pe_file_path)
