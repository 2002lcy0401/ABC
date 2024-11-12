import idaapi
import idautils
import ida_funcs
import ida_bytes
import idc
import os
def save_cfg_as_dot(output_file):
    with open(output_file, 'w') as f:
        f.write("digraph CFG {\n")
        f.write("    node [shape=box];\n")  # 设置节点形状为矩形
        # 遍历所有函数
        for func_ea in idautils.Functions():
            func = idaapi.get_func(func_ea)
            if not func:
                continue
            flowchart = idaapi.FlowChart(func)
            for block in flowchart:
                # 使用起始地址作为节点标签
                node_label = f"0x{block.start_ea:X}"
                f.write(f'    "{node_label}" [label="{node_label}"];\n')
                for succ in block.succs():
                    succ_label = f"0x{succ.start_ea:X}"
                    f.write(f'    "{node_label}" -> "{succ_label}";\n')
        f.write("}\n")
    # print(f"CFG 已成功保存到 {output_file}")

# def cfg_main():
#         # 等待自动分析完成
#     idaapi.auto_wait()
#     output_file = "output_cfg.dot"  # 设置输出文件路径
#     save_cfg_as_dot(output_file)
#     print(f"CFG 已成功保存到 {output_file}")
#     idc.qexit(0)  # 退出 IDA Pro

def cfg_main():
        # 等待自动分析完成
    idaapi.auto_wait()

    # output_file = "output_cfg.dot"  # 设置输出文件路径
    input_pe_path = idaapi.get_input_file_path()
    # 生成输出JSON文件名（与输入PE文件名对应）
    base_name = os.path.splitext(os.path.basename(input_pe_path))[0]
    output_file = f"{base_name}_cfg.dot"
    save_cfg_as_dot(output_file)
    print(f"CFG 已成功保存到 {output_file}")
    idc.qexit(0)  # 退出 IDA Pro



if __name__ == "__main__":
    cfg_main()
