from pe_actions import section_add,padding,header_modify,header_shift,slack,code_cave
import sys
import os

# 获取当前脚本的根目录路径
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
# 将vae目录添加到sys.path
sys.path.append(os.path.join(current_dir, 'vae'))
import vae_generate

    
def adv_name(exe_path):
    base_name, ext = os.path.splitext(exe_path)
    new_filename = f"{base_name}_adv{ext}"
    return new_filename


if __name__ == "__main__":
    # 加载保存的模型权重
    vae_model_pth='../vae/vae_model_epoch_500.pth'
    # 待生成样本的exe文件路径
    exe_path='winmine.exe'
    adv_pth=adv_name(exe_path)
     # 生成新样本
    num_add_data = 10
    new_add_datas = vae_generate.generate_samples(vae_model_pth,num_add_data)
    # section_add(exe_path, adv_pth,new_add_datas[0])
    # padding(exe_path, adv_pth,new_add_datas[0])
    # header_modify(exe_path, adv_pth,new_add_datas[0])
    # header_shift(exe_path, adv_pth,new_add_datas[0])
    # slack(exe_path, adv_pth,new_add_datas[0])
    # code_cave(exe_path, adv_pth,new_add_datas[0]+new_add_datas[1]+new_add_datas[2])