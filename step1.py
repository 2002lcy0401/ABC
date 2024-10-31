import models
import os
import random
from available_actions import pe_actions_no_information,extract_content
import shutil
import functionality_verification


def copy_name(exe_path):
    base_name, ext = os.path.splitext(exe_path)
    new_filename = f"{base_name}_copy{ext}"
    return new_filename   

# 按权重表选取良性文件内容
def get_benign_content(ben_dir,ben_dir_list,ben_weights):
        # 计算总权重
    total_weight = sum(ben_weights.values())
    # 生成一个0到total_weight之间的随机数
    rand_val = random.uniform(0, total_weight)
    # 根据随机数找到对应的选择
    cumulative_weight = 0
    for choice, weight in ben_weights.items():
        cumulative_weight += weight
        if rand_val < cumulative_weight:
            file_path = os.path.join(ben_dir, choice)
            with open(file_path, "rb") as file:
                byte_data = file.read()
            add_data = [byte for byte in byte_data]
            return add_data,choice

# 根据设定的权重轮盘赌选择操作
def choose_operation(operations,weights):
    # 计算总权重
    total_weight = sum(weights)
    # 生成一个0到total_weight之间的随机数
    rand_val = random.uniform(0, total_weight)
    # 根据随机数找到对应的选择
    cumulative_weight = 0
    for choice, weight in zip(operations, weights):
        cumulative_weight += weight
        if rand_val < cumulative_weight:
            return choice

# 实施操作
def do_operation(mal_path,adv_path,choice,seed,add_data,add_data_len,time,op_len,ben_path,ben_flag):
    if choice=='header_modify':
        print('header_modify')
        pe_actions_no_information.header_modify(mal_path,adv_path,seed)
        a,b=extract_content.header_extract(mal_path,adv_path,seed)
        add_data[0]=a
        add_data_len[0]=b
        time[0]=time[0]+1
        op_len[0]=[b]
        ben_flag[0]=[ben_path]

    elif choice=='slack':
        print('slack')
        pe_actions_no_information.slack(mal_path,adv_path,seed)
        a,b=extract_content.slack(mal_path,adv_path,seed)
        add_data[1]=a
        add_data_len[1]=b
        time[1]=time[1]+1
        op_len[1]=[b]
        ben_flag[1]=[ben_path]

    elif choice=='section_add':
        print('section_add')
        pe_actions_no_information.section_add(mal_path,adv_path,seed)
        a,b=extract_content.section_count(mal_path,adv_path,seed)
        for i in range(b):
            add_data[2].append(a[i])
        add_data_len[2]=add_data_len[2]+b
        time[2]=time[2]+1
        op_len[2].append(b)
        ben_flag[2].append(ben_path)
    elif choice=='padding':
        print('padding')
        pe_actions_no_information.padding(mal_path,adv_path,seed)
        a,b=extract_content.padding_count(mal_path,adv_path,seed)
        for i in range(b):
            add_data[3].append(a[i])
        add_data_len[3]=add_data_len[3]+b
        time[3]=time[3]+1
        op_len[3].append(b)
        ben_flag[3].append(ben_path)
    else:
        print('choice not found')

def mal_to_adv(mal_path,adv_path,attack_model,ben_dir,choices,ben_dir_list,
               ben_weights,op_weights,add_data,add_data_len,time,step1_maxquery,op_len,ben_flag,adv_copy_path):
    copy_path=copy_name(mal_path)
    shutil.copy(mal_path,copy_path)
    query=0
    while models.predit_label(attack_model,mal_path)[1] and functionality_verification.file_format_check(mal_path):
        query+=1
        seed,ben_path=get_benign_content(ben_dir,ben_dir_list,ben_weights)
        choice=choose_operation(choices,op_weights)
        print(f'第{query}次尝试,选择了{choice}')
        do_operation(mal_path,adv_path,choice,seed,add_data,add_data_len,time,op_len,ben_path,ben_flag)
        print(f'效果:{models.predit_label(attack_model,adv_path)}')
        os.remove(mal_path)
        os.rename(adv_path,mal_path)
        if query>step1_maxquery:
            os.rename(mal_path,adv_path)
            os.rename(copy_path,mal_path)
            print(f'一阶段尝试次数超过{step1_maxquery}次,生成对抗样本失败')
            return 0,add_data,add_data_len,time,query,op_len,ben_flag
    if query<=step1_maxquery:
        os.rename(mal_path,adv_path)
        os.rename(copy_path,mal_path)
        shutil.copy2(adv_path,adv_copy_path)
        print(f'一阶段成功生成对抗样本,共尝试{query}次')
        return 1,add_data,add_data_len,time,query,op_len,ben_flag

