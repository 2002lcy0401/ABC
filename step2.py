# PSO算法进行缩减操作的使用力度
import numpy as np

import models
from available_actions import pe_actions_no_information
import os
import json
import shutil
import time
import matplotlib.pyplot as plt
import functionality_verification



def get_content_from_json(json_path):
    # 打开JSON文件并读取其内容  
    with open(json_path, 'r', encoding='utf-8') as f:  
        # 使用json.load()函数将文件内容解析为Python数据结构  
        data = json.load(f)  
    return data

def adv_name(exe_path):
    base_name, ext = os.path.splitext(exe_path)
    new_filename = f"{base_name}_adv{ext}"
    return new_filename    

def copy_name(exe_path):
    base_name, ext = os.path.splitext(exe_path)
    new_filename = f"{base_name}_copy{ext}"
    return new_filename   


def cal_benign_len(x,data_len,times):
    if len(x)==len(times):
        y=x
    else:
        y=[]
        g=0
        for i in range(len(times)):
            if times[i]==0:
                y.append(0)
            else:
                y.append(x[g])
                g=g+1
    a=int(y[0]*data_len[0])+int(y[1]*data_len[1])+int(y[2]*data_len[2])+int(y[3]*data_len[3])
    return a

def do_actions(mal_path,adv_path,x,data_len,add_data,times):

    if len(x)==len(times):
        y=x
    else:
        y=[]
        g=0
        for i in range(len(times)):
            if times[i]==0:
                y.append(0)
            else:
                y.append(x[g])
                g=g+1

    copy_path=copy_name(mal_path)
    shutil.copy(mal_path,copy_path)
    # print(x)

    if y[0]==0:
        c1=[]
        pe_actions_no_information.header_modify(mal_path,adv_path,c1)
        os.remove(mal_path)
        os.rename(adv_path,mal_path)
    else:
        c1=add_data[0][-int(y[0]*data_len[0]):]
        pe_actions_no_information.header_modify(mal_path,adv_path,c1)
        os.remove(mal_path)
        os.rename(adv_path,mal_path)

    if y[1]==0:
        c2=[]
        pe_actions_no_information.slack(mal_path,adv_path,c2)
        os.remove(mal_path)
        os.rename(adv_path,mal_path)
    else:
        c2=add_data[1][-int(y[1]*data_len[1]):]
        pe_actions_no_information.slack(mal_path,adv_path,c2)
        os.remove(mal_path)
        os.rename(adv_path,mal_path)

    if y[2]==0:
        c3=[]
        pe_actions_no_information.section_add(mal_path,adv_path,c3)
        os.remove(mal_path)
        os.rename(adv_path,mal_path)
    else:
        c3=add_data[2][-int(y[2]*data_len[2]):]
        pe_actions_no_information.section_add(mal_path,adv_path,c3)
        os.remove(mal_path)
        os.rename(adv_path,mal_path)
    if y[3]==0:
        c4=[]
        pe_actions_no_information.padding(mal_path,adv_path,c4)
        os.remove(mal_path)
        os.rename(adv_path,mal_path)
    else:
        c4=add_data[3][-int(y[3]*data_len[3]):]
        pe_actions_no_information.padding(mal_path,adv_path,c4)
        os.remove(mal_path)
        os.rename(adv_path,mal_path)

    os.rename(mal_path,adv_path)
    os.rename(copy_path,mal_path)

# 适应度函数，目标是最小化该函数
def fitness(x,add_data_len,add_data,model,mal_path,adv_path,times):
    # 这是一个示例函数，你可以根据具体情况修改
    a=cal_benign_len(x,add_data_len,times)
    c=sum(x)
    do_actions(mal_path,adv_path,x,add_data_len,add_data,times)
    b=models.predit_label(model,adv_path)[1]
    fun_flag=functionality_verification.file_format_check(adv_path)
    if b:
        return 99999999*1024
    else:
        if fun_flag:
            return a
        else:
            return 99999998*1024
        # return a+c*10000

def pso_run(model,mal_path,adv_mal_path,add_data_len,add_data,times,query,max_query,num_particles,max_iter):
    # PSO 参数
    num_particles = num_particles  # 粒子数量
    max_iter = max_iter  # 最大迭代次数
    w = 0.5  # 惯性权重
    c1 = 1.5  # 自我认知学习因子
    c2 = 1.5  # 社会认知学习因子
    # 将恶意文件复制到top_k文件夹中
    query=query
    attack_model=model

    n = len([num for num in times if num != 0]) # 每个字节数组的长度
    dim = n  # 维度
    # 初始化粒子的位置和速度
    particles = np.random.normal(loc=0.5, scale=0.2, size=(num_particles, dim))
    particles = np.clip(particles, 0, 1)  # 确保所有值在0到1之间
    particles[0] = np.ones(dim)  # 确保有全是1的个体

    velocities = np.random.uniform(-0.1, 0.1, (num_particles, dim))
        # 保证至少90%的速度为负数
    num_negatives = int(0.9 * velocities.size)
    negative_indices = np.random.choice(velocities.size, num_negatives, replace=False)
    velocities.flat[negative_indices] = np.abs(velocities.flat[negative_indices]) * -1

    # 初始化个体最优位置和全局最优位置
    p_best = particles.copy()
    g_best=particles[0]
    for i in range(len(particles)):
        cur=fitness(particles[i],add_data_len,add_data,model,mal_path,adv_mal_path,times)
        if cur<fitness(g_best,add_data_len,add_data,model,mal_path,adv_mal_path,times):
            g_best=particles[i]


    g_best_fitness_history = []
    g_best_confidence_history = []


    all_w=[ [] for i in range(len(max_query))]
    query_index=0
    # PSO算法主循环
    for iteration in range(max_iter):

        if query >= max_query[query_index]:
            print(f'PSO算法查询次数超过{max_query[query_index]}次,进行记录')
            g=0
            y=[]
            for k in range(len(times)):
                if times[k]==0:
                    y.append(0)
                else:
                    y.append(g_best[g])
                    g=g+1

            all_w[query_index]=y
            if query_index<len(max_query)-1:
                query_index=query_index+1
            else:
                return query,all_w
            
            # return query,y
        
        for i in range(num_particles):
            query=query+1
            # 计算当前粒子的位置的适应度值
            cur_fitness = fitness(particles[i],add_data_len,add_data,model,mal_path,adv_mal_path,times)
            p_best_fitness = fitness(p_best[i],add_data_len,add_data,model,mal_path,adv_mal_path,times)
            # 更新个体最优位置
            if cur_fitness < p_best_fitness:
                p_best[i] = particles[i].copy()

        # 更新全局最优位置
        g_best = p_best[np.argmin([fitness(p,add_data_len,add_data,model,mal_path,adv_mal_path,times) for p in p_best])]
        # 记录当前全局最优位置的适应度值
        g_best_fitness_history.append(fitness(g_best,add_data_len,add_data,model,mal_path,adv_mal_path,times))
        
        for i in range(num_particles):
            # 更新粒子的速度
            r1 = np.random.rand(dim)
            r2 = np.random.rand(dim)
            velocities[i] = (w*velocities[i] +c1*r1*(p_best[i]-particles[i])+c2*r2*(g_best - particles[i]))

            # 将velocities数组转换为int32类型
            # velocities = velocities.astype(np.int32)
            # 更新粒子的位置
            particles[i] += velocities[i]
            # 保证粒子的位置在边界内
            particles[i] = np.clip(particles[i], 0, 1)
        # 打印每次迭代的全局最优解
        print(f"Iteration {iteration + 1}/{max_iter}, Best Fitness: {fitness(g_best,add_data_len,add_data,model,mal_path,adv_mal_path,times)}")
        print("Best Particle: ", g_best)

    # # 绘制全局最优位置的适应度值变化过程
    # plt.plot(range(1, max_iter + 1), g_best_fitness_history, marker='o')
    # plt.xlabel('Iteration')
    # plt.ylabel('Best Fitness')
    # plt.title('Best Fitness over Iterations')
    # plt.grid(True)
    # plt.show()

        # 返回最优个体和其适应度
    # g=0
    # y=[]
    # for k in range(len(times)):
    #     if times[k]==0:
    #         y.append(0)
    #     else:
    #         y.append(g_best[g])
    #         g=g+1
    # return query,y




def data_to_list(data_list, filename,list1):  
    """  
    将包含文件名和三个列表的数据添加到列表中。  
  
    参数:  
    data_list (list): 存储字典的列表，每个字典包含文件名和三个列表。  
    filename (str): 文件名。  
    list1, list2, list3 (list): 三个列表，分别对应不同的数据类型。  
    """  
    data_dict = {  
        "filename": filename,  
        "weight": list1,  
    }  
    data_list.append(data_dict)  

def save_data_to_json(data_list, filename):  
    """  
    将包含多个字典的列表保存到JSON文件中。  
  
    参数:  
    data_list (list): 包含多个字典的列表，每个字典有'filename', 'list1', 'list2', 'list3'键。  
    filename (str): 要保存的JSON文件的名称。  
    """  
    with open(filename, 'w', encoding='utf-8') as f:  
        json.dump(data_list, f, ensure_ascii=False, indent=4)  





