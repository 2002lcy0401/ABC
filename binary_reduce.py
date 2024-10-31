from available_actions import pe_actions_no_information
import models
import os
import numpy as np
import shutil
def copy_name(exe_path):
    base_name, ext = os.path.splitext(exe_path)
    new_filename = f"{base_name}_copy{ext}"
    return new_filename   

# 判断是否可以删除,0代表不可以删除，1代表可以删除
def judge_delete(mal_path,adv_path,seed,model,a,b,index):
    copy_path=copy_name(mal_path)
    shutil.copy(mal_path,copy_path)

    x=[-1 for i in range(b-a+1)]
    delete_seed=seed[0:a]+x+seed[b+1:]

    real_to_add= [num for num in delete_seed if num >= 0]

    if index==0:
        pe_actions_no_information.header_modify(mal_path,adv_path,real_to_add)
        if models.predit_label(model,adv_path)[1] == 0:  # 0被目标模型错误分类为良性，可以保留
            print('成功删除了',a,'到',b,'部分的数据',models.predit_label(model,adv_path))
            os.remove(adv_path)
            return 1
        else:
            os.remove(adv_path)
            return 0
        
    elif index==1:
        pe_actions_no_information.slack(mal_path,adv_path,real_to_add)
        if models.predit_label(model,adv_path)[1] == 0:  # 0被目标模型错误分类为良性，可以保留
            print('成功删除了',a,'到',b,'部分的数据',models.predit_label(model,adv_path))
            os.remove(adv_path)
            return 1
        else:
            os.remove(adv_path)
            return 0

    elif index==2:
        pe_actions_no_information.section_add(mal_path,adv_path,real_to_add)
        if models.predit_label(model,adv_path)[1] == 0:  # 0被目标模型错误分类为良性，可以保留
            print('成功删除了',a,'到',b,'部分的数据',models.predit_label(model,adv_path))
            os.remove(adv_path)
            return 1
        else:
            os.remove(adv_path)
            return 0

    elif index==3:
        pe_actions_no_information.padding(mal_path,adv_path,real_to_add)
        if models.predit_label(model,adv_path)[1] == 0:  # 0被目标模型错误分类为良性，可以保留
            print('成功删除了',a,'到',b,'部分的数据',models.predit_label(model,adv_path))
            os.remove(adv_path)
            return 1
        else:
            os.remove(adv_path)
            return 0

    # elif index==4:
    #     pe_actions_no_information.code_cave2(mal_path,adv_path,real_to_add)
    #     if models.predit_label(model,adv_path)[1] == 0:  # 0被目标模型错误分类为良性，可以保留
    #         print('成功删除了',a,'到',b,'部分的数据',models.predit_label(model,adv_path))
    #         os.remove(adv_path)
    #         return 1
    #     else:
    #         os.remove(adv_path)
    #         return 0
        
    # elif index==5:
    #     pe_actions_no_information.code_cave2(mal_path,adv_path,real_to_add)
    #     if models.predit_label(model,adv_path)[1] == 0:  # 0被目标模型错误分类为良性，可以保留
    #         print('成功删除了',a,'到',b,'部分的数据',models.predit_label(model,adv_path))
    #         os.remove(adv_path)
    #         return 1
    #     else:
    #         os.remove(adv_path)
    #         return 0


# 计算全局数组中[a,b]区间的总数（优先级）
def priority(global_array,a,b):
    return 0

def binary_index(a,b): # 二分法找到中间值,如果a,b是一个值，报错
    mid = (a+b)//2
    return a,mid,b

def len_seed(seed): # 计算seed中的非负数的总数
    t=0
    for i in range(len(seed)):
        if seed[i]!=-1:
            t=t+1
    return t

def adv_name(exe_path):
    base_name, ext = os.path.splitext(exe_path)
    new_filename = f"{base_name}_adv{ext}"
    return new_filename    

def binary_delete(model,mal_path,adv_mal_path,add_data_len,add_data,query,max_query):
    for i in range(len(add_data_len)):
        if add_data_len[i]!=0:
            index=i
    choices = ['header_modify','slack','section_add', 'padding']
    global_array=[0 for p in range(add_data_len[index])]
    print(f"只有一项是非0,所进行缩减的操作是:{choices[index]}")
    add_data=add_data[index]
    l=len(add_data)-1
    a,mid,b=binary_index(0,l)
    first_left=priority(global_array,a,mid+1)
    first_right=priority(global_array,mid+1,b)
    all_index=[[a,mid+1,0,first_left],[mid+1,b,0,first_right]]  # 存放着所有的分支，每个分支第一位是左区间，第二位是右区间，第三位代表是否被删除过，第四位是优先级
    flag=0 # 0表示可以继续分割，1表示不能再分割
    z=0
    max_query_index=len(max_query)

    all_add_data=[]


    while query<max_query[max_query_index-1]:
        print('第',z,'次循环')
        # 提取第三位为0的子数组（还没有被删除过的区间）
        cur_index = [array for array in all_index if array[2] == 0]
        # 按第四个值进行降序排列
        sorted_index = sorted(cur_index, key=lambda x:x[3],reverse=True)
        for i in sorted_index:
            left=i[0]
            right=i[1]
            query=query+1
            if judge_delete(mal_path,adv_mal_path,add_data,model,left,right,index)==1:
                # 修改全局数组
                for h in range(left,right):
                    global_array[h]=global_array[h]+1
                # 修改全局分支数组
                for u in range(len(all_index)):
                    if all_index[u]==i:
                        all_index[u][2]=1
                i[2]=1
                # 修改add_data
                x=[-1 for v in range(right-left+1)]
                add_data=add_data[0:left]+x+add_data[right+1:]

            if query in max_query:
                print(f'当前query次数为{query},进行记录')
                all_add_data.append(add_data)

        # 此时仍为0，代表需要进行进一步分割
        for i in sorted_index:
            if i[2]==0:
                left=i[0]
                right=i[1]
                if left==right: #表示不能再分了
                    flag=1
                    break
                c,d,e=binary_index(left,right)
                left_priority=priority(global_array,c,d)
                right_priority=priority(global_array,d,e)
                f=[c,d,0,left_priority]
                g=[d,e,0,right_priority]
                all_index.remove(i)
                all_index.append(f)
                all_index.append(g)


        
        if flag==1:
            break
        z=z+1

    if query>max_query[max_query_index-1]:
        print(f'二分删除循环次数超过{max_query}次,退出')
        return all_add_data,index,query
    else:

        print('不能再分割了，提前结束')
        len_a=len(all_add_data)
        len_b=len(max_query)
        if len_a==0:
            for i in range(len_b-len_a):
                all_add_data.append(add_data)
            return all_add_data,index,query
        if len_a<len_b:
            for i in range(len_b-len_a):
                all_add_data.append(all_add_data[len_a-1])
        return all_add_data,index,query

    

# if __name__=='__main__':
#     MALCONV_MODEL_PATH = 'detector/malware_evasion_competition/models/malconv/malconv.checkpoint'
#     attack_model = models.MalConvModel(MALCONV_MODEL_PATH, thresh=0.5)
#     exe_pth = 'mal1.exe'
#     adv_pth = 'mal1_adv.exe'
#     threshold=0.2
#     add_data = []
#     print(models.predit_label(attack_model,exe_pth))

#     # 读取文件并将每一行的数字添加到数组中
#     with open('mal1_add_data.txt', 'r') as file:
#         for line in file:
#             # 移除行尾的换行符并将字符串转换为整数
#             number = int(line.strip())
#             add_data.append(number)
            
#     print('add_data:',add_data,"add_data size:",len(add_data),"add_data type:",type(add_data))
#     pe_actions_no_information.seed_to_add(exe_pth,adv_pth,add_data) # 根据x里面的值进行修改，-1代表删除
#     print(models.predit_label(attack_model,adv_pth))
#     # 输出数组
#     global_array=[0 for i in range(len(add_data))]
#     flag,add_data,global_array,all_index=binary_delete(exe_pth,add_data,threshold,global_array,attack_model)
#     print(all_index)
#     pe_actions_no_information.seed_to_add(exe_pth,adv_pth,add_data) # 根据x里面的值进行修改，-1代表删除
#     print(models.predit_label(attack_model,adv_pth))





