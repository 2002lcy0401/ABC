import step1
import step2
import models
import os
import pre_reduction
from binary_reduce import binary_delete
import numpy as np
import shutil
import json
import functionality_verification
# MALCONV_MODEL_PATH = 'detector/malware_evasion_competition/models/malconv/malconv.checkpoint'
# attack_model = models.MalConvModel(MALCONV_MODEL_PATH, thresh=0.5)
EMBER_MODEL_PATH = 'detector/malware_evasion_competition/models/ember/ember_model.txt'
attack_model = models.EmberModel(EMBER_MODEL_PATH, thresh=0.8336)
max_query=[100,200,300,400,500]
step1_maxquery=50
weight_file='json_result/ember/weight.json'
choices = [ 'header_modify','slack','section_add', 'padding']

adv_dir='adv_result/ember/step1_adv'
pre_adv_dir='adv_result/ember/pre_reduction_adv'
mini_adv_dir='adv_result/ember/step2_adv'
ben_dir='dataset/benign_section_content'
ben_dir_list=os.listdir(ben_dir)

before_times=[]
after_times=[]


with open(weight_file, 'r') as f:
    json_result = json.load(f)
last_weight_result = json_result[-1]

# 访问所需的权重值
# count = last_weight_result['count']
step1_weights = last_weight_result['operation_weight']
ben_weights = last_weight_result['benign_content_weight']

# content_weights = [1 for i in range(len(ben_dir_list))]
# ben_weights={}
# for ben_name,weight in zip(ben_dir_list,content_weights):
#     ben_weights[ben_name]=weight

mal_dir='dataset/malware'
ori_cfg_dir='cfg/ember/ori'
adv_cfg_dir='cfg/ember/adv'

mal_list=os.listdir(mal_dir)
all=0
success=368
all_query=0
preb_rates=[[] for i in range(len(max_query))] #与查询次数对应

preb_rates[0]=[0.4936641048840343 for i in range(368)]
preb_rates[1]=[0.4661559172173643 for i in range(368)]
preb_rates[2]=[0.4521567163365901 for i in range(368)]
preb_rates[3]=[0.4481726868027994 for i in range(368)]
preb_rates[4]=[0.4453032945376927 for i in range(368)]


results_file=['json_result/ember/'+str(i)+'.json' for i in max_query]

for mal in mal_list:
    print('step1_weights:',step1_weights)
    # print('ben_weights:',ben_weights)
    add_data=[[],[],[],[]]
    add_data_len=[0,0,0,0]
    times=[0,0,0,0]
    op_len=[[],[],[],[]]
    ben_flag=[[],[],[],[]]
    mal_path=os.path.join(mal_dir,mal)
    mal_path=os.path.normpath(mal_path)
    
    all+=1
    if all<=374:
        continue


    print(f'process {all}:{mal}')


    mal_adv=mal.split('.')[0]+'_adv.exe'

    adv_path=os.path.join(mal_dir,mal_adv)
    adv_path=os.path.normpath(adv_path)


    # step1阶段生成的对抗样本
    adv_copy_path=os.path.join(adv_dir,mal_adv)
    adv_copy_path=os.path.normpath(adv_copy_path)

    # pre_reduction阶段生成的对抗样本
    pre_adv_copy_path=os.path.join(pre_adv_dir,mal_adv)
    pre_adv_copy_path=os.path.normpath(pre_adv_copy_path)

    # 最终mini的对抗样本
    mal_adv_copy_path=os.path.join(mini_adv_dir,mal_adv)
    mal_adv_copy_path=os.path.normpath(mal_adv_copy_path)


    flag,add_data,add_data_len,times,step1_query,op_len,ben_flag=step1.mal_to_adv(mal_path,adv_path,attack_model,ben_dir,
                                                                  choices,ben_dir_list,ben_weights,
                                                                  step1_weights,add_data,add_data_len,
                                                                  times,step1_maxquery,op_len,ben_flag,adv_copy_path)
    
    if flag:
        print('step1成功')
        before_times.append(sum(times))
        
        # dot_path=functionality_verification.get_file_cfg(mal_path)
        # mal_dot_path=os.path.join(ori_cfg_dir,mal.split('.')[0]+'.dot')
        # shutil.copy(dot_path,mal_dot_path)
        # os.remove(dot_path)
        # os.remove(os.path.join(mal_dir,mal+'.idb'))


        # dot_path=functionality_verification.get_file_cfg(adv_copy_path)
        # adv_dot_path=os.path.join(adv_cfg_dir,mal.split('.')[0]+'.dot')
        # shutil.copy(dot_path,adv_dot_path)
        # os.remove(dot_path)
        # os.remove(os.path.join(adv_dir,mal_adv+'.idb'))

        
        # fun_flag=functionality_verification.cfg_check(mal_dot_path,adv_dot_path,threshold=0.8)
        # print("step1结束,funtionality_verification结果为:",fun_flag)
        fun_flag=True
    else:
        print('step1失败')



    if flag and fun_flag: #第一阶段成功生成对抗样本
        success+=1
        add_data,add_data_len,times,pre_reduction_query,ben_flag=pre_reduction.reduction(mal_path,adv_path,attack_model,
                                                                        add_data,add_data_len,times,step1_query,
                                                                        op_len,max_query,ben_flag,pre_adv_copy_path)

        after_times.append(sum(times))

        for i in range(len(ben_flag)):
            for j in ben_flag[i]:
                ben_weights[j]=ben_weights[j]+10

        for i in range(len(times)):
            if times[i]!=0:
                step1_weights[i]=step1_weights[i]+1



        individual_size = len([num for num in times if num != 0])

        if individual_size==1: #只有一个操作,直接二分法
            weight=[0,0,0,0]
            for k in range(len(add_data_len)):
                if add_data_len[k]!=0:
                    index=k
            weight[index]=1
            all_real_data,index,query=binary_delete(attack_model,mal_path,adv_path,add_data_len,add_data,pre_reduction_query,max_query)

            print('第二阶段（二分法）结束')
            
            # step1_weights[index] = step1_weights[index]+1

            for k in range(len(max_query)):
                print(f'最大查询次数为:{max_query[k]}的效果')
                real_data=all_real_data[k]
                real_to_add= [num for num in real_data if num >= 0]
                real_data_len=len(real_to_add)
                add_data_len[index]=real_data_len
                add_data[index]=real_to_add
                step2.do_actions(mal_path,adv_path,weight,add_data_len,add_data,times)
                
                print('模型检测效果:',models.predit_label(attack_model,adv_path))

                before=os.path.getsize(mal_path)
                after=os.path.getsize(adv_path)
                preb_rate=(after-before)/before
                preb_rates[k].append(preb_rate)

                print(f'扰动率为{preb_rate}')

                if k==len(max_query)-1:
                    shutil.copy(adv_path,mal_adv_copy_path)
                os.remove(adv_path)

        else:

            query,all_weight=step2.pso_run(attack_model,mal_path,adv_path,add_data_len,add_data,times,
                                            pre_reduction_query,max_query,num_particles=10,max_iter=200)


            print('第二阶段(PSO)结束')

            for k in range(len(max_query)):
                print(f'最大查询次数为:{max_query[k]}的效果')
                weight=all_weight[k]
                step2.do_actions(mal_path,adv_path,weight,add_data_len,add_data,times)
                before=os.path.getsize(mal_path)
                after=os.path.getsize(adv_path)
                preb_rate=(after-before)/before
                preb_rates[k].append(preb_rate)
                print(f'{mal}第二阶段成功生成对抗样本')
                print(models.predit_label(attack_model,adv_path))
                print(f'扰动率为{preb_rate}')
                
                if k==len(max_query)-1:
                    shutil.copy(adv_path,mal_adv_copy_path)
                os.remove(adv_path)

    else:
        query=step1_query
    all_query+=query


    print(f'当前共{all}个样本，成功生成{success}个对抗样本,成功率为{success/all}')
    for h in range(len(preb_rates)):
        print(f'最大查询次数为:{max_query[h]}的平均扰动率为{np.mean(preb_rates[h])}')
    # print(f'平均扰动率为{np.mean(preb_rates)}')

        result = {
        'max_query': max_query[h],
        'current':all,
        'success_rate': success/all,
        'perb_rate': np.mean(preb_rates[h])
                }
        
        try:
            with open(results_file[h], 'r') as f:
                results = json.load(f)
        except FileNotFoundError:
            results = []
        results.append(result)
        with open(results_file[h], 'w') as f:
            json.dump(results, f, indent=4)

    weight_result={
        'count':all,
        'operation_weight':step1_weights,
        'benign_content_weight':ben_weights,
    }
    try:
        with open(weight_file, 'r') as f:
            results = json.load(f)
    except FileNotFoundError:
        results = []
    results.append(weight_result)
    with open(weight_file, 'w') as f:
        json.dump(results, f, indent=4)

# 打开一个文件用于写入
with open('times_result/ember/before.txt', 'w') as file:
    # 遍历列表，将每个元素写入文件
    for number in before_times:
        file.write(str(number) + '\n')  # 将数字转换为字符串，并在每个数字后添加换行符
    print("列表已写入到before文件中。")

# 打开一个文件用于写入
with open('times_result/ember/after.txt', 'w') as file:
    # 遍历列表，将每个元素写入文件
    for number in after_times:
        file.write(str(number) + '\n')  # 将数字转换为字符串，并在每个数字后添加换行符
    print("列表已写入到after文件中。")


print('所有样本均已跑完')
print(f'共{all}个样本，成功生成{success}个对抗样本,成功率为{success/all}')

for h in range(len(preb_rates)):
    print(f'最大查询次数为:{max_query[h]}的平均扰动率为{np.mean(preb_rates[h])}')
# print(f'平均扰动率为{np.mean(preb_rates)}')