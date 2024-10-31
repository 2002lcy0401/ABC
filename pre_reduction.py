import models
import os
import json
import shutil
from available_actions import pe_actions_no_information
import math

def copy_name(exe_path):
    base_name, ext = os.path.splitext(exe_path)
    new_filename = f"{base_name}_copy{ext}"
    return new_filename   

def do_actions(mal_path,adv_path,x,data_len,add_data,times,op_len):

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

        c1=add_data[0]
        pe_actions_no_information.header_modify(mal_path,adv_path,c1)
        os.remove(mal_path)
        os.rename(adv_path,mal_path)

    if y[1]==0:
        c2=[]
        pe_actions_no_information.slack(mal_path,adv_path,c2)
        os.remove(mal_path)
        os.rename(adv_path,mal_path)
    else:

        c2=add_data[1]
        pe_actions_no_information.slack(mal_path,adv_path,c2)
        os.remove(mal_path)
        os.rename(adv_path,mal_path)



    if y[2]==0:
        c3=[]
        pe_actions_no_information.section_add(mal_path,adv_path,c3)
        os.remove(mal_path)
        os.rename(adv_path,mal_path)
    else:
        k=y[2]*times[2]
        c3_index=0
        for u in range(math.ceil(k)):
            c3_index=c3_index+op_len[2][times[2]-u-1]
        c3=add_data[2][-(c3_index):]
        pe_actions_no_information.section_add(mal_path,adv_path,c3)
        os.remove(mal_path)
        os.rename(adv_path,mal_path)

    if y[3]==0:
        c4=[]
        pe_actions_no_information.padding(mal_path,adv_path,c4)
        os.remove(mal_path)
        os.rename(adv_path,mal_path)
    else:

        k=y[3]*times[3]
        c4_index=0
        for u in range(math.ceil(k)):
            c4_index=c4_index+op_len[3][times[3]-u-1]
        c4=add_data[3][-(c4_index):]
        pe_actions_no_information.padding(mal_path,adv_path,c4)
        os.remove(mal_path)
        os.rename(adv_path,mal_path)
        # c4=add_data[3][-int(y[3]*data_len[3]):]


    os.rename(mal_path,adv_path)
    os.rename(copy_path,mal_path)




def reduction(mal_path,adv_path,attack_model,add_data,add_data_len,times,step1_query,op_len,max_query,
            ben_flag,pre_adv_copy_path):
    w=[1,1,1,1]
    for i in range(len(times)):
        if times[i]==0:
            w[i]=0
    for i in range(len(times)):
        # if step1_query>max_query:
        #     print('pre_reduction 达到最大查询次数，退出')
        #     return add_data,add_data_len,times,step1_query,ben_flag

        if i==0 or i==1:
            if times[i]==0:
                w[i]=w[i]
            else:
                step1_query+=1
                w[i]=0
                print(f'削减第{i}个操作,设置为0,此时输入的w为{w}')
                do_actions(mal_path,adv_path,w,add_data_len,add_data,times,op_len)
                print(models.predit_label(attack_model,adv_path))
                if models.predit_label(attack_model,adv_path)[1]:
                    w[i]=1
                    os.remove(adv_path)
                else:
                    shutil.copy2(adv_path,pre_adv_copy_path)
                    os.remove(adv_path)
                    times[i]=0
                    add_data[i]=[]
                    add_data_len[i]=0
                    op_len[i]=[]
                    ben_flag[i]=[]
        else:
            q=times[i]
            if q==0:
                w[i]=w[i]
            else:
                for g in range(0,q):
                    step1_query+=1
                    w[i]=g/times[i]
                    print(f'削减第{i}个操作，设置为原来的{g/times[i]},此时输入的w为{w}')
                    do_actions(mal_path,adv_path,w,add_data_len,add_data,times,op_len)
                    print(models.predit_label(attack_model,adv_path))
                    if models.predit_label(attack_model,adv_path)[1]:
                        w[i]=1
                        os.remove(adv_path)
                    else:
                        shutil.copy2(adv_path,pre_adv_copy_path)
                        os.remove(adv_path)
                        times[i]=g
                        if g==0:
                            add_data[i]=[]
                            add_data_len[i]=0
                            op_len[i]=[]
                            ben_flag[i]=[]
                        else:
                            op_len[i]=op_len[i][-g:]
                            index=sum(op_len[i])
                            ben_flag[i]=ben_flag[i][-g:]
                            add_data[i]=add_data[i][-(index):]
                            add_data_len[i]=index
                        break
    return add_data,add_data_len,times,step1_query,ben_flag   

# tset pre_reduction.py

# if __name__ == "__main__":
    # MALCONV_MODEL_PATH = 'detector/malware_evasion_competition/models/malconv/malconv.checkpoint'
    # attack_model = models.MalConvModel(MALCONV_MODEL_PATH, thresh=0.5)
    # content_len=100*1024
    # choices = ['header_modify', 'slack', 'section_add', 'padding', 'header_extend','code_cave']
    # weights = [1, 1, 1, 1,1,1]
    # mal_dir='mal_small'
    # ben_dir='benign_all_correct'
    # mal_list=os.listdir(mal_dir)
    # all=0
    # success=0
    # data_to_save=[]
    # data_to_save2=[]
    # for mal in mal_list:
    #     add_data=[[],[],[],[],[],[]]
    #     add_data_len=[0,0,0,0,0,0]
    #     time=[0,0,0,0,0,0]
    #     all+=1
    #     mal_path=os.path.join(mal_dir,mal)
    #     mal_path=os.path.normpath(mal_path)
    #     mal_adv=mal.split('.')[0]+'_adv.exe'
    #     adv_path=os.path.join(mal_dir,mal_adv)
    #     adv_path=os.path.normpath(adv_path)
    #     flag,add_data,add_data_len,time,query=step1.mal_to_adv(mal_path,adv_path,attack_model,ben_dir,choices,weights,add_data,add_data_len,time,0,content_len)
    #     if flag:
    #         success=success+1
    #         os.remove(adv_path)
    #         step1.add_data_to_list(data_to_save,mal,add_data,add_data_len,time)
    #         print(f'{mal}成功生成对抗样本')
    #         print(time)
    #         print(add_data_len)

    #         print('——————————————————————')
    #         add_data,add_data_len,time,query=reduction(mal_path,adv_path,attack_model,add_data,add_data_len,time,query,content_len)
    #         step2_v3.do_actions(mal_path,adv_path,[1,1,1,1,1,1],add_data_len,add_data,time,content_len)
    #         print(models.predit_label(attack_model,adv_path))
    #         print(f'{mal}成功缩减对抗样本')
    #         print(time)
    #         print(add_data_len)
    #         step1.add_data_to_list(data_to_save2,mal,add_data,add_data_len,time)

    # print(f'共{all}个样本，成功生成{success}个对抗样本')
    # step1.save_data_to_json(data_to_save,'6_100k_data.json')
    # print("数据已成功保存到 6_100k_data.json")
    # step1.save_data_to_json(data_to_save2,'6_100k_data2.json')
    # print("数据已成功保存到 6_100k_data2.json")


# if __name__ == "__main__":
#     MALCONV_MODEL_PATH = 'detector/malware_evasion_competition/models/malconv/malconv.checkpoint'
#     attack_model = models.MalConvModel(MALCONV_MODEL_PATH, thresh=0.5)
#     content_len=100*1024
#     choices = ['header_modify', 'slack', 'section_add', 'padding', 'header_extend','code_cave']
#     weights = [1, 1, 1, 1,1,1]

#     mal_path='mal_small/VirusShare_de3e1267108e0fd57cdb8dd142125183.exe'
#     mal='VirusShare_de3e1267108e0fd57cdb8dd142125183.exe'
#     adv_path='mal_small/VirusShare_de3e1267108e0fd57cdb8dd142125183_adv.exe'
#     print(models.predit_label(attack_model,mal_path))
#     data=step2.get_content_from_json('data.json')
#     mal_name=[]
#     for item in data:
#         mal_name.append(item['filename'])
#     add_data=data[mal_name.index(mal)]['add_data']
#     add_data_len=data[mal_name.index(mal)]['add_data_len']
#     time=data[mal_name.index(mal)]['time']
#     add_data.append([])
#     add_data_len.append(0)
#     time.append(0)
#     print(add_data_len)
#     print(time)

#     query=0
#     add_data,add_data_len,time,query=reduction(mal_path,adv_path,attack_model,add_data,add_data_len,time,query,content_len)
#     print(f'{mal}成功缩减对抗样本')

#     print(add_data[2])
#     print(add_data[3])
#     print(add_data_len)
#     x=[1,1,1,1,1,1]
#     step2.do_actions(mal_path,adv_path,x,add_data_len,add_data,time,content_len)
#     print(models.predit_label(attack_model,adv_path))

    # print(f'共{all}个样本，成功生成{success}个对抗样本')
    # step1.save_data_to_json(data_to_save,'6_100k_data.json')
    # print("数据已成功保存到 6_100k_data.json")