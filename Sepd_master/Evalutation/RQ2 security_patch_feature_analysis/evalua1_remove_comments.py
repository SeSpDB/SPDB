# -*- coding: utf-8 -*-
#!/usr/bin/env python
import os
from os import path
from multiprocessing import Process
import  configuration as config
from helpers import helper_zz
def comments_Eliminate(patch_file_content, target_file_path):#删除注释并保存文件

    f2 = open(target_file_path, "w+")  # 写向目标文件
    flag = 0  # 标记位，标记是否进入多行注释/* */
    for code in patch_file_content:

        length = len(code)  # 每行字符数
        for i in range(length):
            # 单行注释//
            # if i+1 >=len(code):
            #      continue
            try:
                if flag == 0 and code[i] == '/' and code[i + 1] == '/':
                    f2.write("\n")
                    break
                # 多行注释/* .....  */
                elif flag == 0 and code[i] == '/' and code[i + 1] == '*':
                    flag = 1
                elif flag == 1 and code[i] == '*' and code[i + 1] == '/':
                    flag = 0
                    break
                elif flag == 1:
                    continue
                elif flag == 0:
                    f2.write(code[i])
            except Exception as e:
                break
    f2.close()
    print("Success")

def comments_Elimanate2(patch_file_content): #用于返回消除注释的结果

    return_result_lists = []
    flag = 0  # 标记位，标记是否进入多行注释/* */
    for code in patch_file_content:

        length = len(code)  # 每行字符数
        for i in range(length):
            # 单行注释//
            if flag == 0 and code[i] == '/' and code[i + 1] == '/':
                return_result_lists.append("\n")
                break
            # 多行注释/* .....  */
            elif flag == 0 and code[i] == '/' and code[i + 1] == '*':
                flag = 1
            elif flag == 1 and code[i] == '*' and code[i + 1] == '/':
                flag = 0
                break
            elif flag == 1:
                continue
            elif flag == 0:
                return_result_lists.append(code[i])
    print("Success")
    return return_result_lists

def move_decompile(decompilepath=None,save_path=None):

    decompilepath = config.DECOMPILE_PATH
    save_path = config.DECOMPILE_EVALU_PATH

    if decompilepath==None or save_path==None:
        return

    for year_list in os.listdir(decompilepath):
        cve_path = decompilepath  + year_list
        if os.path.isdir(cve_path)!=True:
            continue
        for cve_list in os.listdir(cve_path):
            repo_path = os.path.join(cve_path,cve_list)
            for repo_list in os.listdir(repo_path):
                branch_path = os.path.join(repo_path,repo_list)
                for branch_list in os.listdir(branch_path):
                    originalcommit_path = os.path.join(branch_path,branch_list)
                    for originalcommit_list in os.listdir(originalcommit_path):
                        aftercommit_path = os.path.join(originalcommit_path,originalcommit_list)
                        for aftercommit_list in os.listdir(aftercommit_path):
                            de_commit_savepath = os.path.join(aftercommit_path,aftercommit_list)
                            de_commit_savepath = de_commit_savepath +"/output/"
                            if os.path.exists(de_commit_savepath)!=True:
                                continue
                            #路径存在则保存补丁

                            for de_output_list in os.listdir(de_commit_savepath):
                                if ".patch" not in de_output_list or "decompile" not in de_output_list:
                                    continue
                                de_evalu_path = os.path.join(save_path, cve_list, originalcommit_list, aftercommit_list)
                                #删除无关函数与注释
                                with open(de_commit_savepath+"/"+de_output_list,"a+") as f:
                                    commit_file = f.readlines()
                                if os.path.exists(de_evalu_path)!=True:
                                    os.makedirs(de_evalu_path)
                                clean_de_peatch(repo_list = repo_list,original_commit=helper_zz.find_commitid(originalcommit_list),commit_file=commit_file,de_evalu_path = de_evalu_path,aftercommit_list = aftercommit_list)

                                # command_string = "cp -f "+ de_commit_savepath + "/" +de_output_list + " " + de_evalu_path
                                # helper_zz.command(command_string)



def get_diff_func(diff_file_name,function_dic,diff_result):
    patch_file = []#定义一个列表
    flag= 0 #定义 如果遇到不同的行 则赋值为1，表示停止添加新的文件内容
    modify = 0
    for function_name in function_dic[diff_file_name]:#针对原patch的每一个函数
        for diff_line in diff_result:
            if diff_line.startswith("@@") and diff_line.find(function_name) == -1: #find结果返回子串内容
                flag = 1
                continue
            if diff_line.startswith("@@") and diff_line.find(function_name)!= -1:#遇到了相同的函数名，则后续部分都添加 且以@@开头
                modify = 1
                flag = 0
            if flag == 0:
                patch_file.append(diff_line)
    return patch_file,modify

def clean_de_peatch(repo_list = None,original_commit=None,commit_file=None,de_evalu_path=None,aftercommit_list=None):#删除无关函数
    if repo_list==None or original_commit==None or commit_file ==None or de_evalu_path==None or aftercommit_list==None:
        return
    original_repopath = helper_zz.get_repopath(repo_list)
    function_dic = helper_zz.get_commit_functions2(original_repopath,
                                                   original_commit)  # 5.diff文件中的修改范围与补丁文件中的函数行号范围做交集，返回存在交集的文件名-函数名的映射关系
    for filename in function_dic:
        patch_file_content, modify = get_diff_func(filename, function_dic, commit_file)  # 删除无关函数
        # 如果modify为1 表示对该文件进行了修改操作；为0表示没进行修改
        comments_Eliminate(patch_file_content, de_evalu_path+"/"+str(aftercommit_list))
        # if modify == 1:
        #     with open(de_evalu_path  +".patch","a+") as file:  # 新patch file 写入对应路径 a+ because have many filediff
        #         file.writelines(patch_file)

# def remove_decompile_comment_and_save_related_func():


if __name__ == '__main__':
    decompile_path = config.DECOMPILE_PATH
    save_path = config.DECOMPILE_EVALU_PATH
    move_decompile(decompilepath= decompile_path, save_path = save_path)