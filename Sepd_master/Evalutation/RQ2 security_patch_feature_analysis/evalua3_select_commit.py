# -*- coding: utf-8 -*-

import os.path
import random
import sys

from helpers.assistant import utility_helper
from insertlist import cve_info
import  configuration as config
import evalua1_remove_comments,evalua2_normalization
# CVE_SOURCE_PATH = "./source1012/" #需要对3个sourcecode文件夹进行扫描 12 22

def select_astcommit():
    #1.读取cve相关数据
    nvd_results_lists = cve_info.query_ori_equ_commit()
    flag_index=0
    for CVE_ID,Original_commit,Equal_commit,Owner,Repo_name,Branch in nvd_results_lists:
        YEAR = CVE_ID.split("-")[1]
        if CVE_ID!="CVE-2018-10972" and flag_index==0:
            continue
        flag_index=1
        CVE_EXCLUDE_LISTS =["CVE-2012-4436","CVE-2015-5706","CVE-2017-11808","CVE-2018-10887","CVE-2018-10972"] # 这些文件处理时间较长，直接去掉
        if CVE_ID in CVE_EXCLUDE_LISTS:
            continue

        print ("ast" + CVE_ID)
        if Original_commit!="False":
            CVE_PATH1 = os.path.join(CVE_SOURCE_PATH,YEAR,CVE_ID,Owner+"%"+Repo_name,Branch,Original_commit+"_patch","equal_file_patch")
        else:

            CVE_PATH1 = os.path.join(CVE_SOURCE_PATH, YEAR, CVE_ID, Owner + "%" + Repo_name, Branch,
                                     Equal_commit + "_patch", "equal_file_patch")
        if os.path.exists(CVE_PATH1)!=True: #保证当前sourcecode中存在该CVE_ID
            continue
        after_commit_lists = os.listdir(CVE_PATH1)
        random.shuffle(after_commit_lists)
        aftercommit_count = 0
        for  after_commit_list in after_commit_lists:
            if ".patch" not in after_commit_list:
                continue

            CVE_AST_PATH = os.path.join(CVE_PATH1,after_commit_list[:4]+"_var")
            ast_commit_lists = os.listdir(CVE_AST_PATH)
            random.shuffle(ast_commit_lists)
            ast_count = 0
            for ast_commit_list in ast_commit_lists:
                AST_PATH = CVE_AST_PATH+"/"+ast_commit_list

                if Original_commit!="False":
                    AST_SAVE_PATH = config.RQ4_EVALU_PATH+"/NVD+AST/"+str(CVE_ID)+"/"+str(Original_commit)+"/AST/"
                    AST_Normalize_path = config.RQ4_EVALU_PATH + "NVD+AST/" + str(CVE_ID) + "/" + str(Original_commit) + "/AST_nor/"
                    LABEL_path = config.RQ4_EVALU_PATH + "/NVD+AST/" + str(CVE_ID) + "/" + str(Original_commit) + "/LABEL/"
                else:
                    AST_SAVE_PATH = config.RQ4_EVALU_PATH + "/NVD+AST/" + str(CVE_ID) + "/" + str(Equal_commit)+"/AST/"
                    AST_Normalize_path = config.RQ4_EVALU_PATH + "NVD+AST/" + str(CVE_ID) + "/" + str(Equal_commit) + "/AST_nor/"
                    LABEL_path = config.RQ4_EVALU_PATH + "/NVD+AST/" + str(CVE_ID) + "/" + str(Equal_commit) + "/LABEL/"

                if os.path.exists(AST_SAVE_PATH)!=True:
                    os.makedirs(AST_SAVE_PATH)
                if os.path.exists(LABEL_path)!=True:
                    os.makedirs(LABEL_path)
                command_string = "cp -f " + AST_PATH + " " + AST_SAVE_PATH
                helper_zz.command(command_string)
                #消除注释

                if os.path.exists(AST_Normalize_path)!=True:
                    os.makedirs(AST_Normalize_path)
                AST_content = helper_zz.read_file_content(AST_PATH)
                if len(AST_content)>5000:
                    continue
                AST_Normalize_path = AST_Normalize_path + "nor_" + ast_commit_list
                LABEL_path = LABEL_path +  "nor_" + ast_commit_list

                evalua1_remove_comments.comments_Eliminate(AST_content,AST_Normalize_path)
                #归一化
                AST_Elimanate_content = helper_zz.read_file_content(AST_Normalize_path)
                #消除diff、@@
                AST_Elimanate_content = helper_zz.delete_diff(AST_Elimanate_content)
                AST_Elimanate_content = helper_zz.delete_hunk(AST_Elimanate_content)

                nor_results = evalua2_normalization.mapping(AST_Elimanate_content)

                helper_zz.write_file_content(AST_Normalize_path,nor_results)
                #保存标签文件
                helper_zz.write_file_content(LABEL_path, nor_results)

                ast_count = ast_count + 1
                if ast_count==2:
                    break
            aftercommit_count= aftercommit_count+ 1
            if aftercommit_count==1:
                break

        # CVE_YEAR_PATH = os.path.join(CVE_SOURCE_PATH,YEAR,CVE_ID)
        # for Repo_list in os.listdir(CVE_YEAR_PATH):
        #     CVE_REPO_PATH = os.path.join(CVE_YEAR_PATH,Repo_list)
        #     for Branch in os.listdir(CVE_REPO_PATH):

        print(CVE_ID)
    return

def select_aftercommit():
    #1.读取cve相关数据
    nvd_results_lists = cve_info.query_ori_equ_commit() # 这里的cve数据不需要区分branch，只区分commit
    commit_lists = []
    cve_scand_lists = []
    for CVE_ID,Original_commit,Equal_commit,Owner,Repo_name,Branch in nvd_results_lists:
        YEAR = CVE_ID.split("-")[1]
        print ("after" + CVE_ID)
        if  (Original_commit in commit_lists or Equal_commit in commit_lists) and (CVE_ID in cve_scand_lists ):
            continue
        else:
            if Original_commit!="False":
                commit_lists.append(Original_commit)
                cve_scand_lists.append(CVE_ID)
            else:
                commit_lists.append(Equal_commit)
                cve_scand_lists.append(CVE_ID)
        if Original_commit!="False": #fixme CVE_SOURCODE_PATH 需要更改路径分别对不同的sourcode文件夹进行扫描
            CVE_PATH1 = os.path.join(CVE_SOURCE_PATH,YEAR,CVE_ID,Owner+"%"+Repo_name,Branch,Original_commit+"_patch","equal_file_patch")
        else:
            CVE_PATH1 = os.path.join(CVE_SOURCE_PATH, YEAR, CVE_ID, Owner + "%" + Repo_name, Branch,
                                     Equal_commit + "_patch", "equal_file_patch")
        if os.path.exists(CVE_PATH1)!=True: #保证当前sourcecode中存在该CVE_ID
            continue
        after_commit_lists = os.listdir(CVE_PATH1)
        random.shuffle(after_commit_lists)
        aftercommit_count = 0
        for after_commit_list in after_commit_lists:
            if ".patch" not in after_commit_list:
                continue
            if aftercommit_count==2:
                break
            AFTERCOMMIT_PATH  = os.path.join(CVE_PATH1,after_commit_list)
            if Original_commit!="False":
                AFTER_SAVE_PATH = config.RQ4_EVALU_PATH+"/NVD+AFTER/"+str(CVE_ID)+"/"+str(Original_commit)+"/AFTER/"
                AFTER_Normalize_path = config.RQ4_EVALU_PATH + "NVD+AFTER/" + str(CVE_ID) + "/" + str(Original_commit) + "/AFTER_nor/"
                LABEL_path = config.RQ4_EVALU_PATH+"/NVD+AFTER/"+str(CVE_ID)+"/"+str(Original_commit)+"/LABEL/"
            else:
                AFTER_SAVE_PATH = config.RQ4_EVALU_PATH + "/NVD+AFTER/" + str(CVE_ID) + "/" + str(Equal_commit)+"/AFTER/"
                AFTER_Normalize_path = config.RQ4_EVALU_PATH + "NVD+AFTER/" + str(CVE_ID) + "/" + str(Equal_commit) + "/AFTER_nor/"
                LABEL_path = config.RQ4_EVALU_PATH + "/NVD+AFTER/" + str(CVE_ID) + "/" + str(Equal_commit) + "/LABEL/"

            if os.path.exists(AFTER_SAVE_PATH)!=True:
                os.makedirs(AFTER_SAVE_PATH)
            if os.path.exists(LABEL_path) != True:
                os.makedirs(LABEL_path)
            command_string = "cp -f " + AFTERCOMMIT_PATH + " " + AFTER_SAVE_PATH
            helper_zz.command(command_string)

            #消除注释

            if os.path.exists(AFTER_Normalize_path)!=True:
                os.makedirs(AFTER_Normalize_path)
            AFTER_content = helper_zz.read_file_content(AFTERCOMMIT_PATH)
            if len(AFTER_content)>10000:
                continue
            AFTER_Normalize_path = AFTER_Normalize_path + "nor_" + after_commit_list
            LABEL_path = LABEL_path + "nor_" + after_commit_list

            evalua1_remove_comments.comments_Eliminate(AFTER_content,AFTER_Normalize_path)
            # 归一化
            AFTER_Elimanate_content = helper_zz.read_file_content(AFTER_Normalize_path)
            #消除diff、@@
            AFTER_Elimanate_content = helper_zz.delete_diff(AFTER_Elimanate_content)
            AFTER_Elimanate_content = helper_zz.delete_hunk(AFTER_Elimanate_content)
            nor_results = evalua2_normalization.mapping(AFTER_Elimanate_content)

            helper_zz.write_file_content(AFTER_Normalize_path,nor_results)
            #保存标签文件
            helper_zz.write_file_content(LABEL_path, nor_results)

            aftercommit_count = aftercommit_count+ 1

    return

def select_original_commit(flag=1): #有的文件的nvd为空是因为patch_file=0

    nvd_results_lists = cve_info.query_ori_equ_commit()  # 这里的cve数据不需要区分branch，只区分commit
    # flag = 2 # 1表示after 2表示ast
    for CVE_ID, Original_commit, Equal_commit, Owner, Repo_name, Branch in nvd_results_lists:
        YEAR = CVE_ID.split("-")[1]
        print ("original" + CVE_ID)
        original_commit_path = config.SECURITY_PATCH_PATH % str(CVE_ID)
        if os.path.exists(original_commit_path)!=True or Original_commit=="False":# 这里保证都是对oriinal的数据进行保存
            continue
        original_commit_lists = os.listdir(original_commit_path)
        for original_commit_list in original_commit_lists:
            if Original_commit in original_commit_list or original_commit_list in Original_commit: #存在交集才进行复制操作
                if flag==1:
                    original_commit_save_path = config.RQ4_EVALU_PATH+"/NVD+AFTER/"+str(CVE_ID)+"/"+str(Original_commit)+"/NVD/"
                    original_Normalize_path = config.RQ4_EVALU_PATH+"/NVD+AFTER/"+str(CVE_ID)+"/"+str(Original_commit)+"/NVD_nor/"
                    LABEL_path = config.RQ4_EVALU_PATH+"/NVD+AFTER/"+str(CVE_ID)+"/"+str(Original_commit)+"/LABEL/"
                else:
                    original_commit_save_path = config.RQ4_EVALU_PATH + "/NVD+AST/" + str(CVE_ID) + "/" + str(Original_commit) + "/NVD/"
                    original_Normalize_path = config.RQ4_EVALU_PATH + "/NVD+AST/" + str(CVE_ID) + "/" + str(Original_commit) + "/NVD_nor/"
                    LABEL_path = config.RQ4_EVALU_PATH + "/NVD+AST/" + str(CVE_ID) + "/" + str(Original_commit) + "/LABEL/"
                if os.path.exists(original_commit_save_path)!=True:
                    os.makedirs(original_commit_save_path)
                if os.path.exists(original_Normalize_path)!=True:
                    os.makedirs(original_Normalize_path)
                if os.path.exists(LABEL_path)!=True:
                    os.makedirs(LABEL_path)
                command_string = "cp -f "+os.path.join(original_commit_path,original_commit_list)+" " +original_commit_save_path
                helper_zz.command(command_string)

                # 消除注释

                Original_content = helper_zz.read_file_content(os.path.join(original_commit_path,original_commit_list))
                if len(Original_content)>10000:
                    continue
                original_Normalize_path = original_Normalize_path + "nor_" + original_commit_list
                LABEL_path = LABEL_path + "nor_" + original_commit_list
                # evalua1_remove_comments.comments_Eliminate(Original_content, original_Normalize_path)
                # 归一化
                # Original_Elimanate_content = helper_zz.read_file_content(original_Normalize_path)
                # 消除diff、@@
                Original_Elimanate_content = helper_zz.delete_diff(Original_content)
                Original_Elimanate_content = helper_zz.delete_hunk(Original_Elimanate_content)
                nor_results = evalua2_normalization.mapping(Original_Elimanate_content)

                helper_zz.write_file_content(original_Normalize_path, nor_results)
                #保存标签文件
                helper_zz.write_file_content(LABEL_path, nor_results)

    return

def select_equal_commit(flag=1):#有的文件的nvd为空是因为patch_file=0
    nvd_results_lists = cve_info.query_ori_equ_commit()  # 这里的cve数据不需要区分branch，只区分commit
    # flag = 2 # 1表示after 2表示ast
    for CVE_ID, Original_commit, Equal_commit, Owner, Repo_name, Branch in nvd_results_lists:
        YEAR = CVE_ID.split("-")[1]
        print ("Equal"+CVE_ID)
        equal_commit_path = config.SAVE_EQUALCOMMIT_PATH % (str(YEAR),str(CVE_ID))
        if os.path.exists(equal_commit_path)!=True or Equal_commit=="False":# 这里保证都是对oriinal的数据进行保存
            continue
        original_commit_lists = os.listdir(equal_commit_path)
        for equal_commit_list in original_commit_lists:
            if Equal_commit in equal_commit_list or equal_commit_list in Equal_commit : #存在交集才进行复制操作
                if flag==1: # AFTER
                    equal_commit_save_path = config.RQ4_EVALU_PATH+"/NVD+AFTER/"+str(CVE_ID)+"/"+str(Equal_commit)+"/NVD/"
                    equal_Normalize_path = config.RQ4_EVALU_PATH + "/NVD+AFTER/" + str(CVE_ID) + "/" + str(Equal_commit) + "/NVD_nor/"
                    LABEL_path = config.RQ4_EVALU_PATH + "/NVD+AFTER/" + str(CVE_ID) + "/" + str(Equal_commit) + "/LABEL/"
                else: # AST
                    equal_commit_save_path = config.RQ4_EVALU_PATH + "/NVD+AST/" + str(CVE_ID) + "/" + str(Equal_commit) + "/NVD/"
                    equal_Normalize_path = config.RQ4_EVALU_PATH + "/NVD+AST/" + str(CVE_ID) + "/" + str(Equal_commit) + "/NVD_nor/"
                    LABEL_path =  config.RQ4_EVALU_PATH + "/NVD+AST/" + str(CVE_ID) + "/" + str(Equal_commit) + "/LABEL/"
                # 创建不存在的文件夹
                if os.path.exists(equal_commit_save_path)!=True:
                    os.makedirs(equal_commit_save_path)
                if os.path.exists(equal_Normalize_path) != True:
                    os.makedirs(equal_Normalize_path)
                if os.path.exists(LABEL_path)!=True:
                    os.makedirs(LABEL_path)
                # 复制
                command_string = "cp -f "+os.path.join(equal_commit_path,equal_commit_list)+" " +equal_commit_save_path
                helper_zz.command(command_string)

                # 消除注释

                Equal_content = helper_zz.read_file_content(os.path.join(equal_commit_path, equal_commit_list))
                if len(Equal_content)>5000:
                    continue
                equal_Normalize_path = equal_Normalize_path + "nor_" + equal_commit_list
                LABEL_path = LABEL_path +"nor_" + equal_commit_list
                # evalua1_remove_comments.comments_Eliminate(Equal_content, equal_Normalize_path)
                # 归一化
                # Equal_Elimanate_content = helper_zz.read_file_content(equal_Normalize_path)
                # 消除diff、@@
                Equal_Elimanate_content = helper_zz.delete_diff(Equal_content) # 消除diff
                Equal_Elimanate_content = helper_zz.delete_hunk(Equal_Elimanate_content) #
                nor_results = evalua2_normalization.mapping(Equal_Elimanate_content)

                helper_zz.write_file_content(equal_Normalize_path, nor_results)
                #标签文件
                helper_zz.write_file_content(LABEL_path, nor_results)

    return


def select_evaludataset():
    return

def select_ast_and_after_commit():
    CVE_SOURCE_PATH_LISTS = ["./sourcecode1022/","./source1012/","./sourcecode0212/"]  # 需要对3个sourcecode文件夹进行扫描 12 22
    for CVE_SOURCE_PATH_LIST in CVE_SOURCE_PATH_LISTS:
        global CVE_SOURCE_PATH
        CVE_SOURCE_PATH = CVE_SOURCE_PATH_LIST
        #select ast commit
        select_astcommit()
        # select after commit
        # select_aftercommit()

def select_nvd_commit():
    flag_lists = [1,2] # 1：after文件夹 2：ast文件夹
    for flag_list in flag_lists:
        select_original_commit(flag=flag_list)
        select_equal_commit(flag = flag_list)
    return


# 选择PatchRNN的训练数据集 # NVD original、NVD equal、AST、After
def Select_PatchRNN_data(Switch_Flag=None):
    # 首先定义存储路径
    RNNPATCH_SAVE_PATH = config.Patch_Save_Path # 实验数据的存储路径
    if os.path.exists(RNNPATCH_SAVE_PATH)!=True:
        os.makedirs(RNNPATCH_SAVE_PATH)
    # 1. 选择1份Original nvd
    if Switch_Flag==1:
        nvd_result_lists = cve_info.query_ori_equ_commit() # 这里的cve数据不需要区分branch，只区分commit
        for CVE_ID,Original_commit,Equal_commit,Owner,Repo_name,Branch in nvd_result_lists:
            YEAR = CVE_ID.split("-")[1]
            original_commit_path = config.SECURITY_PATCH_PATH % str(CVE_ID)
            if os.path.exists(original_commit_path)!=True or Original_commit=="False":# 这里保证都是对original的数据进行处理的
                continue
            original_commit_lists = os.listdir(original_commit_path)
            for original_commit_list in original_commit_lists:
                if Original_commit in original_commit_list or original_commit_list in Original_commit:
                    original_commit_save_path = RNNPATCH_SAVE_PATH + "/NVD_ori/"+str(CVE_ID)+"/"
                    if os.path.exists(original_commit_save_path)!=True:
                        os.makedirs(original_commit_save_path)

                    # 复制补丁
                    command_string = "cp -f "+os.path.join(original_commit_path,original_commit_list)+" " +original_commit_save_path
                    helper_zz.command(command_string)
                else:
                    continue

    # 2. 选择euqal nvd
    if Switch_Flag==2:
        nvd_result_lists = cve_info.query_ori_equ_commit()  # 这里的cve数据不需要区分branch，只区分commit
        for CVE_ID ,Original_commit,Equal_commit,Owner,Repo_name,Branch in nvd_result_lists:
            YEAR = CVE_ID.split("-")[1]
            equal_commit_path = config.SAVE_EQUALCOMMIT_PATH % (str(YEAR),str(CVE_ID)) # fixme 后续需要寻找 这里的equal commit是从哪里创建并移动的
            if os.path.exists(equal_commit_path)!=True or Equal_commit==False:
                continue
            original_commit_lists = os.listdir(equal_commit_path)
            for equal_commit_list in original_commit_lists:
                if Equal_commit in equal_commit_list or equal_commit_list in Equal_commit:#两个字段存在交集才进行移动
                    # 定义路径
                    equal_commit_save_path = RNNPATCH_SAVE_PATH + "/NVD_equal/"+str(CVE_ID)+"/"
                    # 创建不存在的文件夹
                    if os.path.exists(equal_commit_save_path)!=True:
                        os.makedirs(equal_commit_save_path)

                    # 复制补丁
                    command_string = "cp -f "+os.path.join(equal_commit_path,equal_commit_list)+" " +equal_commit_save_path
                    helper_zz.command(command_string)

                else:
                    continue

    # todo 注意 ast 和 after都需要对不同的sourcecode文件夹进行扫描
    # 3. 选择1份其中ast
    CVE_SOURCE_PATH_LISTS = ["./sourcecode1022/", "./source1012/", "./sourcecode0212/"]  # 需要对3个sourcecode文件夹进行扫描 12 22
    if Switch_Flag==3:
        for AST_CVE_SOURCE_PATH in CVE_SOURCE_PATH_LISTS:
            print(AST_CVE_SOURCE_PATH)
            nvd_results_lists = cve_info.query_ori_equ_commit()
            flag_index=0
            for CVE_ID,Original_commit,Equal_commit,Owner,Repo_name,Branch in nvd_results_lists:
                YEAR = CVE_ID.split("-")[1]
                if CVE_ID!="CVE-2018-10972" and flag_index==0:
                    continue
                flag_index=1
                CVE_EXCLUDE_LISTS =["CVE-2012-4436","CVE-2015-5706","CVE-2017-11808","CVE-2018-10887","CVE-2018-10972"] # 这些文件处理时间较长，直接去掉
                if CVE_ID in CVE_EXCLUDE_LISTS:
                    continue

                print ("ast" + CVE_ID)
                if Original_commit!="False":
                    CVE_PATH1 = os.path.join(AST_CVE_SOURCE_PATH,YEAR,CVE_ID,Owner+"%"+Repo_name,Branch,Original_commit+"_patch","equal_file_patch")
                else:
                    CVE_PATH1 = os.path.join(AST_CVE_SOURCE_PATH, YEAR, CVE_ID, Owner + "%" + Repo_name, Branch,Equal_commit + "_patch", "equal_file_patch")
                if os.path.exists(CVE_PATH1)!=True: #保证当前sourcecode中存在该CVE_ID
                    continue
                after_commit_lists = os.listdir(CVE_PATH1)
                random.shuffle(after_commit_lists)
                aftercommit_count = 0 # 控制选择after commit的个数
                for  after_commit_list in after_commit_lists:
                    if ".patch" not in after_commit_list:
                        continue

                    CVE_AST_PATH = os.path.join(CVE_PATH1,after_commit_list[:4]+"_var")
                    after_commit_lists = os.listdir(CVE_AST_PATH)
                    random.shuffle(after_commit_lists)
                    ast_count = 0
                    for after_commit_list in after_commit_lists:
                        AST_PATH = CVE_AST_PATH+"/"+after_commit_list

                        if Original_commit!="False": #original
                            AST_SAVE_PATH = RNNPATCH_SAVE_PATH+"/AST/"+str(CVE_ID)+"/"
                        else: #equal
                            AST_SAVE_PATH = RNNPATCH_SAVE_PATH + "/AST/" + str(CVE_ID) + "/"

                        # 创建空文件夹
                        if os.path.exists(AST_SAVE_PATH)!=True:
                            os.makedirs(AST_SAVE_PATH)

                        AST_content = helper_zz.read_file_content(AST_PATH)
                        if len(AST_content) > 2000:
                            continue
                        # 复制文件
                        command_string = "cp -f " + AST_PATH + " " + AST_SAVE_PATH
                        helper_zz.command(command_string)

                        ast_count = ast_count + 1 # 保证ast只选择一个
                        if ast_count==1:
                            break
                    aftercommit_count = aftercommit_count+ 1 #控制选择after commit的个数
                    if aftercommit_count==1: # 只选择一个after commit
                        break


                # CVE_YEAR_PATH = os.path.join(CVE_SOURCE_PATH,YEAR,CVE_ID)
                # for Repo_list in os.listdir(CVE_YEAR_PATH):
                #     CVE_REPO_PATH = os.path.join(CVE_YEAR_PATH,Repo_list)
                #     for Branch in os.listdir(CVE_REPO_PATH):

                print(CVE_ID)
    # 4. 选择 after
    if Switch_Flag==4:
        for After_CVE_SOURCE_PATH in CVE_SOURCE_PATH_LISTS:
            # 1.读取cve相关数据
            nvd_results_lists = cve_info.query_ori_equ_commit()  # 这里的cve数据不需要区分branch，只区分commit
            commit_lists = []
            cve_scand_lists = []
            for CVE_ID, Original_commit, Equal_commit, Owner, Repo_name, Branch in nvd_results_lists:
                YEAR = CVE_ID.split("-")[1]
                print ("after" + CVE_ID)
                if (Original_commit in commit_lists or Equal_commit in commit_lists) and (CVE_ID in cve_scand_lists):
                    continue
                else:
                    if Original_commit != "False":
                        commit_lists.append(Original_commit)
                        cve_scand_lists.append(CVE_ID)
                    else:
                        commit_lists.append(Equal_commit)
                        cve_scand_lists.append(CVE_ID)
                if Original_commit != "False":  # fixme CVE_SOURCODE_PATH 需要更改路径分别对不同的sourcode文件夹进行扫描
                    CVE_PATH1 = os.path.join(After_CVE_SOURCE_PATH, YEAR, CVE_ID, Owner + "%" + Repo_name, Branch,
                                             Original_commit + "_patch", "equal_file_patch")
                else:
                    CVE_PATH1 = os.path.join(After_CVE_SOURCE_PATH, YEAR, CVE_ID, Owner + "%" + Repo_name, Branch,
                                             Equal_commit + "_patch", "equal_file_patch")
                if os.path.exists(CVE_PATH1) != True:  # 保证当前sourcecode中存在该CVE_ID
                    continue
                after_commit_lists = os.listdir(CVE_PATH1)
                random.shuffle(after_commit_lists) # 保证随机选择after commit
                aftercommit_count = 0
                for after_commit_list in after_commit_lists:
                    if ".patch" not in after_commit_list:
                        continue

                    AFTERCOMMIT_PATH = os.path.join(CVE_PATH1, after_commit_list)
                    if Original_commit != "False":
                        AFTER_SAVE_PATH = RNNPATCH_SAVE_PATH + "/AFTER/" + str(CVE_ID) + "/"
                    else:
                        AFTER_SAVE_PATH = RNNPATCH_SAVE_PATH + "/AFTER/" + str(CVE_ID) + "/"
                    # 创建空文件夹
                    if os.path.exists(AFTER_SAVE_PATH) != True:
                        os.makedirs(AFTER_SAVE_PATH)

                    After_content = helper_zz.read_file_content(AFTERCOMMIT_PATH)
                    if len(After_content) > 2000:
                        continue

                    # 复制
                    command_string = "cp -f " + AFTERCOMMIT_PATH + " " + AFTER_SAVE_PATH
                    helper_zz.command(command_string)

                    aftercommit_count = aftercommit_count + 1
                    if aftercommit_count==1: # 只选择一个after commit
                        break

    return 0


# if __name__ == '__main__': # 这个函数是用来对双向孪生网络进行整理数据集的
#     # select_aftercommit() #需要对不同的sourcode文件夹进行扫描
#     # select_original_commit()
#     # select_equal_commit()
#     flag = 1
#     if flag==1:
#         select_ast_and_after_commit()
#     else:
#         select_nvd_commit()

if __name__ == '__main__':
    Switch_Flag=1 #1.Original  2.Equal 3.AST  4.After
    Select_PatchRNN_data(Switch_Flag)
