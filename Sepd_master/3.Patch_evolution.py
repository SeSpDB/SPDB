# -*- coding: UTF-8 -*-
from math import fabs
from random import random
import helpers.assistant  as utility_helper
import helpers.src_parser as src_parser
import sys
import pickle
import copy
import os
import patch_varients
import configuration as config
from collections import Iterable
import random
import subprocess

def extract_cve_details(patch_info, cve_id=None):
    detailed_cve_info = {}
    detailed_cve_info[cve_id] = []
    index_list = []
    with open(patch_info, 'r') as file:
        line_buffer = file.readlines()
    for line in line_buffer:
        if line.startswith("#"):  # Skipping commented lines
            continue
        cve, repo, commit = line[:-1].split(" ")
        index_list = (cve, repo, commit)
        detailed_cve_info[cve].append(index_list)
    return detailed_cve_info


# Original function: compute_file_difference
def compute_file_difference(repo, branch, specific_commit, diff_file_name, func_dictionary, temp_file_name,
                            save_directory=config_settings.SAVE_PATCH_PATH):
    # Setting up paths
    save_directory = save_directory % (global_year, global_cve_id)
    base_path = save_directory + repo + "/" + branch + "/" + specific_commit + "_patch/"
    path_before_commit = base_path + "before_file/"
    path_after_commit = base_path + "after_file/"
    # Validating paths
    if not os.path.exists(save_directory) or not os.path.exists(base_path) or not os.path.exists(path_before_commit) or not os.path.exists(path_after_commit):
        return
    # Reading files in the directory
    files_before = os.listdir(path_before_commit)
    files_after = os.listdir(path_after_commit)
    # Generating patches using git diff
    index = 0
    is_first_commit_flag = 0  # Ensuring only one before commit difference is generated
    for file_before in files_before:
        # Skipping directories
        if os.path.isdir(path_before_commit + file_before):
            continue
        # Extracting file prefix
        file_before_prefix = os.path.splitext(file_before)[0]
        for file_after in files_after:
            index = files_after.index(file_after)
            file_after_prefix = os.path.splitext(file_after)[0]
            # Skipping if file name does not match
            if temp_file_name not in file_before:
                continue
            utility_helper.command("cd " + base_path + ";mkdir equal_file_patch")
            equal_patch_path = base_path + "equal_file_patch/"
            # Creating diff
            diff_command = "git diff " + path_before_commit + file_before + " " + path_after_commit + file_after + " > " + equal_patch_path + file_before_prefix[:4] + "_" + file_after_prefix[:4] + ".patch"
            diff_result = utility_helper.command(diff_command)
            patch_file, is_modified = filter_diff_function(diff_file_name, func_dictionary, diff_result)  # Filtering unrelated functions
            # Check if file is modified
            if is_modified:
                with open(equal_patch_path + file_before_prefix[:4] + "_" + file_after_prefix[:4] + ".patch", "w") as file:
                    file.writelines(patch_file)


def fetch_similar_file_differences(repo, branch, initial_commit, diff_file, func_map, save_directory=config_settings.SAVE_PATCH_PATH):
    save_directory = save_directory % (global_year, global_cve)
    common_directory = save_directory + repo + "/" + branch + "/" + initial_commit + "_patch/"
    before_directory = common_directory + "before_file/"
    after_directory = common_directory + "after_file/"
    temp_diff_file = diff_file.split("/")[-1]
    # Check path validity
    if not os.path.exists(save_directory) or not os.path.exists(common_directory) or not os.path.exists(before_directory) or not os.path.exists(after_directory):
        return
    files_after_commit = os.listdir(after_directory)
    # Loop to generate patch
    for file_after in files_after_commit:
        temp_after_path = after_directory + file_after + "/"
        if not os.path.exists(temp_after_path):
            continue
        # Extract prefix
        file_after_prefix = os.path.splitext(file_after)[0]
        file_before_patch = file_after_prefix[:4] + "_var"
        file_before_prefix = file_after_prefix[:4] + "_" + temp_diff_file.split(".")[0] + "_var"
        file_before_path = temp_after_path + file_before_prefix
        file_before_third = file_after_prefix[:4] + "_var"

        for index in range(6):
            utility_helper.command("cd " + common_directory + ";mkdir equal_file_patch")
            equal_patch_directory = common_directory + "equal_file_patch/" + file_after_prefix[:4] + "_var/"
            if not os.path.exists(equal_patch_directory):
                os.makedirs(equal_patch_directory)
            # Generate patch
            diff_command = "git diff " + file_before_path + str(index) + ".c" + " " + temp_after_path + file_after + "_patched_uD_" + temp_diff_file
            diff_result = utility_helper.command(diff_command)
            patch_file, is_modified = filter_diff_function(diff_file, func_map, diff_result)  # Filtering unrelated functions
            # Check if file is modified
            if is_modified:
                with open(equal_patch_directory + file_before_third + str(index) + ".patch", "a+") as file:
                    file.writelines(patch_file)
            # Process patch variants
            process_patch_variants(equal_patch_directory, file_before_patch, file_after_prefix, index)


def fetch_similar_func_differences(repo, branch, initial_commit, diff_file, func_map, save_directory=config_settings.SAVE_PATCH_PATH):
    # Check if function dictionary is empty
    if not func_map[diff_file]:
        return
    save_directory = save_directory % (global_year, global_cve)
    common_directory = save_directory + repo + "/" + branch + "/" + initial_commit + "_patch/"
    after_func_directory = common_directory + "after_func/"
    before_func_directory = common_directory + "before_func/"
    # Check path validity
    if not os.path.exists(save_directory) or not os.path.exists(common_directory) or not os.path.exists(before_func_directory) or not os.path.exists(after_func_directory):
        return
    # Read files in the directory
    files_after_commit = os.listdir(after_func_directory)
    # Generate patch for each file
    for file_after in files_after_commit:
        temp_after_path = after_func_directory + file_after + "/"
        if not os.path.exists(temp_after_path):
            continue
        # Extract file prefix
        file_after_func_prefix = os.path.splitext(file_after)[0]
        file_before_func_prefix = file_after_func_prefix[:4] + "_var"
        file_before_func_path = temp_after_path + file_before_func_prefix

        for index in range(6):
            utility_helper.command("cd " + common_directory + ";mkdir equal_func_patch")
            equal_func_directory = common_directory + "equal_func_patch/" + file_after_func_prefix[:4] + "_var/"
            if not os.path.exists(equal_func_directory):
                os.makedirs(equal_func_directory)
            # Generate diff
            diff_command = "git diff " + file_before_func_path + str(index) + ".c" + " " + temp_after_path + file_after + ".c"
            diff_result = utility_helper.command(diff_command)
            patch_file, is_modified = filter_diff_function(diff_file, func_map, diff_result)  # Filtering unrelated functions
            # Check if file is modified
            if is_modified:
                with open(equal_func_directory + file_before_func_prefix + str(index) + ".patch", "w") as file:
                    file.writelines(patch_file)
            # Process patch variants
            process_patch_variants(equal_func_directory, file_before_func_prefix, file_after_func_prefix, index)



def derive_actual_function_diff(repo, branch, commit_initial, diff_file_name, func_mapping, save_dir=config_settings.SAVE_PATCH_PATH):
    if not func_mapping[diff_file_name]:
        return
    save_dir = save_dir % (global_year, global_cve)
    common_dir = save_dir + repo + "/" + branch + "/" + commit_initial + "_patch/"
    after_func_dir = common_dir + "after_func/"
    before_func_dir = common_dir + "before_func/"

    if not os.path.exists(after_func_dir) or not os.path.exists(before_func_dir):
        return
    files_before = os.listdir(before_func_dir)
    files_after = os.listdir(after_func_dir)
    index = 0
    single_commit_flag = 0
    for file_before in files_before:
        if os.path.isdir(before_func_dir + file_before):
            continue
        if single_commit_flag == 1:
            break
        single_commit_flag += 1
        file_before_prefix = os.path.splitext(file_before)[0]
        for file_after in files_after:
            file_after_prefix = os.path.splitext(file_after)[0]
            file_after_complete = file_after + "/" + file_after + ".c"
            utility_helper.command("cd " + common_dir + ";mkdir equal_func_patch")
            equal_func_path = common_dir + "equal_func_patch/"
            diff_cmd = "git diff " + before_func_dir + file_before + " " + after_func_dir + file_after_complete
            diff_result = utility_helper.command(diff_cmd)
            patch_content, modified = filter_diff_function(diff_file_name, func_mapping, diff_result)
            if modified:
                with open(equal_func_path + file_before_prefix[:4] + "_" + file_after_prefix[:4] + ".patch", "w") as file:
                    file.writelines(patch_content)




def get_patch_var(equal_path,before_file_first,after_file_first,index=None):

    equal_path = equal_path +before_file_first + str(index)+".patch"
    if os.path.exists(equal_path)!=True:
        return 


    patch_varients.patcher(equal_path,index)
    patch_file_names =  before_file_first +str(index)+ ".patch"

    patch_reset(equal_path,patch_file_names)

def patch_reset(equal_path,patch_file_names):
    if os.path.exists(equal_path)!=True:
        return

    string ="patch -p1 < "+equal_path 

    responce = utility_helper.command(string)
    return

def filter_diff_function(diff_file_name,function_dic,diff_result):
    patch_file = []#定义一个列表
    flag= 0 
    modify = 0
    for function_name in function_dic[diff_file_name]:#
        for diff_line in diff_result:
            if diff_line.startswith("@@") and diff_line.find(function_name) == -1:
                flag = 1
                continue
            if diff_line.startswith("@@") and diff_line.find(function_name)!= -1:
                modify = 1
                flag = 0
            if flag == 0:
                patch_file.append(diff_line)
    return patch_file,modify

def store_file_after_patch(repo, branch, yi_commit, afterpatchcommit, after_file_content,before_file_content,filename,random_num, save_path=config.SAVE_PATCH_PATH):
    save_path = save_path % (global_year, global_cve_id)
    save_directory = save_path + repo + "/" + branch + "/" + initial_commit + "_patch/" + "after_file/"
    save_directory = save_directory + patched_commit + "/"
    if not os.path.exists(save_directory):
        os.makedirs(save_directory)
    if not isinstance(content_after, Iterable) or not isinstance(content_before, Iterable):
        return
    with open(save_directory + patched_commit + "_patched_uD_" + file_name, 'w') as file:
        file.write("\n".join(content_after))
    for i in range(6):
        with open(save_directory + patched_commit[:4] + "_" + file_name.split(".")[0] + "_var" + str(i) + ".c", 'w') as file:
            file.write("\n".join(content_before))


def save_after_func(repo, branch, yi_commit, afterpatchcommit,beforepatchcommit,yi_cve,cve_commit_element_content,random_num,save_path = config.SAVE_PATCH_PATH):

    save_path = save_path %(year_global)
    save_path = save_path + cve_global  + "/"
    save_path = save_path+repo+"/"+branch+"/"+yi_commit+"_patch/"+"after_func/"
    save_var_path = save_path +afterpatchcommit+"/"
    if os.path.exists(save_var_path)!=True:
        os.makedirs(save_var_path)
    if os.path.exists(save_path) != True:
        os.makedirs(save_path)

    if yi_cve not in cve_commit_element_content or 'aftercommits' not in cve_commit_element_content[yi_cve] or\
            afterpatchcommit not in cve_commit_element_content[yi_cve]['aftercommits'] :
        return

    for element in cve_commit_element_content[yi_cve]['aftercommits'][afterpatchcommit]:
        if isinstance(cve_commit_element_content[yi_cve]['aftercommits'][afterpatchcommit][element],Iterable)!=True:
            continue
        with open(save_var_path + afterpatchcommit + ".c", 'a+') as file: #
            file.write("\n".join(cve_commit_element_content[yi_cve]['aftercommits'][afterpatchcommit][element]))

    if yi_cve not in cve_commit_element_content or 'beforecommits' not in cve_commit_element_content[yi_cve] or\
            beforepatchcommit not in cve_commit_element_content[yi_cve]['beforecommits'] :
        return


    for i in range(config.AST_PATCH_COUNTS): # 保存指定数量的before_file
        if os.path.exists(save_var_path + afterpatchcommit + "_var"+str(i)+".c"): #保证对文件不重复写
            continue
        for element in cve_commit_element_content[yi_cve]['aftercommits'][afterpatchcommit]:
            print(element)
            if element not in cve_commit_element_content[yi_cve]['beforecommits'][beforepatchcommit]:
                continue
            if isinstance(cve_commit_element_content[yi_cve]['beforecommits'][beforepatchcommit][element],Iterable)!=True:
                continue
            with open(save_var_path + afterpatchcommit[:4] + "_var"+str(random_num)+".c", 'a+') as file:  # a+表示追加写
                file.write("\n".join(cve_commit_element_content[yi_cve]['beforecommits'][beforepatchcommit][element]))

def save_before_func(repo, branch, yi_commit, beforepatchcommit, yi_cve, cve_commit_element_content, save_path = config.SAVE_PATCH_PATH):
    save_path = save_path %(year_global)
    save_path = save_path + cve_global  + "/"
    save_path = save_path+repo+"/"+branch+"/"+yi_commit+"_patch/"+"before_func/"
    if os.path.exists(save_path) != True:
        os.makedirs(save_path)
    # fixme 记得加入判断以下字段是否存在

    if yi_cve not in cve_commit_element_content or 'beforecommits' not in cve_commit_element_content[yi_cve] or\
            beforepatchcommit not in cve_commit_element_content[yi_cve]['beforecommits'] :
        return

    for element in cve_commit_element_content[yi_cve]['beforecommits'][beforepatchcommit]:
        with open(save_path + beforepatchcommit + ".c", 'a+') as file: # a+表示追加写
            print("save_path",type(save_path))
            print("save_path", type(save_path))
            file.write("\n".join(cve_commit_element_content[yi_cve]['beforecommits'][beforepatchcommit][element]))

def save_before_file(repo, branch, yi_commit, beforepatchcommit, file_content, filename,save_path=config.SAVE_PATCH_PATH):

    save_path = save_path %(year_global)
    save_path = save_path + cve_global  + "/"
    save_path = save_path +repo+"/"+branch+"/"+yi_commit+"_patch/"+"before_file/"
    if os.path.exists(save_path)!=True:
        os.makedirs(save_path)


    if isinstance(file_content,Iterable)!=True:
        return
    with open(save_path + beforepatchcommit +"_prepatch_uD_"+filename, 'w') as file:
        file.write("\n".join(file_content))

def extract_primary_file_commits222(repopath,branch,filename):
    command_string = 'cd ' + repo_directory + ';git log --pretty=oneline --first-parent ' + branch + ' -- -p ' + file_name
    result_buffer = utility_helper.execute_command(command_string)
    primary_file_commits = []
    result_buffer.reverse()
    commit_length = int(len(result_buffer) * 0.2)
    index = 0
    count = 0
    for line in result_buffer:
        if len(result_buffer) < 100 or commit_length != 0 or count % commit_length == 0:
            commit_id = line[:12]
            primary_file_commits.append(commit_id)
            if index > 100 or len(primary_file_commits) > 100:
                break
            index += 1
        count += 1
    return primary_file_commits

def extract_primary_file_commits(repopath,branch,filename):
    command_line = 'cd ' + repo_path + ';git log --pretty=oneline --first-parent ' + branch_name + ' -- -p ' + filename
    execution_result = utility_helper.execute_command(command_line)
    main_file_commits_list = []
    for line in execution_result:
        commit_identifier = line[:12]
        main_file_commits_list.append(commit_identifier)
    return main_file_commits_list

def identify_post_patch_commits(repopath,branch,filename,patchcommit):
    primary_commits = extract_primary_file_commits(repo_directory, branch, filename)
    if patch_commit not in primary_commits:
        print("Unexpected: Patch commit", patch_commit, "not in main commit history of", repo_directory, branch, filename)
        return None
    index = primary_commits.index(patch_commit)
    return primary_commits[index-1:]


def get_negative_file(repo,branch,negative_commits,repopath,filename,function_dic,yi_cve,yi_maincommit,save_path=config.SAVE_PATCH_PATH):
    cve_commit_element_content = {}
    cve_commit_element_content[yi_cve] = {}
    cve_commit_element_content[yi_cve]['beforecommits'] = {}

    for beforepatchcommit in negative_commits: 
        if beforepatchcommit not in cve_commit_element_content[yi_cve]['beforecommits']:
            cve_commit_element_content[yi_cve]['beforecommits'][beforepatchcommit] = {}

        for funcname in function_dic[filename]: 
            element = (filename, funcname)
            before_file_buf = utility_helper.get_filecontent(repopath, beforepatchcommit, filename)
            before_funccontent = src_parser.get_function_content_1(before_file_buf, funcname)

            if len(before_funccontent) == 0:

                continue
            funccontent1 = list(before_funccontent)[0]
            cve_commit_element_content[yi_cve]['beforecommits'][beforepatchcommit][element] = before_funccontent
        save_negative_func(repo, branch, yi_maincommit, beforepatchcommit ,yi_cve , cve_commit_element_content,save_path)
    return

def save_negative_func(repo, branch, yi_commit, beforepatchcommit ,yi_cve , cve_commit_element_content,save_path):
    save_path = save_path %(year_global)
    save_path = save_path + cve_global  + "/"
    save_path = save_path+repo+"/"+branch+"/"+yi_commit+"_patch/"+"before_func/negative_sample/"
    if os.path.exists(save_path) != True:
        os.makedirs(save_path)
    # fixme 记得加入判断以下字段是否存在
    if yi_cve not in cve_commit_element_content or 'beforecommits' not in cve_commit_element_content[yi_cve] or\
            beforepatchcommit not in cve_commit_element_content[yi_cve]['beforecommits'] :
        return

    for element in cve_commit_element_content[yi_cve]['beforecommits'][beforepatchcommit]:
        if isinstance(cve_commit_element_content[yi_cve]['beforecommits'][beforepatchcommit][element],Iterable)!=True:
            continue
        with open(save_path + beforepatchcommit + ".c", 'a') as file:
            file.write("\n".join(cve_commit_element_content[yi_cve]['beforecommits'][beforepatchcommit][element]))
    return


def Patch_save_singlecommit(repo,branch,patchesinfo_path,cve_id = None,output_dir=None,year=None,save_source_path = None):
    global global_output_dir, global_cve, global_repo, global_branch, global_year
    global_output_dir = dir_output
    global_year = patch_year
    global_cve = cve_ident
    global_repo = repo_path_id
    global_branch = branch_id

    for scanned_cve_id in os.listdir(source_save_path % str(patch_year)):  #
        temp_cve_path = source_save_path % str(patch_year) #
        if cve_ident == scanned_cve_id:
            temp_cve_path = temp_cve_path + repo_path_id
            if os.path.exists(temp_cve_path):
                temp_cve_path = temp_cve_path + branch_id
                if os.path.exists(temp_cve_path): # 
                    return # 

    print("Time Now:", utility_helper.current_datetime())

    repo_actual_path = utility_helper.obtain_repo_path(repo_path_id)
    print("Save_Single_Patch_Commit.py")
    cve_data = utility_helper.extract_cve_info(patch_info_path, cve_id=cve_ident) #
    func_content_map = {}
    commit_content_map = {}

    branch_mod = branch_id
    if "/" in branch_id:
        branch_mod = branch_id.replace("/", "?")
        patch_locate_result = global_output_dir + branch_mod
    else:
        patch_locate_result = global_output_dir + branch_id  #

    if not os.path.exists(patch_locate_result):
        return

    chosen_commit_list = utility_helper.choose_commits(repo_path_id, branch_id) #
    print('Chosen commits for', branch_id, ':', chosen_commit_list)

    for (each_cve, orig_repo, orig_commit) in cve_data[cve_ident]:
        each_cve = cve_ident
        main_commit = orig_commit
        commit_time = utility_helper.get_commit_time(repo_actual_path, main_commit)
        if commit_time is None:
            return
        if chosen_commit_list is None:
            commit_filter_list = []
        else:
            commit_filter_list = [commit[0] for commit in chosen_commit_list if commit[1] is not None and commit[1] > commit_time]

        print('Tracking patch evolution for', each_cve)
        print('Adding commits post patch:', commit_filter_list)

        repo_path_nvd = utility_helper.obtain_repo_path(orig_repo)
        functions_dict = utility_helper.retrieve_commit_functions(repo_path_nvd, orig_commit)
        func_content_map[each_cve] = {}
        commit_content_map[each_cve] = {}
        commit_content_map[each_cve]['beforecommits'] = {}
        commit_content_map[each_cve]['aftercommits'] = {}
        for file_name in functions_dict:
            if not file_name.endswith(".c") and not file_name.endswith(".cpp"):
                continue

            commit_before_patch = utility_helper.get_prior_commit(repo_actual_path, main_commit, branch_id, file_name)
            if commit_before_patch is None:
                break
            print("Commit before patch:", commit_before_patch)
            commits_after = fetch_post_patch_commits(repo_actual_path, branch_id, file_name, main_commit)
            if commits_after is not None:
                if len(commits_after) > 100:
                    commits_after = commits_after[:100]

            if commits_after is None:
                commits_after = commit_filter_list
            else:
                commits_after += commit_filter_list

            commit_count = 0
            if not commits_after:
                continue

            after_commit_buffer = str()
            before_commit_buffer = str()
            temp_file_name = file_name
            fail_flag_func = 0
            count_save_after = 0
            random_val = random.randint(1, 6)
            for each_after_commit in commits_after:
                if commit_count > config.AFTER_PATCH_COUNTS:
                    break
                else:
                    commit_count += 1

                if each_after_commit not in commit_content_map[each_cve]['aftercommits']:
                    commit_content_map[each_cve]['aftercommits'][each_after_commit] = {}
                    commit_content_map[each_cve]['beforecommits'][commit_before_patch] = {}

                for func_name in functions_dict[file_name]:
                    elem_tuple = (file_name, func_name)
                    if elem_tuple not in func_content_map[each_cve]:
                        func_content_map[each_cve][elem_tuple] = set()

                    after_commit_content = utility_helper.obtain_file_content(repo_actual_path, each_after_commit, file_name)
                    content_after_func = src_parser.extract_func_content(after_commit_content, func_name)

                    before_commit_content = utility_helper.obtain_file_content(repo_actual_path, commit_before_patch, file_name)
                    content_before_func = src_parser.extract_func_content(before_commit_content, func_name)

                    if len(content_after_func) == 0:
                        print(each_cve, repo_actual_path, each_after_commit, file_name, func_name, 'not found')
                        content_after_func = "Null"

                    commit_content_map[each_cve]['aftercommits'][each_after_commit][elem_tuple] = content_after_func
                    commit_content_map[each_cve]['beforecommits'][commit_before_patch][elem_tuple] = content_before_func

                    fail_flag_func = 1
                    count_save_after += 1

                temp_file_name = file_name.split("/")[-1]
                if fail_flag_func == 1:
                    print("Time Now:", utility_helper.current_datetime())
                    if count_save_after % 2 == 0:
                        store_file_after_patch(repo_path_id, branch_mod, main_commit, each_after_commit, after_commit_content, before_commit_content, temp_file_name, random_val, save_path=source_save_path)
                        save_after_commit_func(repo_path_id, branch_mod, main_commit, each_after_commit, commit_before_patch, each_cve, commit_content_map, random_val, save_path=source_save_path)

            if fail_flag_func == 1:
                print("Time Now:", utility_helper.current_datetime())
                store_file_before_patch(repo_path_id, branch_mod, main_commit, commit_before_patch, before_commit_content, temp_file_name, save_path=source_save_path)
                save_before_commit_func(repo_path_id, branch_mod, main_commit, commit_before_patch, each_cve, commit_content_map, save_path=source_save_path)

            if fail_flag_func == 1:
                print("Time Now:", utility_helper.current_datetime())
                fetch_similar_func_differences(repo, branch_test, yi_maincommit, patch_filename, patch_function_dic,random_num,save_path = save_source_path)
                derive_actual_function_diff(repo, branch_test, yi_maincommit, patch_filename, patch_function_dic,save_path = save_source_path)

                fetch_similar_func_differences(repo, branch_test, yi_maincommit, patch_filename, patch_function_dic,random_num,save_path = save_source_path)
                compute_file_difference(repo, branch_test, yi_maincommit, patch_filename, patch_function_dic,file_name_temp,save_path = save_source_path) 


def Patchevolution_tracker(repo,branch,patchesinfo_path,cve_id = None,output_dir=None,year=None,save_source_path=None):
    global outputdir,cve_global,repo_global,branch_global,year_global
    outputdir = output_dir
    year_global = year
    cve_global = cve_id
    repo_global = repo
    branch_global = branch

    for SCAND_CVEID in os.listdir(save_source_path%str(year)): 
        CVE_TEMP_PATH = save_source_path%str(year) 
        if cve_id == SCAND_CVEID:
            CVE_TEMP_PATH = CVE_TEMP_PATH + repo
            if os.path.exists(CVE_TEMP_PATH): 
                CVE_TEMP_PATH = CVE_TEMP_PATH + branch
                if os.path.exists(CVE_TEMP_PATH): 
                    return  

    print("time：",utility_helper.get_now_datetime())

    repopath = utility_helper.get_repopath(repo)
    print("patchevolution_tracker.py")
    cve_nvd_info=utility_helper.get_cveinfos(patchesinfo_path,cve_id = cve_id)
    cve_functioncontent = {}
    cve_commit_element_content = {}
    branch_test = branch
    if "/" in branch: 
        branch_test = branch
        branch_test = branch_test.replace("/","?")
        patchlocator_result = outputdir + branch_test
    else:
        patchlocator_result = outputdir + branch
    
    if os.path.exists(patchlocator_result)!=True:
        return -1
    with open(patchlocator_result,"r") as f:
        Locate_patch_info = f.readlines()

    chosencommits = utility_helper.get_chosencommits(repo,branch) 
    # chosencommits = None
    print('chosencommits for',branch,':',chosencommits)

    return_flag_save = 0

    for patch_line in Locate_patch_info:
        patch_line=patch_line[:-1]
        if any(ignore in patch_line for ignore in ['#','[','None','too many candidates','not exist','initcommit','fail',"[]"]):
            continue 
        yi_cve,yi_maincommit = patch_line.split(" ")[:2]
        patchtime = utility_helper.get_committime(repopath,yi_maincommit)
        if patchtime==None :
            continue
        if chosencommits==None:
            chosencommits_filter=[]
        else:
            chosencommits_filter = [commit[0] for commit in chosencommits if commit[1]!=None and commit[1]>patchtime]# 

        print('Patch evolution tracking for',yi_cve)
        print('add some commits after patch:',chosencommits_filter )#

        original_nvd_repopath = utility_helper.get_repopath(repo) 

        patch_function_dic=utility_helper.get_commit_functions2(original_nvd_repopath,yi_maincommit)
        cve_functioncontent[yi_cve] ={}
        cve_commit_element_content[yi_cve]={}

        cve_commit_element_content[yi_cve]['beforecommits'] = {}
        cve_commit_element_content[yi_cve]['aftercommits']={}
        for patch_filename in patch_function_dic:

            if  patch_filename.endswith(".c")!=True and patch_filename.endswith(".cpp")!=True: #选择.c或.cpp文件
              continue

            beforepatchcommit=utility_helper.get_bereocommit2(repopath=repopath, commit=yi_maincommit, branch=branch, filename=patch_filename)#
            if beforepatchcommit ==None:
                break

            aftercommits = identify_post_patch_commits(repopath,branch,patch_filename,yi_maincommit)
            if aftercommits!=None:
                if len(aftercommits)>config.AFTER_PATCH_COUNTS: 
                    aftercommits = aftercommits[:config.AFTER_PATCH_COUNTS]

            if aftercommits==None:
                aftercommits=chosencommits_filter 
            else:
                aftercommits += chosencommits_filter #
            if not aftercommits: # 可能返回为None

                continue

            commmit_count=0
            after_file_buf = str()
            before_file_buf = str()
            file_name_temp = patch_filename
            file_func_save_fail = 0
            return_flag_save = 0
            save_after_count = 0
            random_num = random.randint(1, 6)

            for afterpatch_commit in aftercommits:
                if commmit_count>config.AFTER_PATCH_COUNTS: 
                    break
                else:
                    commmit_count = commmit_count + 1

                if afterpatch_commit not in cve_commit_element_content[yi_cve]['aftercommits']:
                    cve_commit_element_content[yi_cve]['aftercommits'][afterpatch_commit]={}
                    cve_commit_element_content[yi_cve]['beforecommits'][beforepatchcommit]={}

                for funcname in patch_function_dic[patch_filename]: #
                    element = (patch_filename,funcname)
                    if element not in cve_functioncontent[yi_cve]:
                        cve_functioncontent[yi_cve][element]=set()
                    ## 寻找after func内容
                    after_file_buf = utility_helper.get_filecontent(repopath,afterpatch_commit,patch_filename) #
                    after_funccontent = src_parser.get_function_content_1(after_file_buf,funcname) #

                    #寻找before func内容
                    before_file_buf=utility_helper.get_filecontent(repopath,beforepatchcommit,patch_filename)
                    before_funccontent=src_parser.get_function_content_1(before_file_buf,funcname)

                    if len(after_funccontent)==0:

                        print(yi_cve, repopath, afterpatch_commit, patch_filename, funcname, 'not exist')
                        after_funccontent = "Null" 

                    try:
                        cve_commit_element_content[yi_cve]['aftercommits'][afterpatch_commit][element] = after_funccontent 
                        cve_commit_element_content[yi_cve]['beforecommits'][beforepatchcommit][element] = before_funccontent
                    except:
                        print ("key_error!the programer will run again!")

                    file_func_save_fail = 1#
                    return_flag_save = 1 #
                    save_after_count = save_after_count + 1

                file_name_temp = patch_filename.split("/")[-1]#

                if file_func_save_fail==1:

                    print("当前时间：",utility_helper.get_now_datetime())
                    if save_after_count%2==0:
                        store_file_after_patch(repo, branch_test, yi_maincommit, afterpatch_commit, after_file_buf,before_file_buf,file_name_temp,random_num,save_path = save_source_path) #对每一个aftercommit，保存其对应的function
                        save_after_func(repo, branch_test, yi_maincommit, afterpatch_commit,beforepatchcommit,yi_cve,cve_commit_element_content,random_num,save_path = save_source_path) #aftercommit有多个 放在循环内

            if file_func_save_fail==1:
                print("当前时间：",utility_helper.get_now_datetime())
                save_before_file(repo, branch_test, yi_maincommit, beforepatchcommit,before_file_buf,file_name_temp,save_path = save_source_path)  # 对每一个beforecommit，保存其对应的function
                save_before_func(repo, branch_test, yi_maincommit, beforepatchcommit, yi_cve , cve_commit_element_content,save_path = save_source_path) #beforecommit只有一个 所以放在循环外


            if file_func_save_fail==1:
                print("当前时间：",utility_helper.get_now_datetime())
                fetch_similar_func_differences(repo, branch_test, yi_maincommit, patch_filename, patch_function_dic,random_num,save_path = save_source_path)
                derive_actual_function_diff(repo, branch_test, yi_maincommit, patch_filename, patch_function_dic,save_path = save_source_path)

                fetch_similar_func_differences(repo, branch_test, yi_maincommit, patch_filename, patch_function_dic,random_num,save_path = save_source_path)
                compute_file_difference(repo, branch_test, yi_maincommit, patch_filename, patch_function_dic,file_name_temp,save_path = save_source_path)


    print("运行结束！！")
    print("当前时间：",utility_helper.get_now_datetime())

    cve_commit_element_content2 = copy.deepcopy(cve_commit_element_content)
    for yi_cve in cve_commit_element_content:
        if 'aftercommits' not in cve_commit_element_content[yi_cve]:
            del cve_commit_element_content2[yi_cve]
            continue
        for afterpatch_commit in cve_commit_element_content[yi_cve]['aftercommits']:
            if len(cve_commit_element_content[yi_cve]['aftercommits'][afterpatch_commit])==0:
                del cve_commit_element_content2[yi_cve]['aftercommits'][afterpatch_commit]
        if len(cve_commit_element_content2[yi_cve]['aftercommits'])==0:
            del cve_commit_element_content2[yi_cve]

    return return_flag_save


if __name__ == '__main__':
    repo=sys.argv[1]
    branch=sys.argv[2]
    patches_info=sys.argv[3]
    Patchevolution_tracker(repo,branch,patches_info)
