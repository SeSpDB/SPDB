# -*- coding: UTF-8 -*-
from math import fabs as compute_absolute
import helpers.assistant as utility_helper
import sys
import pickle
import copy
import os
import configuration as config_settings
from collections import Iterable
import subprocess
from pathlib import Path


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
            patch_file, is_modified = get_diff_func(diff_file_name, func_dictionary, diff_result)  # Filtering unrelated functions
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
            patch_file, is_modified = get_diff_func(diff_file, func_map, diff_result)  # Filtering unrelated functions
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
            patch_content, modified = get_diff_func(diff_file_name, func_mapping, diff_result)
            if modified:
                with open(equal_func_path + file_before_prefix[:4] + "_" + file_after_prefix[:4] + ".patch", "w") as file:
                    file.writelines(patch_content)



def get_patch_var(equal_path, before_file_first, after_file_first, index=None):
    equal_path = equal_path + before_file_first + str(index) + ".patch"
    if os.path.exists(equal_path) != True:
        return  # 前面已经新建了相关的文件

    # 对上述补丁做6种变换
    patch_varients.patcher(equal_path, index)  # 对与index相匹配的序号做对应的变换
    patch_file_names = before_file_first + str(index) + ".patch"
    # 打补丁
    patch_reset(equal_path, patch_file_names)


def patch_reset(equal_path, patch_file_names):
    if os.path.exists(equal_path) != True:
        return
    # string = "cd " +equal_path;
    string = "patch -p1 <" + equal_path  # +patch_file_names
    utility_helper.command(string)
    return


def filter_diff_function(diff_file_name, function_dic, diff_result):
    patch_file = []  # 定义一个列表
    flag = 0  # 定义 如果遇到不同的行 则赋值为1，表示停止添加新的文件内容
    modify = 0
    for function_name in function_dic[diff_file_name]:  # 针对原patch的每一个函数
        for diff_line in diff_result:
            if diff_line.startswith("@@") and diff_line.find(function_name) == -1:
                flag = 1
                continue
            if diff_line.startswith("@@") and diff_line.find(function_name) != -1:  # 遇到了相同的函数名，则后续部分都添加 且以@@开头
                modify = 1
                flag = 0
            if flag == 0:
                patch_file.append(diff_line)
    return patch_file, modify


def store_commit_related_files(repo_directory=None, compile_directory=None, commit_id=None, file_name=None, sequence_number=None, branch_name=None, original_commit=None):
    if compile_directory is None or commit_id is None or file_name is None or sequence_number is None or repo_directory is None or branch_name is None or original_commit is None:
        return
    save_path_after = compile_directory + "/" + branch_name + "/" + original_commit + 'Patches/' + commit_id + "%" + str(sequence_number)
    if not os.path.exists(save_path_after):
        os.makedirs(save_path_after)
    # 1. Store source files
    command_copy_src = "cp -f " + repo_directory + file_name + " " + save_path_after + ' 2>/dev/null || :'
    os.system(command_copy_src)
    # 2. Store .o files
    path_src = Path(file_name)
    parent_path_src = path_src.parent
    directory_temp = repo_directory + str(parent_path_src)
    file_name_new = file_name.split('.')[0].split('/')[-1] + '.o'
    if os.path.exists(directory_temp):
        for file in os.listdir(directory_temp):
            if file.endswith(file_name_new):
                command_copy_obj = 'cp -f ' + directory_temp + '/' + file + ' ' + save_path_after + ' 2>/dev/null || :'
                os.system(command_copy_obj)
    return


def store_file_after_patch(repo, branch, initial_commit, patched_commit, content_after, content_before, file_name, save_path=config_settings.SAVE_PATCH_PATH):
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



def store_functions_after_patch(repo, branch, initial_commit, post_patch_commit, pre_patch_commit, cve_id, commit_func_content, save_path=config_settings.SAVE_PATCH_PATH):
    save_path = save_path % (global_year, global_cve_id)
    save_dir = save_path + repo + "/" + branch + "/" + initial_commit + "_patch/" + "after_func/"
    save_var_dir = save_dir + post_patch_commit + "/"
    if not os.path.exists(save_var_dir):
        os.makedirs(save_var_dir)
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    if cve_id not in commit_func_content or 'aftercommits' not in commit_func_content[cve_id] or post_patch_commit not in commit_func_content[cve_id]['aftercommits']:
        return

    for element in commit_func_content[cve_id]['aftercommits'][post_patch_commit]:
        if not isinstance(commit_func_content[cve_id]['aftercommits'][post_patch_commit][element], Iterable):
            continue
        with open(save_var_dir + post_patch_commit + ".c", 'a+') as file:
            file.write("\n".join(commit_func_content[cve_id]['aftercommits'][post_patch_commit][element]))

    if cve_id not in commit_func_content or 'beforecommits' not in commit_func_content[cve_id] or pre_patch_commit not in commit_func_content[cve_id]['beforecommits']:
        return
    for i in range(6):
        if os.path.exists(save_var_dir + post_patch_commit[:4] + "_var" + str(i) + ".c"):
            continue
        for element in commit_func_content[cve_id]['aftercommits'][post_patch_commit]:
            if element not in commit_func_content[cve_id]['beforecommits'][pre_patch_commit]:
                continue
            if not isinstance(commit_func_content[cve_id]['beforecommits'][pre_patch_commit][element], Iterable):
                continue
            with open(save_var_dir + post_patch_commit[:4] + "_var" + str(i) + ".c", 'a+') as file:
                file.write("\n".join(commit_func_content[cve_id]['beforecommits'][pre_patch_commit][element]))


def store_functions_before_patch(repo, branch, initial_commit, pre_patch_commit, cve_id, commit_func_content, save_path=config_settings.SAVE_PATCH_PATH):
    save_path = save_path % (global_year, global_cve_id)
    save_dir = save_path + repo + "/" + branch + "/" + initial_commit + "_patch/" + "before_func/"
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    if cve_id not in commit_func_content or 'beforecommits' not in commit_func_content[cve_id] or pre_patch_commit not in commit_func_content[cve_id]['beforecommits']:
        return

    for element in commit_func_content[cve_id]['beforecommits'][pre_patch_commit]:
        if not isinstance(commit_func_content[cve_id]['beforecommits'][pre_patch_commit][element], Iterable):
            continue
        with open(save_dir + pre_patch_commit + ".c", 'a+') as file:
            file.write("\n".join(commit_func_content[cve_id]['beforecommits'][pre_patch_commit][element]))


def archive_file_prior_to_patch(repo, branch, initial_commit, pre_patch_commit, file_contents, file_name, save_directory=config_settings.PATCH_SAVE_PATH):
    save_directory = save_directory % (global_year, global_cve)
    directory_before_file = save_directory + repo + "/" + branch + "/" + initial_commit + "_patch/" + "before_file/"
    if not os.path.exists(directory_before_file):
        os.makedirs(directory_before_file)

    if not isinstance(file_contents, Iterable):
        return

    with open(directory_before_file + pre_patch_commit + "_prepatch_uD_" + file_name, 'w') as file:
        file.write("\n".join(file_contents))


def fetch_primary_file_commits_v2(repo_directory, branch, file_name):
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


def extract_primary_file_commits(repo_path, branch_name, filename):
    command_line = 'cd ' + repo_path + ';git log --pretty=oneline --first-parent ' + branch_name + ' -- -p ' + filename
    execution_result = utility_helper.execute_command(command_line)
    main_file_commits_list = []
    for line in execution_result:
        commit_identifier = line[:12]
        main_file_commits_list.append(commit_identifier)
    return main_file_commits_list


def identify_post_patch_commits(repo_directory, branch, filename, patch_commit):
    primary_commits = extract_primary_file_commits(repo_directory, branch, filename)
    if patch_commit not in primary_commits:
        print("Unexpected: Patch commit", patch_commit, "not in main commit history of", repo_directory, branch, filename)
        return None
    index = primary_commits.index(patch_commit)
    return primary_commits[index-1:]


def retrieve_negative_sample_files(repo, branch, neg_commits, repo_path, filename, func_dict, cve_id, main_commit, save_path=config_settings.PATCH_SAVE_PATH):
    element_content_cve_commit = {}
    element_content_cve_commit[cve_id] = {}
    element_content_cve_commit[cve_id]['pre_commit_functions'] = {}

    for pre_commit in neg_commits:
        if pre_commit not in element_content_cve_commit[cve_id]['pre_commit_functions']:
            element_content_cve_commit[cve_id]['pre_commit_functions'][pre_commit] = {}

        for func_name in func_dict[filename]:
            element = (filename, func_name)
            pre_commit_file_content = utility_helper.get_filecontent(repo_path, pre_commit, filename)
            pre_commit_func_content = src_parser.parse_function_content(pre_commit_file_content, func_name)

            if not pre_commit_func_content:
                continue
            element_content_cve_commit[cve_id]['pre_commit_functions'][pre_commit][element] = pre_commit_func_content
    store_negative_samples(repo, branch, main_commit, cve_id, element_content_cve_commit, save_path)


def store_negative_samples(repository, branch_identifier, init_commit, cve_identifier, commit_func_content, directory_path=config_settings.PATCH_SAVE_PATH):
    directory_path = directory_path % (global_year, global_cve_id)
    directory_neg_samples = directory_path + repository + "/" + branch_identifier + "/" + init_commit + "_patch/" + "pre_patch_functions/negative_samples/"
    if not os.path.exists(directory_neg_samples):
        os.makedirs(directory_neg_samples)

    if cve_identifier not in commit_func_content or 'pre_commit_functions' not in commit_func_content[cve_identifier]:
        return

    for pre_commit in commit_func_content[cve_identifier]['pre_commit_functions']:
        for element in commit_func_content[cve_identifier]['pre_commit_functions'][pre_commit]:
            if not isinstance(commit_func_content[cve_identifier]['pre_commit_functions'][pre_commit][element], Iterable):
                continue
            with open(directory_neg_samples + pre_commit + ".c", 'a') as file:
                file_content = "\n".join(commit_func_content[cve_identifier]['pre_commit_functions'][pre_commit][element])
                file.write(file_content)
    return



def fetch_initial_commit(repo_path=None):
    if repo_path is None:
        return
    command_string = "cd " + repo_path + "; git log --oneline"
    result = utility_helper.execute_command(command_string)
    first_commit = result[0][:8]  # Taking first 8 characters of the first commit
    return first_commit


def Retrieve_Initial_Commit(repo_directory=None):
    if repo_directory is None:
        return None
    command_line = "cd " + repo_directory + "; git log --oneline"
    result = utility_helper.execute_command(command_line)
    first_commit = result[0][:8]  # Extract the first 8 characters of the first commit
    return first_commit


def reset_commit(repo_path=None, commit_id=None):
    if repo_path is None or commit_id is None:
        return
    reset_command = 'cd ' + repo_path + '; git reset --hard ' + commit_id
    utility_helper.execute_command(reset_command)



def configure_project_make(repo_path=None):
    if repo_path is None:
        return 0
    project_dirs = os.listdir(repo_path)
    flag_return = 0
    for file in project_dirs:
        if file.lower() in ["config", "configure"] and os.path.isfile(repo_path + file):
            execute_config_procedure(repo_path + file, repo_path)
            if "Makefile" in os.listdir(repo_path):
                flag_return = 1
                break
    if flag_return:
        make_command = "cd " + repo_path + ";make -j10"
        utility_helper.execute_command(make_command)
    return flag_return


def execute_config_procedure(config_file_name=None, repo_directory=None):
    if config_file_name is None or repo_directory is None:
        return
    config_cmd = 'cd ' + repo_directory + ';./' + config_file_name + ' --without-readline'
    exec_result = utility_helper.execute_command(config_cmd)
    if "unrecognized option" in exec_result:
        config_cmd = 'cd ' + repo_directory + ';./' + config_file_name
        utility_helper.execute_command(config_cmd)


def remove_compiled_files(compile_path=None, repo_directory=None):
    if compile_path is None or repo_directory is None:
        return
    clean_cmd = "cd " + repo_directory + ";make clean"
    utility_helper.execute_command(clean_cmd)
    if os.path.exists(compile_path):
        for file in os.listdir(compile_path):
            if file.endswith(".o"):
                delete_cmd = "cd " + compile_path + ";rm -rf " + file
                os.system(delete_cmd)


def retrieve_patchinfo_v2(patch_info_path=None):
    if patch_info_path is None:
        return
    with open(patch_info_path, "r") as file:
        lines_buf = file.readlines()
    return lines_buf


def Evolution_Tracker(repo_identifier, branch_identifier, patch_details_path, cve_ident=None, destination_dir=None, target_year=None):
    global dest_dir_global, cve_ident_global, repo_ident_global, branch_ident_global, target_year_global
    dest_dir_global = destination_dir
    target_year_global = target_year
    cve_ident_global = cve_ident
    repo_ident_global = repo_identifier
    branch_ident_global = branch_identifier

    print("Time Marker:", utility_helper.current_time())

    repo_path_ref = utility_helper.obtain_repo_path(repo_identifier)
    patch_information = utility_helper.fetch_patch_info(patch_details_path, cve_id=cve_ident)
    func_content_mapping = {}
    commit_element_mapping = {}

    for (current_cve, source_repo, commit_base) in patch_information[cve_ident]:
        path_of_repo = utility_helper.resolve_repo_path(source_repo)
        dict_of_functions = utility_helper.analyze_functions_commit(path_of_repo, commit_base)
        func_content_mapping[current_cve] = {}
        commit_element_mapping[current_cve] = {}
        commit_element_mapping[current_cve]['postcommits'] = {}

        patch_time_marker = utility_helper.retrieve_commit_time(repo_path_ref, commit_base)

        chosen_commit_index = 0
        filtered_chosen_commits = patch_time_marker
        for commit in patch_time_marker:
            if commit[1] is not None and commit[1] > patch_time_marker:
                filtered_chosen_commits.append(commit[0])
                chosen_commit_index += 1

        print("Timestamp:", utility_helper.current_time(), current_cve)
        if os.path.exists(compile_path_result + branch+"/"+str(commit_base)+"Patches/"):
            return
        for file_name in dict_of_functions:
            if not file_name.endswith(".c"):
                continue
            commits_after_patch = identify_post_patch_commits(repo_path_ref, branch_identifier, file_name, commit_base)
            if commits_after_patch is None:
                commits_after_patch = filtered_chosen_commits
                commits_after_patch = commits_after_patch[:50]
            else:
                if len(commits_after_patch) >= 50:
                    commits_after_patch = commits_after_patch[:50]

            commit_count = 0
            after_file_buffer = str()
            before_file_buffer = str()
            temp_file_name = file_name
            function_save_flag = 0
            first_commit_reference = fetch_initial_commit(repo_path_ref)
            print("Initial Commit:", first_commit_reference)

            for commit_post_patch in commits_after_patch:
                reset_commit(repo_path_ref, commit_post_patch)
                compile_flag = execute_config_procedure(repo_path_ref)
                if compile_flag == 0:
                    continue

                print("Time Check:", utility_helper.current_time(), current_cve)
                if commit_post_patch not in commit_element_mapping[current_cve]['postcommits']:
                    commit_element_mapping[current_cve]['postcommits'][commit_post_patch] = {}

                for func_name in dict_of_functions[file_name]:
                    element_tuple = (file_name, func_name)
                    if element_tuple not in func_content_mapping[current_cve]:
                        func_content_mapping[current_cve][element_tuple] = set()
                    file_content_after = utility_helper.get_content_of_file(repo_path_ref, commit_post_patch, file_name)
                    function_content_after = src_parser.extract_function(file_content_after, func_name)

                    if len(function_content_after) == 0:
                        print(current_cve, repo_path_ref, commit_post_patch, file_name, func_name, 'does not exist')
                        function_content_after = "Empty"
                    commit_element_mapping[current_cve]['postcommits'][commit_post_patch][element_tuple] = function_content_after
                    function_save_flag = 1

                temp_file_name = file_name.split("/")[-1]
                compile_temp_path = None
                if function_save_flag == 1:
                    print("Marker:", utility_helper.current_time())
                    compile_temp_path = store_commit_related_files(repo_path_ref, compile_path_result, commit_post_patch, file_name, commit_count, branch_identifier, commit_base)
                    commit_count += 1
                remove_compiled_files(compile_temp_path, repo_path_ref)

            print("Time Marker:", utility_helper.current_time(), current_cve)
            reset_commit(repo_path_ref, first_commit_reference)

    print("Execution Completed!!")
    print("Timestamp:", utility_helper.current_time())

    return function_save_flag

if __name__ == '__main__':
    repo = sys.argv[1]
    branch = sys.argv[2]
    patches_info = sys.argv[3]
    Evolution_Tracker(repo, branch, patches_info)
