# -*- coding: UTF-8 -*-
from cgi import test as perform_test
import time as timer
from ast import Str as StringExpression
from tokenize import Double as DoubleValue, String as StringToken
import helpers.assistant as utility_helper
import helpers.src_parser as src_parser
import PatchFinderModule as PatchFinder
import PatchEvolutionModule as PatchEvolution
import SourceMatcherModule as SourceMatcher
import os, sys
import configSettings as config
import random as rnd
from listInsertModule import cve_details as cve_info

# 获取定义的各种路径
InfoPatchCVE = config.INFO_PATCH_CVE
# 定义 CVE ID 的锁
LockListCVEIDs = []

def LocatePatchRepo(repo_location, branch_detail, patch_info, analysis_year=None, cve_id=None, output_directory=None):
    PatchFinder.locate_patch_in_repo(repo_location, branch_detail, patch_info, year=analysis_year, cve_ID=cve_id, output_dir=output_directory)

def FindPatchSourceCode(repo_location, branch_detail, patch_info_path, target_kernel_list=None, cve_id=None, analysis_year=None, output_directory=None, save_source_path=config.PATH_SAVE_PATCH_SOURCE2):
    PatchFinder.locate_patch_in_source(repo_location, branch_detail, patch_info_path, year=analysis_year, cve_ID=cve_id, output_dir=output_directory)
    save_flag = PatchEvolution.track_patch_evolution(repo_location, branch_detail, patch_info_path, cve_id=cve_id, output_dir=output_directory, year=analysis_year, save_source_path=save_source_path)

    if save_flag == 0:
        PatchEvolution.save_single_commit(repo_location, branch_detail, patch_info_path, cve_id=cve_id, output_dir=output_directory, year=analysis_year, save_source_path=save_source_path)

def RetrieveRepositoryProject(owner_repo_combination):
    if len(owner_repo_combination.split("%")) < 2:
        return False
    owner_name, repo_name = owner_repo_combination.split("%")
    save_path_oss = config.PATH_PROJECT_REPO + owner_repo_combination + "/"
    if os.path.exists(save_path_oss + repo_name):
        file_count = len([lists for lists in os.listdir(save_path_oss + repo_name)])
        if file_count >= 1:
            return True
    print("Cloning project:", owner_name, repo_name)
    git_clone_command = "git clone https://github.com/" + owner_name + "/" + repo_name + ".git"
    if not os.path.exists(save_path_oss):
        os.makedirs(save_path_oss)
    os.chdir(save_path_oss)
    clone_result = utility_helper.execute_command(git_clone_command)

    if isinstance(clone_result, StringToken) and "fatal" in clone_result:
        return False
    if clone_result == 0:
        return False
    if os.path.exists(save_path_oss + repo_name):
        file_count = len([lists for lists in os.listdir(save_path_oss + repo_name)])
        if file_count <= 1 or clone_result == 32768:
            return False
        return True
    return False

def FetchRepoBranchDetails(branch_path_repo, id_cve=None):
    branch_info_repo = {}
    branch_info_repo[id_cve] = []
    index_info = []
    with open(branch_path_repo, "r") as file:
        buffer_string = file.readlines()
    for line in buffer_string:
        if line.startswith("#"):
            continue
        cve_identifier, repo_identifier, branch_identifier = line.strip().split(" ")
        index_info = (cve_identifier, repo_identifier, branch_identifier)
        branch_info_repo[cve_identifier].append(index_info)

    return branch_info_repo


def Locate_patch(mode,START_YEAR,END_YEAR,save_mode=None):

     for year in range(START_YEAR, END_YEAR):
        SavePathCVE = config.PATH_CVE_SAVE + str(year) + "/"
        if not os.path.exists(SavePathCVE) or not os.path.exists(config.PATH_CVE_SCANNED % str(year)):
            print(SavePathCVE)
            print(config.PATH_CVE_SCANNED % str(year))
            print("Path for CVE year does not exist")
            break

        ListCVEFilter = os.listdir(SavePathCVE)
        rnd.shuffle(ListCVEFilter)

        for cve_id in ListCVEFilter:
            rnd.shuffle(ListCVEFilter)
            cve_id = cve_id.split("\n")[0]

            if not os.path.exists(config.PATH_SPECIFIC_CVE % str(year)):
                os.makedirs(config.PATH_SPECIFIC_CVE % str(year))

            scanned = 0
            for scanned_path in utility_helper.find_files(config.DIR_CURRENT, config.KEYWORD_FILE_PATCH_INSPECT):
                if not os.path.exists(scanned_path + "/" + str(year)):
                    continue
                for scanned_cve_id in os.listdir(scanned_path + "/" + str(year)):
                    if cve_id == scanned_cve_id:
                        scanned = 1
                        break

            if scanned == 1:
                continue



            InfoPatch = config.INFO_PATCH % (str(year), cve_id, cve_id)
            BranchRepoInfo = config.INFO_REPO_BRANCH % (str(year), cve_id, cve_id)
            
            if not os.path.exists(BranchRepoInfo):
                continue
            if not os.path.exists(InfoPatch):
                continue

            branch_info = FetchRepoBranchDetails(BranchRepoInfo, cve_id=cve_id)
            for (index, repo, branches) in branch_info[cve_id]:
                repo_exists = RetrieveRepositoryProject(repo)
                if not repo_exists:
                    print("Failed to clone repo:", repo, "Skipping:", cve_id)
                    continue

                for branch in branches.split(","):
                    if "test" in branch:
                        continue

                    output_dir = config.PATH_PATCH_SIMILAR % (str(year), cve_id, repo)
                    if mode == 'repo':
                        LocatePatchRepo(repo, branch, InfoPatch, year=year, cve_id=cve_id, outputdir=output_dir)
                    elif mode == 'source':
                        os.chdir(sys.path[0])
                        print("Time:", utility_helper.get_current_datetime())
                        print(cve_id)
                        FindPatchSourceCode(repo, branch, InfoPatch, cve_id=cve_id, year=year, outputdir=output_dir)

                    else:
                        print('Invalid mode', mode)
                print("Completed processing:", cve_id)
                print("Time:", utility_helper.get_current_datetime())
                rnd.shuffle(ListCVEFilter)


def chongpao(mode, START_YEAR, END_YEAR,save_mode=None):
    for year in range(START_YEAR, END_YEAR):

        CVE_SAVE_PATH = config.CVE_SAVE_PATH + str(year) + "/"
        if os.path.exists(CVE_SAVE_PATH) != True or os.path.exists(config.CVE_SCANED_PATH % str(year)) != True: #fixme 有时候需要修改路径
            print(CVE_SAVE_PATH)
            print (config.CVE_SCANED_PATH%str(year))
            print("当前CVE所在year的路径不存在")
            break
        CVE_LISTS = os.listdir(CVE_SAVE_PATH)
        CVE_LISTS = save_cve(year)  # 为了重新扫描CVE
        random.shuffle(CVE_LISTS)
        # print(CVE_LISTS)
        for CVEID in CVE_LISTS:
            CVEID = CVEID.split("\n")[0]
            if os.path.isdir(CVE_SAVE_PATH + CVEID) != True:
                continue
            SCAND = 0

            
            if os.path.exists(config.SAVE_PATCH_TEST_PATH2 % str(year))!=True:
                os.makedirs(config.SAVE_PATCH_TEST_PATH2 % str(year))
            
            # fixme 重复性检测1 保证对当前路径已经扫描过的CVE不重复扫描
            for SCAND_CVEID in os.listdir(config.SAVE_PATCH_TEST_PATH2 % str(year)):  # config.CVE shifou xuyao tihuan
                if CVEID == SCAND_CVEID:
                    SCAND = 1
                    break
            # fixme 重复性检测2 保证对以前sourcecode路径的CVE不重复扫描
            for query_cve_list in cve_info.query_cve():
                if CVEID == query_cve_list:
                    SCAND =1
                    break
            if SCAND == 1:
                continue

            CVE_PATCH_INFO = config.CVE_PATCH_INFO % (str(year), CVEID, CVEID)  # patch_info的路径
            CVE_REPO_BRANCH = config.CVE_REPO_BRANCH % (
            str(year), CVEID, CVEID)  # cve repo branch的maping路径，fixme 需要考虑CVE_REPO_BRANCH为空的情况

            if os.path.exists(CVE_REPO_BRANCH) != True:
                continue  # 跳过repo——branch为空的情况
            if os.path.exists(CVE_PATCH_INFO) != True: # 跳过patch_info为空的情况
                continue  # 跳过patch_info为空的情况

            repo_branch_info = FetchRepoBranchDetails(repo_branch_path=CVE_REPO_BRANCH, cve_id=CVEID)  # list列表
            for (cve_index, repo, branches) in repo_branch_info[CVEID]:
                # 克隆库 先判断这个repo_在本地是否存在 √ 可以使用，测试过
                repo_exists_flag = RetrieveRepositoryProject(repo)
                if repo_exists_flag != True:
                    print("clone repo：", repo, "fail！continue:", CVEID)
                    continue  # 由于针对同一个CVE可能对应不同的repo，所以这里使用continue

                branchlists = branches.split(",")
                for branch in branchlists:
                    outputdir = config.SIMILIAR_PATCH_PATH % (str(year), CVEID, repo)  # #./output/{year}/{cve}/{repo}/

                    patchesinfo = CVE_PATCH_INFO
                    if mode == 'repo':
                        LocatePatchRepo(repo, branch, patchesinfo, year=year, cve_id=CVEID, outputdir=outputdir)
                    elif mode == 'source':  # 只用这个功能
                        # targetkernel_list=sys.argv[5:]
                        os.chdir(sys.path[0])  # 防止项目根路径出问题
                        print("time：", utility_helper.get_now_datetime())
                        print(CVEID)
                        FindPatchSourceCode(repo, branch, patchesinfo, cve_id=CVEID, year=year,
                                                        targetkernel_list=None, outputdir=outputdir,save_source_path = save_mode)

                    else:
                        print('invalid mode', mode, 'not in ["repo","source"]')
                print("run down!", CVEID)
                print("time：", utility_helper.get_now_datetime())
                random.shuffle(CVE_LISTS)
            # CVE_LIST_LOCK.remove(CVEID)

def save_zhiding(year):
    cve_lists = os.listdir(config.ZHIDING_CVE%year)
    with open(config.SAVE_ZHIDING + str(year)+".txt","a+") as f:
        f.write("\n".join(cve_lists))

def run_process(mode,START_YEAR,END_YEAR,save_mode=None): #多进程
    import multiprocessing as mp
    if save_mode==None:

        process = [
            mp.Process(target=Locate_patch,args=(mode,START_YEAR,END_YEAR,save_mode)),
            # mp.Process(target=Locate_patch, args=(mode, START_YEAR+1, END_YEAR+1, save_mode)),
            # mp.Process(target=Locate_patch, args=(mode, START_YEAR+2, END_YEAR+2, save_mode)),
            # mp.Process(target=Locate_patch, args=(mode, START_YEAR+3, END_YEAR+3, save_mode)),
            # mp.Process(target=Locate_patch, args=(mode, START_YEAR+4, END_YEAR+4, save_mode)),
            # mp.Process(target=Locate_patch, args=(mode, START_YEAR+5, END_YEAR+5, save_mode)),
            # mp.Process(target=Locate_patch, args=(mode, START_YEAR+6, END_YEAR+6, save_mode)),
            # mp.Process(target=Locate_patch, args=(mode, START_YEAR+7, END_YEAR+7, save_mode)),
            # mp.Process(target=Locate_patch, args=(mode, START_YEAR+8, END_YEAR+8, save_mode)),
            # mp.Process(target=Locate_patch, args=(mode, START_YEAR+9, END_YEAR+9, save_mode)),
            # mp.Process(target=Locate_patch, args=(mode, START_YEAR+10, END_YEAR+10, save_mode))
        ]
        # [p.start() for p in process]

        for p in process:
            p.start()
            time.sleep(5)
        for p in process:
            p.join()
            time.sleep(5)

    else:
        process = [
            mp.Process(target=Locate_patch,args=(mode,START_YEAR,END_YEAR,save_mode)),  
            # mp.Process(target=Locate_patch, args=(mode, START_YEAR + 1, END_YEAR + 1, save_mode)),
            # mp.Process(target=Locate_patch, args=(mode, START_YEAR + 2, END_YEAR + 2, save_mode)),
            # mp.Process(target=Locate_patch, args=(mode, START_YEAR + 3, END_YEAR + 3, save_mode)),
            # mp.Process(target=Locate_patch, args=(mode, START_YEAR + 4, END_YEAR + 4, save_mode)),
            # mp.Process(target=Locate_patch, args=(mode, START_YEAR + 5, END_YEAR + 5, save_mode)),
            # mp.Process(target=Locate_patch, args=(mode, START_YEAR + 6, END_YEAR + 6, save_mode)),
            # mp.Process(target=Locate_patch, args=(mode, START_YEAR + 7, END_YEAR + 7, save_mode)),
            # mp.Process(target=Locate_patch, args=(mode, START_YEAR + 8, END_YEAR + 8, save_mode)),
            # mp.Process(target=Locate_patch, args=(mode, START_YEAR + 9, END_YEAR + 9, save_mode)),
            # mp.Process(target=Locate_patch, args=(mode, START_YEAR + 10, END_YEAR + 10, save_mode))
        ]
        # [p.start() for p in process]
        for p in process:
            p.start()
            time.sleep(5)
        for p in process:
            p.join()
            time.sleep(5)
        # [p.join() for p in process]

def save_cve(year):
    cve_lists = ""
    with open(config.SAVE_ZHIDING + str(year)+".txt","r") as f:
        cve_lists = f.readlines()
    return cve_lists
    return
 

if __name__ == '__main__':

    # test_api() #测试api 
    mode= sys.argv[1]
    START_YEAR = int(sys.argv[2]) #从终端输入开始year
    END_YEAR = int(sys.argv[3]) #从终端输入结束yea


    run_process(mode,START_YEAR=START_YEAR,END_YEAR=END_YEAR) # 
    #Locate_patch()