# coding=utf-8


import string
import os
import itertools
import configuration as config


def getCVEcorpus(CVE_PATH):
    CVE_dirs = os.listdir(CVE_PATH)
    for every_CVE in CVE_dirs:
        CVE_path = os.path.join(CVE_PATH, every_CVE)
        # 在每个CVE下面创建切片
        CVE_slice_path = os.path.join(CVE_path, 'cve_corpus.txt')
        if os.path.exists(CVE_slice_path):
            os.remove(CVE_slice_path)
            os.mknod(CVE_slice_path)
        FUN_dirs = os.listdir(CVE_path)

        CVE_corpus_list = []
        #  every_FUN是CVE的每一个commit
        for every_FUN in FUN_dirs:
            if '.txt' in every_FUN:
                continue
            FUN_path = os.path.join(CVE_path, every_FUN)
            patch_and_fun_path = os.listdir(FUN_path)
            #  patch_and_fun_path  为commit下面自定义文件夹的集合  （如：lable）的列表     example    ['lable','NVD']
            for every_patch_and_fun_path in patch_and_fun_path:
                if "LABEL" not in every_patch_and_fun_path:
                    continue
                every_patch_and_fun_path = os.path.join(FUN_path, every_patch_and_fun_path)
                every_patch_and_fun_path_list = os.listdir(every_patch_and_fun_path)
                for every_final_file in every_patch_and_fun_path_list:

                    file_path = os.path.join(every_patch_and_fun_path, every_final_file)  # 只使用这个进行打标签
                    f = open(file_path, 'r')
                    temp_contents = f.readlines()
                    f.close()
                    line_str = ''
                    for everyline in temp_contents:
                        everyline = everyline.strip() + '  '
                        # everyline = everyline.rstrip(string.digits) + '  '
                        line_str += everyline
                    line_str += '\n'
                    CVE_corpus_list.append(line_str)
        CVE_corpus_dict = {}
        x = 0
        for every in CVE_corpus_list:
            if every not in CVE_corpus_dict.values():
                CVE_corpus_dict[x] = every
                x = x + 1
        CVE_corpus_list1 = []
        for every in CVE_corpus_dict:
            CVE_corpus_list1.append(CVE_corpus_dict[every])
        f = open(CVE_slice_path, 'w')
        for every_patch in CVE_corpus_list1:
            f.write(every_patch)
        f.close()


def iter_self_fun(iter_self_list):
    iter_list = []
    not_scan_list = []
    for every in iter_self_list:
        not_scan_list.append(every)
        for every_other in iter_self_list:
            if every_other not in not_scan_list:
                temp_str = ''
                temp_str += every
                temp_str += ' ??? '
                temp_str += every_other
                temp_str += ' ??? 1\n'
                iter_list.append(temp_str)
    return iter_list


def iter_self(CVE_PATH):
    iter_self_list = []
    CVE_dirs = os.listdir(CVE_PATH)
    for every_CVE in CVE_dirs:
        CVE_path = os.path.join(CVE_PATH, every_CVE)
        CVE_slice_path = os.path.join(CVE_path, 'cve_corpus.txt')
        iter_self_path = os.path.join(CVE_path, 'iter_self.txt')
        f = open(CVE_slice_path, 'r')
        CVE_corpus_list = f.readlines()
        f.close()
        CVE_corpus_list1 = []
        for every in CVE_corpus_list:
            every = every.strip()
            CVE_corpus_list1.append(every)
        iter_self_list = iter_self_fun(CVE_corpus_list1)
        f = open(iter_self_path, 'w')
        for everyline in iter_self_list:
            f.write(everyline)
        f.close()
        print('okok')


def get_1_corpus(CVE_PATH, output_1_path):
    global txt_lable_1_i
    CVE_dirs = os.listdir(CVE_PATH)
    corpus_path_1 = os.path.join(output_1_path, 'train_input_lable1_{}.txt'.format(txt_lable_1_i))
    if not os.path.exists(corpus_path_1):
        f = open(corpus_path_1, 'w')
        f.close()
    for every_CVE in CVE_dirs:
        if '.txt' in every_CVE:
            continue
        if txt_lable_1_i>=3:
            break #数据量平衡
        CVE_path = os.path.join(CVE_PATH, every_CVE)
        iter_self_path = os.path.join(CVE_path, 'iter_self.txt')
        f = open(iter_self_path, 'r+')
        temp_lines = f.readlines()
        f.close()
        size = os.path.getsize(corpus_path_1)
        if size != 0:
            if size > 1024 * 1024 * 100:
                txt_lable_1_i += 1
                corpus_path_1 = os.path.join(output_1_path, 'train_input_lable1_{}.txt'.format(txt_lable_1_i))
                if not os.path.exists(corpus_path_1):
                    f = open(corpus_path_1, 'w')
                    f.close()
        f = open(corpus_path_1, 'a')
        for every in temp_lines:
            f.write(every)
        f.close()
        print("lable 1 : This CVE done!")


def get_0_corpus(CVE_PATH, line_value, output_0_path):
    global txt_lable_0_i
    CVE_dirs = os.listdir(CVE_PATH)
    corpus_path_0 = os.path.join(output_0_path, 'train_input_lable0_{}.txt'.format(txt_lable_0_i))
    if not os.path.exists(corpus_path_0):
        f = open(corpus_path_0, 'w')
        f.close()
    not_scan_list = []
    for every_CVE in CVE_dirs:
        if '.txt' in every_CVE:
            continue
        if txt_lable_0_i >= 113:
            break
        not_scan_list.append(every_CVE)
        for every_CVE_other in CVE_dirs:
            if '.txt' in every_CVE_other:
                continue
            if txt_lable_0_i>=113:
                break
            if every_CVE_other not in not_scan_list:
                path1 = os.path.join(CVE_PATH, every_CVE)
                path1 = os.path.join(path1, 'cve_corpus.txt')
                path2 = os.path.join(CVE_PATH, every_CVE_other)
                path2 = os.path.join(path2, 'cve_corpus.txt')
                list1 = []
                list2 = []
                f = open(path1, 'r')
                list_temp1 = f.readlines()
                f.close()
                for every in list_temp1:
                    every = every.strip()
                    list1.append(every)
                f = open(path2, 'r')
                list_temp2 = f.readlines()
                f.close()

                #  num  为一个CVE的每一条选择和其他CVE正交的条数
                num = line_value
                if len(list_temp2) < line_value:
                    num = len(list_temp2)
                for i in range(num):
                    every = list_temp2[i].strip()
                    list2.append(every)

                # for every in list_temp2:
                #     every = every.strip()
                #     list2.append(every)

                for x in itertools.product(list1, list2):
                    str_temp = ''
                    str_temp += x[0]
                    str_temp += ' ??? '
                    str_temp += x[1]
                    str_temp += ' ???  0\n'
                    if txt_lable_0_i >= 113:
                        break
                    size = os.path.getsize(corpus_path_0)
                    if size != 0:
                        if size > 1024 * 1024 * 100:
                            txt_lable_0_i += 1
                            corpus_path_0 = os.path.join(output_0_path,
                                                         'train_input_lable0_{}.txt'.format(txt_lable_0_i))
                            if not os.path.exists(corpus_path_0):
                                f = open(corpus_path_0, 'w')
                                f.close()
                    f = open(corpus_path_0, 'a')
                    f.write(str_temp)
                    f.close()
                    print('lable 0 : This CVE done!')


def add_corpus():
    corpus1_path = r'E:\my_LSTM\deep-siamese-text-similarity-master\train_snli\testdata\corpus_1.txt'
    corpus0_path = r'E:\my_LSTM\deep-siamese-text-similarity-master\train_snli\testdata\corpus_0.txt'
    final_path = r'E:\my_LSTM\deep-siamese-text-similarity-master\train_snli\testdata\slice_corpus.txt'
    f = open(corpus1_path, 'r')
    temp_list = f.readlines()
    f.close()
    f = open(final_path, 'a')
    for every in temp_list:
        f.write(every)
    f.close()
    print('done!')
    f = open(corpus0_path, 'r')
    temp_list = f.readlines()
    f.close()
    f = open(final_path, 'a')
    for every in temp_list:
        f.write(every)
    f.close()
    print('done!')


if __name__ == "__main__":
    #   CVE_PATH存放切片路径
    # CVE_PATH = config.CVE_CORPUS_AFTER
    CVE_PATH = config.CVE_CORPUS_AST
    if os.path.exists(CVE_PATH)!=True:
        os.makedirs(CVE_PATH)

    global txt_lable_1_i
    global txt_lable_0_i
    txt_lable_1_i = 0
    txt_lable_0_i = 0
    # output_1_path = '../siamese-lstm-gpu/train_snli'
    # output_0_path = '../siamese-lstm-gpu/train_snli'
    # output_1_path = config.CVE_CORPUS_AFTER_RESULT
    # output_0_path = config.CVE_CORPUS_AFTER_RESULT

    output_1_path = config.CVE_CORPUS_AST_RESULT
    output_0_path = config.CVE_CORPUS_AST_RESULT

    if os.path.exists(output_1_path)!=True:
        os.makedirs(output_1_path)
    #   getCVEcorpus    去除CVE中重复的内容
    getCVEcorpus(CVE_PATH)
    # #   iter_self      每一个CVE得到标签为1的数据
    iter_self(CVE_PATH)
    #    将标签为1的数据放入文件夹
    get_1_corpus(CVE_PATH,output_1_path)
    #  line_value  为一个CVE的每一条选择和其他CVE正交的条数
    #   将标签为0的数据放入文件夹
    get_0_corpus(CVE_PATH,1,output_0_path)

    #  下面的函数可以注释掉
    # add_corpus()
    print('done!')




