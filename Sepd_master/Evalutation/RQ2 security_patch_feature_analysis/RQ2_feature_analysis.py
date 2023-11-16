import pandas as pd
from sklearn.preprocessing import StandardScaler # 用于特征标准化的类
import seaborn as sns # 用于绘制热图的工具包
# 降维包
from sklearn.decomposition import PCA  # 主成分分析器
from sklearn.manifold import TSNE # t-SNE库
import matplotlib.pyplot as plt # 用于绘制图形的工具包
# 初始化 StandardScaler
scaler = StandardScaler()

# 你的文件列表
after_files = ['/home/jcyang/data/destop/tracer-reomote/Patchlocator-master/Evalutation/RQ2/patch_features/after_commit_1.csv',
        '/home/jcyang/data/destop/tracer-reomote/Patchlocator-master/Evalutation/RQ2/patch_features/after_commit_2.csv',
        '/home/jcyang/data/destop/tracer-reomote/Patchlocator-master/Evalutation/RQ2/patch_features/after_commit_3.csv'
         ]
equal_files = '/home/jcyang/data/destop/tracer-reomote/Patchlocator-master/Evalutation/RQ2/patch_features/equal_commit_1.csv'
origin_files = '/home/jcyang/data/destop/tracer-reomote/Patchlocator-master/Evalutation/RQ2/patch_features/orginal_commit_1.csv'
# 读取 CSV 文件

#df = pd.read_csv(files) #error_bad_lines=False

def read_aftercommit():
    count=0
# 对每个文件进行处理
    for filename in after_files:
        # 读取 CSV 文件
        df = pd.read_csv(filename)
        # 对每一列进行标准化
        for column in df.columns:
            if column == "name":
                df = df.drop('name',axis = 1) #删除name列
                continue
            # 提取列中的数值
            values = df[column].values.reshape(-1, 1)

            # 将数值标准化
            scaled_values = scaler.fit_transform(values)

            # 将标准化的数值替换回 DataFrame
            df[column] = pd.DataFrame(scaled_values)
        if count==0:
            df_temp = df
        else:
            df_temp = pd.concat([df_temp,df],axis=0)
        count+=1
    return df_temp

def read_csv (path = None):
    if path is None:
        return
    df = pd.read_csv(path)
    # 对每一列进行标准化
    for column in df.columns:
        if column == "name":
            df = df.drop('name', axis=1)  # 删除name列
            continue
        # 提取列中的数值
        values = df[column].values.reshape(-1, 1)

        # 将数值标准化
        scaled_values = scaler.fit_transform(values)

        # 将标准化的数值替换回 DataFrame
        df[column] = pd.DataFrame(scaled_values)
    return df

# 可视化
def fea_combine(pca_after, pca_equal, pca_ori):
    #after
    df_aftercommit = pd.DataFrame(data=pca_after, columns=['Principal Component 1', 'Principal Component 2'])
    df_aftercommit['Synthesis method'] = 'AST Trans Patches'
    #equal
    df_equal = pd.DataFrame(data=pca_equal, columns=['Principal Component 1', 'Principal Component 2'])
    df_equal['Synthesis method'] = 'Locating Patches'
    #origin
    df_ori = pd.DataFrame(data=pca_ori, columns=['Principal Component 1', 'Principal Component 2'])
    df_ori['Synthesis method'] = 'NVD Patches'

    # 合并所有的 DataFrame 到一个 DataFrame
    df_sum = pd.concat([df_aftercommit, df_equal, df_ori])
    return  df_sum

def PCA_analysis(df_aftercommit, df_equal, df_ori):
    # 降维度
    pca = PCA(n_components=2)
    pca_df_after = pca.fit_transform(df_aftercommit)
    pca_df_equal = pca.fit_transform(df_equal)
    pca_df_ori = pca.fit_transform(df_ori)
    # 合并所有的 DataFrame 到一个 DataFrame

    #df_sum = fea_combine(pca_df_after, pca_df_equal, pca_df_ori)
    df_sum = Patch_Category_combine(pca_df_after, pca_df_equal, pca_df_ori)
    return df_sum

def Patch_Category_combine(pca_after, pca_equal, pca_ori):
    #after
    df_aftercommit = pd.DataFrame(data=pca_after, columns=['Principal Component 1', 'Principal Component 2'])

    #equal
    df_equal = pd.DataFrame(data=pca_equal, columns=['Principal Component 1', 'Principal Component 2'])

    df_systhesis = pd.concat([df_aftercommit, df_equal])
    df_systhesis['Patch Category'] = 'SeSp Synthesis Patches'

    #origin
    df_ori = pd.DataFrame(data=pca_ori, columns=['Principal Component 1', 'Principal Component 2'])
    df_ori['Patch Category'] = 'Natural Security Patches'

    # 合并所有的 DataFrame 到一个 DataFrame
    df_sum = pd.concat([df_systhesis, df_ori])
    return  df_sum

def TSNE_analysis(df_aftercommit, df_equal, df_ori):
    # 可以根据需要设置 n_components 和 perplexity 参数的值
    tsne = TSNE(n_components=2, perplexity=100)

    # 对每个 DataFrame 进行 t-SNE
    tsne_df_after = tsne.fit_transform(df_aftercommit)
    tsne_df_equal = tsne.fit_transform(df_equal)
    tsne_df_ori = tsne.fit_transform(df_ori)

    # 将它们转换回 DataFrame，并添加 'patch_type' 列
    df_aftercommit = pd.DataFrame(data=tsne_df_after, columns=['Principal Component 1', 'Principal Component 2'])
    df_aftercommit['patch_type'] = 'aftercommit'

    df_equal = pd.DataFrame(data=tsne_df_equal, columns=['Principal Component 1', 'Principal Component 2'])
    df_equal['patch_type'] = 'equal'

    df_ori = pd.DataFrame(data=tsne_df_ori, columns=['Principal Component 1', 'Principal Component 2'])
    df_ori['patch_type'] = 'origin'
    # 合并所有的 DataFrame 到一个 DataFrame

    df_sum = pd.concat([df_aftercommit, df_equal, df_ori])

    return df_sum

if __name__ == '__main__':
    # 1.特征向量化 读取 CSV 文件
    df_aftercommit = read_aftercommit()
    df_equal = read_csv(equal_files)
    df_ori = read_csv(origin_files)

    # 2.降维度 可选的有3种方法 1.主成分分析 2.线性判别分析 3.核主成分分析

    df_sum = PCA_analysis(df_aftercommit,df_equal, df_ori) # 主成分分析
    #df_sum = PCA_analysis(df_aftercommit, df_equal, df_ori) # 主成分分析

    #df_sum = TSNE_analysis(df_aftercommit, df_equal, df_ori) # t-SNE

    # 2.补丁特征关系分析，
    # 2.1 散点图矩阵
    plt.figure(figsize=(10, 6))
    sns.set_style("darkgrid") # ticks white darkgrid
    sns.set_context('paper')
    sns.scatterplot(data=df_sum, x='Principal Component 1', y='Principal Component 2', hue='Patch Category',palette=['gray', 'red'])# , 'blue'  Patch Category 'Synthesis method'



    # sns.pairplot(df_aftercommit)
    # sns.pairplot(df_equal)
    # sns.pairplot(df_ori)

    # 3.画图
    # 添加标题和轴标签

    #plt.title('T-sne of Patches')
    # plt.title('Principal Component Analysis of Three Patch Synthesis Methods')

    plt.title('Principal Component Analysis of \n Patch Synthesis Methods and Natural Security Patches')
    plt.xlabel('Principal Component 1')
    plt.ylabel('Principal Component 2')

    # 显示图形
    #plt.show()
    plt.savefig('PCA_analysis.png', dpi=800)








    