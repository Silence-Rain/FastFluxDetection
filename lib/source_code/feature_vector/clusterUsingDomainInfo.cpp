#include "clusterUsingDomainInfo.h"

//解析line 得到 域名 -IP -time -isupdate isTraining is false after cluster get features
struct domain_IP_TTl_ clusterUsingDomainInfo::parsingDomainIPString(string line,bool isTraining)
{
    //提取域名，插入到容器中
    struct domain_IP_TTl_ domianIPInfo;
    domianIPInfo.IPList.clear();
    size_t clabel;
    string subline;
    clabel = line.find_last_of(',');
    int traingDataFlag = atoi(line.substr(clabel + 1,line.length() - clabel - 1).c_str());
    subline = line.substr(0,clabel);
    size_t lable = subline.find_first_of(',');
    domianIPInfo.domainName = subline.substr(0, lable);
    size_t IPlabel = subline.find_first_of(':', lable +1);
    if(IPlabel != string::npos)
    {
        for(size_t index = lable; index < IPlabel;)
        {
            size_t lab = subline.find_first_of(',', index +1);
            if(lab != string::npos && lab <= IPlabel)
            {
                string IP = subline.substr(index + 1,lab - index -1);
                domianIPInfo.IPList.insert(IP);
                index = lab;
                IP.clear();
            }
            else if (lab > IPlabel)
            {
                string IP = subline.substr(index + 1,IPlabel - index -1);
                domianIPInfo.IPList.insert(IP);
                IP.clear();
                break;
            }
        }
        size_t timelab = subline.find_first_of(',', IPlabel +1);
        domianIPInfo.elapseTime = atoi(subline.substr(IPlabel +1, timelab- IPlabel -1).c_str());
        size_t updatelab = subline.find_first_of(',', timelab +1);
        domianIPInfo.isupdate = atoi(subline.substr(timelab +1, updatelab -timelab -1).c_str());
        size_t rolelab = subline.find_first_of(',', updatelab +1);
        domianIPInfo.role = atoi(subline.substr(updatelab +1, rolelab - updatelab  -1).c_str());
        size_t countrylab = subline.find_last_of(',');
        float ipPercentage = (atof(subline.substr(countrylab +1,subline.length() - countrylab -1).c_str()))
                              /domianIPInfo.IPList.size();
        domianIPInfo.ipLocationEntroy = ipPercentage;
    }
    else
    {
        domianIPInfo.IPList.clear();
        string empstr = "";
        domianIPInfo.IPList.insert(empstr);
        size_t timelab = subline.find_first_of(',', lable +1);
        domianIPInfo.elapseTime = atoi(subline.substr(lable +1, timelab- lable -1).c_str());
        size_t updatelab = subline.find_first_of(',', timelab +1);
        domianIPInfo.isupdate = atoi(subline.substr(timelab +1, updatelab -timelab -1).c_str());
        size_t rolelab = subline.find_first_of(',', updatelab +1);
        domianIPInfo.role = atoi(subline.substr(updatelab +1, rolelab - updatelab  -1).c_str());
        size_t countrylab = subline.find_last_of(',');
        float ipPercentage = (atof(subline.substr(countrylab +1,subline.length() - countrylab -1).c_str()))
                              /domianIPInfo.IPList.size();
        domianIPInfo.ipLocationEntroy = ipPercentage;
        
    }
    if(isTraining == true)
    {
        domianIPInfo.traingFlag = traingDataFlag;
    }
    else
    {
        domianIPInfo.traingFlag = 2;//表示测试数据
    }
    return domianIPInfo;
}
//初始化域名后缀
void clusterUsingDomainInfo::initFun()
{
    m_trieTree = new trieTree();
    m_DGA_detection.init_dns_suf_set();
    m_DGA_detection.init_legal_domain_set();
    m_trieTree->constructTrieTree(Dict_File_Normailized);
}
//解析域名字符串，提取域名的2LD和3LD 如www.baidu.com 2d:baidu
nLdDomainLevel clusterUsingDomainInfo::getDomainNLDs(string domainName)
{
    size_t label;
    size_t slabel;
    char *secondLevelDomain = NULL;
    string secondLevelDomainStr;
    string secondLevelDomainLabel;
    string thirdLevelDomain;
    string subDomain;
    m_domainLDs.secondLD.clear();
    m_domainLDs.thirdLD.clear();
    char *dname = (char*)domainName.c_str();
    if(dname != NULL)
    {
        secondLevelDomain = m_DGA_detection.get_primary_domain(dname);
    }
    if(secondLevelDomain == NULL)
    {
        m_domainLDs.secondLD = "";
        m_domainLDs.thirdLD = "";
        return m_domainLDs;
    }
    secondLevelDomainStr.clear();
    secondLevelDomainStr.assign(secondLevelDomain);
    slabel = secondLevelDomainStr.find_first_of('.');
    secondLevelDomainLabel= secondLevelDomainStr.substr(0, slabel);
    m_domainLDs.secondLD = secondLevelDomainLabel;
    subDomain = domainName.substr(0, domainName.length() - secondLevelDomainStr.length());
    if(subDomain.length() == 0)
    {
        m_domainLDs.thirdLD = "";
    }
    else
    {
        label = subDomain.find_last_of('.');
        string subThirDomian = subDomain.substr(0, label);
        int index = subThirDomian.find_last_of('.');
        if(index == string::npos)
        {
            m_domainLDs.thirdLD = subThirDomian;
        }
        else
        {
            thirdLevelDomain = subDomain.substr(index + 1, subThirDomian.length() - index - 1);
            m_domainLDs.thirdLD = thirdLevelDomain;
        }
    }
    return  m_domainLDs;
}
//统计NLD个数
int clusterUsingDomainInfo::tLDCountsInDomain(string domainName)
{
    int counts = 2;
    size_t label;
    size_t slabel;
    char *secondLevelDomain = NULL;
    string secondLevelDomainStr;
    string secondLevelDomainLabel;
    string thirdLevelDomain;
    string subDomain;
    char *dname = (char*)domainName.c_str();
    if(dname != NULL)
    {
        secondLevelDomain = m_DGA_detection.get_primary_domain(dname);
    }
    else
    {
        return -1;
    }
    secondLevelDomainStr.clear();
    secondLevelDomainStr.assign(secondLevelDomain);
    m_domainLDs.secondLD = secondLevelDomainLabel;
    subDomain = domainName.substr(0, domainName.length() - secondLevelDomainStr.length() );
    if(subDomain.length()!=0)
    {
        for(int i = 0; i< subDomain.length();i++)
        {
            if(subDomain.at(i) == '.')
            {
                counts++;
            }
        }
        return counts;
    }
    else
    {
        return counts;
    }
}
//计算域名ngram， para string domainName 仅表示域名标签 如baidu.com 仅baidu
set<string> clusterUsingDomainInfo::n_GramFeatureCalcu(string domainName, int n)
{
    set<string>ngramVec;
    ngramVec.clear();
    string ngram;
    if(domainName.length() != 0)
    {
        for(int i = 0 ; i < domainName.length();i++)
        {
            if(domainName.length() - i >=n)
            {
                ngram = domainName.substr(i,n);
                ngramVec.insert(ngram);
                ngram.clear();
            }
        }
    }
    return ngramVec;
}
double clusterUsingDomainInfo::ngramValue(set<string>ngrams,Trie_node root)
{
    vector<int>ngramNums;
    ngramNums.clear();
    double average = 0.0;
    int counts = 0;
    unsigned int sum = 0;
    unsigned int doubleSum = 0;
    char *tmptr = NULL;
    if(root == NULL)
    {
        cout<<"trieTree create is not successful"<<endl;
        return -1;
    }
    else
    {
        if(ngrams.size() !=0 )
        {
            for(set<string>::iterator iter = ngrams.begin();iter!= ngrams.end();++iter)
            {
                tmptr = (char*)(*iter).c_str();
                counts = m_trieTree->statisticsNgramsOccurenceTimes(root, tmptr);
                sum += counts;
                ngramNums.push_back(counts);
            }
            double avg = double(sum)/ngrams.size();
            int temp = (int)avg*100;
            average= ((double)temp)/100;
        }
        else
        {
            average = 0.0;
        }
    }
    return average;
}
//基于提取得到的域名ngram，统计其在字典中出现的次数,得到其平均值、方差、中位数
vector<double> clusterUsingDomainInfo::nGramAverageAnddeviationCalcu(set<string>ngrams,Trie_node root)
{
    vector<double> retal;
    vector<int>ngramNums;
    ngramNums.clear();
    double average = 0.0;
    double deviation = 0.0;
    double standardDevi = 0.0;
    double median;
    int counts = 0;
    unsigned int sum = 0;
    unsigned int doubleSum = 0;
    char *tmptr = NULL;
    if(root == NULL)
    {
        cout<<"trieTree create is not successful"<<endl;
        exit(0);
    }
    else
    {
        if(ngrams.size() !=0 )
        {
            for(set<string>::iterator iter = ngrams.begin();iter!= ngrams.end();++iter)
            {
                tmptr = (char*)(*iter).c_str();
                counts = m_trieTree->statisticsNgramsOccurenceTimes(root, tmptr);
                sum += counts;
                ngramNums.push_back(counts);
            }
            double avg = double(sum)/ngrams.size();
            int temp = (int)avg*100;
            average= ((double)temp)/100;
            for(vector<int>::iterator it = ngramNums.begin();it != ngramNums.end();++it)
            {
                doubleSum += (*it - average)*(*it - average);
            }
            deviation = double(doubleSum)/ngrams.size(); //方差
            standardDevi = (double(int(sqrt(deviation)*100) )/100); //标准差
            median = medianCalcu(ngramNums);
        }
        else
        {
            average = 0.0;
            standardDevi = 0.0;
            median = 0.0;
        }
    }
    retal.push_back(average);
    retal.push_back(standardDevi);
    retal.push_back(median);
    return retal;
}
//nGram特征的中位数计算
double clusterUsingDomainInfo::medianCalcu(vector<int>ngramSet)
{
    double median;
    sort(ngramSet.begin(),ngramSet.end());
    int n = ngramSet.size();
    if( n%2 == 1)
    {
        median = ngramSet[n/2];
    }
    else
    {
        median = double((ngramSet[n/2] + ngramSet[n/2 -1 ]))/2;
    }
    return median;
}
//计算 domain 2LD 3LD熵 para:domianLD;
double clusterUsingDomainInfo::getEntroy(string domainName)
{
    double Hx = 0.0;
    double tmp = 0.0;
    map<char,int>characNum;
    int counts = 1;
    map<char,int>::iterator iter = characNum.begin();
    characNum.clear();
    for(int i = 0; i < domainName.length(); i++)
    {
        if(characNum.size() == 0)
        {
            characNum.insert(make_pair<char,int>(domainName.at(i),counts));
        }
        else
        {
            iter = characNum.find(domainName.at(i));
            if(iter == characNum.end())
            {
                characNum.insert(make_pair<char,int>(domainName.at(i),counts));
            }
            else
            {
                char chac = iter->first;
                int nums = iter->second;
                nums = nums + 1;
                characNum.erase(iter);
                characNum.insert(make_pair<char,int>(chac,nums));
            }
        }
    }
    for(map<char,int>::iterator it = characNum.begin(); it != characNum.end();++it)
    {
        double prob = double(it->second)/domainName.length();
        tmp -= prob*log2(prob);
    }
    int entroy = (int)(tmp*100);
    Hx = ((double) entroy)/100;
    if(Hx !=0)
    {
        return  Hx;
    }
    else
    {
        return 0.0;
    }
}
int clusterUsingDomainInfo::lengthOfNLDs(string dnameNld)//计算NLD的长度
{
    if(dnameNld.length() !=0)
    {
        return dnameNld.length();
    }
    else
    {
        return 0;
    }
}
int clusterUsingDomainInfo::lengthOfDomain(string domainName)
{
    return domainName.length();
}
//get numericPercentageInDomain
double clusterUsingDomainInfo::numericPercentageInDomain(string domainName)
{
    double percentage = 0.0;
    int counts = 0;
    if(domainName.length() != 0)
    {
        for(int i = 0; i< domainName.length();i++)
        {
            if(( domainName.at(i) >='0')&&(domainName.at(i) <='9') )
            {
                counts++;
            }
        }
        percentage = double(counts)/domainName.length();
    }
    else
    {
        percentage = 0.0;
    }
    return percentage;
}
trieTree* clusterUsingDomainInfo::getTrieTree()
{
    return m_trieTree;
}
clusterUsingDomainInfo::~clusterUsingDomainInfo()
{
    delete m_trieTree;
}
//集合并运算
set<string> operator+(const set<string> &a, const set<string>& b)
{
	set<string> temp;
	temp = a;
	for(set<string>::iterator iter = b.begin(); iter!= b.end();++iter)
	{
		temp.insert(*iter);
	}
	return temp;
}
//集合交运算
set<string> operator*(const set<string> &a, const set<string>& b)
{
	set<string> temp1,temp2;
	temp1 = a;
	for(set<string>::iterator iter = b.begin(); iter!= b.end();++iter)
	{
		if(temp1.find(*iter) != temp1.end())
		{
			temp2.insert(*iter);
		}
	}
	return temp2;
}
void clusterUsingDomainInfo::ngramCalcu(const char* rfilebuf,const char* wfilebuf,Trie_node root,
                                        bool isbenign)
{
    nLdDomainLevel m_Level;
    string line;
    set<string> onegrams;
    set<string> twograms;
    set<string> threegrams;
    double tmp1 = 0.0;
    double tmp2 = 0.0;
    double tmp3 = 0.0;
    vector<double>ngrams;
    ifstream fin(rfilebuf,ios::in);
    if(!fin.is_open())
    {
        cout<<"open file error:"<<rfilebuf<<endl;
        return;
    }
    ofstream fout(wfilebuf,ios::out);
    if(!fout.is_open())
    {
        cout<<"open file error:"<<wfilebuf<<endl;
        return;
    }
    while(!fin.eof() ) //all the domian
    {
        onegrams.clear();
        twograms.clear();
        threegrams.clear();
        getline(fin, line);
        if(line.size() == 0 )
        {
            continue;
        }
        else
        {
            size_t lab = line.find_first_of(',');
            string domain = line.substr(0,lab);
            m_Level = getDomainNLDs(domain);
            if(m_Level.secondLD.length() != 0)
            {
                onegrams = n_GramFeatureCalcu(m_Level.secondLD,1);
                twograms = n_GramFeatureCalcu(m_Level.secondLD,2);
                threegrams = n_GramFeatureCalcu(m_Level.secondLD,3);
                tmp1 = ngramValue(onegrams,root);
                tmp2 = ngramValue(twograms,root);
                tmp3 = ngramValue(threegrams,root);
                ngrams.push_back(tmp1);
                ngrams.push_back(tmp2);
                ngrams.push_back(tmp3);
                tmp1 = 0.0;
                tmp2 = 0.0;
                tmp3 = 0.0;
            }
            else
            {
                continue;
            }
        }
        fout<<line<<",";
        for(int i  = 0; i< ngrams.size();i++)
        {
                fout<<ngrams.at(i)<<",";
        }
        if(isbenign == true)
        {
            fout<<0<<endl;
        }
        else
        {
            fout<<1<<endl;
        }
        ngrams.clear();
    }
}
void clusterUsingDomainInfo::featureVectorCalcu(map<int,vector<struct domain_IP_TTl_> >domainIpPara,
                                        Trie_node root,const char *wfilebuf,bool isTraing)
{
    for(map<int,vector<struct domain_IP_TTl_> >::iterator iter = domainIpPara.begin();
        iter != domainIpPara.end();++iter)
    {
        featureVectorCalculate(iter->second,root,wfilebuf,isTraing);
    }
}
void clusterUsingDomainInfo::featureVectorCalculate(vector<struct domain_IP_TTl_>domains,
                                        Trie_node root,const char *wfilebuf,bool isTraing)
{
    vector<double> temp;
    set<string>sgramsOfsecLD;
    set<string>sgramsOfthirLD;
    set<string>tgramsOfsecLD;
    set<string>tgramsOfthirLD;
    vector<double>ssAverDeviation;  //2ld_2gram
    vector<double>tsAverDeviation;  //3ld_2gram
    vector<double>stAverDeviation;  //2ld_3gram
    vector<double>ttAverDeviation;  //3ld_3gram
    double secLDEntroy;
    double thirLDEntroy;
    int countNLDs;
    int lenofsLD;
    int lenoftLD;
    int lenofDomain;
    double perofSec;
    double perofThir;
    nLdDomainLevel nLdDomainstruct;
    int counts = 0;
    ofstream fout(wfilebuf, ios::out|ios::app);
    if(!fout.is_open())
    {
        cout<<"create featureVector file error"<<endl;
        return;
    }
    for(vector<struct domain_IP_TTl_>::iterator iter = domains.begin(); iter != domains.end();++iter)
    {
        nLdDomainstruct = getDomainNLDs(iter->domainName);//提取二级域名及三级域名
        //ngram 计算
        sgramsOfsecLD =  n_GramFeatureCalcu(nLdDomainstruct.secondLD, 2);
        sgramsOfthirLD = n_GramFeatureCalcu(nLdDomainstruct.thirdLD, 2);
        tgramsOfsecLD =  n_GramFeatureCalcu(nLdDomainstruct.secondLD, 3);
        tgramsOfthirLD = n_GramFeatureCalcu(nLdDomainstruct.thirdLD, 3);
        //平均值、方差计算
        ssAverDeviation = nGramAverageAnddeviationCalcu(sgramsOfsecLD,root);
        tsAverDeviation = nGramAverageAnddeviationCalcu(sgramsOfthirLD,root);
        stAverDeviation =  nGramAverageAnddeviationCalcu(tgramsOfsecLD,root);
        ttAverDeviation =  nGramAverageAnddeviationCalcu(tgramsOfthirLD,root);
        //Entroy 计算
        secLDEntroy =  getEntroy(nLdDomainstruct.secondLD);
        thirLDEntroy = getEntroy(nLdDomainstruct.thirdLD);
        //nLd计算及二、三级域名长度
        //countNLDs = tLDCountsInDomain(iter->domainName);
        lenofsLD = lengthOfNLDs(nLdDomainstruct.secondLD);
        lenoftLD = lengthOfNLDs(nLdDomainstruct.thirdLD);
        lenofDomain = lengthOfDomain(iter->domainName);
        //计算数字比率
        perofSec = numericPercentageInDomain(nLdDomainstruct.secondLD);
        perofThir = numericPercentageInDomain(nLdDomainstruct.thirdLD);
        for(vector<double>::iterator it = ssAverDeviation.begin(); it!= ssAverDeviation.end();++it)
        {
            //2gram,2lD average median deviation;
            temp.push_back(*it);
        }
        for(vector<double>::iterator it = stAverDeviation.begin(); it!= stAverDeviation.end();++it)
        {
            //3gram,2lD average median deviation;
            temp.push_back(*it);
        }
        for(vector<double>::iterator it = tsAverDeviation.begin(); it!= tsAverDeviation.end();++it)
        {
            //2gram,3lD average median deviation;
            temp.push_back(*it);
        }
        for(vector<double>::iterator it = ttAverDeviation.begin(); it!= ttAverDeviation.end();++it)
        {
            //3gram,3lD average median deviation;
            temp.push_back(*it);
        }
        temp.push_back(secLDEntroy);
        temp.push_back(thirLDEntroy);
        temp.push_back(double(lenofsLD));
        temp.push_back(double(lenoftLD));
        temp.push_back(perofSec);
        temp.push_back(perofThir);
        if(isTraing == true)
        {
            temp.push_back((double)iter->traingFlag);
        }
        //写文件;
        fout<<iter->domainName<<",";
        for(int i = 0; i < temp.size(); i++)
        {
            if( (i + 1) == temp.size())
            {
                fout<<temp.at(i);
            }
            else
            {
                fout<<temp.at(i)<<",";
            }
        }
        fout<<endl;
        //clear 变量
        temp.clear();
        sgramsOfsecLD.clear();
        sgramsOfthirLD.clear();
        tgramsOfsecLD.clear();
        tgramsOfthirLD.clear();
        ssAverDeviation.clear();  //2ld_2gram
        tsAverDeviation.clear();  //3ld_2gram
        stAverDeviation.clear();  //2ld_3gram
        ttAverDeviation.clear(); //3ld_3gram
        secLDEntroy = 0.0;
        thirLDEntroy =0.0;
        countNLDs = 0;
        lenofsLD = 0;
        lenoftLD = 0;
        lenofDomain = 0;
        perofSec = 0.0;
        perofThir = 0.0;
        nLdDomainstruct.secondLD.clear();
        nLdDomainstruct.thirdLD.clear();
    }
    fout.close();
}
//读取训练数据、测试数据到map,便于特征提取//isTraining == 0 traing file 1:test file
map<int,vector<struct domain_IP_TTl_> > clusterUsingDomainInfo::getDomainFromInfoTestFile(
                                        const char *rFilebuff,bool isTraining)
{
    struct domain_IP_TTl_  tmpdomain_IP;
    vector<struct domain_IP_TTl_> tempdomaineVector;
    map<int,vector<struct domain_IP_TTl_> >domain_IP_map;
    int counts = 0;
    string line;
    string dname;
    ifstream fin(rFilebuff,ios::in);
    if(!fin.is_open())
    {
        cout<<"open rfile:"<<rFilebuff<<":error:"<<endl;
        exit(0);
    }
    while(!fin.eof() ) //读文件，一次读取一行，解析相关字段内容，直到读到文件末尾。
    {
        tmpdomain_IP.IPList.clear();
        tmpdomain_IP.domainName.clear();
        getline(fin, line);
        if(line.size() == 0 )
        {
            continue;
        }
        else
        {
            if(isTraining == false)//test data
            {
                size_t clabel = line.find_last_of(',');
                string cluster = line.substr(clabel + 1, line.length());
                int cflag = atoi(cluster.c_str());
                tmpdomain_IP = parsingDomainIPString(line,isTraining);
                if(domain_IP_map.size() == 0)
                {
                    tempdomaineVector.push_back(tmpdomain_IP);
                    domain_IP_map.insert(make_pair<int,vector<struct domain_IP_TTl_> >(cflag,tempdomaineVector));
                    tempdomaineVector.clear();
                }
                else
                {
                    map<int,vector<struct domain_IP_TTl_> >::iterator its = domain_IP_map.find(cflag);
                    if(its != domain_IP_map.end())//类标存在
                    {
                        struct domain_IP_TTl_  curdomain_IP;
                        curdomain_IP = tmpdomain_IP;
                        vector<struct domain_IP_TTl_> curdomaineVector = its->second;
                        curdomaineVector.push_back(curdomain_IP);
                        domain_IP_map.erase(cflag);
                        domain_IP_map.insert(make_pair<int,vector<struct domain_IP_TTl_> >(cflag,curdomaineVector));
                    }
                    else
                    {
                        tempdomaineVector.push_back(tmpdomain_IP);
                        domain_IP_map.insert(make_pair<int,vector<struct domain_IP_TTl_> >(cflag,tempdomaineVector));
                    }
                }
            }
            else
            {
                tmpdomain_IP = parsingDomainIPString(line,isTraining);
                tempdomaineVector.push_back(tmpdomain_IP);
            }
        }
    }
    if(isTraining == true)
    {
        domain_IP_map.insert(make_pair<int,vector<struct domain_IP_TTl_> >(0,tempdomaineVector));
    }
    fin.close();
    return domain_IP_map;
}
extern "C" {
    clusterUsingDomainInfo obj;
    map<int,vector<struct domain_IP_TTl_> > domainMap;
    void init()
    {
        obj.initFun();
    }
    void getFeatureVector(const char* rfile, const char* wfile)
    {
        domainMap = obj.getDomainFromInfoTestFile(rfile, false);
        obj.featureVectorCalcu(domainMap, obj.getTrieTree()->getTrieTreeRoot(), wfile, false);
    }
}