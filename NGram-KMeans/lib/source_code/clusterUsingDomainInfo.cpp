#include "clusterUsingDomainInfo.h"
clusterUsingDomainInfo::clusterUsingDomainInfo()
{
}
void clusterUsingDomainInfo::alexTopAMillionProcess(const char *rFilebuff,const char *wFilebuff)
{
    ifstream fin(rFilebuff);
    if(!fin.is_open())
    {
        cout<<"create file error:"<<rFilebuff<<endl;
        return;
    }
    ofstream fout (wFilebuff,ios::out);
    if(!fout.is_open())
    {
        cout<<"create file error:"<<wFilebuff<<endl;
        return;
    }
    string line;
    while(!fin.eof() ) //读文件，一次读取一行，解析相关字段内容，直到读到文件末尾。
    {
        getline(fin, line);
        if(line.size() == 0 )
        {
            continue;
        }
        else
        {
            size_t index = line.find_first_of(',');
            if(index!= string::npos)
            {
                string domain = line.substr(index + 1, line.length() - index -1);
                fout<<domain<<endl;
                domain.clear();
            }
        }
    }
    fin.close();
    fout.close();
}
//过滤重复的Malicious Domains
void clusterUsingDomainInfo::filterMaliciousDomains(const char *rFilebuff,const char *wFilebuff)
{
    set<string>malicious;
    string line;
    ifstream fin(rFilebuff,ios::in);
    if(!fin.is_open())
    {
        cout<<"open rfile:"<<rFilebuff<<":error:"<<endl;
		return;
    }
    ofstream fout(wFilebuff,ios::out);
    if(!fout.is_open())
    {
        cout<<"open rfile:"<<wFilebuff<<":error:"<<endl;
		return;
    }
    while(!fin.eof() ) //读文件，一次读取一行，解析相关字段内容，直到读到文件末尾。
    {
        getline(fin, line);
        if(line.size() == 0 )
        {
            continue;
        }
        else
        {
            malicious.insert(line);
        }
    }
    for(set<string>::iterator iter = malicious.begin();iter!=malicious.end();++iter)
    {
        fout<<*iter<<endl;
    }
    fin.close();
    fout.close();
}
u_long clusterUsingDomainInfo::ip2long(const char *ip)
{
    u_long iplong;
    iplong = ntohl(inet_addr(ip));
    return  iplong;
}
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
void clusterUsingDomainInfo::outputDnsAbstractFile(const char *rFilebufAbstract,
                                                   const char *wFilebufAbstract)
{
    //读取DNS摘要文件，提取该域名的主域名，判断该主域名是否位于白名单中，若存在则
    //过滤否则输出到文件
    m_DGA_detection.readDNSAbstractFile(rFilebufAbstract,wFilebufAbstract);
}
set<string> clusterUsingDomainInfo::readIPBlacklist(const char *rfilebuff)
{
    set<string>ipBlackList;
    string line;
    string ipstr;
    ifstream fin (rfilebuff,ios::in);
    char tmp[32];
    while(!fin.eof())
    {
        line.clear();
        getline(fin, line);
        if(line.size() == 0 )
        {
            continue;
        }
        else
        {
            memset(tmp,0,sizeof(tmp));
            long ip = long(ip2long(line.c_str()));
            sprintf(tmp,"%ld",ip);
            ipstr.assign(tmp);
            ipBlackList.insert(ipstr);
        }
    }
    fin.close();
    return ipBlackList;
}
//实现domain ：IP1，iP2...IPn 映射,过滤掉IP黑名单中的域名 ,
//blackdomainfile :ip黑名单中对应的domain,whois role is 2 的域名
void clusterUsingDomainInfo::processorDomainFile(const char *rFilebuf,const char *ipblackfi,
                            const char *wFilebuf,const char *blackdomainfile)
{
    map<string, set<string> >tempMap;
    set<string>IPList;
    tempMap.clear();
    string line;
    ifstream fin(rFilebuf,ios::in);
    if(!fin.is_open())
    {
        cout<<"open file error:"<<rFilebuf<<endl;
        return;
    }
    ofstream fout(wFilebuf, ios::out);
    if(!fout.is_open())
    {
        cout<<"create file error:"<<wFilebuf<<endl;
        return;
    }
    ofstream fblackout(blackdomainfile, ios::out|ios::app);
    if(!fblackout.is_open())
    {
        cout<<"create file error:"<<blackdomainfile<<endl;
        return;
    }
    set<string>ipblacklist;
    ipblacklist.clear();
    set<string>::iterator ipblackiter;
    string resolved_IP;
    ipblacklist = readIPBlacklist(ipblackfi);
    while(!fin.eof())
    {
        IPList.clear();
        getline(fin, line);
        if(line.size() == 0 )
        {
            continue;
        }
        else
        {
            //提取当前行的 域名、解析IP
            size_t lable1 = line.find_first_of(',');
            if(lable1 == string::npos)//没有IP
            {
                continue;
            }
            else
            {
                for(size_t index = lable1; index < line.length();)
                {
                    size_t lab = line.find_first_of(',',index + 1);
                    if(lab != string::npos)
                    {
                        resolved_IP.clear();
                        resolved_IP = line.substr(index + 1, lab - index - 1);
                        ipblackiter = ipblacklist.find(resolved_IP);
                        if(ipblackiter != ipblacklist.end())
                        {
                            fblackout<<line<<endl;
                            break;
                        }
                        else
                        {
                            index = lab;
                        }
                    }
                    else
                    {
                        resolved_IP.clear();
                        resolved_IP = line.substr(index + 1, line.length() - index - 1);
                        ipblackiter = ipblacklist.find(resolved_IP);
                        if(ipblackiter != ipblacklist.end())
                        {
                            fblackout<<line<<endl;
                            break;
                        }
                        else
                        {
                            fout<<line<<endl;
                            break;
                        }
                    }
                }
            }
        }
    }
    fin.close();
    fout.close();
    fblackout.close();
}
void clusterUsingDomainInfo::normalizeDict(const char *rFilebuf, const char *wFilebuf)
{
    string line;
    string::iterator iter;
    ifstream fin(rFilebuf,ios::in);
    if(!fin.is_open())
    {
        cout<<"open dict file error"<<endl;
        exit(0);
    }
    ofstream fout(wFilebuf,ios::app);
    if(!fout.is_open())
    {
        cout<<"create dict file error"<<endl;
        exit(0);
    }
    while(!fin.eof())
    {
        getline(fin, line);
        if(line.size() == 0 )
        {
            continue;
        }
        else
        {
            for(iter = line.begin(); iter!= line.end();++iter)
            {
                if((*iter >= 'a')&&(*iter <= 'z') )
                {
                    ;
                }
                else
                {
                    break;
                }
            }
            if(iter == line.end())
            {
                fout<<line<<endl;
            }
        }
    }
    fin.close();
}
vector<string> clusterUsingDomainInfo::getDomainSet()
{
    return m_sdomain;
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
time_t clusterUsingDomainInfo::MakeTime(string &str)
{
    // str 格式为： 10-sep-2015
    for(size_t i = 0 ;i < str.length(); i++)
    {
        if(isupper(str[i]))
        {
            str[i] = str[i] +32;
        }
    }
    map<string,string>dict;
    dict.insert(make_pair<string,string>("jan","1"));
    dict.insert(make_pair<string,string>("feb","2"));
    dict.insert(make_pair<string,string>("mar","3"));
    dict.insert(make_pair<string,string>("apr","4"));
    dict.insert(make_pair<string,string>("may","5"));
    dict.insert(make_pair<string,string>("jun","6"));
    dict.insert(make_pair<string,string>("jul","6"));
    dict.insert(make_pair<string,string>("aug","8"));
    dict.insert(make_pair<string,string>("sep","9"));
    dict.insert(make_pair<string,string>("oct","10"));
    dict.insert(make_pair<string,string>("nov","11"));
    dict.insert(make_pair<string,string>("dec","12"));
	struct tm tmStruct ;
	TimeSpec ts;
	memset(&tmStruct, 0, sizeof(tmStruct));
	memset(&ts, 0, sizeof(ts));
	time_t timep = 0;
	if (str.empty())
	{
		return timep;
	}else
	{
	    size_t flabel  = str.find_first_of('-');
	    size_t elabel  = str.find_last_of('-');
	    string month = str.substr(flabel + 1, elabel - flabel - 1);
	    map<string,string>::iterator iter = dict.find(month);
	    if(iter!= dict.end())
        {
            str.replace(flabel + 1,month.length(),iter->second);
        }
	}
	sscanf(str.c_str(), "%d-%d-%d", &ts.mday,&ts.month,&ts.year);
	tmStruct.tm_year = ts.year - 1900;
	tmStruct.tm_mon = ts.month - 1;
	tmStruct.tm_mday = ts.mday;
	tmStruct.tm_hour = 0;
	tmStruct.tm_min = 0;
	tmStruct.tm_sec = 0;
	tmStruct.tm_isdst = 0;
	timep = mktime(&tmStruct);
	return timep;
}
//二级域名分组
map<string,vector<string> > clusterUsingDomainInfo::secondLDGrouping(const char*rFilebuff)
{
    map<string,vector<string> > m_dnameGrouping;
    m_dnameGrouping.clear();
    char *secondLevelDomain = NULL;
    char *dNameCharPtr = NULL;
    string secondLevelDomainStr;
    vector<string>temp;
    temp.clear();
    string temp2LDstr ;
    vector<string>tmpVec ;
    set<string> m_sdomain;
    ifstream fin (rFilebuff,ios::in);
    string line;
    string domain;
    int count = 0;
    while(!fin.eof() ) //读文件，一次读取一行，解析相关字段内容，直到读到文件末尾。
    {
        getline(fin, line);
        if(line.size() == 0 )
        {
            continue;
        }
        else
        {
            size_t label = line.find_first_of(',');
            if(label!= string::npos)
            {
                domain = line.substr(0,label);
            }
            else
            {
                domain = line;
            }
            dNameCharPtr = (char*)domain.c_str();
            
            secondLevelDomain = m_DGA_detection.get_primary_domain(dNameCharPtr);
            
            if(secondLevelDomain == NULL)
            {
                continue;
            }
            secondLevelDomainStr.clear();
            secondLevelDomainStr.assign(secondLevelDomain);
            
            if(m_dnameGrouping.size() == 0) 
            {
                temp.push_back(line);
                m_dnameGrouping.insert(make_pair<string,vector<string> >(secondLevelDomainStr,temp));
                temp.clear();
            }
            else
            {
                map<string,vector<string> > ::iterator itf = m_dnameGrouping.find(secondLevelDomainStr);
                if(itf == m_dnameGrouping.end())
                {
                    temp.push_back(line);
                    m_dnameGrouping.insert(make_pair<string,vector<string> >(secondLevelDomainStr,temp));
                    temp.clear();
                }
                else
                {
                    temp2LDstr = itf->first;
                    tmpVec = itf->second;
                    tmpVec.push_back(line);
                    m_dnameGrouping.erase(itf);
                    m_dnameGrouping.insert(make_pair<string,vector<string> >(temp2LDstr,tmpVec));
                    temp2LDstr.clear();
                    tmpVec.clear();
                }
            }
        }
    }
    return m_dnameGrouping;
}
trieTree* clusterUsingDomainInfo::getTrieTree()
{
    return m_trieTree;
}
clusterUsingDomainInfo::~clusterUsingDomainInfo()
{
    delete m_trieTree;
}
//readFile,domainfile  过滤掉存在三级域名的文件，
void clusterUsingDomainInfo::getZWWDomain(const char *readFile,const char *domainfile,
                                          const char *writeFile,const char *writeFile2)
{
    vector<vector<int> >domianID;
    string line;
    string domain;
    nLdDomainLevel m_Level;
    set<string>domainSet;
    ifstream fin (readFile,ios::in);
    int count = 0;
    string primaryDoamin;
    char *primaryDoaminPtr = NULL;
    map<string,string>primayDo;
    if(!fin.is_open())
    {
        cout<<"openfile error:"<<readFile<<endl;
        return;
    }
    ofstream fout(domainfile,ios::out|ios::app);
    if(!fout.is_open())
    {
        cout<<"openfile error:"<<domainfile<<endl;
        return;
    }
    ofstream fout2(writeFile2,ios::out|ios::app);
    if(!fout2.is_open())
    {
        cout<<"openfile error:"<<writeFile2<<endl;
        return;
    }
    while(!fin.eof() ) //读文件解析出域名
    {
        getline(fin, line);
        if(line.size() == 0 )
        {
            continue;
        }
        else
        {
            m_Level = getDomainNLDs(line);
            if(m_Level.secondLD.length() != 0)
            {
                if(m_Level.thirdLD.length()== 0)
                {
                    fout2<<line<<endl;
                }
            }
            else
            {
                continue;
            }
        }
    }
}
void clusterUsingDomainInfo::readFirstTenThoundsand(const char *readFile,const char *writeFile)
{
    string line;
    ifstream fin (readFile,ios::in);
    ofstream fout(writeFile,ios::out|ios::app);
    int counts = 0;
    while(!fin.eof() ) //读文件，一次读取一行，解析相关字段内容，直到读到文件末尾。
    {
        getline(fin, line);
        if(line.size() == 0 )
        {
            continue;
        }
        else
        {
            size_t lab = line.find_first_of(',');
            string domain = line.substr(lab +1,line.length() - lab - 1);
            fout<<domain<<endl;
            domain.clear();
        }
    }
    fin.close();
    fout.close();
}
void clusterUsingDomainInfo::trainDataProcssOfZWW(const char *readFile,const char *writeFile,
                                                  bool isbengin)
{
    string line;
    ifstream fin (readFile,ios::in);
    ofstream fout(writeFile,ios::out|ios::app);
    while(!fin.eof() ) //读文件，一次读取一行，解析相关字段内容，直到读到文件末尾。
    {
        getline(fin, line);
        if(line.size() == 0 )
        {
            continue;
        }
        else
        {
            size_t labfirst = line.find_first_of(',');
            string domain = line.substr(0, labfirst -1 );
            fout<<domain<<endl;
            domain.clear();
        }
    }
    fin.close();
    fout.close();
}
void clusterUsingDomainInfo::getlostDoamin(const char *readFile,const char *rFilewhois,
                                           const char *rbadFile,const char *wlostwrite)
{
    string line;
    ifstream fin (readFile,ios::in);
    ifstream fin2(rFilewhois,ios::in);
    ofstream fout(wlostwrite,ios::out|ios::app);
    ofstream fout2(rbadFile,ios::out|ios::app);
    set<string>lost;
    set<string>domainwhois;
    map<string,string>domains;
    map<string,string>::iterator its;
    line.clear();
    while(!fin2.eof() ) //读whois文件
    {
        getline(fin2, line);
        if(line.size() == 0 )
        {
            continue;
        }
        else
        {
            size_t flag = line.find_first_of(':');
            if(flag != string::npos)
            {
                size_t lab = line.find_first_of(',');
                string domian = line.substr(0,lab);
                domains.insert(make_pair<string,string>(domian,line));
            }
        }
    }
    cout<<"domains whois size:"<<domains.size()<<endl;
    line.clear();
    while(!fin.eof() ) //all the domian
    {
        getline(fin, line);
        if(line.size() == 0 )
        {
            continue;
        }
        else
        {
            domainwhois.insert(line);
        }
    }
     cout<<"domains all size:"<<domainwhois.size()<<endl;
}
void clusterUsingDomainInfo::domain3ldbigthanfive(map<string,vector<string> > paraGrouping,
                                                   const char* wfilebuf)
{
    ofstream fout(wfilebuf,ios::out|ios::app);
    nLdDomainLevel m_Level;
    for(map<string,vector<string> >::iterator iter = paraGrouping.begin();iter !=
        paraGrouping.end();++iter)
    {
        for(vector<string>::iterator it = iter->second.begin();it!= iter->second.end();++it)
        {
            m_Level = getDomainNLDs(*it);
            if(m_Level.secondLD.length() != 0)
            {
                if(m_Level.thirdLD.length()>=4)
                {
                    fout<<*it<<endl;
                    break;
                }
            }
            else
            {
                break;
            }
        }
    }
    fout.close();
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
void clusterUsingDomainInfo::getResolvedIPSimilarityMatrix(const char *domain_ipfile,
                                                           const char *similarmatrxifile)
{
    set<string>IPList;
    set<string>tmpinsersection;
    set<string>tmpunion;
    vector<set<string> > ipMatrix;
    vector<double>tempVec;
    vector<vector<double> > Matrix;
    string line;
    int counts = 0;
    ifstream fin (domain_ipfile,ios::in);
    if(!fin.is_open())
    {
        cout<<"openfile error:"<<domain_ipfile<<endl;
        return;
    }
    ofstream fout(similarmatrxifile,ios::out);
    if(!fout.is_open())
    {
        cout<<"openfile error:"<<similarmatrxifile<<endl;
        return;
    }
    while(!fin.eof())
    {
        counts++;
        if(counts>1000)
        {
            break;
        }
        IPList.clear();
        getline(fin,line);
        if(line.size() == 0)
        {
            continue;
        }
        else
        {
            size_t lable = line.find_first_of(',');
            size_t IPlabel = line.find_first_of(':', lable +1);
            if(IPlabel != string::npos)
            {
                for(size_t index = lable; index < IPlabel;)
                {
                    size_t lab = line.find_first_of(',', index +1);
                    if(lab != string::npos && lab <= IPlabel)
                    {
                        string IP = line.substr(index + 1,lab - index -1);
                        IPList.insert(IP);
                        index = lab;
                        IP.clear();
                    }
                    else if (lab > IPlabel)
                    {
                        string IP = line.substr(index + 1,IPlabel - index -1);
                        IPList.insert(IP);
                        IP.clear();
                        break;
                    }
                }
            }
            else
            {
                continue;
            }
            ipMatrix.push_back(IPList);
        }
    }
    for(size_t i = 0 ;i < ipMatrix.size();i++)
    {
        for(size_t j = 0; j< ipMatrix.size();j++)
        {
            tmpinsersection = ipMatrix.at(i)*ipMatrix.at(j);
            tmpunion =  ipMatrix.at(i)+ipMatrix.at(j);
            double  tmp = (double)tmpinsersection.size()/tmpunion.size();
            tempVec.push_back(tmp) ;
            tmpinsersection.clear();
            tmpunion.clear();
        }
        Matrix.push_back(tempVec) ;
        tempVec.clear();
    }
    cout<<"size:"<<Matrix.size()<<endl;
    for(vector<vector<double> > ::iterator iter = Matrix.begin();iter != Matrix.end();++iter)
    {
        for(size_t i = 0 ; i< iter->size();i++)
        {
            if( i + 1 == iter->size())
            {
                fout<<iter->at(i)<<endl;
            }
            else
            {
                fout<<iter->at(i)<<",";
            }
        }
    }
}
void clusterUsingDomainInfo::getThreeLevelDoamin(const char *Alexfile,const char *AlexfileZWW,
                                                 const char *wfile)
{
    map<string,string>Alexfilemap;
    set<string>AlexfileZWWset;
    string line;
    string secondLevelDomainStr;
    char *secondLevelDomain = NULL;
    ifstream fin (Alexfile,ios::in);
    if(!fin.is_open())
    {
        cout<<"openfile error:"<<Alexfile<<endl;
        return;
    }
    ifstream fin2 (AlexfileZWW,ios::in);
    if(!fin2.is_open())
    {
        cout<<"openfile error:"<<AlexfileZWW<<endl;
        return;
    }
    ofstream fout(wfile,ios::out);
    if(!fout.is_open())
    {
        cout<<"openfile error:"<<wfile<<endl;
        return;
    }
    while(!fin.eof())
    {
        getline(fin,line);
        
        if(line.size() == 0)
        {
            continue;
        }
        else
        {
            size_t lab  = line.find_first_of(',');
            string domainName = line.substr(0,lab);
            string subline = line.substr(lab,line.length()- lab);
            secondLevelDomain = m_DGA_detection.get_primary_domain((char*)domainName.c_str());
            
            if(secondLevelDomain != NULL)
            {
                secondLevelDomainStr.clear();
                secondLevelDomainStr.assign(secondLevelDomain);
                string subDomain = domainName.substr(0, domainName.length() - secondLevelDomainStr.length());
                if(subDomain.length() == 0)
                {
                    Alexfilemap.insert(make_pair<string,string>(secondLevelDomainStr,subline));
                }
                else
                {
                    fout<<line<<endl;
                }
            }
            else
            {
                continue;
            }
        }
    }
    map<string,string>tmp;
    while(!fin2.eof())
    {
        getline(fin2,line);
        if(line.size() == 0)
        {
            continue;
        }
        else
        {
            AlexfileZWWset.insert(line);
        }
    }
    for(set<string>::iterator iter = AlexfileZWWset.begin();iter!= AlexfileZWWset.end();++iter)
    {
        secondLevelDomain = m_DGA_detection.get_primary_domain( (char*)iter->c_str());
        if(secondLevelDomain != NULL)
        {
            secondLevelDomainStr.clear();
            secondLevelDomainStr.assign(secondLevelDomain);
            tmp.insert(make_pair<string,string>(secondLevelDomainStr,*iter));
        }
    }
    map<string,string>::iterator it;
    for(map<string,string>::iterator its = Alexfilemap.begin();its != Alexfilemap.end();++its)
    {
        it = tmp.find(its->first);
        if(it!= tmp.end())
        {
            fout<<it->second<<its->second<<endl;
        }
        else
        {
            fout<<its->first<<its->second<<endl;
        }
    }
    fin.close();
    fin2.close();
    fout.close();
}
void clusterUsingDomainInfo::getMeaningfulCharactersRatio(const char* rfilebuf,
                                                          const char* wfilebuf,Trie_node root)
{
    nLdDomainLevel m_Level;
    string line;
    double zero = 0.0;
    double one = 0.0;
    vector<int>wordlen;
    set<string>domainSet;
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
        getline(fin, line);
        if(line.size() == 0 )
        {
            continue;
        }
        else
        {
            size_t lab = line.find_first_of(',');
            string domian = line.substr(0,lab);
            domainSet.insert(domian);
        }
    }
    for(set<string>::iterator iter = domainSet.begin();iter!= domainSet.end();++iter)
    {
        int lab = 0;
        int flag = 0;
        int times = 0;
        bool isword = false;
        wordlen.clear();
        int sum = 0;
        string word;
        double MeaningfulCharacterRatio = 0.0;
        m_Level = getDomainNLDs(*iter);
        if(m_Level.secondLD.length() != 0)
        {
            if(m_Level.secondLD.length() == 3)
            {
                //is a word
                isword = m_trieTree->statisticsSrtingIsWord(root,(char*)m_Level.secondLD.c_str());
                if(isword == false)
                {
                    fout<<*iter<<","<<zero<<endl;
                }
                else
                {
                    fout<<*iter<<","<<one<<endl;
                }
            }
            else
            {
                int beg = 0;
                int ends = m_Level.secondLD.length();
                for(;ends >=beg + 3;)
                {
                    word.clear();
                    word = m_Level.secondLD.substr(beg,ends - beg);
                    cout<<"word = "<<word<<endl;
                    //判断Word是否是一个单词是单词
                    isword = m_trieTree->statisticsSrtingIsWord(root,(char*)word.c_str());
                    if(isword == true)
                    {
                        wordlen.push_back(word.length());
                        beg = ends;
                        ends = m_Level.secondLD.length();
                    }
                    else if( (isword == false)&&(ends == beg + 3))
                    {
                        beg = ends - 2;
                        ends = m_Level.secondLD.length();
                    }
                    else
                    {
                        ends = ends -1;
                    }
                }
            }
        }
        else
        {
            continue;
        }
        for(vector<int>::iterator it = wordlen.begin();it!= wordlen.end();++it)
        {
            sum += *it;
        }
        MeaningfulCharacterRatio = double(sum)/m_Level.secondLD.length();
        fout<<*iter<<","<<MeaningfulCharacterRatio<<endl;
    }
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
        for(vector<double>::iterator it = tsAverDeviation.begin(); it!= tsAverDeviation.end();++it)
        {
            //2gram,3lD average median deviation;
            temp.push_back(*it);
        }
        for(vector<double>::iterator it = stAverDeviation.begin(); it!= stAverDeviation.end();++it)
        {
            //3gram,2lD average median deviation;
            temp.push_back(*it);
        }
        for(vector<double>::iterator it = ttAverDeviation.begin(); it!= ttAverDeviation.end();++it)
        {
            //3gram,3lD average median deviation;
            temp.push_back(*it);
        }
        temp.push_back(secLDEntroy);
        temp.push_back(thirLDEntroy);
        //temp.push_back(double(countNLDs));
        temp.push_back(double(lenofsLD));
        temp.push_back(double(lenoftLD));
        temp.push_back(double(lenofDomain));
        temp.push_back(perofSec);
        temp.push_back(perofThir);
        // temp.push_back(double(iter->elapseTime));
        // temp.push_back(double(iter->isupdate));
        // temp.push_back(double(iter->role));
        // temp.push_back(iter->ipLocationEntroy);
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