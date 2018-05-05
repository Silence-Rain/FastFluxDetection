#include "clusterUsingDomainInfo.h"
clusterUsingDomainInfo::clusterUsingDomainInfo()
{
    getIPInfo = new getIPLocationFromIPCIS();
    m_getDomainFromDatabase = new getDomainFromDatabase();
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
        //counts++;
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
        //counts++;
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
//domainPara is 2LD group 该函数实现 测试数据和训练数据 whois信息的获取
void clusterUsingDomainInfo::getWhoisInfo(map<string,vector<string> >domainPara,
      const char *wfilebuff,const char *blackdomainfile,bool isTraining,bool isMacilicous)
{
    int counts = 0;
    int nums = 0;
    int times = 0;
    string line;
    string key_api = "";
    int flag;
    double isupdeate;
    struct whoisInfo_ curdomianWhois;
    ofstream fblackout(blackdomainfile,ios::out|ios::app);
    if(!fblackout.is_open())
    {
        cout<<"open rfile:"<<blackdomainfile<<":error:"<<endl;
		return;
    }
    ofstream fout(wfilebuff,ios::out);
    if(!fout.is_open())
    {
        cout<<"open rfile:"<<wfilebuff<<":error:"<<endl;
		return;
    }
    string key_api_0 = "206b0412b9900a7e80ef3ea226956da65178d5c759403b7b65ad3ca15f1b1702";
    string key_api_1 = "c5f6e0e7ec8f48bfa1e77b6e84a36a4dce4b409e11d6c788c457365a8a63fd88";
    string key_api_2 = "ff9a5da177e848fce33c24e742cd297f2dce9afab69a8408ad7da5d38006df01";
    string key_api_3 = "764b42ca8dedff35330ca8c0796c3a7f17646add7184b1678e70849346c800d9";
    string key_api_4 = "5284116e8ebaf710acb99ace62b207e16e6666f61029a0d28718d66462810aa1";
    string key_api_5 = "0e616d004e5600bc7b81b4acbbc59e21a7cb7a8a5483a8088f88f979fd305e0c";
    string key_api_6 = "fa396de3920584c9a9fac111f6b4f7170597aa4fabc79d48154886821de3cf0e";
    string key_api_7 = "66d7874a377596e9dad00a6b554685a920cb1df187eeefd5ec934cee684f2b09";
    string key_api_8 = "88221f841fa061af9b35e442aeef9a7e2005a8b1a79a9b4310203db24c4d147b";
    string key_api_9 = "757da4d350a48f718c676fb3e79c247b41a5a7a3342bc93dbec58740dae097f1";
    string key_api_10 = "e99d19343790d0bd03dd687ea0830ba116a6ba3ecd040dbbe99e456d914200ec";
    string key_api_11 = "e488819aa04142eaa112adb6887dcc6a9d4de814c056115313cbd830c1d283bc";
    string key_api_12 = "f34ebc2ead89c35dcca28ffe388f4f36b3c9df319ad62547786e40de93a60c26";
    string key_api_13 = "41df0f86848dfb5d2253c9d1bb895c1c6451247df43f433b6ce32b4585407730";
    string key_api_14 = "25b2b85d88d5a295841a0362b250fed919631ccda166460d2b46aa644642757c";
    string key_api_15 = "d7e28b8996d246ce9ee046ad02402e42af568c0af983fb68fa7f2be38320bddb";
    string key_api_16 = "a41d71fea072a70661e49acb775a14fa5f101041bb50e5a3fa03e76c8c9677bc";
    string key_api_17 = "30628d5622fac373ec9dd1cdae90485f3c15b21405860397c45a5aa9ed577fa6";
    //string key_api_18  ="7a629ed6af627acf7e96ea0d62185e21cba59245855cb2f13fb45023b0ad8bf1";

    for(map<string,vector<string> >::iterator iter= domainPara.begin();
        iter!= domainPara.end();++iter)
    {
        /*
        counts++;

        nums ++;
        if(nums >= 3000)
        {
            nums = 0;
            sleep(600);
        }
        */
        curdomianWhois.registerTime = 0;
        curdomianWhois.expiredTime = 0;
        curdomianWhois.updateTime = 0;
        curdomianWhois.role = 0;
        curdomianWhois.Ipsets.clear();
        /*
        if(counts%18 == 0)
        {
            key_api = key_api_0;
        }
        else if(counts%18 == 1)
        {
            key_api = key_api_1;
        }
        else if(counts%18 == 2)
        {
            key_api = key_api_2;
        }
        else if(counts%18 == 3)
        {
            key_api = key_api_3;
        }
        else if(counts%18 == 4)
        {
            key_api = key_api_4;
        }
        else if(counts%18 == 5)
        {
            key_api = key_api_5;
        }
        else if(counts%18 == 6)
        {
            key_api = key_api_6;
        }
        else if(counts%18 == 7)
        {
            key_api = key_api_7;
        }
        else if(counts%18 == 8)
        {
            key_api = key_api_8;
        }
        else if(counts%18 == 9)
        {
            key_api = key_api_9;
        }
        else if(counts%18 == 10)
        {
            key_api = key_api_10;
        }
        else if(counts%18 == 11)
        {
            key_api = key_api_11;
        }
        else if(counts%18 == 12)
        {
            key_api = key_api_12;
        }
        else if(counts%18 == 13)
        {
            key_api = key_api_13;
        }
        else if(counts%18 == 14)
        {
            key_api = key_api_14;
        }
        else if(counts%18 == 15)
        {
            key_api = key_api_15;
        }
        else if(counts%18 == 16)
        {
            key_api = key_api_16;
        }
        else if(counts%18 == 17)
        {
            key_api = key_api_17;
        }
        */
        if( (iter->first).length() != 0) //primary domain is not empty
        {
            //获取域名的whois、解析IP信息 存入whoisInfo.txt 和reslovedIPInfo.txt
            getPrimaryDomianOwnerInfo(iter->first, key_api_5,isTraining,"/home/xdzang/DGA_Detection/");
        }
        else
        {
            //empty continue;
            continue;
        }
        //读取whoisInfo.txt 和reslovedIPInfo.txt提取IP whois信息
        curdomianWhois = processDataWhoisInfo("/home/xdzang/DGA_Detection/whoisInfo.txt",
                            "/home/xdzang/DGA_Detection/reslovedIPInfo.txt",isTraining);
        for(vector<string>::iterator its = iter->second.begin();its != iter->second.end();
                ++its)
        {

            if(isTraining == false) //test data
            {
                if(curdomianWhois.role == 2)
                {
                    fblackout<<*its<<endl; //domain ,IP:anyother
                }
                else
                {
                    fout<<*its<<":"; //domain ,IP:anyother
                    double years = 0.0;
                    if(curdomianWhois.updateTime - curdomianWhois.registerTime >=0)
                    {
                        isupdeate = 1.0;
                    }
                    else
                    {
                        isupdeate = 0.0;
                    }
                    if(isupdeate == 1.0) //update
                    {
                        int tmp = curdomianWhois.updateTime - curdomianWhois.registerTime;
                        years = (double)tmp/(365*24*3600);
                        years = (int)years*100/100 + 1;
                        fout<<years<<","<<isupdeate<<",";
                        //cout<<years<<","<<isupdeate<<",";
                    }
                    else
                    {
                        int tmp = curdomianWhois.expiredTime - curdomianWhois.registerTime;
                        years = (double)tmp/(365*24*3600);
                        years = (int)years*100/100 + 1;
                        fout<<years<<","<<isupdeate<<",";
                        //cout<<years<<","<<isupdeate<<",";
                    }
                    fout<<curdomianWhois.role<<endl;
                    //cout<<curdomianWhois.role<<endl;

                }


            }

            else //traing data
            {
                if (isMacilicous == true)
                {
                    if(curdomianWhois.role != 0) //2表示恶意 0 表示safe,1表示 unsure
                    {
                        fout<<*its<<",";
                        for(set<string>::iterator it = curdomianWhois.Ipsets.begin();
                                it != curdomianWhois.Ipsets.end();)
                        {
                            cout<<*it<<endl;
                            fout<<ip2long((*it).c_str());
                            ++it;
                            if(it != curdomianWhois.Ipsets.end())
                            {
                                fout<<",";
                            }
                            else
                            {
                                fout<<":";
                            }

                        }
                        double years = 0.0;
                        if(curdomianWhois.updateTime - curdomianWhois.registerTime >=0)
                        {
                            isupdeate = 1.0;
                        }
                        else
                        {
                            isupdeate = 0.0;
                        }
                        if(isupdeate ==1.0)
                        {
                            int tmp = curdomianWhois.updateTime - curdomianWhois.registerTime;
                            years = (double)tmp/(365*24*3600);
                            years = (int)years*100/100 + 1;
                            fout<<years<<","<<isupdeate<<",";
                        }
                        else
                        {
                            int tmp = curdomianWhois.expiredTime - curdomianWhois.registerTime;
                            years = (double)tmp/(365*24*3600);
                            years = (int)years*100/100 + 1;
                            fout<<years<<","<<isupdeate<<",";
                        }
                        fout<<curdomianWhois.role<<endl;
                    }
                    else
                    {
                        break;
                    }
                }
                else
                {
                    //benign
                    if(curdomianWhois.role != 2) //2表示恶意 0 表示safe,1表示 unsure
                    {
                        fout<<*its<<",";
                        for(set<string>::iterator it = curdomianWhois.Ipsets.begin();
                                it != curdomianWhois.Ipsets.end();)
                        {
                            cout<<*it<<endl;
                            fout<<ip2long((*it).c_str());
                            ++it;
                            if(it != curdomianWhois.Ipsets.end())
                            {
                                fout<<",";
                            }
                            else
                            {
                                fout<<":";
                            }

                        }
                        double years = 0.0;
                        if(curdomianWhois.updateTime - curdomianWhois.registerTime >=0)
                        {
                            isupdeate = 1.0;
                        }
                        else
                        {
                            isupdeate = 0.0;
                        }
                        if(isupdeate ==1.0)
                        {
                            int tmp = curdomianWhois.updateTime - curdomianWhois.registerTime;
                            years = (double)tmp/(365*24*3600);
                            years = (int)years*100/100 + 1;
                            fout<<years<<","<<isupdeate<<",";
                        }
                        else
                        {
                            int tmp = curdomianWhois.expiredTime - curdomianWhois.registerTime;
                            years = (double)tmp/(365*24*3600);
                            years = (int)years*100/100 + 1;
                            fout<<years<<","<<isupdeate<<",";
                        }
                        fout<<curdomianWhois.role<<endl;
                    }
                    else
                    {
                        break;
                    }
                }
            }

        }

    }
    fout.close();
    fblackout.close();
}
u_long clusterUsingDomainInfo::ip2long(const char *ip)
{
    u_long iplong;
    iplong = ntohl(inet_addr(ip));
    return  iplong;
}

//解析line 得到 域名 -IP -time -isupdate isTrainging is false after cluster get features
struct domain_IP_TTl_ clusterUsingDomainInfo::parsingDomainIPString(string line,bool isTrainging)
{
    //提取域名，插入到容器中
    struct domain_IP_TTl_ domianIPInfo;
    domianIPInfo.IPList.clear();
    size_t clabel;
    string subline;
    clabel = line.find_last_of(',');
    //cout<<"line:"<<line<<endl;
    int traingDataFlag = atoi(line.substr(clabel + 1,line.length() - clabel - 1).c_str());
    subline = line.substr(0,clabel);
    //cout<<"subline:"<<subline<<endl;
    size_t lable = subline.find_first_of(',');
    domianIPInfo.domainName = subline.substr(0, lable);
    //cout<<"domain name:"<<domianIPInfo.domainName<<endl;
    size_t IPlabel = subline.find_first_of(':', lable +1);
    if(IPlabel != string::npos)
    {

        for(size_t index = lable; index < IPlabel;)
        {
            size_t lab = subline.find_first_of(',', index +1);
            if(lab != string::npos && lab <= IPlabel)
            {
                string IP = subline.substr(index + 1,lab - index -1);
                //cout<<"IP1:"<<IP<<endl;
                domianIPInfo.IPList.insert(IP);
                index = lab;
                IP.clear();
            }
            else if (lab > IPlabel)
            {
                string IP = subline.substr(index + 1,IPlabel - index -1);
                //cout<<"IP2:"<<IP<<endl;
                domianIPInfo.IPList.insert(IP);
                IP.clear();
                break;
            }
        }
        //cout<<"line:"<<subline<<endl;
        size_t timelab = subline.find_first_of(',', IPlabel +1);
        domianIPInfo.elapseTime = atoi(subline.substr(IPlabel +1, timelab- IPlabel -1).c_str());
        //cout<< "domianIPInfo.elapseTime:"<<domianIPInfo.elapseTime<<endl;
        size_t updatelab = subline.find_first_of(',', timelab +1);
        domianIPInfo.isupdate = atoi(subline.substr(timelab +1, updatelab -timelab -1).c_str());
        //cout<< "domianIPInfo.isupdate:"<<domianIPInfo.isupdate<<endl;
        size_t rolelab = subline.find_first_of(',', updatelab +1);
        domianIPInfo.role = atoi(subline.substr(updatelab +1, rolelab - updatelab  -1).c_str());
        //cout<< "domianIPInfo.role:"<<domianIPInfo.role<<endl;
        size_t countrylab = subline.find_last_of(',');
        float ipPercentage = (atof(subline.substr(countrylab +1,subline.length() - countrylab -1).c_str()))
                              /domianIPInfo.IPList.size();

        //int tempValue = int(ipPercentage*100 );
        //domianIPInfo.ipLocationEntroy = double(tempValue/100);
        domianIPInfo.ipLocationEntroy = ipPercentage;
        //cout<<"domianIPInfo.ipLocationEntroy:"<<domianIPInfo.ipLocationEntroy<<endl;
    }
    else
    {
        domianIPInfo.IPList.clear();
        string empstr = "";
        domianIPInfo.IPList.insert(empstr);
        size_t timelab = subline.find_first_of(',', lable +1);
        domianIPInfo.elapseTime = atoi(subline.substr(lable +1, timelab- lable -1).c_str());
        //cout<< "domianIPInfo.elapseTime:"<<domianIPInfo.elapseTime<<endl;
        size_t updatelab = subline.find_first_of(',', timelab +1);
        domianIPInfo.isupdate = atoi(subline.substr(timelab +1, updatelab -timelab -1).c_str());
        //cout<< "domianIPInfo.isupdate:"<<domianIPInfo.isupdate<<endl;
        size_t rolelab = subline.find_first_of(',', updatelab +1);
        domianIPInfo.role = atoi(subline.substr(updatelab +1, rolelab - updatelab  -1).c_str());
        //cout<< "domianIPInfo.role:"<<domianIPInfo.role<<endl;
        size_t countrylab = subline.find_last_of(',');
        float ipPercentage = (atof(subline.substr(countrylab +1,subline.length() - countrylab -1).c_str()))
                              /domianIPInfo.IPList.size();
        //cout<<"size:"<<domianIPInfo.IPList.size()<<endl;
        //cout<<"ipPercentage:"<<ipPercentage<<endl;
        //int tempValue = int(ipPercentage*100 );
        //domianIPInfo.ipLocationEntroy = double(tempValue/100);
        domianIPInfo.ipLocationEntroy = ipPercentage;
        //cout<<"domianIPInfo.ipLocationEntroy:"<<domianIPInfo.ipLocationEntroy<<endl;
    }

    if(isTrainging == true)
    {
        domianIPInfo.traingFlag = traingDataFlag;
    }
    else
    {
        domianIPInfo.traingFlag = 2;//表示测试数据
    }
    //cout<<"size:"<<domianIPInfo.IPList.size()<<endl;
    /*
    cout<<domianIPInfo.domainName<<",";
    for(set<string>::iterator it = domianIPInfo.IPList.begin();it!=domianIPInfo.IPList.end();++it)
    {
        cout<<*it<<",";
    }
    cout<<domianIPInfo.elapseTime<<","<<domianIPInfo.isupdate<<","<<domianIPInfo.role<<",";
    cout<<domianIPInfo.ipLocationEntroy<<","<<domianIPInfo.traingFlag<<endl;
    */
    return domianIPInfo;
}
//读取训练数据、测试数据到map,便于特征提取//isTrainging == 0 traing file 1:test file
map<int,vector<struct domain_IP_TTl_> >clusterUsingDomainInfo::getDomianFromInfoTestFile(
                                        const char *rFilebuff,bool isTrainging)
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
        /*
        counts++;
        if(counts >5)
        {
            break;
        }
        */
        tmpdomain_IP.IPList.clear();
        tmpdomain_IP.domainName.clear();
        getline(fin, line);
        //cout<<"line:"<<line<<endl;
        if(line.size() == 0 )
        {
            continue;
        }
        else
        {

            if(isTrainging == false)//test data
            {
                size_t clabel = line.find_last_of(',');
                string cluster = line.substr(clabel + 1, line.length());
                int cflag = atoi(cluster.c_str());
                tmpdomain_IP = parsingDomainIPString(line,isTrainging);
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
                        //cout<<"dname:"<<dname<<endl;
                        tempdomaineVector.push_back(tmpdomain_IP);
                        //cout<<"tempdomaineVector size():"<<tempdomaineVector.size()<<endl;
                        domain_IP_map.insert(make_pair<int,vector<struct domain_IP_TTl_> >(cflag,tempdomaineVector));
                    }

                }
            }
            else
            {
                tmpdomain_IP = parsingDomainIPString(line,isTrainging);
                tempdomaineVector.push_back(tmpdomain_IP);
            }
        }

    }
    if(isTrainging == true)
    {
        domain_IP_map.insert(make_pair<int,vector<struct domain_IP_TTl_> >(0,tempdomaineVector));
    }
      /*
    for(map<int,vector<struct domain_IP_TTl_> >::iterator iter = domain_IP_map.begin();iter != domain_IP_map.end();++iter)
    {

        cout<<"flag = "<<iter->first<<",nums = "<<iter->second.size()<<endl;

        for(vector<struct domain_IP_TTl_>::iterator it = iter->second.begin(); it!= iter->second.end();++it)
        {
            cout<<it->domainName<<",";
            for(set<string>::iterator its = it->IPList.begin(); its!= it->IPList.end();++its)
            {
                cout<<*its<<",";
            }

            cout<<it->elapseTime<<","<<it->isupdate<<","<<it->role<<","<<it->ipLocationEntroy;
            cout<<","<<it->traingFlag<<endl;
        }

    }
    */
    fin.close();
    return domain_IP_map;

}
//filebuf virustotal 可执行文件 domain_report
//获取域名的whois、解析IP信息 存入whoisInfo.txt 和reslovedIPInfo.txt
int clusterUsingDomainInfo::getPrimaryDomianOwnerInfo(string domain,string key,
                                                   bool isTraining,string fileLocation)
{
    const char* whoisfile = "/home/xdzang/DGA_Detection/whoisInfo.txt";
    const char* reslovedIPfile = "/home/xdzang/DGA_Detection/reslovedIPInfo.txt";
    ofstream fout1 (whoisfile,ios::out);
    if(!fout1.is_open())
    {
        cout<<"create file error:"<<whoisfile<<endl;
        return 0;
    }
    ofstream fout2 (reslovedIPfile,ios::out);
    if(!fout2.is_open())
    {
        cout<<"create file error:"<<reslovedIPfile<<endl;
        return 0;
    }
    //char *domainPtr = NULL;
    //domainPtr = (char*)domain.c_str();
    //struct owner_Info_ curDomainInfo;
    //string primaryDoamin;
    //char *primaryDoaminPtr;
    //primaryDoaminPtr = m_DGA_detection.get_primary_domain(domainPtr);
    //if(primaryDoaminPtr == NULL)
    //{
        //cout<<"primaryDoamin is empty return"<<endl;
        //return 0;
    //}
    //cout<<"primaryDoaminPtr:"<<primaryDoaminPtr<<endl;
    //primaryDoamin.assign(primaryDoaminPtr);
    string file = fileLocation+"domain_report --apikey " + key + "  --report ";
    string domainLog = domain+">"+fileLocation+"domain.log";
    string domian_report = file + domainLog;
    cout<<"domian_report:"<<domian_report<<endl;
    system(domian_report.c_str());
    if(isTraining == true)//traing data
    {
        system("cat /home/xdzang/DGA_Detection/domain.log | jq '.[\"resolutions\"]'>>/home/xdzang/DGA_Detection/reslovedIPInfo.txt");
        system("cat /home/xdzang/DGA_Detection/domain.log | jq '.[\"whois\"]' >>/home/xdzang/DGA_Detection/whoisInfo.txt");
        system("cat /home/xdzang/DGA_Detection/domain.log | jq '.[\"Webutation domain info\"][\"Verdict\"]' >>/home/xdzang/DGA_Detection/whoisInfo.txt");
        system("cat /home/xdzang/DGA_Detection/domain.log | jq '\"Webutation domain info\"' >>/home/xdzang/DGA_Detection/whoisInfo.txt");
        system("cat /home/xdzang/DGA_Detection/domain.log | jq '.[\"Webutation domain info\"][]' >>/home/xdzang/DGA_Detection/whoisInfo.txt");
    }
    else
    {
        system("cat /home/xdzang/DGA_Detection/domain.log | jq '.[\"whois\"]' >>/home/xdzang/DGA_Detection/whoisInfo.txt");
        system("cat /home/xdzang/DGA_Detection/domain.log | jq '.[\"Webutation domain info\"][\"Verdict\"]' >>/home/xdzang/DGA_Detection/whoisInfo.txt");
        system("cat /home/xdzang/DGA_Detection/domain.log | jq '\"Webutation domain info\"' >>/home/xdzang/DGA_Detection/whoisInfo.txt");
        system("cat /home/xdzang/DGA_Detection/domain.log | jq '.[\"Webutation domain info\"][]' >>/home/xdzang/DGA_Detection/whoisInfo.txt");
    }
    fout1.close();
    fout2.close();
    return 1;
}
//读取whoisInfo.txt 和reslovedIPInfo.txt提取IP whois信息
struct whoisInfo_  clusterUsingDomainInfo::processDataWhoisInfo(const char* whoisFile,
                                                const char* IPFile,bool isTraining)
{
    struct whoisInfo_ traingDataWhois;
    FILE *fp = NULL;
	char buf[20480]; //用于读取文件的一行的存储数组
	char *pos;  //用于一行字符读取操作
	char* tmp_pos;//用于一行字符读取操作
	int nlen; //复制数组时定长使用
	char info[256];
	int i;

	string   create_time;
	string   expire_time;
	string   update_time;
	string line;
	string IPstring = "ip_address";
	unsigned int  role = 0;
	if((fp=fopen(whoisFile,"r"))==NULL)
	{
		cout<<"error :cannot open file:"<<whoisFile<<endl;
		//return NULL;
	}
	memset(buf,0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	if(!feof(fp))
	{
        if(pos=strstr(buf,"Creation Date:")) //找到“创建时间”
		{
			memset(info, 0,sizeof(info));
			tmp_pos=pos+strlen("Creation Date:") + 1;
			i=0;
			while(tmp_pos && *tmp_pos &&(*tmp_pos!='\\')&&(*tmp_pos!='\"'))//查找指定字符“\n”，并定位tmp_pos到“\n”处
			{
				info[i]=*tmp_pos;
				i++;
				tmp_pos++;
			}
			info[i]='\0';
			create_time.clear();
			create_time.assign(info);
			char month[3];
			char week[3];
            int mon;
            int year, day, hour, min, sec;
            char timezone[10];
			 //Creation Date: 2013-11-10T14:02:44Z
            //string substring = create_time.substr(0,lab);
            if (sscanf(create_time.c_str(),"%4d-%2d-%2d%1s%2d:%2d:%2d%1s"
                       ,&year,&mon,&day,week,&hour,&min,&sec,timezone) == 8)
            {
                    char str[20];
                    sprintf(str,"%d-%d-%d\n", day, mon, year);
                    //cout<<"Created On time:"<<str<<endl;
                    create_time.clear();
                    create_time.assign(str);
                    traingDataWhois.registerTime = MakeTime(create_time);
            }
            else if(sscanf(create_time.c_str(),"%d-%3s-%4d",&day,month,&year) == 3)
            {
                    //Date: 11-oct-1999
                    char str[20];
                    sprintf(str,"%d-%s-%d\n", day, month, year);
                    //cout<<"Created On time:"<<str<<endl;
                    create_time.clear();
                    create_time.assign(str);
                    traingDataWhois.registerTime = MakeTime(create_time);
            }
            else
            {
                traingDataWhois.registerTime = 0;
            }
		}
		else if(pos=strstr(buf,"Created On:"))
        {
            //cout<<"find Created On"<<endl;
            memset(info, 0,sizeof(info));
			tmp_pos=pos + strlen("Created On:") + 1;
			i=0;
			while(tmp_pos && *tmp_pos &&(*tmp_pos!='\\')&&(*tmp_pos!='\"'))//查找指定字符“\n”，并定位tmp_pos到“\n”处
			{
				info[i]=*tmp_pos;
				i++;
				tmp_pos++;
			}
			info[i]='\0';
			create_time.clear();
			create_time.assign(info);
			//cout<<"create_time:"<<create_time<<endl;
            char month[3];
            int mon;
            int year, day, hour, min, sec;
            char timezone[10];
            int match = sscanf(create_time.c_str(), "%d-%3s-%4d%2d:%2d:%2d%3s",
                        &day, month, &year, &hour, &min, &sec, timezone);
            //cout<<"match:"<<match<<endl;
            if (match == 7)
            {
                //Date:29-Apr-2008 17:53:02 UTC
                char str[20];
                sprintf(str,"%d-%s-%d\n", day, month, year);
                //cout<<"Created On time:"<<str<<endl;
                create_time.clear();
                create_time.assign(str);
                traingDataWhois.registerTime = MakeTime(create_time);
            }
            else if(sscanf(create_time.c_str(), "%4d-%2d-%2d",&year,&mon,&day) == 3)
            {
                //date 1995-02-28
                char str[20];
                sprintf(str,"%d-%d-%d\n", day, mon, year);
                //cout<<"Created On time:"<<str<<endl;
                create_time.clear();
                create_time.assign(str);
                traingDataWhois.registerTime = MakeTime(create_time);
            }
            else
            {
                traingDataWhois.registerTime = 0;
            }

        }
        else if(pos=strstr(buf,"Domain Registration Date:"))
        {
            //cout<<"Domain Registration Date:"<<endl;
            memset(info, 0,sizeof(info));
			tmp_pos=pos + strlen("Domain Registration Date:") + 1;
			i=0;
			while(tmp_pos && *tmp_pos &&(*tmp_pos!='\\')&&(*tmp_pos!='\"'))//查找指定字符“\n”，并定位tmp_pos到“\n”处
			{
				info[i]=*tmp_pos;
				i++;
				tmp_pos++;
			}
			info[i]='\0';
			create_time.clear();
			create_time.assign(info);
			//cout<<"create_time:"<<create_time<<endl;
			char week[3];
            char month[3];
            int year, day, hour, min, sec;
            char timezone[10];
            int match = sscanf(create_time.c_str(), "%3s%3s%2d%2d:%2d:%2d%3s%4d",
            week, month, &day, &hour, &min, &sec, timezone, &year);
            if (match == 8)
            {
                //Date:Sun Mar 18 04:55:43 GMT 2007
                char str[20];
                sprintf(str,"%d-%s-%d\n", day, month, year);
                //cout<<"Created On time:"<<str<<endl;
                create_time.clear();
                create_time.assign(str);
                traingDataWhois.registerTime = MakeTime(create_time);
            }
            else
            {
                traingDataWhois.registerTime = 0;
            }

        }
        else if(pos=strstr(buf,"Domain Create Date:"))
        {
            memset(info, 0,sizeof(info));
			tmp_pos=pos + strlen("Domain Create Date:") + 1;
			i=0;
			while(tmp_pos && *tmp_pos &&(*tmp_pos!='\\')&&(*tmp_pos!='\"'))//查找指定字符“\n”，并定位tmp_pos到“\n”处
			{
				info[i]=*tmp_pos;
				i++;
				tmp_pos++;
			}
			info[i]='\0';
			create_time.clear();
			create_time.assign(info);
			//cout<<"create_time:"<<create_time<<endl;
			char week[3];
            char month[3];
            int year, day, hour, min, sec;
            char timezone[10];
            int match = sscanf(create_time.c_str(), "%2d-%3s-%4d%2d:%2d:%2d%3s",
                        &day,month,&year, &hour, &min, &sec, timezone);
            if (match == 7)
            {
                char str[20];
                sprintf(str,"%d-%s-%d\n", day, month, year);
                //cout<<"Created On time:"<<str<<endl;
                create_time.clear();
                create_time.assign(str);
                traingDataWhois.registerTime = MakeTime(create_time);
            }
            else
            {
                traingDataWhois.registerTime = 0;
            }
        }
		else
        {
            traingDataWhois.registerTime = 0;
        }
        if(pos=strstr(buf,"Registry Expiry Date:"))
        {

            memset(info, 0,sizeof(info));
            tmp_pos=pos+strlen("Registry Expiry Date:") + 1;
            i=0;
            while(tmp_pos && *tmp_pos &&(*tmp_pos!='\\')&&(*tmp_pos!='\"'))//查找指定字符“\n”，并定位tmp_pos到“\n”处
            {
                info[i]=*tmp_pos;
                i++;
                tmp_pos++;
            }
            info[i]='\0';
            expire_time.clear();
            expire_time.assign(info);
            //Registry Expiry Date: 2017-11-10T14:02:44Z
            char month[3];
            int mon;
            char time[3];
            int year, day,hour,min,sec;
            //cout<<"Registry Expiry Date:"<<expire_time<<endl;
            if (sscanf(expire_time.c_str(), "%4d-%2d-%2d%1s%2d:%2d:%2d%1s",
                        &year,&mon,&day,month,&hour,&min,&sec,time) == 8)
            {
                char str[20];
                sprintf(str,"%d-%d-%d\n", day, mon, year);
                //cout<<"expiredTime:"<<str<<endl;
                expire_time.clear();
                expire_time.assign(str);
                traingDataWhois.expiredTime = MakeTime(expire_time);
            }
            else
            {
                traingDataWhois.expiredTime = 0;
            }
        }
        else if(pos=strstr(buf,"Expiration Date:")) //找到“过期时间”
        {
            //cout<<"find Expiration Date:"<<endl;
            memset(info, 0,sizeof(info));
            tmp_pos=pos+strlen("Expiration Date:") +1;
            i=0;
            while(tmp_pos && *tmp_pos &&(*tmp_pos!='\\')&&(*tmp_pos!='\"'))//查找指定字符“\n”，并定位tmp_pos到“\n”处
            {
                info[i]=*tmp_pos;
                i++;
                tmp_pos++;
            }
            info[i]='\0';
            expire_time.clear();
            expire_time.assign(info);
            //cout<<"expire_time:"<<expire_time<<endl;
            char week[3];
            char month[3];
            int mon;
            int year, day, hour, min, sec;
            char timezone[10];
            if (sscanf(expire_time.c_str(), "%2d-%3s-%4d%2d:%2d:%2d%3s",
                        &day,month,&year, &hour, &min, &sec, timezone) == 7)
            {
                //Date:29-Apr-2008 17:53:02 UTC
                char str[20];
                sprintf(str,"%d-%s-%d\n", day, month, year);
                //cout<<"expire_time:"<<str<<endl;
                expire_time.clear();
                expire_time.assign(str);
                traingDataWhois.expiredTime = MakeTime(expire_time);
            }
            else if(sscanf(expire_time.c_str(), "%4d-%2d-%2d",&year,&mon,&day)== 3)
            {
                //Expiration Date:   2018-02-27
                char str[20];
                sprintf(str,"%d-%d-%d\n", day, mon, year);
                //cout<<"expire_time::"<<str<<endl;
                expire_time.clear();
                expire_time.assign(str);
                traingDataWhois.expiredTime = MakeTime(expire_time);
            }
            else if(sscanf(expire_time.c_str(), "%3s%3s%2d%2d:%2d:%2d%3s%4d",
                    week, month, &day, &hour, &min, &sec, timezone, &year) ==8)
            {
                //Date:Sun Mar 18 04:55:43 GMT 2007
                char str[20];
                sprintf(str,"%d-%s-%d\n", day, month, year);
                //cout<<"expire_time:"<<str<<endl;
                expire_time.clear();
                expire_time.assign(str);
                traingDataWhois.expiredTime = MakeTime(expire_time);
            }
            else if(sscanf(expire_time.c_str(), "%2d-%3s-%d4",&day,month,&year)== 3)
            {
                //Expiration Date: 11-oct-2017
                char str[20];
                sprintf(str,"%d-%s-%d\n", day, month, year);
                //cout<<"expiredTime:"<<str<<endl;
                expire_time.clear();
                expire_time.assign(str);
                traingDataWhois.expiredTime = MakeTime(expire_time);
            }
            else
            {
                traingDataWhois.expiredTime = 0;
            }

        }
		else
        {
            traingDataWhois.expiredTime = 0;
        }
		if(pos=strstr(buf,"Updated Date:")) //找到“过期时间”
		{
			memset(info, 0,sizeof(info));
			tmp_pos=pos+ strlen("Updated Date:")+1;
			i=0;
			while(tmp_pos && *tmp_pos &&(*tmp_pos!='\\')&&(*tmp_pos!='\"'))//查找指定字符“\n”，并定位tmp_pos到“\n”处
			{
				info[i]=*tmp_pos;
				i++;
				tmp_pos++;
			}
			info[i]='\0';
			update_time.clear();
			update_time.assign(info);
			//cout<<"update_time:"<<update_time<<endl;
			char week[3];
            char month[3];
            int mon;
            int year, day, hour, min, sec;
            char timezone[10];
			//size_t lab = update_time.find_first_of('T');
			//if(lab !=string::npos)
            //{
                //cout<<"update_11:"<<endl;
                //string substring = expire_time.substr(0,lab);
            if (sscanf(update_time.c_str(), "%4d-%2d-%2d%1s%2d:%2d:%2d%1s",
                        &year,&mon,&day,week,&hour,&min,&sec,timezone) == 8)
            {
                //Date: 2017-02-21T20:45:10Z
                //cout<<"day664:"<<day<<":month:"<<month<<":year:"<<year<<endl;
                char str[20];
                sprintf(str,"%d-%d-%d\n", day, mon, year);
                //cout<<"updateTime:"<<str<<endl;
                update_time.clear();
                update_time.assign(str);
                traingDataWhois.updateTime = MakeTime(update_time);
            }
            else if (sscanf(update_time.c_str(), "%d-%3s-%4d%2d:%2d:%2d%3s",
                        &day,month,&year, &hour, &min, &sec, timezone) == 7)
            {
                    //cout<<"day44:"<<day<<":month:"<<month<<":year:"<<year<<endl;
                    //6-May-2015 23:47:47 UTC
                    char str[20];
                    sprintf(str,"%d-%s-%d\n", day, month, year);
                    //cout<<"updateTime:"<<str<<endl;
                    update_time.clear();
                    update_time.assign(str);
                    traingDataWhois.updateTime = MakeTime(update_time);
            }
            else if(sscanf(update_time.c_str(), "%2d-%2d-%4d",&day,&mon,&year)== 3)
            {
                    //cout<<"day33:"<<day<<":month:"<<month<<":year:"<<year<<endl;
                    char str[20];
                    sprintf(str,"%d-%d-%d\n", day, mon, year);
                    //cout<<"update_time On time:"<<str<<endl;
                    update_time.clear();
                    update_time.assign(str);
                    traingDataWhois.updateTime = MakeTime(update_time);
            }
            else if(sscanf(update_time.c_str(),"%3s%3s%2d%2d:%2d:%2d%3s%4d",
                        week, month, &day, &hour, &min, &sec, timezone, &year) == 8)
            {
                    // Fri Feb 03 17:04:12 GMT 2017
                    //cout<<"day22:"<<day<<":month:"<<month<<":year:"<<year<<endl;
                    char str[20];
                    sprintf(str,"%d-%s-%d\n",day,month,year);
                    //cout<<"updateTime:"<<str<<endl;
                    update_time.clear();
                    update_time.assign(str);
                    traingDataWhois.updateTime = MakeTime(update_time);
            }
             else if(sscanf(update_time.c_str(), "%2d-%3s-%4d",&day,month,&year)== 3)
             {
                 //cout<<"day11:"<<day<<":month:"<<month<<":year:"<<year<<endl;
                char str[20];
                sprintf(str,"%d-%s-%d\n", day, month, year);
                //cout<<"updateTime:"<<str<<endl;
                update_time.clear();
                update_time.assign(str);
                traingDataWhois.updateTime = MakeTime(update_time);
             }
            else
            {
                    traingDataWhois.updateTime = 0;
            }
    }
    else
    {
        traingDataWhois.updateTime = 0;
    }
}
	memset(buf, 0,sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	if(!feof(fp))
	{
		if(pos=strstr(buf,"\"safe\"")) //是否有Webutation domain info属性信息，有则利用Verdict判定域名角色类型，没有则将域名角色类型设置为unsure
		{
			role = 0;
		}
		else if(pos=strstr(buf,"\"malicious\""))
		{
			role = 1;
		}
		else
		{
			role = 2;
		}
		traingDataWhois.role = role;
	}

    if(isTraining == true) //test data 无需解析IP
    {
        ifstream fin(IPFile,ios::in);
        if(!fin.is_open())
        {
            cout<<"open file error:"<<IPFile<<endl;
        }
        while(!fin.eof() ) //读文件，一次读取一行，解析相关字段内容，直到读到文件末尾。
        {
        //counts++;
            getline(fin, line);
            if(line.size() == 0 )
            {
                continue;
            }
            else
            {
                size_t label = line.find(IPstring);
                if(label!=string::npos)
                {
                    size_t beging = line.find_first_of(':');
                    size_t ending = line.find_last_of('"');
                    string IP = line.substr(beging + 3,ending- beging -3);
                    traingDataWhois.Ipsets.insert(IP);
                    if(traingDataWhois.Ipsets.size()>=5)
                    {
                        break;
                    }
                }
            }
        }
        fin.close();
    }


	//cout<<"creat:"<<traingDataWhois.registerTime<<",upde:"<<traingDataWhois.updateTime<<",expire:";
	//cout<<traingDataWhois.expiredTime<<",role:"<<traingDataWhois.role<<endl;
 fclose(fp);
 return traingDataWhois;
}
void clusterUsingDomainInfo::outputDnsAbstractFile(const char *rFilebufAbstract,
                                                   const char *wFilebufAbstract)
{
    //读取DNS摘要文件，提取该域名的主域名，判断该主域名是否位于白名单中，若存在则
    //过滤否则输出到文件
    m_DGA_detection.readDNSAbstractFile(rFilebufAbstract,wFilebufAbstract);
}
set<string>clusterUsingDomainInfo::readIPBlacklist(const char *rfilebuff)
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
    /*
    for(set<string>::iterator it = ipBlackList.begin();it!=ipBlackList.end();++it)
    {
        cout<<"iplong:"<<*it<<endl;
    }
    */
    return ipBlackList;
}
//实现domain ：IP1，iP2...IPn 映射,过滤掉IP黑名单中的域名 ,
//blackdomainfile :ip黑名单中对应的domain,whois role is 2 的域名
void clusterUsingDomainInfo::processorDomainFile(const char *rFilebuf,const char *ipblackfi,
                            const char *wFilebuf,const char *blackdomainfile)
{
    //int counts = 0;
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
    //cout<<"size:"<<ipblacklist.size()<<endl;
    while(!fin.eof())
    {

        IPList.clear();
        getline(fin, line);
        //cout<<"line:"<<line<<endl;
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
                            //cout<<"domian is malicious:"<<endl;
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
                            //cout<<"domian is malicious:"<<endl;
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
    //cout<<"domainName:"<<domainName<<endl;
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
        //cout<<"secondLevelDomain:"<<secondLevelDomain<<endl;
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
    //cout<<"m_domainLDs.secondLD:"<<m_domainLDs.secondLD<<endl;
    subDomain = domainName.substr(0, domainName.length() - secondLevelDomainStr.length());
    //cout<<"subDomain:"<<subDomain<<endl;
    if(subDomain.length() == 0)
    {
        m_domainLDs.thirdLD = "";
        //cout<<"thirdLevelDomain:"<<m_domainLDs.thirdLD<<endl;
    }
    else
    {

        label = subDomain.find_last_of('.');
        //cout<<"label:"<<label<<endl;
        string subThirDomian = subDomain.substr(0, label);
        //cout<<"subThirDomian:"<<subThirDomian<<endl;
        int index = subThirDomian.find_last_of('.');
        if(index == string::npos)
        {
            m_domainLDs.thirdLD = subThirDomian;
            //cout<<"thirdLevelDomain:"<<m_domainLDs.thirdLD<<endl;
        }
        else
        {
            thirdLevelDomain = subDomain.substr(index + 1, subThirDomian.length() - index - 1);
            m_domainLDs.thirdLD = thirdLevelDomain;
            //cout<<"thirdLevelDomain:"<<m_domainLDs.thirdLD<<endl;
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
    //cout<<"dame:"<<dname<<endl;
    if(dname != NULL)
    {
        secondLevelDomain = m_DGA_detection.get_primary_domain(dname);
        //cout<<"secondLevelDomain:"<<secondLevelDomain<<endl;
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
        //cout<<"counts:"<<counts<<endl;
        return counts;
    }
    else
    {
        //cout<<"counts:"<<counts<<endl;
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
vector<double>clusterUsingDomainInfo::nGramAverageAnddeviationCalcu(set<string>ngrams,Trie_node root)
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
                //cout<<"ngrams:"<<*iter<<endl;
                tmptr = (char*)(*iter).c_str();
                counts = m_trieTree->statisticsNgramsOccurenceTimes(root, tmptr);
                sum += counts;
                ngramNums.push_back(counts);
            }
            double avg = double(sum)/ngrams.size();
            //cout<<"avg:"<<avg<<endl;
            int temp = (int)avg*100;
            //cout<<"temp:"<<temp<<endl;
            average= ((double)temp)/100;
           // cout<<"average:"<<average<<endl;
            for(vector<int>::iterator it = ngramNums.begin();it != ngramNums.end();++it)
            {
                doubleSum += (*it - average)*(*it - average);
            }

            deviation = double(doubleSum)/ngrams.size(); //方差
            standardDevi = (double(int(sqrt(deviation)*100) )/100); //标准差

            median = medianCalcu(ngramNums);
            //cout<<"standardDevi:"<<standardDevi<<endl;
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
    /*
    for(vector<int>::iterator it = ngramSet.begin(); it!= ngramSet.end();it++)
    {
        cout<< "tem value:"<<*it<<",";
    }
    cout<<endl;
    */
    int n = ngramSet.size();
    if( n%2 == 1)
    {
        median = ngramSet[n/2];
    }
    else
    {
        median = double((ngramSet[n/2] + ngramSet[n/2 -1 ]))/2;
    }
    //cout<<"median:"<<median<<endl;
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
    //cout<<"domainName.length():"<<domainName.length()<<endl;
    for(map<char,int>::iterator it = characNum.begin(); it != characNum.end();++it)
    {
        //cout<<"first:"<<it->first<<",second:"<<it->second<<endl;
        double prob = double(it->second)/domainName.length();
        tmp -= prob*log2(prob);
        //Hx += prob*log2(prob);
        //cout<<"character :"<<it->first<<",and its value:"<<it->second<<",and its prob:"<<prob<<endl;
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
        double percent = double(counts)/domainName.length();
        int tmp = int (percent*100);
        percentage = double(tmp/100);
    }
    else
    {
        percentage = 0.0;
    }
    //cout<<"numeric counts:"<<counts<<endl;

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
    //cout<<"str:"<<str<<endl;
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
            //cout<<"str:"<<str<<endl;
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
	//cout<<"time is:"<<timep<<endl;
	//cout<<"string:"<<asctime(&tmStruct)<<endl;;
	return timep;
}
//二级域名分组
map<string,vector<string> >clusterUsingDomainInfo::secondLDGrouping(const char*rFilebuff)
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
            //cout<<"line:"<<line<<endl;
            size_t label = line.find_first_of(',');
            if(label!= string::npos)
            {
                domain = line.substr(0,label);
                //cout<<"domain:"<<domain<<endl;
            }
            else
            {
                domain = line;
            }
            dNameCharPtr = (char*)domain.c_str();
            //cout<<"dNameCharPtr:"<<dNameCharPtr<<endl;
            secondLevelDomain = m_DGA_detection.get_primary_domain(dNameCharPtr);
            //cout<<"secondLevelDomain:"<<secondLevelDomain<<endl;
            if(secondLevelDomain == NULL)
            {
                continue;
            }
            secondLevelDomainStr.clear();
            secondLevelDomainStr.assign(secondLevelDomain);
            //cout<<"secondLevelDomainStr:"<<secondLevelDomainStr<<endl;
            if(m_dnameGrouping.size() == 0) //empty
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
    /*
    cout<<"m_dnameGrouping size:"<<m_dnameGrouping.size()<<endl;
    for(map<string,vector<string> >::iterator its = m_dnameGrouping.begin();
        its != m_dnameGrouping.end();++its)
    {
            cout<<"secondLDs:"<<its->first<<",and its size:"<<its->second.size()<<endl;
            for(vector<string>::iterator vits = its->second.begin(); vits!= its->second.end();
                ++vits)
            {
                cout<<"domains:"<<*vits<<endl;
            }
    }
    */
    return m_dnameGrouping;

}
void clusterUsingDomainInfo::featureVectorCalcu(map<int,vector<struct domain_IP_TTl_> >domainIpPara,
                                        Trie_node root,const char *wfilebuf,bool isTraing)
{
    //cout<<"domainIpPara.size:"<<domainIpPara.size()<<endl;
    for(map<int,vector<struct domain_IP_TTl_> >::iterator iter = domainIpPara.begin();
        iter != domainIpPara.end();++iter)
    {
        //cout<<"iter->second size:"<<iter->second.size()<<endl;
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
    //cout<<"domains size:"<<domains.size()<<endl;
    for(vector<struct domain_IP_TTl_>::iterator iter = domains.begin(); iter != domains.end();++iter)
    {

        /*
        counts++;
        if(counts>2)
        {
            break;
        }
        */
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
        countNLDs = tLDCountsInDomain(iter->domainName);
        lenofsLD = lengthOfNLDs(nLdDomainstruct.secondLD);
        lenoftLD = lengthOfNLDs(nLdDomainstruct.thirdLD);
        lenofDomain = lengthOfDomain(iter->domainName);
        //计算数字比率
        perofSec = numericPercentageInDomain(nLdDomainstruct.secondLD);
        perofThir = numericPercentageInDomain(nLdDomainstruct.thirdLD);
        //int Asnums = getIPLocation(iter->iplist);
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
        temp.push_back(double(countNLDs));
        temp.push_back(double(lenofsLD));
        temp.push_back(double(lenoftLD));
        temp.push_back(double(lenofDomain));
        temp.push_back(perofSec);
        temp.push_back(perofThir);
        temp.push_back(double(iter->elapseTime));
        temp.push_back(double(iter->isupdate));
        temp.push_back(double(iter->role));
        temp.push_back(iter->ipLocationEntroy);
        if(isTraing == true)
        {
            temp.push_back((double)iter->traingFlag);
        }
        //写文件;
        fout<<iter->domainName<<",";
        for(int i = 0; i < temp.size(); i++)
        {
            if( (i+ 1) == temp.size())
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
        //cout<<"counts:"<<counts;
    }
    fout.close();
}
trieTree* clusterUsingDomainInfo::getTrieTree()
{
    return m_trieTree;
}
clusterUsingDomainInfo::~clusterUsingDomainInfo()
{
    //cout<<"parents deconstructor:"<<endl;
    delete m_trieTree;
    delete getIPInfo;
    delete m_getDomainFromDatabase;
}
/*
void clusterUsingDomainInfo::usingPythonGetTraingFile(const char *getIPpython,const char *getIPLocationpython)
{
    Py_Initialize();
    if(!Py_IsInitialized())
    {
        exit(0);
    }
    PyRun_SimpleString("print \"Hello, world\"");
    PyRun_SimpleString("import sys");
    PyRun_SimpleString("sys.path.append('./')");
    PyObject* pyParams1= Py_BuildValue("s",getIPpython);
    ifstream fgetIP(getIPpython,ios::in);
    if(fgetIP.is_open() && (PyRun_SimpleString("execfile('pyParams1')") != 0))
    {
        fgetIP.close();
        cout<<"PyRun_SimpleFile failed!:"<<getIPpython<<endl;
        exit(0);

    }
    PyObject* pyParams2= Py_BuildValue("s",getIPLocationpython);
    ifstream fgetIPLocation(getIPLocationpython,ios::in);
    if(fgetIPLocation.is_open() && (PyRun_SimpleString("execfile(pyParams2)") != 0))
    {
        fgetIPLocation.close();
        cout<<"PyRun_SimpleFile failed!:"<<getIPLocationpython<<endl;
        exit(0);

    }
    Py_Finalize();
}
*/
void clusterUsingDomainInfo::getDomainInfoFromDataBase(const char *domainInfoFile)
{
    m_getDomainFromDatabase->connect_database();
    m_getDomainFromDatabase->readDataInFile(domainInfoFile);
}
void clusterUsingDomainInfo::getDGADomainInfoFromDataBase()
{
    m_getDomainFromDatabase->getDGADomain();
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
                //else
                //{
                    //fout<<line<<endl;
                //}
            }
            else
            {
                continue;
            }


        }
    }
     /*
    const char *tmpfile = "/home/xdzang/DGA_Detection/maliciousIDfile";
    //m_getDomainFromDatabase->getWholeDomian_ID(domainfile,tmpfile);
    //cout<<"size:"<<primayDo.size()<<endl;

    cout<<"size:"<<domianID.size()<<endl;
    ofstream fout(tmpfile,ios::out|ios::app);
    for(vector<vector<int> >::iterator it = domianID.begin(); it != domianID.end();++it)
    {
        for(int i = 0;i < it->size();i++)
        {
            if(i + 1 == it->size())
            {
                fout<<it->at(i)<<endl;
            }
            else
            {
                fout<<it->at(i)<<",";
            }
        }



    }

   m_getDomainFromDatabase->getWholeDomian_ZWW(tmpfile,writeFile);
*/
}
void clusterUsingDomainInfo::getIPLocation(const char *domainInfoFile,const char *wInfoFile,
                                           bool istraing,bool isbenign)
{
    getIPInfo->connect_database();
    getIPInfo->readIPLocationInIPCIS();
    getIPInfo->getIPLocationNums(domainInfoFile,wInfoFile,getIPInfo->getInfo(),istraing,isbenign);
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
    //ifstream fin3(rbadFile,ios::in);
    ofstream fout(wlostwrite,ios::out|ios::app);
    ofstream fout2(rbadFile,ios::out|ios::app);
    set<string>lost;
    set<string>domainwhois;
    map<string,string>domains;
    //set<string>::iterator its;
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
            //size_t lab = line.find_first_of(',');
            //string domian = line.substr(0,lab);
            domainwhois.insert(line);
        }
    }
     cout<<"domains all size:"<<domainwhois.size()<<endl;
/*
    while(!fin3.eof() ) //读bad文件
    {
        getline(fin3, line);
        if(line.size() == 0 )
        {
            continue;
        }
        else
        {
            size_t lab = line.find_first_of(',');
            string domian = line.substr(0,lab);
            domainwhois.insert(domian);
        }
    }

    cout<<"all domian:"<<domains.size()<<",processDoamin:"<<domainwhois.size()<<endl;

    for(map<string,string>::iterator iter = domains.begin();iter!=domains.end();++iter)
    {
        its = domainwhois.find(iter->first);
        if(its == domainwhois.end())
        {
            fout<<iter->second<<endl;
        }
    }

    for(set<string>::iterator iter = domainwhois.begin();iter!=domainwhois.end();++iter)
    {
        its = domains.find(*iter);
        if(its == domains.end())
        {
            fout<<*iter<<endl;
        }
    }
    for(map<string,string>::iterator it = domains.begin();it!= domains.end();it++)
    {
        fout2<<it->second<<endl;
    }
*/
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
            //int valtmp = (int)(tmp*100);
            //double val = (double)tmp/100;
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
        //cout<<"line:"<<line<<endl;
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
            //cout<<"second level = "<<secondLevelDomain<<endl;
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
    /*
    for(map<string,string>::iterator it = Alexfilemap.begin();it!=Alexfilemap.end();++it)
    {
        cout<<"Alexfilemap first = "<<it->first<<",second = "<<it->second<<endl;
    }
    */
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
    /*
    for(set<string>::iterator it = AlexfileZWWset.begin();it!=AlexfileZWWset.end();++it)
    {
        cout<<"AlexfileZWWset element = "<<*it<<endl;
    }
    */
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
    /*
    for(map<string,string>::iterator it = tmp.begin();it!=tmp.end();++it)
    {
        cout<<"AlexfileZWWset first = "<<it->first<<",second = "<<it->second<<endl;
    }
    */
    map<string,string>::iterator it;
    for(map<string,string>::iterator its = Alexfilemap.begin();its != Alexfilemap.end();++its)
    {
        //cout<<"first = "<<its->first<<",second = "<<its->second<<endl;
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
int main()
{
    clusterUsingDomainInfo cluDomain;
    vector<struct domain_IP_TTl_> traingfileVector;
    cluDomain.initFun();
    map<string,vector<string> >testprimaryGrouping;
    map<int,vector<struct domain_IP_TTl_> >getWholeDomainInfo;


    //获取整个域名信息 计算特征向量
    /*
    getWholeDomainInfo = cluDomain.getDomianFromInfoTestFile(
                        "/home/xdzang/DGA_Detection/domainfilecluester_7w",false);
    cluDomain.featureVectorCalcu(getWholeDomainInfo,cluDomain.getTrieTree()->getTrieTreeRoot(),
                            "/home/xdzang/DGA_Detection/domainfilecluester_7w_features",false);
    */
    return 0;
}
