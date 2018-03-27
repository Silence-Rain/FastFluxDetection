#include "getDGADomianNamesResolvedIP.h"
int getResolvedIPFromIPCIS_DNS_DB::connect_database()
{
    /* initial mysql */
	if(!(mysql_init(&mysql)))
	{
		cout<<"mysql_init() failed"<<endl;
		return 1;
	}
	/* set reconnect option */
	unsigned int value;
	value = 24*3600;
	mysql_options(&mysql, MYSQL_OPT_CONNECT_TIMEOUT, (char *)&value);
	value = 1;
	mysql_options(&mysql, MYSQL_OPT_RECONNECT, (char *)&value);

	/* get connected to database */
	if (mysql_real_connect(&mysql, DB_DEFAULT_DB_HOST, DB_DEFAULT_DB_USER, DB_DEFAULT_DB_PWD, DB_DEFAULT_DB_NAME, DB_DEFAULT_DB_PORT, NULL, 0)
         == NULL)
	{
		cout<<"mysql_real_connect() failed:"<<endl;
		return 1;
	}


	return 0;
}
void getResolvedIPFromIPCIS_DNS_DB::disconnect_database()
{
    //MYSQL mysql;
	mysql_close(&mysql);
}
map<int,string> getResolvedIPFromIPCIS_DNS_DB::getDGAAttributesFromDomain_name(const char* domain_id,const char* tmpStr)
{
     MYSQL_RES *query_result;
     MYSQL_ROW  row;
	 char ttlChar[128];//域名
	 string strTTL;
	 string myselect;
     if(connect_database())
     {
		cout<<"mysql_connect_database() failed"<<endl;
		exit(0);
	 }
	 char str[128];
     sprintf(str,"select %s,%s from domain_name where is_dga =1",domain_id,tmpStr);
     myselect.clear();
     myselect.assign(str);
     //cout<<"myselect:"<<myselect<<endl;
     if( mysql_real_query(&mysql, myselect.c_str(), myselect.length()) ) //查询失败
     {
       cout<<"mysql_real_query(%s) error:"<<endl;
     }
     else //查询成功
     {
        query_result = mysql_store_result(&mysql);
        if(!query_result)
        {
          cout<<"mysql_query_result is NULL"<<endl;;
        }
        else
        {
            if(mysql_num_rows(query_result) == 0)
            {
                cout<<"mysql_num_rows(%s) return 0"<<endl;
                mysql_free_result(query_result);
            }
            else
            {
                while(row = mysql_fetch_row(query_result))
                {
                    int domainID = atoi(row[0]);
                    memset(ttlChar, 0,sizeof(ttlChar));
                    strcpy(ttlChar, row[1]);
                    strTTL.clear();
                    strTTL.assign(ttlChar);
                    m_domianAttributes.insert(make_pair<int,string>(domainID,strTTL));

                }
                mysql_free_result(query_result);
            }
        }
    }
    /*
    for(map<int,string>::iterator  iter = m_domianAttributes.begin();iter!= m_domianAttributes.end();++iter)
    {
        cout<<iter->first<<","<<iter->second<<endl;
    }
    */
    myselect.clear();
    disconnect_database();
    cout<<"after query ID and TTL"<<endl;
    return m_domianAttributes;
}
//将域名相关信息写入文件具体格式为：域名，解析IP，TTL，FirstTime
void getResolvedIPFromIPCIS_DNS_DB::getResolvedIPAndWriteInFile(const char *wfilebuf)
{
    MYSQL_RES *query_result;
    MYSQL_ROW  row;
    string select;
    string domain_name;
    string resolved_IP;
    string found_Time;
    getDGAAttributesFromDomain_name("domain_id","ttl");
    ofstream fout(wfilebuf,ios::out|ios::app);
    if(!fout.is_open())
    {
        cout<<"open write file error"<<endl;
        return;
    }
    if(connect_database())
    {
		cout<<"mysql_connect_database() failed"<<endl;
		exit(0);
    }
   // first ID second TTL
    for(map<int,string>::iterator  iter = m_domianAttributes.begin();iter!= m_domianAttributes.end();++iter)
    {
        int ID = iter->first;
        char str[128];
        sprintf(str,"select domain_name,ip,ftime from resolved_ip where domain_id = %d ",ID);
        select.clear();
        select.assign(str);
        if( mysql_real_query(&mysql, select.c_str(), select.length()) ) //查询失败
        {
          cout<<"mysql_real_query(%s) error:"<<endl;
        }
        else //查询成功
        {
            query_result = mysql_store_result(&mysql);
            if(!query_result)
            {
              cout<<"mysql_query_result is NULL"<<endl;;
            }
            else
            {
                if(mysql_num_rows(query_result) == 0)
                {
                    cout<<"mysql_num_rows(%s) return 0"<<endl;
                    mysql_free_result(query_result);
                }
                else
                {

                    while(row = mysql_fetch_row(query_result))
                    {
                        char tmp[256];
                        memset(tmp, 0,sizeof(tmp));
                        strcpy(tmp, row[0]);
                        domain_name.clear();
                        domain_name.assign(tmp);

                        memset(tmp, 0,sizeof(tmp));
                        strcpy(tmp, row[1]);
                        resolved_IP.clear();
                        resolved_IP.assign(tmp);

                        memset(tmp, 0,sizeof(tmp));
                        strcpy(tmp, row[2]);
                        found_Time.clear();
                        found_Time.assign(tmp);
                        cout<<domain_name<<","<<resolved_IP<<","<<iter->second<<","<<found_Time<<endl;
                        //fout<<domain_name<<","<<resolved_IP<<","<<iter->second<<","<<found_Time<<endl;

                    }
                    mysql_free_result(query_result);

                }
            }
        }
    }
    select.clear();
    disconnect_database();
    fout.close();
    return;
}
//获取二级域名对应的名字服务器
void getResolvedIPFromIPCIS_DNS_DB::getNameServerofPrimaryDoamin(const char *wfilebuf)
{
    MYSQL_RES *query_result;
    MYSQL_ROW  row;
    char *primaryDomain = NULL;
    string select;
    string ns_name;
    string found_Time;
    getDGAAttributesFromDomain_name("domain_id","primary_domain");
    ofstream fout(wfilebuf,ios::out|ios::app);
    if(!fout.is_open())
    {
        cout<<"open write file error"<<endl;
        return;
    }
    if(connect_database())
    {
		cout<<"mysql_connect_database() failed"<<endl;
		exit(0);
    }
    cout<<"begin query three level domain and ip"<<endl;
    for(map<int,string>::iterator  iter = m_domianAttributes.begin();iter!= m_domianAttributes.end();++iter)
    {
        int ID = iter->first;
        primaryDomain = (char *)iter->second.c_str();
        char str[128];
        sprintf(str,"select ns_name,ftime from ns where domain_id = %d and domain_name ='%s'",ID,
                primaryDomain);
        select.clear();
        select.assign(str);
        //cout<<"cur select:"<<select<<endl;
        if( mysql_real_query(&mysql, select.c_str(), select.length()) ) //查询失败
        {
          cout<<"mysql_real_query(%s) error:"<<endl;
        }
        else //查询成功
        {
            query_result = mysql_store_result(&mysql);
            if(!query_result)
            {
              cout<<"mysql_query_result is NULL"<<endl;;
            }
            else
            {
                if(mysql_num_rows(query_result) == 0)
                {
                    cout<<"mysql_num_rows(%s) return 0"<<endl;
                    mysql_free_result(query_result);
                }
                else
                {

                    while(row = mysql_fetch_row(query_result))
                    {
                        char tmp[256];
                        memset(tmp, 0,sizeof(tmp));
                        strcpy(tmp, row[0]);
                        ns_name.clear();
                        ns_name.assign(tmp);

                        memset(tmp, 0,sizeof(tmp));
                        strcpy(tmp, row[1]);
                        found_Time.clear();
                        found_Time.assign(tmp);


                        cout<<iter->second<<","<<ns_name<<","<<found_Time<<endl;
                        //fout<<iter->second<<","<<ns_name<<","<<found_Time<<endl;

                    }
                    mysql_free_result(query_result);


                }
            }
        }
    }
    select.clear();
    disconnect_database();
    fout.close();
    return;
}
//初始化合法域名后缀集合
int getResolvedIPFromIPCIS_DNS_DB::init_legal_domain_set()
{
    FILE   *fp = NULL;
	char   buf[DOMAIN_LEN];
	char   *temppos;
	int    index;
	char   dns_suf_str[DOMAIN_LEN];
	string dns_suf;
	if((fp = fopen(LEGAL_LIST_FILE, "r"))==NULL)
	{
		cout<<"Cannot open file :"<<LEGAL_LIST_FILE<<endl;
		return 1;
	}
	while(!feof(fp))
	{
		fgets(buf, sizeof(buf), fp);
		if(!feof(fp))
		{
			/* get dns_suf */
			temppos = buf;
			memset(dns_suf_str, 0, sizeof(dns_suf_str));
			index = 0;

			while( temppos && *temppos && (*temppos!='\n') && (*temppos!='\r')&& (*temppos!=' ') )
			{
				dns_suf_str[index] = tolower(*temppos);
				++index;
				if(index == DOMAIN_LEN-1)
                {
                    break;
                }
				temppos++;
			}
			dns_suf_str[index]='\0';
			dns_suf.clear();
			dns_suf.assign(dns_suf_str);
			suffix_set.insert(dns_suf);

		}
	}

	fclose(fp);
	return 0;
}
//初始化域名后缀集合
int getResolvedIPFromIPCIS_DNS_DB::init_dns_suf_set()
{
	FILE   *fp = NULL;
	char   buf[DOMAIN_LEN];
	char   *temppos;
	int    index;
	char   dns_suf_str[DOMAIN_LEN];
	string dns_suf;
	if((fp = fopen(DNS_SUF_FILE, "r"))== NULL)
	{
		cout<<"Cannot open file:"<<DNS_SUF_FILE<<endl;
		return 1;
	}
	while(!feof(fp))
	{
		fgets(buf, sizeof(buf), fp);
		if(!feof(fp))
		{
			/* get dns_suf */
			temppos = buf;
			memset(dns_suf_str, 0, sizeof(dns_suf_str));
			index = 0;
			while( temppos && *temppos && (*temppos!='\n') && (*temppos!='\r') )
			{
				dns_suf_str[index] = tolower(*temppos);
				++index;
				if(index == DOMAIN_LEN-1)
                {
                    break;
                }
				temppos++;
			}

			dns_suf_str[index]='\0';
			dns_suf.clear();
			dns_suf.assign(dns_suf_str);
			dns_suf_set.insert(dns_suf);
		}
	}

	fclose(fp);
	return 0;
}
//判断域名后缀是否合法
int getResolvedIPFromIPCIS_DNS_DB::is_dns_suf(char* dns_suf_str)
{
    string dns_suf;
	set<string>::iterator dns_suf_set_it;

	dns_suf.clear();
	dns_suf.assign(dns_suf_str);
	dns_suf_set_it = dns_suf_set.find(dns_suf);
	if(dns_suf_set_it == dns_suf_set.end())
    {
        return 0;
    }
	else
    {
        return 1;
    }

}
void getResolvedIPFromIPCIS_DNS_DB::InitFun()
{
    init_dns_suf_set();
    init_legal_domain_set();
}
//获取域名的二级域名
char* getResolvedIPFromIPCIS_DNS_DB::get_primary_domain(const char* dname)
{
    //cout<<"dname:"<<dname<<endl;
    int    domain_name_len;
	int    index;
	char   domain_name_str[DOMAIN_LEN];     //域名小写字符串
	char   tmp_domain_name_str[DOMAIN_LEN];
	char   suffix[DNS_MSUF_LEN];
	int    flag;
	int    has_flabel;
	char   first_label[LABEL_LEN]; //一层管理域
	int    has_slabel;
	char   second_label[LABEL_LEN];//二层管理域
	char   primary_domain_str[DOMAIN_LEN];
	char   *primary_domain;

	//域名全部转换成小写字符串
    domain_name_len = strlen(dname);
	memset(domain_name_str, 0, sizeof(domain_name_str));
	for(index = 0; index < domain_name_len; index++)
    {
        domain_name_str[index] = tolower(dname[index]);
    }

	//去除含有特殊字符的域名
	for(index = 0; index < domain_name_len; index++)
	{
		if( ( (dname[index]>='0') && (dname[index]<='9') )  ||  ( (dname[index]>='a') && (dname[index]<='z') )  ||  ( (dname[index]>='A') && (dname[index]<='Z') )  ||  (dname[index]=='.')  ||  (dname[index]=='-')  ||  (dname[index]=='_')  )
        {
			domain_name_str[index]=tolower(dname[index]);
        }
		else
		{
			// fprintf(fp_error, "domain name has special character: %s\n", dname);
			return NULL;
		}
	}

	//初始化各变量
	memset(tmp_domain_name_str, 0, sizeof(tmp_domain_name_str));
	strcpy(tmp_domain_name_str, domain_name_str);

	memset(suffix, 0, sizeof(suffix));
	flag = 0;
	has_flabel = 0;
	memset(first_label, 0, sizeof(first_label));
	has_slabel = 0;
	memset(second_label, 0, sizeof(second_label));

	//求取后缀、一层标签、二层标签
	index = strlen(tmp_domain_name_str)-1;
    //cout<<"index:"<<index<<endl;
	while(index >= 0)
	{
		if(tmp_domain_name_str[index] == '.')
		{
			if( ( (flag == 0) || (flag == 1) ) && is_dns_suf(tmp_domain_name_str + index) ) //是后缀
			{
				memset(suffix, 0, sizeof(suffix));
				strcpy(suffix, domain_name_str+index);
				tmp_domain_name_str[index]='\0';
				//cout<<"suffix:"<<suffix<<",tmp_domain_name_str:"<<tmp_domain_name_str<<endl;
				flag = 1;
			}
			else
			{
				if(strlen(tmp_domain_name_str+index+1)>=LABEL_LEN)
				{
					//cout<<"AAA"<<endl;
					return NULL;
				}

				if(flag == 1)
				{
					has_flabel = 1;
					memset(first_label, 0, sizeof(first_label));
					strcpy(first_label, tmp_domain_name_str+index+1);
					tmp_domain_name_str[index]='\0';
					flag = 2;
					//cout<<"has_flabel == 1,first_label:"<<first_label<<endl;
				}
				else if(flag ==2)
				{
					has_slabel=1;
					memset(second_label, 0,sizeof(second_label));
					strcpy(second_label, tmp_domain_name_str+index+1);
					tmp_domain_name_str[index]='\0';
					flag=3;
					//cout<<"has_slabel == 1,first_label:"<<first_label<<endl;
				}
				else
                {
                    //cout<<"BBB"<<endl;
                    break;
                }

			}
		}

		index--;
	}
    //cout<<"11111"<<endl;
	if( (index < 0) && strcmp(tmp_domain_name_str, "www") )
	{
		if(strlen(tmp_domain_name_str) >= LABEL_LEN)
		{
			// fprintf(fp_error, "domain name's label length is too long(>=%u): %s\n", LABEL_LEN, dname);
			return NULL;
		}
		if(flag == 1)
		{
			has_flabel = 1;
			memset(first_label, 0, sizeof(first_label));
			strcpy(first_label, tmp_domain_name_str);
			//cout<<"first_label:"<<first_label<<endl;
		}
		else if(flag == 2)
		{
			has_slabel = 1;
			memset(second_label, 0, sizeof(second_label));
			strcpy(second_label, tmp_domain_name_str);
			//cout<<"second_label:"<<first_label<<endl;
		}
		else
        {
            ;
        }

	}
    //cout<<"2222"<<endl;
    //cout<<"has_flabel:"<<has_flabel<<"strlen(first_label):"<<strlen(first_label)<<endl;
	if(!has_flabel || (strlen(first_label)<1))
	{
		// fprintf(fp_error, "domain name has no first level domain: %s\n", dname);
		//cout<<"333"<<endl;
		return NULL;
	}
	//cout<<"first_label:"<<first_label<<",suffix:"<<suffix<<endl;
	memset(primary_domain_str, 0, sizeof(primary_domain_str));
	snprintf(primary_domain_str, sizeof(primary_domain_str), "%s%s", first_label, suffix);//生成二级域名
	//cout<<"output primary_domain_str:"<<primary_domain_str<<endl;
	primary_domain = primary_domain_str;
	return primary_domain;
}
//实现二级域名和解析IP映射timewidow 2小时
void getResolvedIPFromIPCIS_DNS_DB::prmaimaryDomain_IPMapping(const char* rfilebuff,const char* wfilebuff,int timewidow)
{
    char *primaryDomain = NULL;
    domain_info resolvedDomainInfo;
    int tmpTime = 0;
    string line;
    float avg = 0;
    int count = 0;
    ifstream fin (rfilebuff,ios::in);
    if(!fin.is_open())
	{
		cout<<"open wfile"<<rfilebuff<<"error:"<<endl;
		exit(0);
	}
    ofstream fout(wfilebuff,ios::out);
    if(!fout.is_open())
    {
        cout<<"open write file error"<<endl;
        exit(0);
    }
    map<string,domain_info>primaryDomainInfoMap;
    while(!fin.eof() ) //读文件，一次读取一行，解析相关字段内容，直到读到文件末尾。
    {
       getline(fin, line);
       if(line.size() == 0 )
       {
            continue;
        }
        else
        {
           size_t firstLabel = line.find_first_of(',');
           string secondLevelDomain = line.substr(0,firstLabel);
           size_t secondLabel = line.find_first_of(',',firstLabel + 1 );
           string resolvedIP = line.substr(firstLabel+1,secondLabel- firstLabel - 1);
           size_t thirdLabel = line.find_first_of(',',secondLabel + 1 );
           string TTL = line.substr(secondLabel+1,thirdLabel - secondLabel - 1);
           string foundTime = line.substr(thirdLabel+1,line.length() - thirdLabel -1);

           if(primaryDomainInfoMap.size() == 0)//文件首行插入
           {
                tmpTime = atoi(foundTime.c_str());
                resolvedDomainInfo.resolvedIPset.insert(resolvedIP);
                resolvedDomainInfo.ttlelements.insert(atoi(TTL.c_str()));
                resolvedDomainInfo.foundtimeSet.insert(atoi(foundTime.c_str()));
                primaryDomainInfoMap.insert(make_pair<string,domain_info>(secondLevelDomain,resolvedDomainInfo));
           }
           else
           {
                if(atoi(foundTime.c_str()) - tmpTime <= timewidow)
                {

                    map<string,domain_info>::iterator iter = primaryDomainInfoMap.find(secondLevelDomain);
                    if(iter != primaryDomainInfoMap.end())
                    {
                        string tmpPrimaryDomain = iter->first;
                        domain_info tmpDomainInfoMapping = iter->second;
                        primaryDomainInfoMap.erase(iter);
                        tmpDomainInfoMapping.resolvedIPset.insert(resolvedIP);
                        tmpDomainInfoMapping.ttlelements.insert(atoi(TTL.c_str()));
                        tmpDomainInfoMapping.foundtimeSet.insert(atoi(foundTime.c_str()));
                        primaryDomainInfoMap.insert(make_pair<string,domain_info>(tmpPrimaryDomain,tmpDomainInfoMapping));
                    }
                    else
                    {
                        domain_info tmpResolvedInfo;
                        tmpResolvedInfo.resolvedIPset.insert(resolvedIP);
                        tmpResolvedInfo.ttlelements.insert(atoi(TTL.c_str()));
                        tmpResolvedInfo.foundtimeSet.insert(atoi(foundTime.c_str()));
                        primaryDomainInfoMap.insert(make_pair<string,domain_info>(secondLevelDomain,tmpResolvedInfo));
                    }
                }
                else
                {
                    for(map<string,domain_info>::iterator it = primaryDomainInfoMap.begin();it!=
                        primaryDomainInfoMap.end();++it)
                    {

                        fout<<it->first<<",";
                        for(set<string>::iterator resIt = it->second.resolvedIPset.begin();resIt !=
                                                          it->second.resolvedIPset.end();++resIt)
                        {
                            //cout<<"resolveIp size:"<<it->second.resolvedIPset.size();
                            fout<<*resIt<<",";
                        }
                        fout<<*(it->second.ttlelements.begin())<<",";
                        fout<<*(it->second.foundtimeSet.begin())<<endl;


                    }
                    resolvedDomainInfo.foundtimeSet.clear();
                    resolvedDomainInfo.resolvedIPset.clear();
                    resolvedDomainInfo.ttlelements.clear();
                    primaryDomainInfoMap.clear();
                    tmpTime = atoi(foundTime.c_str());
                    resolvedDomainInfo.resolvedIPset.insert(resolvedIP);
                    resolvedDomainInfo.ttlelements.insert(atoi(TTL.c_str()));
                    resolvedDomainInfo.foundtimeSet.insert(atoi(foundTime.c_str()));
                    primaryDomainInfoMap.insert(make_pair<string,domain_info>(secondLevelDomain,resolvedDomainInfo));
                }

           }

        }
    }
    for(map<string,domain_info>::iterator it = primaryDomainInfoMap.begin();it!=
                        primaryDomainInfoMap.end();++it)
    {

        fout<<it->first<<",";
        for(set<string>::iterator resIt = it->second.resolvedIPset.begin();resIt !=
            it->second.resolvedIPset.end();++resIt)
        {
            //cout<<"resolveIp size:"<<it->second.resolvedIPset.size();
            fout<<*resIt<<",";
        }
        fout<<*(it->second.ttlelements.begin())<<",";
        fout<<*(it->second.foundtimeSet.begin())<<endl;



    }
    fin.close();
    fout.close();
}
//基于时间对域名排序
void getResolvedIPFromIPCIS_DNS_DB::rawDataSortUsingTime(const char* rfilebuff,const char* wfilebuff)
{
    string line;
    multimap<int,string>domainMaping;
    ifstream fin (rfilebuff,ios::in);
    if(!fin.is_open())
	{
		cout<<"open wfile"<<rfilebuff<<"error:"<<endl;
		exit(0);
	}
    ofstream fout(wfilebuff,ios::out);
    if(!fout.is_open())
    {
        cout<<"open write file error"<<endl;
        exit(0);
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
           size_t Label = line.find_last_of(',');
           string foundtime = line.substr(Label +1,line.length());
           int tmpTime = atoi(foundtime.c_str());
           domainMaping.insert(make_pair<int,string>(tmpTime,line));
       }

    }

    for(multimap<int,string>::iterator iter = domainMaping.begin();iter!= domainMaping.end();++iter)
    {
        fout<<iter->second<<endl;

    }
    /*
    cout<<"size:"<<domainMaping.size()<<endl;
    multimap<int,string>::iterator iter = domainMaping.begin();
    cout<<"start time:"<<iter->first<<endl;
    multimap<int,string>::iterator it = domainMaping.end();
    cout<<"end time:"<<(--it)->first<<endl;
    cout<<"last time:"<<(iter->first)-((--it)->first)<<endl;
    */
    fin.close();
    fout.close();

}//按时间排序后的二级域名 IP映射
void getResolvedIPFromIPCIS_DNS_DB::secondLevelMapping(const char* rfilebuff,const char* wfilebuff)
{
    string line;
    char *primaryDomain = NULL;
    string secondLevelDomain;
    int count = 0;
    ifstream fin (rfilebuff,ios::in);
    if(!fin.is_open())
	{
		cout<<"open wfile"<<rfilebuff<<"error:"<<endl;
		exit(0);
	}
    ofstream fout(wfilebuff,ios::out);
    if(!fout.is_open())
    {
        cout<<"open write file error"<<endl;
        exit(0);
    }
    while(!fin.eof() ) //读文件，一次读取一行，解析相关字段内容，直到读到文件末尾。
    {
        /*
        count++;
        if(count>=100)
        {
            break;
        }
        */
       getline(fin, line);
       if(line.size() == 0 )
       {
            continue;
       }
       else
       {
           size_t Label = line.find_first_of(',');
           string doaminName = line.substr(0,Label);
           string subline = line.substr(Label + 1,line.length());
           primaryDomain = get_primary_domain(doaminName.c_str());
           secondLevelDomain.clear();
           secondLevelDomain.assign(primaryDomain);
           fout<<secondLevelDomain<<","<<subline<<endl;
       }

    }
    fin.close();
    fout.close();
}
//二级域名和全域名映射
void getResolvedIPFromIPCIS_DNS_DB::domainMapping(const char* rfilebuff,const char* wfilebuff)
{
    char *primaryDomain = NULL;
    string secondLevelDomain;
    string line;
    multimap<string,string>domainMaping;
    ifstream fin (rfilebuff,ios::in);
    if(!fin.is_open())
	{
		cout<<"open wfile"<<rfilebuff<<"error:"<<endl;
		exit(0);
	}
    ofstream fout(wfilebuff,ios::out);
    if(!fout.is_open())
    {
        cout<<"open write file error"<<endl;
        exit(0);
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
           size_t firstLabel = line.find_first_of(',');
           string doaminName = line.substr(0,firstLabel);
           primaryDomain = get_primary_domain(doaminName.c_str());
           secondLevelDomain.clear();
           secondLevelDomain.assign(primaryDomain);
           domainMaping.insert(make_pair<string,string>(secondLevelDomain,doaminName));
       }

    }
    for(multimap<string,string>::iterator iter = domainMaping.begin();iter!= domainMaping.end();++iter)
    {
        fout<<iter->first<<","<<iter->second<<endl;
    }
    fin.close();
    fout.close();
}
// int  main()
// {
//     getResolvedIPFromIPCIS_DNS_DB curObj;
//     curObj.InitFun();
//     // //"/home/xdzang/Fast_Flux_Detection/after_test1.txt");
//     // //curObj.get_primary_domain("www.facebook.com");
//     // //curObj.getNameServerofPrimaryDoamin("/home/xdzang/Fast_Flux_Detection/domainNameServerData.dat");

//     // curObj.prmaimaryDomain_IPMapping("/home/xdzang/Fast_Flux_Detection/secondDomainDataSort.dat",
//     //                           "/home/xdzang/Fast_Flux_Detection/secondDomainIPMapping2.dat",3600);

//     cout<<curObj.get_primary_domain("www.aaa.com");
//     return 0;
// }

extern "C" {
    getResolvedIPFromIPCIS_DNS_DB obj;

    void init()
    {
        return obj.InitFun();
    }

    char* getPrimaryDomain(const char* str)
    {
        return obj.get_primary_domain(str);
    }
}

