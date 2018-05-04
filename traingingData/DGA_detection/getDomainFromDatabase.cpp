#include "getDomainFromDatabase.h"
int getDomainFromDatabase::connect_database()
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
void getDomainFromDatabase::disconnect_database()
{
    //MYSQL mysql;
	mysql_close(&mysql);
}
int getDomainFromDatabase::connect_database2()
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
	if (mysql_real_connect(&mysql, DB_DEFAULT_DB_HOST, DB_DEFAULT_DB_USER, DB_DEFAULT_DB_PWD, DB_IPCIS_DB_NAME, DB_DEFAULT_DB_PORT, NULL, 0)
         == NULL)
	{
		cout<<"mysql_real_connect() failed:"<<endl;
		return 1;
	}


	return 0;
}
void getDomainFromDatabase::disconnect_database2()
{
    //MYSQL mysql;
	mysql_close(&mysql);
}
void getDomainFromDatabase::readDataInFile(const char *wfilebuf)
{
    MYSQL_RES *query_result;
    MYSQL_ROW  row;
    bool flag = false;
    char query[256];
	//memset(query, 0, sizeof(query));
	char dname[128];//域名
	string dname_str;
	unsigned int resolved_ip;
	map<string,set<unsigned int> > domain_IP_list;
	map<string,set<unsigned int> >::iterator iter;
	set<unsigned int> iplist;
    ofstream fout(wfilebuf,ios::out|ios::app);
	if(!fout.is_open())
	{
		cout<<"open file"<<wfilebuf<<"error:"<<endl;
		exit(0);
	}
	//连接数据库
	if(connect_database())
	{
		cout<<"mysql_connect_database() failed"<<endl;
		exit(0);
	}
	for(int i = 0 ;i < 24;i++)
    {
        memset(query,0,sizeof(query));
        snprintf(query, sizeof(query), "select domain_name,ip from resolved_ip_20170427%02d limit",i);
        cout<<"query:"<<query<<endl;
        if( mysql_real_query(&mysql, query, strlen(query)) ) //查询失败
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
                    //cout<<"rows:"<<mysql_num_rows(query_result)<<endl;
                    while(row = mysql_fetch_row(query_result))
                    {
                        memset(dname, 0,sizeof(dname));
                        strcpy(dname, row[0]);
                        dname_str.clear();
                        dname_str.assign(dname);
                        resolved_ip = strtoul(row[1],0,10);
                        if(domain_IP_list.size() == 0)
                        {
                            iplist.insert(resolved_ip);
                            domain_IP_list.insert(make_pair<string, set<unsigned int> >(dname_str,iplist));
                            iplist.clear();
                        }
                        else if (domain_IP_list.size()<1000000)
                        {
                            iter = domain_IP_list.find(dname_str);
                            if(iter == domain_IP_list.end())//域名不存在
                            {
                                iplist.insert(resolved_ip);
                                domain_IP_list.insert(make_pair<string, set<unsigned int> >(dname_str,iplist));
                                iplist.clear();
                            }
                            else //域名存在
                            {
                                set<unsigned int>tmpIPList = iter->second;
                                set<unsigned int>::iterator its = tmpIPList.find(resolved_ip);
                                if(its == tmpIPList.end())
                                {
                                    if(tmpIPList.size()<10)
                                    {
                                        tmpIPList.insert(resolved_ip);
                                        domain_IP_list.erase(dname_str);
                                        domain_IP_list.insert(make_pair<string,
                                        set<unsigned int> >(dname_str,tmpIPList));
                                    }

                                }
                                else
                                {
                                    continue;
                                }
                            }
                        }
                        else
                        {

                            flag = true;
                            break;
                        }

                    }

                }
            mysql_free_result(query_result);
         }
      }
     if(flag ==true || i == 23)
     {
        flag = false;
        //cout<<"size:"<<domain_IP_list.size()<<",and i:"<<i<<endl;
        for(map<string, set<unsigned int> >::iterator it = domain_IP_list.begin();it != domain_IP_list.end();++it)
        {
            fout<<it->first<<",";
            for(set<unsigned int>::iterator ipit = it->second.begin();ipit != it->second.end();)
            {
                fout<<*ipit;
                ++ipit;
                if(ipit != it->second.end())
                {
                    fout<<",";
                }
                else
                {
                    fout<<endl;
                }
            }

        }
        fout.close();
        break;
     }
 }
    //断开数据库连接
    disconnect_database();
}
void getDomainFromDatabase::getWholeDomian_ID(const char *rfilebuf,const char *wfilebuf)
{
    string line;
    MYSQL_RES *query_result;
    MYSQL_ROW  row;
    bool flag = false;
    char query[256];
	char dname[128];//域名
	vector<int>tmp;
	vector<vector<int> >IDVector;
	IDVector.clear();
	int is_dga;
	int count = 0;
    ifstream fin (rfilebuf,ios::in);
    set<string>domainset;
    set<string>::iterator its;
    if(!fin.is_open())
    {
        cout<<"open file error:"<<rfilebuf<<endl;
        exit(0);
    }
    ofstream fout(wfilebuf,ios::out|ios::app);
    if(!fout.is_open())
    {
        cout<<"open file error:"<<wfilebuf<<endl;
        exit(0);
    }
    string domianID;
    string primaryDomain;
    map<string,string>primarydomian_ID;
    //连接数据库
	if(connect_database())
	{
		cout<<"mysql_connect_database() failed"<<endl;
		exit(0);
	}
    while(!fin.eof() ) //读文件，一次读取一行，解析相关字段内容，直到读到文件末尾。
    {
        /*
        count++;
        if(count >10)
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
            domainset.insert(line);
        }
    }
    cout<<"domainset size:"<<domainset.size()<<endl;
            //memset(query,0,sizeof(query));
    string queryStr = "select domain_id,primary_domain from domain_name";
            //string left = "'";
            //string right= "'";
            //string queryStr = select + left + line + right + " limit 1";
    cout<<"query:"<<queryStr<<endl;
    if( mysql_real_query(&mysql, queryStr.c_str(), queryStr.length()) ) //查询失败
    {
        cout<<"mysql_real_query(%s) error:"<<endl;
    }
    else //查询成功
    {

                //cout<<"success:"<<endl;
        query_result = mysql_store_result(&mysql);
        if(!query_result)
        {
            cout<<"mysql_query_result is NULL"<<endl;
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
                           //tmp.push_back(atoi(row[0]));
                           //fout<<row[0]<<endl;
                    domianID.clear();
                    primaryDomain.clear();
                    domianID.assign(row[0]);
                    primaryDomain.assign(row[1]);
                    primarydomian_ID.insert(make_pair<string,string>(domianID,primaryDomain));
                }
                        //IDVector.push_back(tmp);
                        //tmp.clear();
                    mysql_free_result(query_result);
            }
        }
    }
    cout<<"map size:"<<primarydomian_ID.size()<<endl;
    for(map<string,string>::iterator  iter = primarydomian_ID.begin();iter != primarydomian_ID.end();
        ++iter)
    {
        //cout<<iter->first<<","<<iter->second<<endl;
        its = domainset.find(iter->second);
        if(its != domainset.end())
        {
            fout<<iter->first<<","<<iter->second<<endl;
        }
    }
    disconnect_database();
    fin.close();
    fout.close();
}
 void getDomainFromDatabase::getWholeDomian_ZWW(const char *rfilebuf,const char *wfilebuf)
 {
     MYSQL_RES *query_result;
     MYSQL_ROW  row;
     char query[256];
	 char dname[128];//域名
	 string dname_str;
	 string line;
	 vector<int>ID;
	 ID.clear();
	 ifstream fin (rfilebuf,ios::in);
	 if(!fin.is_open())
     {
         return;
     }
     ofstream fout(wfilebuf,ios::out|ios::app);
     if(!fout.is_open())
     {
         return;
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
            size_t lab = line.find_first_of(',');
            string idstr = line.substr(0,lab);
            ID.push_back(atoi(idstr.c_str()));
            idstr.clear();
        }
     }
     if(connect_database2())
     {
		cout<<"mysql_connect_database() failed"<<endl;
		exit(0);
	 }
	 string select = "select domain_name from resolved_ip where domain_id = ";
	 char tmp[16];
	 string id;
	 string queryStr;
	 bool flag = false;
	 string left ="'";
	 string right = "'";
	 cout<<"size of ID:"<<ID.size()<<endl;
	 int counts = 0;
    for(vector<int> ::iterator iter = ID.begin();iter !=ID.end();++iter)
    {
            /*
           counts++;
           if(counts <8986)
           {
               continue;
           }
            */
           sprintf(tmp,"%d",*iter);
           id.assign(tmp);
           queryStr = select+ left + id + right + " limit 3";
           cout<<"query:"<<queryStr<<endl;
           if( mysql_real_query(&mysql, queryStr.c_str(), queryStr.length()) ) //查询失败
           {
                cout<<"mysql_real_query(%s) error:"<<endl;
           }
           else //查询成功
           {
             //cout<<"success:"<<endl;
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
                    //cout<<"000:"<<endl;
                    while(row = mysql_fetch_row(query_result))
                    {
                        memset(dname, 0,sizeof(dname));
                        strcpy(dname, row[0]);
                        dname_str.clear();
                        dname_str.assign(dname);
                        if(dname_str.length() != 0)
                        {
                            fout<<dname_str<<endl;
                            //flag = true;
                        }


                    }
                    mysql_free_result(query_result);
                }
            }
         }
         /*
         if(flag == true )
         {
             flag = false;
             break;
         }
         */
         memset(tmp,0,sizeof(tmp));
         id.clear();
         queryStr.clear();
      //}

    }
    disconnect_database2();
    fout.close();
 }
 void getDomainFromDatabase::getDGADomain()
 {
     MYSQL_RES *query_result;
     MYSQL_ROW  row;
	 vector<string>ID;
	 ID.clear();
	 char ids[128];//域名
	 string idstr;
	 /*
	 ifstream fin (rfilebuf,ios::in);
	 if(!fin.is_open())
     {
         return;
     }
     ofstream fout(wfilebuf,ios::out|ios::app);
     if(!fout.is_open())
     {
         return;
     }
    */
     if(connect_database2())
     {
		cout<<"mysql_connect_database() failed"<<endl;
		exit(0);
	 }
	 string select = "select domain_id from domain_name where is_dga = 1 limit 10 ";
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
                    memset(ids, 0,sizeof(ids));
                    strcpy(ids, row[0]);
                    idstr.clear();
                    idstr.assign(ids);
                    ID.push_back(idstr);
                }
                mysql_free_result(query_result);
            }
        }
    }

    for(vector<string>::iterator  iter = ID.begin();iter!= ID.end();++iter)
    {
        cout<<*iter<<endl;
    }
    select.clear();
    disconnect_database2();
    //fout.close();
 }
/*
int main()
{
    getDomainFromDatabase cur_fast_flux;
    cur_fast_flux.connect_database();
    cur_fast_flux.readDataInFile("/home/xdzang/DGA_Detection/domainInfo.dat");
    return 0;
}
*/
