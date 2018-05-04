#include "getIPLocationFromIPCIS.h"

struct ipKeyInfo_ ipKeyInfo;

int getIPLocationFromIPCIS::connect_database()
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
	if ( mysql_real_connect(&mysql, DB_DEFAULT_DB_HOST_IPCIS, DB_DEFAULT_DB_USER_IPCIS,
        DB_DEFAULT_DB_PWD_IPCIS, DB_DEFAULT_DB_NAME_IPCIS, DB_DEFAULT_DB_PORT_IPCIS, NULL, 0)
         == NULL)
	{
		cout<<"mysql_real_connect() failed:"<<endl;
		return 1;
	}


	return 0;
}
void getIPLocationFromIPCIS::disconnect_database()
{
    //MYSQL mysql;
	mysql_close(&mysql);
}
map<struct ipKeyInfo_,string>getIPLocationFromIPCIS::readIPLocationInIPCIS()
{
    struct ipKeyInfo_ ipKeyInfomation;
    //map<struct ipKeyInfo_,string>allIPInfo;
    MYSQL_RES *query_result;
    MYSQL_ROW  row;
    bool flag = false;
    char query[256];
	char cotry[64];
	string countryStr;
	unsigned int ipbegins;
	unsigned int ipEnds;
	//连接数据库
	if(connect_database())
	{
		cout<<"mysql_connect_database() failed"<<endl;
		exit(0);
	}
    memset(query,0,sizeof(query));
    snprintf(query, sizeof(query), "select ipStart,ipEnd,country from IP2Location");
    //cout<<"query:"<<query<<endl;
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
                    ipbegins = strtoul(row[0],0,10);
                    ipEnds = strtoul(row[1],0,10);
                    memset(cotry, 0,sizeof(cotry));
                    strcpy(cotry, row[2]);
                    countryStr.clear();
                    countryStr.assign(cotry);
                    ipKeyInfomation.IPLow = ipbegins;
                    ipKeyInfomation.IPUp =  ipEnds;
                    allIPInfo.insert(make_pair<struct ipKeyInfo_,string>(ipKeyInfomation,countryStr));
                    //cout<<"ipbegins:"<<ipbegins<<",ipEnds:"<<ipEnds<<",countryStr:"<<countryStr<<endl;
                }

            }
            mysql_free_result(query_result);
        }
    }
    //断开数据库连接
    disconnect_database();
    /*
    for(map<struct ipKeyInfo_,string>::iterator iter = allIPInfo.begin();iter!= allIPInfo.end();
        ++iter)
    {
           cout<<"["<<iter->first.IPLow<<","<<iter->first.IPUp<<"] ,"<<iter->second<<endl;
    }
    */
    return allIPInfo;
}
map<struct ipKeyInfo_,string>getIPLocationFromIPCIS::getInfo()
{
    return allIPInfo;
}
bool operator <(struct ipKeyInfo_ info1,struct ipKeyInfo_ info2)
{
	return  info1.IPUp < info2.IPUp;
}
void getIPLocationFromIPCIS::getIPLocationNums(const char* rfilebuff,const char* wfilebuff,
                const map<struct ipKeyInfo_,string> &IPLocation,bool istraing,bool isbenign)
{
    string line;
    string zero = "0";
    set<string>countrySet;
    ifstream fin(rfilebuff,ios::in);
    if(!fin.is_open())
    {
        cout<<"open file error:"<<rfilebuff<<endl;
        return;
    }
    ofstream fout(wfilebuff,ios::out|ios::app);
    if(!fout.is_open())
    {
        cout<<"open file error:"<<wfilebuff<<endl;
        return;
    }
    map<struct ipKeyInfo_,string>::const_iterator iter = IPLocation.begin();
    struct ipKeyInfo_ temp;
    while(!fin.eof())
    {
        countrySet.clear();
        getline(fin, line);
        if(line.size() == 0 )
        {
            continue;
        }
        else
        {
            size_t labstart = line.find_first_of(',');
            size_t labend = line.find_first_of(':',labstart + 1);
            if(labend != string::npos)
            {
                for(size_t index = labstart; index < labend;)
                {
                    size_t lab = line.find_first_of(',', index +1);
                    if(lab != string::npos && lab <= labend)
                    {
                        string IP = line.substr(index + 1,lab - index -1);
                        //cout<<"IP:"<<IP<<endl;
                        //查找IP所在位置
                        u_long curIP = atol(IP.c_str());
                        temp.IPUp = curIP;
                        iter = IPLocation.lower_bound(temp);
                        if(iter != IPLocation.end())
                        {
                            //cout<<"000:"<<endl;
                            if(temp.IPUp >= iter->first.IPLow)
                            {
                                string location = iter->second;
                                countrySet.insert(location);
                                location.clear();
                            }
                        }
                        index = lab;
                        IP.clear();
                    }
                    else if (lab > labend)
                    {
                        string IP = line.substr(index + 1,labend - index -1);
                        //cout<<"IP:"<<IP<<endl;
                        //查找IP所在位置
                        u_long curIP = atol(IP.c_str());
                        temp.IPUp = curIP;
                        iter = IPLocation.lower_bound(temp);
                        if(iter != IPLocation.end())
                        {
                            if(temp.IPUp >= iter->first.IPLow)
                            {
                                string location = iter->second;
                                countrySet.insert(location);
                                location.clear();
                            }
                        }
                        IP.clear();
                        break;
                    }
                }
            }
            else
            {
                ;
            }
        }//写文件
        if(istraing == true)
        {
            if(isbenign == true)
            {
                fout<<line<<","<<countrySet.size()<<","<<0<<endl;
            }
            else
            {
                fout<<line<<","<<countrySet.size()<<","<<1<<endl;
            }
        }
        else
        {
                fout<<line<<","<<countrySet.size()<<endl;
        }
    }
}
/*
int main()
{
    getIPLocationFromIPCIS cur_fast_flux;
    cur_fast_flux.connect_database();
    map<struct ipKeyInfo_,string> curIPInfo;
    curIPInfo = cur_fast_flux.readIPLocationInIPCIS();
    cur_fast_flux.getIPLocationNums("/home/xdzang/DGA_Detection/test.txt",
               "/home/xdzang/DGA_Detection/testIP_write.txt",curIPInfo,false,true);
    return 0;
}
*/
