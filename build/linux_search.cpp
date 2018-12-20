#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netdb.h>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <cstdio>
#include <algorithm>
#include "include/rapidjson/document.h"
#include "include/rapidjson/writer.h"
#include "include/rapidjson/stringbuffer.h"

using namespace std;

#define DNS_DGA_LOCATION         "./data"//"/data/lzhang/Fast_Flux_Detection/Src_Data"

struct IPaddressinfo
{
    string country;
    string region;
    string city;
    string longitude;
    string latitude;
};
struct IPandTTL
{
    set<string> IPlist;
    string TTL;
};
struct TimeSpec
{
    int year;
    int month;
    int mday;
    int hour;
    int min;
    int sec;
};

//文件预处理
void fileprocessing(const char*Infile,const char*outfile)
{
    map<string,IPandTTL>doaminIP;
    string line;
    map<string,IPandTTL>::iterator iter;
    char *ptr;
    struct IPandTTL tmpIPandTTL;
    set<string> iplistset;
    int count = 0;
    ifstream fin(Infile, ios::in);
    if(!fin.is_open())
    {
        cout<<"open file"<<Infile<<"error:"<<endl;
        return;
    }
    ofstream fout(outfile,ios::out);
    if(!fout.is_open())
    {
        cout<<"open file"<<outfile<<"error:"<<endl;
        return;
    }
    while(!fin.eof())
    {
        getline(fin, line);
        //cout<<line<<endl;
        iplistset.clear();
        if(line.size() == 0)//空行
        {
            continue;
        }
        else
        {
            size_t index_f = line.find_first_of('[');
            size_t index_e = line.find_first_of(']',index_f+1);
            string Iplist = line.substr(index_f + 1, index_e - index_f -1);
            string domain = line.substr(0,index_f);
            string curTTL = line.substr(index_e + 1, line.length()- index_e -1);
            string IPlist = line.substr(index_f+1,index_e-index_f-1);
            size_t symbol = IPlist.find_first_of(',');
            if(symbol!= std::string::npos)
            {
                ptr = strtok((char*)(IPlist.c_str()),",");
                while(ptr)
                {
                    char buf[16];
                    bzero(buf, sizeof(buf));
                    strcpy(buf,ptr);
                    string temp(buf);
                    //cout<<temp<<endl;
                    iplistset.insert(temp);
                    ptr = strtok(NULL,",");
                }
                if(doaminIP.size()==0)
                {
                    tmpIPandTTL.IPlist = iplistset;
                    tmpIPandTTL.TTL = curTTL;
                    doaminIP.insert(pair<string,IPandTTL>(domain,tmpIPandTTL));
                }
                else
                {
                    iter = doaminIP.find(domain);
                    if(iter== doaminIP.end())
                    {
                        tmpIPandTTL.IPlist = iplistset;
                        tmpIPandTTL.TTL = curTTL;
                        doaminIP.insert(pair<string,IPandTTL>(domain,tmpIPandTTL));
                    }
                    else
                    {
                        struct IPandTTL  tmpiplist;
                        string tmpdomain;
                        tmpiplist.IPlist.clear();;
                        tmpiplist.TTL.clear();
                        tmpdomain.clear();
                        tmpiplist.IPlist = iter->second.IPlist;
                        tmpiplist.TTL =  iter->second.TTL;
                        tmpdomain = iter->first;
                        doaminIP.erase(iter);
                        for(set<string>::iterator it = iplistset.begin(); it!= iplistset.end();++it)
                        {

                            tmpiplist.IPlist.insert(*it);
                        }
                        doaminIP.insert(pair<string,IPandTTL>(tmpdomain,tmpiplist));
                    }
                }
            }
            else
            {
                continue; // no IP
            }
        }
    }
    for(map<string,IPandTTL>::iterator its = doaminIP.begin();its!= doaminIP.end();++its)
    {
        fout<<its->first<<'[';
        for(set<string>::iterator itset = its->second.IPlist.begin();itset != its->second.IPlist.end();++itset)
        {
            count++;
            if(count == its->second.IPlist.size())
            {
                fout<<*itset<<']';
            }
            else
            {
                fout<<*itset<<',';
            }

        }
        count = 0;
        fout<<its->second.TTL<<endl;
    }
}
//时间转换函数
time_t MakeTime(const string &str)
{
    // str 格式为： 2015-01-19 10:57:56
    struct tm tmStruct;
    TimeSpec ts;
    memset(&tmStruct, 0, sizeof(tmStruct));
    memset(&ts, 0, sizeof(ts));
    time_t timep = 0;
    if (str.empty())
    {
        return timep;
    }
    sscanf(str.c_str(), "%d-%d-%d %d:%d:%d", &ts.year, &ts.month, &ts.mday,&ts.hour, &ts.min, &ts.sec);
    tmStruct.tm_year = ts.year - 1900;
    tmStruct.tm_mon = ts.month - 1;
    tmStruct.tm_mday = ts.mday;
    tmStruct.tm_hour = ts.hour;
    tmStruct.tm_min = ts.min;
    tmStruct.tm_sec = ts.sec;
    tmStruct.tm_isdst = 0;
    timep = mktime(&tmStruct);

    return timep;
}
//长整型转十分点进制IP，便于从IPCIS获取地理位置相关信息
string convertLongTIP(char *IPAddr)
{
    char buf[16];
    memset(buf, 0, sizeof(buf));
    long long   ip ;
    sscanf(IPAddr, "%lld",&ip);
    sprintf (buf, "%u.%u.%u.%u",
    (u_char) * ((char *) &ip + 3),
    (u_char) * ((char *) &ip + 2),
    (u_char) * ((char *) &ip + 1), (u_char) * ((char *) &ip + 0));
    string ipstr(buf);
    return ipstr;
}
//whois 信息获取
void getwhoisfromfile(const char*Infile,const char*outfile)
{
    const string &timeFromat = " 00:00:00";
    char  filename[256];
    char  search_str[256];
    string line;
    char  buf[32];
    size_t label;
    FILE* fp_stream = NULL;
    ifstream fin(Infile, ios::in);
    vector<string>nameServer;
    int count;
    string linesubStr;
    time_t secondsOfWhoisTime;
    if(!fin.is_open())
    {
        cout<<"open file"<<Infile<<"error:"<<endl;
        return;
    }
    ofstream fout(outfile,ios::out);
    if(!fout.is_open())
    {
        cout<<"open file"<<outfile<<"error:"<<endl;
        return;
    }

    int ccc = 0;
    while(!fin.eof())
    {
        ccc++;
        cout<<ccc<<"..."<<endl;

        getline(fin, line);
        count = 0;
        if(line.size() == 0)//空行
        {
            continue;
        }
        else
        {
            linesubStr.clear();
            linesubStr = line.substr(0,line.length()-1);
            fout<<linesubStr<<',';
            size_t index_f = linesubStr.find_first_of('[');
            string domain = linesubStr.substr(0, index_f);
            bzero(search_str, sizeof(search_str));
            bzero(buf, sizeof(buf));
            //get the Date in whois info
            //根据系统环境采取不同的grep
            snprintf(search_str, sizeof(search_str), 
                "whois %s|grep 'Date'|cut -d ':' -f 2|sed s/[[:space:]]//g", domain.c_str());
            if((fp_stream=popen(search_str, "r"))== NULL)//查询到的字节流为空
            {
                cout<< "execute command linesubStr";
            }
            else
            {
                while(fgets(buf, sizeof(buf), fp_stream)!=NULL)
                {
                    count++;
                    if(!feof(fp_stream))
                    {
                        string tmp = string(buf);
                        size_t t_label = tmp.find_first_of('T');
                        string tmpbuf = tmp.substr(0,t_label);
                        if(tmpbuf.length() > 5)
                        {
                            string curtimeformat = tmpbuf + timeFromat;
                            secondsOfWhoisTime = MakeTime(curtimeformat);
                            if(count == 3)
                            {
                                fout<<secondsOfWhoisTime<<':';
                            }
                            else
                            {
                                fout<<secondsOfWhoisTime<<',';
                            }

                        }
                        else
                        {
                            continue;
                        }

                    }
                }
            }

            pclose(fp_stream);

            //get nameServers in whois
            bzero(search_str, sizeof(search_str));
            bzero(buf, sizeof(buf));
            snprintf(search_str, sizeof(search_str), "whois %s|grep 'Name Server'|head -2|cut -d ':' -f 2|sed s/[[:space:]]//g", domain.c_str());
            if((fp_stream=popen(search_str, "r"))==NULL)//查询到的字节流为空
            {
                cout<< "execute command linesubStr";
            }
            else
            {
                while(fgets(buf, sizeof(buf), fp_stream)!=NULL)
                {
                    if(!feof(fp_stream))
                    {
                        string tmp = string(buf);
                        string tmpbuf = tmp.substr(0,tmp.length()-1);
                        if(tmpbuf.length()!=0)
                        {
                            nameServer.push_back(tmpbuf);
                        }
                        else
                        {
                            continue;
                        }

                    }
                }
            }
            pclose(fp_stream);

            //get IP address in nameServer
            bzero(search_str, sizeof(search_str));
            bzero(buf, sizeof(buf));
            //get the IP of nameServers
            for(vector<string>::iterator iter = nameServer.begin();iter!=nameServer.end();++iter)
            {
                snprintf(search_str, sizeof(search_str), "nslookup %s|grep 'Address'|cut -d ':' -f 2|sed s/[[:space:]]//g", iter->c_str());
                if((fp_stream=popen(search_str, "r"))==NULL)//查询到的字节流为空
                {
                    cout<< "execute command linesubStr";
                }
                else
                {
                    while(fgets(buf, sizeof(buf), fp_stream)!=NULL)
                    {
                        if(!feof(fp_stream))
                        {
                            string tmp = string(buf);
                            string tmpbuf = tmp.substr(0,tmp.length()-1);

                            if((tmpbuf.length()!=0) &&(label= tmpbuf.find('#')== std::string::npos))
                            {
                                if(iter == nameServer.end()-1)//last one
                                {
                                    fout<<tmpbuf<<endl;
                                }
                                else
                                {
                                    fout<<tmpbuf<<',';
                                }
                            }
                            else
                            {
                                continue;
                            }
                        }
                    }
                }
                pclose(fp_stream);
            }
        }
    }
}
//获取解析IP地址
vector<string> getManagementInfo(const char* Infile)
{
    string line;
    vector<string>resolvedIPlist;
    ifstream fin(Infile, ios::in);

    if(!fin.is_open())
    {
        cout<<"open file"<<Infile<<"error:"<<endl;
    }
    while(!fin.eof())
    {
        getline(fin, line);
        if(line.size() == 0)//空行
        {
            continue;
        }
        else
        {
            size_t index_f = line.find_first_of('[');
            size_t index_e = line.find_last_of(']');
            string ipaddrstring = line.substr(index_f + 1, index_e-index_f - 1);
            size_t label = ipaddrstring.find_first_of(',');
            size_t tmp = 0;

            while(label!= std::string::npos)
            {
                string tmpIP = ipaddrstring.substr(tmp,label-tmp);
                tmp = label+1;
                resolvedIPlist.push_back(convertLongTIP((char*)tmpIP.c_str()));
                label = ipaddrstring.find_first_of(',', label+1);
            }
            if(label== std::string::npos)
            {
                string lastIP = ipaddrstring.substr(tmp,ipaddrstring.length());
                resolvedIPlist.push_back(convertLongTIP((char*)lastIP.c_str()));
            }
            
            // for(vector<string>::iterator iter = resolvedIPlist.begin();iter!= resolvedIPlist.end();++iter)
            // {
            //     cout<<*iter<<endl;
            // }
        }
    }

    return resolvedIPlist;
}
//获取名字服务器IP
vector<string> getLocationInfo(const char* Infile)
{
    string line;
    vector<string>nameServerIPlist;
    ifstream fin(Infile, ios::in);
    if(!fin.is_open())
    {
        cout<<"open file"<<Infile<<"error:"<<endl;
    }
    while(!fin.eof())
    {
        getline(fin, line);
        if(line.size() == 0)//空行
        {
            continue;
        }
        else
        {
            //get IP of nameServer
            size_t tmp = 0;
            size_t label = 0;
            size_t lastlabel = line.find_first_of(':');
            string nameIPlist = line.substr(lastlabel +1, line.length()-lastlabel-1);
            label = nameIPlist.find_first_of(',');

            while(label!= std::string::npos)
            {
                string tmpIP = nameIPlist.substr(tmp,label-tmp);
                tmp = label+1;
                nameServerIPlist.push_back(tmpIP);
                label = nameIPlist.find_first_of(',', label+1);
            }
            if(label== std::string::npos)
            {
                string lastIP = nameIPlist.substr(tmp,nameIPlist.length());
                nameServerIPlist.push_back(lastIP);
            }
            
            // for(vector<string>::iterator iter = nameServerIPlist.begin();iter!= nameServerIPlist.end();++iter)
            // {
            //     cout<<*iter<<endl;
            // }
            
        }
    }
    return nameServerIPlist;
}
//连接IPCIS 获取相关地址对应的信息
vector<IPaddressinfo> getIPinformationfromIPCIS(vector<string> IPLocationInfo)
{
   char  search_str[256];
   char  buf[2048];
   const char *cityptr = "city";
   const char *longitudeptr = "longitude";
   const char *latitudeptr = "latitude";
   const char *locationptr = "location";
   struct IPaddressinfo curIPaddressinfo;
   vector<IPaddressinfo>IPaddressinfoList;
   size_t labelmcity = 0;
   size_t labcity_f = 0;
   size_t labcity_e = 0;
   size_t loclabel = 0;
   size_t loclabc_f = 0;
   size_t loclabc_e = 0;
   size_t longlabc_f = 0;
   size_t longlabc_e = 0;
   size_t latlabc_f = 0;
   size_t latlabc_e = 0;
   size_t locationlabel = 0;
   FILE* fp_stream = NULL;
   string geturl = "curl -s -k -x 'http://yunyang:yangyun123@202.112.23.167:8080' ";
   string curURL;
   for(vector<string>::iterator iter = IPLocationInfo.begin(); iter!= IPLocationInfo.end();++iter)
   {
        bzero(search_str, sizeof(search_str));
        snprintf(search_str, sizeof(search_str),"http://ipdb2000.njnet.edu.cn/IPCIS_php/manage_geo_searchapi.php/?ip=%s"
            ,(*iter).c_str());
        string search(search_str);
        curURL = geturl + search;

        if((fp_stream = popen(curURL.c_str(), "r"))== NULL)//查询到的字节流为空
        {
            cout<< "execute command line";
        }
        else
        {
            while(fgets(buf, sizeof(buf), fp_stream)!= NULL)
            {
                if(!feof(fp_stream))
                {
                    string outputString = string(buf);

                    // 排除掉一些空string的影响，正常的JSON都很长
                    if (outputString.size() >= 20)
                    {
                        rapidjson::StringStream s(outputString.c_str());
                        rapidjson::Document d;
                        d.ParseStream(s);

                        curIPaddressinfo.country = d["location"]["country"].GetString();
                        curIPaddressinfo.region = d["location"]["region"].GetString();
                        curIPaddressinfo.city = d["location"]["city"].GetString();
                        curIPaddressinfo.longitude = d["location"]["longitude"].GetString();
                        curIPaddressinfo.latitude = d["location"]["latitude"].GetString();
                    }
                }
            }
            pclose(fp_stream);
        }
        IPaddressinfoList.push_back(curIPaddressinfo);
    }
   
    // for(vector<IPaddressinfo>::iterator iter = IPaddressinfoList.begin();iter != IPaddressinfoList.end();++iter)
    // {
    //     cout<<iter->country<<", "<<iter->region<<", "<<iter->city<<", "<<iter->longitude<<", "<<iter->latitude<<endl;
    // }
   
    return IPaddressinfoList;
}
//输出IP和地理信息的映射
void writeIPLocation(const char* path, vector<string> iplist, vector<IPaddressinfo> locations)
{
    ofstream outFile(path, ios::out);
    map<string, IPaddressinfo> m;

    for (int i = 0; i < iplist.size(); i++)
    {
        m.insert(pair<string, IPaddressinfo>(iplist[i], locations[i]));
    }

    outFile<<"{"<<endl;
    for (map<string, IPaddressinfo>::iterator it = m.begin(); it != m.end(); ++it)
    {
        outFile<<"\""<<it->first<<"\": "
            <<"{\"country\":\""<<it->second.country<<"\", \"region\":\""<<it->second.region
            <<"\", \"city\":\""<<it->second.city<<"\", \"longitude\":\""<<it->second.longitude
            <<"\", \"latitude\":\""<<it->second.latitude<<"\"},"<<endl;
    }
    outFile<<"}"<<endl;
}

int main(int argc, char** argv)
{
    char* label = argv[1];
    char originalFile[64];
    char tempFile[64];
    char dataFile[64];
    snprintf(originalFile, sizeof(originalFile), "./data/dga_to_fast-flux_%s", label);
    snprintf(tempFile, sizeof(tempFile), "./temp/%s_after.tmp", label);
    snprintf(dataFile, sizeof(dataFile), "./temp/%s.dat", label);

    vector<string> nameServerIPlist, resolvedIPlist;
    vector<IPaddressinfo> nsIPLocation, resolvedIPLocation;

    fileprocessing(originalFile, tempFile);
    getwhoisfromfile(tempFile, dataFile);
    resolvedIPlist = getManagementInfo(dataFile);
    nameServerIPlist = getLocationInfo(dataFile);
    resolvedIPLocation = getIPinformationfromIPCIS(resolvedIPlist);
    nsIPLocation = getIPinformationfromIPCIS(nameServerIPlist);
    writeIPLocation("./temp/resolved.dict", resolvedIPlist, resolvedIPLocation);
    writeIPLocation("./temp/ns.dict", nameServerIPlist, nsIPLocation);

    return 0;
}
