#ifndef GETDGADOMIANNAMESRESOLVEDIP_H_INCLUDED
#define GETDGADOMIANNAMESRESOLVEDIP_H_INCLUDED
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <string>
#include <arpa/inet.h>
#include <map>
#include <set>
#include <mysql.h>
#include <math.h>
#include <string.h>
#include <iostream>
#include <vector>
using  namespace std;
#define DB_DEFAULT_DB_HOST   "127.0.0.1"
#define DB_DEFAULT_DB_NAME   "IPCIS_DNS_DB"
#define DB_DEFAULT_DB_PORT   3307
#define DB_DEFAULT_DB_USER   "root"
#define DB_DEFAULT_DB_PWD    "rootofmysql"

#define DNS_MSUF_LEN        				80
#define LABEL_LEN            				64
#define DOMAIN_LEN                          128
#define DOMAIN_LENGTH                       32*sizeof(unsigned int)
#define LEGAL_LIST_FILE                     "../../lib/source_code/Legal_Domains_Suffixes"
#define DNS_SUF_FILE         				"../../lib/source_code/Internet_Domains_Suffixes"

typedef struct domain_info_
{
    set<string>resolvedIPset;
    set<int>ttlelements;
    set<int>foundtimeSet;
}domain_info;

class getResolvedIPFromIPCIS_DNS_DB
{
    public:
        int connect_database();
        void disconnect_database();
        map<int,string> getDGAAttributesFromDomain_name(const char* domain_id,const char* tmpStr);
        void getResolvedIPAndWriteInFile(const char *wfilebuf);
        void getNameServerofPrimaryDoamin(const char *wfilebuf);
        char* get_primary_domain(const char* dname);
        int is_dns_suf(char* dns_suf_str);
        int init_legal_domain_set();
        int init_dns_suf_set();
        void InitFun();
        void prmaimaryDomain_IPMapping(const char* rfilebuff,const char* wfilebuff,int timewidow);
        void domainMapping(const char* rfilebuff,const char* wfilebuff);
        void rawDataSortUsingTime(const char* rfilebuff,const char* wfilebuff);
        void secondLevelMapping(const char* rfilebuff,const char* wfilebuff);
    private:
        MYSQL mysql;
        map<int,string> m_domianAttributes;
        set<string> dns_suf_set;
        set<string> suffix_set;//白名单，过滤合法域名

};


#endif // GETDGADOMIANNAMESRESOLVEDIP_H_INCLUDED
