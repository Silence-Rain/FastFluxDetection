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
#include <arpa/nameser.h>
#include <netdb.h>
#include <fstream>
#include <iostream>
#include <string>
#include <map>
#include <set>
#include <memory.h>
using namespace std;
//#include <mysql.h>
#define DNS_MSUF_LEN        				80
#define LABEL_LEN            				64
#define MAX_DOMAIN_LEN                      1024
#define CREATE_TABLE_TIME        3600
//#define DB_DEFAULT_DB_HOST   "127.0.0.1"
//#define DB_DEFAULT_DB_NAME   "DAOS_DNS"
//#define DB_DEFAULT_DB_PORT   3307
//#define DB_DEFAULT_DB_USER   "root"
//#define DB_DEFAULT_DB_PWD    "rootofmysql"
#define DOMAIN_LEN           128
#define DOMAIN_LENGTH                       32*sizeof(unsigned int)
#define FILE_LOCATION                       "/home/xdzang/DGA_Detection"
#define LEGAL_LIST_FILE                     "/home/xdzang/DGA_Detection/Legal_Domains_Suffixes"
#define DNS_SUF_FILE         				"/home/xdzang/DGA_Detection/Internet_Domains_Suffixes"
using namespace std;

struct DETECTED_TIME
{
	unsigned int ftime;//首次检测时间
	unsigned int ltime;  //最后检测时间
};
struct RESOLVED_IP_INFO
{
	unsigned int timestamp;//检测时间
	unsigned int ttl;  //缓存时间
	unsigned int times;//解析次数
};
struct NS_INFO
{
	unsigned int timestamp;//检测时间
	unsigned int ttl;  //缓存时间
	unsigned int times;//解析次数
};
struct DOMAIN_INFO
{
	// unsigned int is_dga;//是否是DGA域名
	struct DETECTED_TIME domain_detected_time;
	map<unsigned int, struct RESOLVED_IP_INFO> domain_resolvedIP_map;  //域名解析ip->RESOLVED_IP_INFO
	map<string, struct NS_INFO> domain_ns_server_map;     //DNS服务器->NS_INFO
};
class DGA_detection
{
    public:
        void getDomainFromIPCIS_DNS_DB(const char* wFilename);
        int is_dns_suf(char* dns_suf_str);
        int init_legal_domain_set();
        int init_dns_suf_set();
        int connect_database();
        void disconnect_database();
        void readDomain_ResolvedIP_NSseverInfoFromDatabase();
        void readDNSAbstractFile(const char* rFilename, const char* wFilename);
        char* get_primary_domain(char* dname);//获取域名的二级域名标签
    private:
        //域名->域名信息
        map<string,struct DOMAIN_INFO> dns_domain_info_map;
        set<string> dns_suf_set;
        set<string> suffix_set;//白名单，过滤合法域名
        //MYSQL mysql;
        //MYSQL_RES* query_result;
        //MYSQL_ROW  row;
        //map<string,struct DOMAIN_INFO> dns_domain_info_map;//域名->域名信息
};

