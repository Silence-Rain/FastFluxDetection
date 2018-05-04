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
	unsigned int ftime;//�״μ��ʱ��
	unsigned int ltime;  //�����ʱ��
};
struct RESOLVED_IP_INFO
{
	unsigned int timestamp;//���ʱ��
	unsigned int ttl;  //����ʱ��
	unsigned int times;//��������
};
struct NS_INFO
{
	unsigned int timestamp;//���ʱ��
	unsigned int ttl;  //����ʱ��
	unsigned int times;//��������
};
struct DOMAIN_INFO
{
	// unsigned int is_dga;//�Ƿ���DGA����
	struct DETECTED_TIME domain_detected_time;
	map<unsigned int, struct RESOLVED_IP_INFO> domain_resolvedIP_map;  //��������ip->RESOLVED_IP_INFO
	map<string, struct NS_INFO> domain_ns_server_map;     //DNS������->NS_INFO
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
        char* get_primary_domain(char* dname);//��ȡ�����Ķ���������ǩ
    private:
        //����->������Ϣ
        map<string,struct DOMAIN_INFO> dns_domain_info_map;
        set<string> dns_suf_set;
        set<string> suffix_set;//�����������˺Ϸ�����
        //MYSQL mysql;
        //MYSQL_RES* query_result;
        //MYSQL_ROW  row;
        //map<string,struct DOMAIN_INFO> dns_domain_info_map;//����->������Ϣ
};

