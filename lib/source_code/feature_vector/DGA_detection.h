#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <iostream>
#include <fstream>
#include <iostream>
#include <string>
#include <map>
#include <set>
#include <memory.h>
using namespace std;
#define DNS_MSUF_LEN        				80
#define LABEL_LEN            				64
#define MAX_DOMAIN_LEN                      1024
#define CREATE_TABLE_TIME        3600
#define DOMAIN_LEN           128
#define DOMAIN_LENGTH                       32*sizeof(unsigned int)
#define FILE_LOCATION                       "../../lib/source_code/feature_vector/"
#define LEGAL_LIST_FILE                     "../../lib/source_code/feature_vector/Legal_Domains_Suffixes"
#define DNS_SUF_FILE         				"../../lib/source_code/feature_vector/Internet_Domains_Suffixes"
using namespace std;

class DGA_detection
{
    public:
        int is_dns_suf(char* dns_suf_str);
        int init_legal_domain_set();
        int init_dns_suf_set();
        char* get_primary_domain(char* dname);//获取域名的二级域名标签
    private:
        set<string> dns_suf_set;
        set<string> suffix_set;//白名单，过滤合法域名
};

