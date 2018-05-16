#ifndef GETDGADOMIANNAMESRESOLVEDIP_H_INCLUDED
#define GETDGADOMIANNAMESRESOLVEDIP_H_INCLUDED
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <string>
#include <set>
#include <math.h>
#include <string.h>
#include <iostream>
using  namespace std;

#define DNS_MSUF_LEN        				80
#define LABEL_LEN            				64
#define DOMAIN_LEN                          128
#define DOMAIN_LENGTH                       32*sizeof(unsigned int)
#define LEGAL_LIST_FILE                     "../../lib/source_code/primary_domain/Legal_Domains_Suffixes"
#define DNS_SUF_FILE         				"../../lib/source_code/primary_domain/Internet_Domains_Suffixes"


class getResolvedIPFromIPCIS_DNS_DB
{
    public:
        char* get_primary_domain(const char* dname);
        int is_dns_suf(char* dns_suf_str);
        int init_legal_domain_set();
        int init_dns_suf_set();
        void InitFun();
    private:
        set<string> dns_suf_set;
        set<string> suffix_set;//白名单，过滤合法域名

};


#endif // GETDGADOMIANNAMESRESOLVEDIP_H_INCLUDED
