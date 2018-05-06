#include "DGA_detection.h"
int DGA_detection::init_legal_domain_set()
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
int DGA_detection::init_dns_suf_set()
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
int DGA_detection::is_dns_suf(char* dns_suf_str)
{
    string dns_suf;
	set<string>::iterator dns_suf_set_it;

	dns_suf.clear();
	dns_suf.assign(dns_suf_str);
	dns_suf_set_it = dns_suf_set.find(dns_suf);
	if(dns_suf_set_it == dns_suf_set.end())
    {
        //cout<<"00000"<<endl;
        return 0;
    }
	else
    {
        //cout<<"1111111"<<endl;
        return 1;
    }

}
char* DGA_detection::get_primary_domain(char* dname)
{
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
	while(index >= 0)
	{
		if(tmp_domain_name_str[index] == '.')
		{
			if( ( (flag == 0) || (flag == 1) ) && is_dns_suf(tmp_domain_name_str + index) ) //是后缀
			{
				memset(suffix, 0, sizeof(suffix));
				strcpy(suffix, domain_name_str+index);
				tmp_domain_name_str[index]='\0';
				flag = 1;
			}
			else
			{
				if(strlen(tmp_domain_name_str+index+1)>=LABEL_LEN)
				{
					//域名过长
					return NULL;
				}

				if(flag == 1)
				{
					has_flabel = 1;
					memset(first_label, 0, sizeof(first_label));
					strcpy(first_label, tmp_domain_name_str+index+1);
					tmp_domain_name_str[index]='\0';
					flag = 2;
				}
				else if(flag ==2)
				{
					has_slabel=1;
					memset(second_label, 0,sizeof(second_label));
					strcpy(second_label, tmp_domain_name_str+index+1);
					tmp_domain_name_str[index]='\0';
					flag=3;
				}
				else
                {
                    break;
                }

			}
		}

		index--;
	}
	if( (index < 0) && strcmp(tmp_domain_name_str, "www") )
	{
		if(strlen(tmp_domain_name_str) >= LABEL_LEN)
		{
			return NULL;
		}
		if(flag == 1)
		{
			has_flabel = 1;
			memset(first_label, 0, sizeof(first_label));
			strcpy(first_label, tmp_domain_name_str);
		}
		else if(flag == 2)
		{
			has_slabel = 1;
			memset(second_label, 0, sizeof(second_label));
			strcpy(second_label, tmp_domain_name_str);
		}

	}
	if(!has_flabel || (strlen(first_label)<1))
	{
		return NULL;
	}
	memset(primary_domain_str, 0, sizeof(primary_domain_str));
	snprintf(primary_domain_str, sizeof(primary_domain_str), "%s%s", first_label, suffix);//生成二级域名
	primary_domain = primary_domain_str;
	return primary_domain;
}
void DGA_detection::readDNSAbstractFile(const char* rFilename, const char* wFilename)
{

    int counts = 0;
    int i = 0;
    string line;
    char* temppos;
    string domain_name;
    string domain_str;
    char buff[DOMAIN_LEN+1];
	char* primary_domain;
    char rFilebuf[LABEL_LEN];
    char wFilebuf[LABEL_LEN];
	FILE* fd_st = NULL;
	char dname[DOMAIN_LEN];//域名
	string dname_str;//域名
	unsigned int timestamp;//时间戳
	unsigned int ttl;//缓存时间
	unsigned int resolved_ip;//解析IP
	char dns_name[DOMAIN_LEN];//DNS服务器
	string ns_server_str;//DNS权威服务器
	set<string>::iterator suffix_set_it;
	set<string>::iterator black_domain_set_it;

    //域名解析ip->RESOLVED_IP_INFO
	map<unsigned int, struct RESOLVED_IP_INFO>::iterator domain_resolvedIP_map_it;
	//DNS服务器->DETECTED_TIME
	map<string,struct NS_INFO>::iterator domain_ns_server_map_it;
	//域名->域名信息
	map<string,struct DOMAIN_INFO>::iterator dns_domain_info_map_it;

    memset(rFilebuf, 0, sizeof(rFilebuf));
	snprintf(rFilebuf, sizeof(rFilebuf), "%s/%s", FILE_LOCATION, rFilename);
	if((fd_st = fopen(rFilebuf, "rb"))== NULL)
	{
		cout<<"open rfile  error "<<rFilebuf<<endl;
		exit(0);
	}
	memset(wFilebuf, 0, sizeof(wFilebuf));
	snprintf(wFilebuf, sizeof(wFilebuf), "%s/%s", FILE_LOCATION, wFilename);
    ofstream fout(wFilebuf);
    if(!fout.is_open())
	{
		cout<<"open wfile"<<wFilebuf<<"error:"<<endl;
		exit(0);
	}
	while(!feof(fd_st))
	{
	    counts++;
	    //每读一行，清空缓存
	    memset(dname, 0 ,sizeof(dname));
	    memset(dns_name, 0 ,sizeof(dns_name));
	    timestamp = 0;
	    ttl = 0;//缓存时间
        resolved_ip = 0;//解析IP
		fread(&dname,DOMAIN_LENGTH,1,fd_st);//域名
		if(!feof(fd_st)) //提取DNS域名后，获取二级域名，判断其是否在白名单中，过滤掉合法域名（白名单）
		{
			temppos = dname;
			memset(buff, 0, sizeof(buff));
			for(i = 0;i < DOMAIN_LEN;i++)
			{
				buff[i] = tolower(temppos[i]);
			}
			buff[i]='\0';
			domain_name.clear();
			domain_name.assign(dname);
			primary_domain = get_primary_domain(dname);
			//cout<<"domain name:"<<buff<<",primary domain:"<<primary_domain<<endl;
			domain_str.clear();
			domain_str.assign(primary_domain);
			suffix_set_it = suffix_set.find(domain_str);//suffix_set 白名单
			if(suffix_set_it == suffix_set.end())
			{
			    //该域名不在白名单中，应该创建域名及其相关信息的映射
			    //cout<<"invalid domain"<<endl;
                fread(&timestamp, sizeof(unsigned int),1,fd_st);//时间戳
                fread(&ttl, sizeof(unsigned int),1,fd_st);//缓存时间
                fread(&resolved_ip, sizeof(unsigned int),1,fd_st);//解析IP
                fread(&dns_name, DOMAIN_LENGTH,1,fd_st);//DNS服务器
                //fout<<dname<<","<<timestamp<<","<<ttl<<","<<resolved_ip<<","<<dns_name<<endl;
                if(resolved_ip != 0)
                {
                    fout<<dname<<","<<resolved_ip<<","<<ttl<<","<<timestamp<<endl;
                }

			}
			else
            {
                //合法域名，过滤
                //cout<<"normal"<<endl;
                fread(&timestamp, sizeof(unsigned int),1,fd_st);//时间戳
                fread(&ttl, sizeof(unsigned int),1,fd_st);//缓存时间
                fread(&resolved_ip, sizeof(unsigned int),1,fd_st);//解析IP
                fread(&dns_name, DOMAIN_LENGTH,1,fd_st);//DNS服务器
            }
            /*
            if(counts>=15)
            {
                break;
            }
            */
		}

	}
    cout<<counts<<endl;
	fclose(fd_st);
}
