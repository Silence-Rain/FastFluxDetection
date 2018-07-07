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
		if(((dname[index]>='0') && (dname[index]<='9')) 
			|| ((dname[index]>='a') && (dname[index]<='z')) 
			|| ((dname[index]>='A') && (dname[index]<='Z')) || (dname[index]=='.')
			|| (dname[index]=='-') || (dname[index]=='_'))
        {
			domain_name_str[index]=tolower(dname[index]);
        }
		else if (dname[index] == '\r')
		{
			break;
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