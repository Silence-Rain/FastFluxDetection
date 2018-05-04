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
    //cout<<"dname:"<<dname<<endl;
    int    domain_name_len;
	int    index;
	char   domain_name_str[DOMAIN_LEN];     //����Сд�ַ���
	char   tmp_domain_name_str[DOMAIN_LEN];
	char   suffix[DNS_MSUF_LEN];
	int    flag;
	int    has_flabel;
	char   first_label[LABEL_LEN]; //һ�������
	int    has_slabel;
	char   second_label[LABEL_LEN];//���������
	char   primary_domain_str[DOMAIN_LEN];
	char   *primary_domain;

	//����ȫ��ת����Сд�ַ���
    domain_name_len = strlen(dname);
	memset(domain_name_str, 0, sizeof(domain_name_str));
	for(index = 0; index < domain_name_len; index++)
    {
        domain_name_str[index] = tolower(dname[index]);
    }

	//ȥ�����������ַ�������
	for(index = 0; index < domain_name_len; index++)
	{
		if( ( (dname[index]>='0') && (dname[index]<='9') )  ||  ( (dname[index]>='a') && (dname[index]<='z') )  ||  ( (dname[index]>='A') && (dname[index]<='Z') )  ||  (dname[index]=='.')  ||  (dname[index]=='-')  ||  (dname[index]=='_')  )
        {
			domain_name_str[index]=tolower(dname[index]);
        }
		else
		{
			// fprintf(fp_error, "domain name has special character: %s\n", dname);
			return NULL;
		}
	}

	//��ʼ��������
	memset(tmp_domain_name_str, 0, sizeof(tmp_domain_name_str));
	strcpy(tmp_domain_name_str, domain_name_str);

	memset(suffix, 0, sizeof(suffix));
	flag = 0;
	has_flabel = 0;
	memset(first_label, 0, sizeof(first_label));
	has_slabel = 0;
	memset(second_label, 0, sizeof(second_label));

	//��ȡ��׺��һ���ǩ�������ǩ
	index = strlen(tmp_domain_name_str)-1;
    //cout<<"000"<<endl;
	while(index >= 0)
	{
		if(tmp_domain_name_str[index] == '.')
		{
			if( ( (flag == 0) || (flag == 1) ) && is_dns_suf(tmp_domain_name_str + index) ) //�Ǻ�׺
			{
				memset(suffix, 0, sizeof(suffix));
				strcpy(suffix, domain_name_str+index);
				tmp_domain_name_str[index]='\0';
				//cout<<"suffix:"<<suffix<<",tmp_domain_name_str:"<<tmp_domain_name_str<<endl;
				flag = 1;
			}
			else
			{
				if(strlen(tmp_domain_name_str+index+1)>=LABEL_LEN)
				{
					// fprintf(fp_error, "domain name's label length is too long(>=%u): %s\n",
                   //LABEL_LEN, dname);
					//��������
					return NULL;
				}

				if(flag == 1)
				{
					has_flabel = 1;
					memset(first_label, 0, sizeof(first_label));
					strcpy(first_label, tmp_domain_name_str+index+1);
					tmp_domain_name_str[index]='\0';
					flag = 2;
					//cout<<"has_flabel == 1,first_label:"<<first_label<<endl;
				}
				else if(flag ==2)
				{
					has_slabel=1;
					memset(second_label, 0,sizeof(second_label));
					strcpy(second_label, tmp_domain_name_str+index+1);
					tmp_domain_name_str[index]='\0';
					flag=3;
					//cout<<"has_slabel == 1,first_label:"<<first_label<<endl;
				}
				else
                {
                    break;
                }

			}
		}

		index--;
	}
    //cout<<"11111"<<endl;
	if( (index < 0) && strcmp(tmp_domain_name_str, "www") )
	{
		if(strlen(tmp_domain_name_str) >= LABEL_LEN)
		{
			// fprintf(fp_error, "domain name's label length is too long(>=%u): %s\n", LABEL_LEN, dname);
			return NULL;
		}
		if(flag == 1)
		{
			has_flabel = 1;
			memset(first_label, 0, sizeof(first_label));
			strcpy(first_label, tmp_domain_name_str);
			//cout<<"first_label:"<<first_label<<endl;
		}
		else if(flag == 2)
		{
			has_slabel = 1;
			memset(second_label, 0, sizeof(second_label));
			strcpy(second_label, tmp_domain_name_str);
			//cout<<"second_label:"<<first_label<<endl;
		}
		else
        {
            ;
        }

	}
     //cout<<"2222"<<endl;
	if(!has_flabel || (strlen(first_label)<1))
	{
		// fprintf(fp_error, "domain name has no first level domain: %s\n", dname);
		//cout<<"333"<<endl;
		return NULL;
	}
	//cout<<"first_label:"<<first_label<<",suffix:"<<suffix<<endl;
	memset(primary_domain_str, 0, sizeof(primary_domain_str));
	snprintf(primary_domain_str, sizeof(primary_domain_str), "%s%s", first_label, suffix);//���ɶ�������
	cout<<"output primary_domain_str:"<<primary_domain_str<<endl;
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
	char dname[DOMAIN_LEN];//����
	string dname_str;//����
	unsigned int timestamp;//ʱ���
	unsigned int ttl;//����ʱ��
	unsigned int resolved_ip;//����IP
	char dns_name[DOMAIN_LEN];//DNS������
	string ns_server_str;//DNSȨ��������
	set<string>::iterator suffix_set_it;
	set<string>::iterator black_domain_set_it;

    //��������ip->RESOLVED_IP_INFO
	map<unsigned int, struct RESOLVED_IP_INFO>::iterator domain_resolvedIP_map_it;
	//DNS������->DETECTED_TIME
	map<string,struct NS_INFO>::iterator domain_ns_server_map_it;
	//����->������Ϣ
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
	    //ÿ��һ�У���ջ���
	    memset(dname, 0 ,sizeof(dname));
	    memset(dns_name, 0 ,sizeof(dns_name));
	    timestamp = 0;
	    ttl = 0;//����ʱ��
        resolved_ip = 0;//����IP
		fread(&dname,DOMAIN_LENGTH,1,fd_st);//����
		if(!feof(fd_st)) //��ȡDNS�����󣬻�ȡ�����������ж����Ƿ��ڰ������У����˵��Ϸ���������������
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
			suffix_set_it = suffix_set.find(domain_str);//suffix_set ������
			if(suffix_set_it == suffix_set.end())
			{
			    //���������ڰ������У�Ӧ�ô����������������Ϣ��ӳ��
			    //cout<<"invalid domain"<<endl;
                fread(&timestamp, sizeof(unsigned int),1,fd_st);//ʱ���
                fread(&ttl, sizeof(unsigned int),1,fd_st);//����ʱ��
                fread(&resolved_ip, sizeof(unsigned int),1,fd_st);//����IP
                fread(&dns_name, DOMAIN_LENGTH,1,fd_st);//DNS������
                //fout<<dname<<","<<timestamp<<","<<ttl<<","<<resolved_ip<<","<<dns_name<<endl;
                if(resolved_ip != 0)
                {
                    fout<<dname<<","<<resolved_ip<<","<<ttl<<","<<timestamp<<endl;
                }

			}
			else
            {
                //�Ϸ�����������
                //cout<<"normal"<<endl;
                fread(&timestamp, sizeof(unsigned int),1,fd_st);//ʱ���
                fread(&ttl, sizeof(unsigned int),1,fd_st);//����ʱ��
                fread(&resolved_ip, sizeof(unsigned int),1,fd_st);//����IP
                fread(&dns_name, DOMAIN_LENGTH,1,fd_st);//DNS������
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
