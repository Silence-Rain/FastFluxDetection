/*
*dga_domain_whois.txt 文件格式：
*1、domain_name 域名名称
*2、domain_whois 域名归属信息
*3、‘.["Webutation domain info"]["Verdict"]‘ 利用Verdict判定域名角色类型，域名角色类型共有三种：safe、unsure、maclicious,没有则将域名角色类型设置为unsure
*4、‘.["Webutation domain info"][]‘ 4\5两行信息作为判定域名角色的证据，存在数据库中 ，第4行内容为域名信誉得分
*5、‘.["categories"][]‘ 域名服务分类
*
*/
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdbool.h>
#include <cstring>
#include <string>
#include <errno.h>
#include <iostream>
#include <fstream>
#include <mysql.h>

using namespace std;

#define DB_DEFAULT_DB_HOST   "127.0.0.1"
#define DB_DEFAULT_DB_NAME   "DNS"
#define DB_DEFAULT_DB_PORT   3307
#define DB_DEFAULT_DB_USER   "root"
#define DB_DEFAULT_DB_PWD    "rootofmysql"

void process_domain_whois_info(char* filename);//解析domain_whois文本信息，将其插入数据库中
int  connect_database();   //返回0表示成功连接数据库，1表示失败
void disconnect_database();

FILE* fp_error=NULL;
MYSQL mysql;
char  query[10240];
MYSQL_RES* query_result;
MYSQL_ROW  row;

int main()
{	
	char filename[64];
	bzero(filename, sizeof(filename));
	snprintf(filename, sizeof(filename), "running_error_domain_whois_message");
	if((fp_error=fopen(filename, "w+"))==NULL)
	{
		fprintf(stdout, "Cannot create file '%s'\n", filename);
		return 1;
	}

	if(connect_database())
	{
		fprintf(fp_error, "mysql_connect_database() failed\n");
		return 1;
	}
	process_domain_whois_info((char*)"./dga_domain_whois.txt");	
	disconnect_database();

	fclose(fp_error);
	return 0;
}


void process_domain_whois_info(char* filename)
{	
	FILE* fp=NULL;
	char buf[20480]; //用于读取文件的一行的存储数组
	char* pos;  //用于一行字符读取操作
	char* tmp_pos;//用于一行字符读取操作
	int nlen; //复制数组时定长使用
	char info[256];
	int i;
	
	string   domain_name;//域名二级域名
	string   registrant;//注册者
	string   unit;//注册单位
	string   registrar;//注册商
	string   phone;
	string   email;
	string   address;
	string   addr_city;
	string   addr_province;
	string   addr_country;
	string   create_time;
	string   expire_time;
	unsigned int  role=0;
	string evidence;
	string evidence_str;
	
	if((fp=fopen(filename,"r"))==NULL)
	{
		fprintf(fp_error, "error :cannot open file %s\n",filename);
		return;
	}
	bzero(buf, sizeof(buf));	
	fgets(buf, sizeof(buf), fp);
	if(!feof(fp))
	{	
		for(i=0;i<strlen(buf)-1;i++)
		{	
			info[i]=buf[i];	
		}
		info[i]='\0';
		domain_name.clear();
		domain_name.assign(info);
	}
	// printf("domain_name= %s\n",domain_name.c_str());

		bzero(buf, sizeof(buf));
		fgets(buf, sizeof(buf), fp);
		if(!feof(fp))
		{	

			if(pos=strstr(buf,"Registrar:")) //找到“注册商”  
			{
				//printf("pos= %s\n",pos);
				tmp_pos=strstr(pos,"\\n"); //查找指定字符“\n”，并定位tmp_pos到“\n”处
				//printf("tmp_pos= %s\n",tmp_pos);
				nlen=strlen(pos)-strlen(tmp_pos)-11; //此时nlen为有效信息的长度
				//printf("nlen=%d\n",nlen);
				for(i=0;i<nlen;i++)
				{	
					info[i]=pos[i+11];		
				}
				info[i]='\0';
				registrar.clear();
				registrar.assign(info);
				// printf("registrar= %s\n",registrar.c_str());
			}
			if(pos=strstr(buf,"Creation Date:")) //找到“创建时间”  
			{
				tmp_pos=strstr(pos,"\\n"); //查找指定字符“\n”，并定位tmp_pos到“\n”处
				nlen=strlen(pos)-strlen(tmp_pos)-15; //此时nlen为有效信息的长度
				for(i=0;i<nlen;i++)
				{	
					info[i]=pos[i+15];	
					
				}
				info[i]='\0';
				create_time.clear();
				create_time.assign(info);			
				// printf("create_time= %s\n",create_time.c_str());
			}
			if(pos=strstr(buf,"Expiration Date:")) //找到“过期时间”  
			{
				tmp_pos=strstr(pos,"\\n"); //查找指定字符“\n”，并定位tmp_pos到“\n”处
				nlen=strlen(pos)-strlen(tmp_pos)-17; //此时nlen为有效信息的长度
				for(i=0;i<nlen;i++)
				{	
					info[i]=pos[i+17];		
				}
				info[i]='\0';
				expire_time.clear();
				expire_time.assign(info);
				// printf("expire_time= %s\n",expire_time.c_str());				
			}
			if(pos=strstr(buf,"Registrant Name:")) //找到“注册者”  
			{
				tmp_pos=strstr(pos,"\\n"); //查找指定字符“\n”，并定位tmp_pos到“\n”处
				nlen=strlen(pos)-strlen(tmp_pos)-17; //此时nlen为有效信息的长度
				for(i=0;i<nlen;i++)
				{	
					info[i]=pos[i+17];	
				}
				info[i]='\0';
				registrant.clear();
				registrant.assign(info);
				// printf("registrant= %s\n",registrant.c_str());					
			} 
			if(pos=strstr(buf,"Registrant Organization:")) //找到注册单位 
			{
				tmp_pos=strstr(pos,"\\n"); //查找指定字符“\n”，并定位tmp_pos到“\n”处
				nlen=strlen(pos)-strlen(tmp_pos)-25; //此时nlen为有效信息的长度
				for(i=0;i<nlen;i++)
				{	
					info[i]=pos[i+25];	
				}
				info[i]='\0';
				unit.clear();
				unit.assign(info);	
				// printf("unit= %s\n",unit.c_str());					
			} 
			if(pos=strstr(buf,"Registrant Street:")) //找到注册者街道
			{
				tmp_pos=strstr(pos,"\\n"); //查找指定字符“\n”，并定位tmp_pos到“\n”处
				nlen=strlen(pos)-strlen(tmp_pos)-19; //此时nlen为有效信息的长度
				for(i=0;i<nlen;i++)
				{	
					info[i]=pos[i+19];	
				}
				info[i]='\0';
				address.clear();
				address.assign(info);		
				// printf("address= %s\n",address.c_str());
			} 
			if(pos=strstr(buf, "Registrant City:")) //找到注册者城市  
			{
				tmp_pos=strstr(pos,"\\n"); //查找指定字符“\n”，并定位tmp_pos到“\n”处
				nlen=strlen(pos)-strlen(tmp_pos)-17; //此时nlen为有效信息的长度
				for(i=0;i<nlen;i++)
				{	
					info[i]=pos[i+17];	
				}
				info[i]='\0';
				addr_city.clear();
				addr_city.assign(info);	
				address.append("|").append(addr_city);
				// printf("address= %s\n",address.c_str());
			}
			if(pos=strstr(buf, "Registrant State/Province:")) //找到注册者州/省
			{
				tmp_pos=strstr(pos,"\\n"); //查找指定字符“\n”，并定位tmp_pos到“\n”处
				nlen=strlen(pos)-strlen(tmp_pos)-27; //此时nlen为有效信息的长度
				for(i=0;i<nlen;i++)
				{	
					info[i]=pos[i+27];	
				}
				info[i]='\0';
				addr_province.clear();
				addr_province.assign(info);
				address.append("|").append(addr_province);
				// printf("address= %s\n",address.c_str());
			} 
			if(pos=strstr(buf, "Registrant Country:")) //找到注册者国家  
			{
				tmp_pos=strstr(pos,"\\n"); //查找指定字符“\n”，并定位tmp_pos到“\n”处
				nlen=strlen(pos)-strlen(tmp_pos)-20; //此时nlen为有效信息的长度
				for(i=0;i<nlen;i++)
				{	
					info[i]=pos[i+20];	
				}
				info[i]='\0';
				addr_country.clear();
				addr_country.assign(info);
				address.append("|").append(addr_country);
				// printf("address= %s\n",address.c_str());
			} 			
			if(pos=strstr(buf, "Registrant Phone:")) //找到注册者联系方式
			{
				tmp_pos=strstr(pos,"\\n"); //查找指定字符“\n”，并定位tmp_pos到“\n”处
				nlen=strlen(pos)-strlen(tmp_pos)-18; //此时nlen为有效信息的长度
				for(i=0;i<nlen;i++)
				{	
					info[i]=pos[i+18];	
				}
				info[i]='\0';
				phone.clear();
				phone.assign(info);	
				// printf("phone= %s\n",phone.c_str());				
			}
			if(pos=strstr(buf, "Registrant Email:")) //找到注册者邮箱
			{
				tmp_pos=strstr(pos,"\\n"); //查找指定字符“\n”，并定位tmp_pos到“\n”处
				nlen=strlen(pos)-strlen(tmp_pos)-18; //此时nlen为有效信息的长度
				for(i=0;i<nlen;i++)
				{	
					info[i]=pos[i+18];	
				}
				info[i]='\0';
				email.clear();
				email.assign(info);	
				// printf("email= %s\n",email.c_str());
			}

		}

	bzero(buf, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	if(!feof(fp))
	{
		if(pos=strstr(buf,"\"safe\"")) //是否有Webutation domain info属性信息，有则利用Verdict判定域名角色类型，没有则将域名角色类型设置为unsure
		{
			role=0;
		}
		else if(pos=strstr(buf,"\"unsure\""))
		{
			role=1;
		}
		else if(pos=strstr(buf,"\"malicious\""))
		{
			role=2;
		}
		else
		{
			role=1;
		}
	}
	
	// printf("role=%u\n",role);

	evidence.clear();
	while(!feof(fp))
	{
		bzero(buf, sizeof(buf));
		fgets(buf, sizeof(buf), fp);
		if(!feof(fp))
		{		
			for(i=0;i<strlen(buf)-1;i++)
			{	
				info[i]=buf[i];	
			}
			info[i]='\0';
			evidence_str.clear();
			evidence_str.assign(info);
			evidence.append(evidence_str);
		}			
	}
	printf("evidence=%s\n",evidence.c_str());
	//域名角色类型判定结果
	bzero(query, sizeof(query));
	snprintf(query, sizeof(query), "update dga_activity set role=%u where primary_domain='%s'",role,domain_name.c_str());
	if( mysql_real_query(&mysql, query, strlen(query)) )  //更新不成功
		fprintf(fp_error, "mysql_real_query(%s) error: %s\n", query, mysql_error(&mysql));
	//域名角色类型判定证据
	bzero(query, sizeof(query));
	snprintf(query, sizeof(query), "update dga_activity set evidence='%s' where primary_domain='%s'",evidence.c_str(),domain_name.c_str());
	if( mysql_real_query(&mysql, query, strlen(query)) )  //更新不成功
		fprintf(fp_error, "mysql_real_query(%s) error: %s\n", query, mysql_error(&mysql));
	//域名归属信息
	bzero(query, sizeof(query));
	snprintf(query, sizeof(query), "insert ignore into domain_whois(primary_domain,registrant,registrar,phone,unit,address,email,register_date,expire_date) values ('%s', '%s','%s', '%s','%s', '%s','%s','%s','%s')",
									domain_name.c_str(),registrant.c_str(),registrar.c_str(),phone.c_str(),unit.c_str(),address.c_str(),email.c_str(),create_time.c_str(),expire_time.c_str());
	if( mysql_real_query(&mysql, query, strlen(query)) )  //更新不成功
		fprintf(fp_error, "mysql_real_query(%s) error: %s\n", query, mysql_error(&mysql));
	
}

int connect_database()
{
	/* initial mysql */
	if(!(mysql_init(&mysql)))
	{
		fprintf(fp_error, "mysql_init() failed\n");
		return 1;
	}
	
	/* set reconnect option */
	unsigned int value;
	value=24*3600;
	mysql_options(&mysql, MYSQL_OPT_CONNECT_TIMEOUT, (char *)&value);
	
	value=1;
	mysql_options(&mysql, MYSQL_OPT_RECONNECT, (char *)&value);
	
	/* get connected to database */
	if (mysql_real_connect(&mysql, DB_DEFAULT_DB_HOST, DB_DEFAULT_DB_USER, DB_DEFAULT_DB_PWD, DB_DEFAULT_DB_NAME, DB_DEFAULT_DB_PORT, NULL, 0) == NULL)
	{
		fprintf(fp_error, "mysql_real_connect() failed: %s\n", mysql_error(&mysql));
		return 1;
	}
	
	
	return 0;
}





void disconnect_database()
{
	mysql_close(&mysql);
}



