#ifndef GETIPLOCATIONFROMIPCIS_H_INCLUDED
#define GETIPLOCATIONFROMIPCIS_H_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <fstream>
#include <iostream>
#include <string>
#include <arpa/inet.h>
#include <map>
#include <set>
#include <mysql.h>
#include <math.h>
#include<string.h>
#include<iostream>
using  namespace std;
#define DB_DEFAULT_DB_HOST_IPCIS   "211.65.193.23"
#define DB_DEFAULT_DB_NAME_IPCIS   "center_ipcis"
#define DB_DEFAULT_DB_PORT_IPCIS   3306
#define DB_DEFAULT_DB_USER_IPCIS   "root"
#define DB_DEFAULT_DB_PWD_IPCIS    "admin246531"
struct ipKeyInfo_
{
	u_long IPLow;
	u_long IPUp;
};
extern struct ipKeyInfo_ ipKeyInfo;

class getIPLocationFromIPCIS
{
    public:
        int connect_database();//myQL;
        void disconnect_database();
        map<struct ipKeyInfo_,string> readIPLocationInIPCIS();
        void getIPLocationNums(const char* rfilebuff,const char* wfilebuff,const
                               map<struct ipKeyInfo_,string> &IPLocation,bool istraing,bool isbenign);
        friend bool operator <(struct ipKeyInfo_ info1,struct ipKeyInfo_ info2);
        map<struct ipKeyInfo_,string>getInfo();
    private:
        MYSQL mysql;
        map<struct ipKeyInfo_,string> allIPInfo;
};



#endif // GETIPLOCATIONFROMIPCIS_H_INCLUDED
