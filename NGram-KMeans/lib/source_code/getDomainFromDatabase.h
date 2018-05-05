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
#include <string.h>
#include <iostream>
#include <vector>
using  namespace std;
#define DB_DEFAULT_DB_HOST   "127.0.0.1"
#define DB_DEFAULT_DB_NAME   "DAOS_DNS"
#define DB_IPCIS_DB_NAME     "IPCIS_DNS_DB"
#define DB_DEFAULT_DB_PORT   3307
#define DB_DEFAULT_DB_USER   "root"
#define DB_DEFAULT_DB_PWD    "rootofmysql"
class getDomainFromDatabase
{
    public:
        int connect_database();//myQL;
        void disconnect_database();
        void readDataInFile(const char *wfilebuf);
        int connect_database2();//myQL;
        void disconnect_database2();
        void getWholeDomian_ID(const char *rfilebuf,const char *wfilebuf);
        void getWholeDomian_ZWW(const char *rfilebuf,const char *wfilebuf);
        void getDGADomain();
    private:
        MYSQL mysql;
};

