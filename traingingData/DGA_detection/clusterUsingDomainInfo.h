#ifndef CLUSTERUSINGDOMAININFO_H_INCLUDED
#define CLUSTERUSINGDOMAININFO_H_INCLUDED
#include <locale.h>
#include <stddef.h>
#include <wchar.h>
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
#include <vector>
#include <memory.h>
#include <math.h>
#include <algorithm>
#include "DGA_detection.h"
#include "trieTree.h"
#include "Python.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "getDomainFromDatabase.h"
#include "getIPLocationFromIPCIS.h"
using namespace std;

#define  Domain_File        	"/home/xdzang/DGA_Detection/Domain.txt"
//#define  Domain_File        	"/home/xdzang/DGA_Detection/test.txt"
#define  Dict_File              "/home/xdzang/DGA_Detection/English_Words_Dict"
#define  Dict_File_Normailized  "/home/xdzang/DGA_Detection/English_Words_Dict_Normalized"
#define  Feature_Vector_File    "/home/xdzang/DGA_Detection/featureVectorFile.txt"
//#define FILE_PATH               "/home/xdzang/DGA_Detection/"
typedef struct _nLdDomainLevel
{
    string secondLD;
    string thirdLD;

}nLdDomainLevel;

struct domain_IP_TTl_
{
    string domainName;
    set<string>IPList;
    int elapseTime;
    int isupdate;
    int role;
    //double  ASpercent;
    double  ipLocationEntroy;
    int traingFlag;
}domain_IP_TTl;

struct TimeSpec
{
	int year;
	int month;
	int mday;
};
struct whoisInfo_
{
    long registerTime;
    long expiredTime;
    long updateTime;
    int role;
    set<string>Ipsets;
}whoisInfoTraining;
class clusterUsingDomainInfo
{
    public:
        clusterUsingDomainInfo();
        ~clusterUsingDomainInfo();
        void alexTopAMillionProcess(const char *rFilebuff,const char *wFilebuff);
        void filterMaliciousDomains(const char *rFilebuff,const char *wFilebuff);
        map<int,vector<struct domain_IP_TTl_> > getDomianFromInfoTestFile(const char *rFilebuff,bool isTrainging);
        vector<struct domain_IP_TTl_>getDomianFromInfoTrainingFile(const char *rFilebuff);
        int getPrimaryDomianOwnerInfo(string domain,string key,bool isTraining,string fileLocation);
        time_t MakeTime(string &str);
        //struct owner_Info_ processWhoisInfo(const char* whoisFile);
        struct whoisInfo_  processDataWhoisInfo(const char* whoisFile,const char* IPFile,bool isTraining);
        void normalizeDict(const char *rFilebuf, const char *wFilebuf);
        void processorDomainFile(const char *rFilebuf,const char *ipblackfi,
                            const char *wFilebuf,const char *blackdomainfile);
        void outputDnsAbstractFile(const char *rFilebufAbstract,const char *wFilebufAbstract);
        vector<string> getDomainSet();
        void initFun();
        nLdDomainLevel getDomainNLDs(string domainName);
        set<string> n_GramFeatureCalcu(string domainName,int n);
        double getEntroy(string domainName);
        double calculateDistanceOfDomiansUsingNgrams(string dnameFir,string dnameSec);
        int lengthOfNLDs(string dnameNld);
        int lengthOfDomain(string domainName);
        double numericPercentageInDomain(string domainName);
        int tLDCountsInDomain(string domainName);
        map<string,vector<string> >secondLDGrouping(const char*rFilebuff);
        void featureVectorCalculate(vector<struct domain_IP_TTl_>domains,Trie_node root,
                                    const char *wfilebuf,bool isTraing);
        vector<double>nGramAverageAnddeviationCalcu(set<string>ngrams,Trie_node root);
        double medianCalcu(vector<int>ngramSet);
        trieTree* getTrieTree();
        void usingPythonGetTraingFile(const char *getIPpython,const char *getIPLocationpython);
        void traingDataProcess(const char *rfilebuff,const char *wfilebuff);
        void getWhoisInfo(map<string,vector<string> >domainPara,const char *wfilebuff,
                          const char *blackdomainfile,bool isTraining,bool isMacilicous);
        u_long ip2long(const char *ip);
        struct domain_IP_TTl_ parsingDomainIPString(string line,bool isTrainging);
        void featureVectorCalcu(map<int,vector<struct domain_IP_TTl_> >domainIpPara,Trie_node root,
                                const char *wfilebuf,bool isTraing);
        set<string>readIPBlacklist(const char *rfilebuff);
        void getDomainInfoFromDataBase(const char *domainInfoFile);
        void getIPLocation(const char *domainInfoFile,const char *wInfoFile,bool istraing,
                           bool isbenign);
        void readFirstTenThoundsand(const char *readFile,const char *writeFile);
        void trainDataProcssOfZWW(const char *readFile,const char *writeFile,bool isbengin);
        void getZWWDomain(const char *readFile,const char *domainfile,
                                          const char *writeFile,const char *writeFile2);

        void getlostDoamin(const char *readFile,const char *rFilewhois,
                           const char *rbadFile,const char *wlostwrite);
       void domain3ldbigthanfive(map<string,vector<string> > paraGrouping,const char* wfilebuf);
        friend set<string> operator+(const set<string> &a, const set<string>& b);//集合并运算
        friend set<string> operator*(const set<string> &a, const set<string>& b);//集合交运算
       void getResolvedIPSimilarityMatrix(const char *domain_ipfile,const char *similarmatrxifile);
       void getThreeLevelDoamin(const char *Alexfile,const char *AlexfileZWW,const char *wfile);
       //以下为对比试验部分
       void getMeaningfulCharactersRatio(const char* rfilebuf,const char* wfilebuf,Trie_node root);
       void ngramCalcu(const char* rfilebuf,const char* wfilebuf,Trie_node root,bool isbenign);
       double ngramValue(set<string>ngrams,Trie_node root);
       void getDGADomainInfoFromDataBase();
    private:
        DGA_detection m_DGA_detection;
        trieTree *m_trieTree;
        vector<string>m_sdomain;//提取摘要文件中域名
        nLdDomainLevel m_domainLDs;
        vector<string>m_2gramVec;
        vector<string>m_3gramVec;
        getDomainFromDatabase *m_getDomainFromDatabase;
        getIPLocationFromIPCIS *getIPInfo;


};

#endif // CLUSTERUSINGDOMAININFO_H_INCLUDED
