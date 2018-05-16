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
using namespace std;

#define  Dict_File_Normailized  "../../lib/source_code/feature_vector/English_Words_Dict_Normalized"

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
    double  ipLocationEntroy;
    int traingFlag;
}domain_IP_TTl;

class clusterUsingDomainInfo
{
    public:
        ~clusterUsingDomainInfo();
        map<int,vector<struct domain_IP_TTl_> > getDomainFromInfoTestFile(const char *rFilebuff,bool isTraining);
        void initFun();
        nLdDomainLevel getDomainNLDs(string domainName);
        set<string> n_GramFeatureCalcu(string domainName,int n);
        double getEntroy(string domainName);
        int lengthOfNLDs(string dnameNld);
        int lengthOfDomain(string domainName);
        double numericPercentageInDomain(string domainName);
        int tLDCountsInDomain(string domainName);
        void featureVectorCalculate(vector<struct domain_IP_TTl_>domains,Trie_node root,
                                    const char *wfilebuf,bool isTraing);
        vector<double> nGramAverageAnddeviationCalcu(set<string>ngrams,Trie_node root);
        double medianCalcu(vector<int>ngramSet);
        trieTree* getTrieTree();
        struct domain_IP_TTl_ parsingDomainIPString(string line,bool isTraining);
        void featureVectorCalcu(map<int,vector<struct domain_IP_TTl_> >domainIpPara,Trie_node root,
                                const char *wfilebuf,bool isTraing);
        friend set<string> operator+(const set<string> &a, const set<string>& b);//集合并运算
        friend set<string> operator*(const set<string> &a, const set<string>& b);//集合交运算
        void ngramCalcu(const char* rfilebuf,const char* wfilebuf,Trie_node root,bool isbenign);
        double ngramValue(set<string>ngrams,Trie_node root);
    private:
        DGA_detection m_DGA_detection;
        trieTree *m_trieTree;
        vector<string>m_sdomain;//提取摘要文件中域名
        nLdDomainLevel m_domainLDs;
        vector<string>m_2gramVec;
        vector<string>m_3gramVec;

};

#endif // CLUSTERUSINGDOMAININFO_H_INCLUDED
