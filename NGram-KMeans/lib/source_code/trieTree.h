
//构建字典树，用于查找nGram在字典中出现的次数及最长有意义的字符串
#ifndef TRIETREE_H_INCLUDED
#define TRIETREE_H_INCLUDED
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include<iostream>
#include <fstream>
#include<cstring>
#include <string>
#include <map>
#include <set>
#include <vector>
#include <memory.h>
using namespace std;

#define MAX_CHILD       26 //26个英文字符
#define DICT_FILE       "/home/xdzang/DGA_Detection/DICT_Test.txt"

typedef struct Tree
{
    unsigned int counts; //用来标记千缀或单词个数
    bool flag; //用来标记该节点是否可以形成一个单词
    struct Tree *child[MAX_CHILD];
}Node,*Trie_node;

class trieTree
{
    public:
        ~trieTree();
        Node  *CreateTrie();
        void  insert_node(Trie_node root,char *str);
        void  search_str(Trie_node root,char *str);
        void  del(Trie_node root);
        Trie_node getTrieTreeRoot();
        int  statisticsNgramsOccurenceTimes(Trie_node root,char *str);
        set<string>readDictFile(const char *rFilebuff);
        Trie_node constructTrieTree(const char *rFilebuff);
        bool statisticsSrtingIsWord(Trie_node root,char *str);
    private:
        set<string>dictWords;
        Trie_node m_trieTreeRoot;

};

#endif // TRIETREE_H_INCLUDED
