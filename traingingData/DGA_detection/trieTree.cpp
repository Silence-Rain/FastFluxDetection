#include"trieTree.h"
Node* trieTree::CreateTrie()                             //����trie�ڵ���
{
    Node *node = (Node*)malloc(sizeof(Node));
    node->counts = 0;
    node->flag = false;
    memset(node->child, 0, sizeof(node->child));
    return node;
}
void trieTree::insert_node(Trie_node root,char *str)      //trie��������
{
    if(root == NULL || *str == '\0')
    {
        return;
    }
    Node *temp = root;

    char *ptr = str;

    while(*ptr != '\0')
    {
        if(temp->child[*ptr-'a'] == NULL)
        {
            Node *tmp = CreateTrie();
            temp->child[*ptr-'a'] = tmp;
        }
        temp = temp->child[*ptr-'a'];
        ptr++;
        temp->counts = temp->counts + 1;
    }
    temp->flag = true;
}
//ͳ��gram���ֵ��г��ֵĴ���
int  trieTree::statisticsNgramsOccurenceTimes(Trie_node root,char *str)
{
    int counts = 0;
    if(NULL == root || *str == '\0')
    {
        printf("trie is empty or str is null\n");
        return -1;
    }
    char *ptrStr = str;
    Node *tempDode = root;
    while((*ptrStr!='\0')&&( (*ptrStr >='a')&&(*ptrStr <='z') ) )
    {
        if(tempDode->child[*ptrStr-'a'] != NULL)
        {
            tempDode = tempDode->child[*ptrStr-'a'];
            ptrStr++;
        }
        else
        {
            break;
        }

    }
    if(*ptrStr =='\0')
    {
        counts = tempDode->counts;
        if(tempDode->flag == false)
        {
            cout<< str<<":is a prefix,occurence:"<<counts<<endl;
        }
        else
        {
           cout<< str<<": is  a word,occurence:"<<counts<<endl;
        }

    }
    else
    {
        counts = 0;
        cout<< str<<": is not in trie Tree:"<<counts<<endl;
    }
    return counts;
}
bool trieTree::statisticsSrtingIsWord(Trie_node root,char *str)
{
    bool isWord = false;
    if(NULL == root || *str=='\0')
    {
        printf("trie is empty or str is null\n");
        return isWord;
    }
    char *ptrStr = str;
    Node *t = root;
    while((*ptrStr!='\0')&&( (*ptrStr >='a')&&(*ptrStr <='z') ))
    {
        if(t->child[*ptrStr-'a'] != NULL)
        {
            t = t->child[*ptrStr-'a'];
            ptrStr++;
        }
        else
        {
           break;
        }

    }
    if(*ptrStr =='\0')
    {
        if(t->flag == false)
        {
           isWord = false;
        }
        else
        {
           cout<<"is word:"<<str<<endl;
           isWord = true;
        }

    }
    else
    {
        cout<< str<<": is not in trie Tree"<<endl;
    }
    return isWord;
}
void trieTree::search_str(Trie_node root,char *str)             //���Ҵ��Ƿ��ڸ�trie����
{
    if(NULL == root || *str=='\0')
    {
        printf("trie is empty or str is null\n");
        return;
    }
    char *p = str;
    Node *t = root;
    while(*p!='\0')
    {
        if(t->child[*p-'a'] != NULL)
        {
            t = t->child[*p-'a'];
            p++;
        }
        else
        {
           break;
        }

    }
    if(*p =='\0')
    {
        if(t->flag == false)
        {
            cout<< str<<":is not in trie Tree,but its prefix"<<endl;
        }
        else
        {
           cout<< str<<": is  in trie Tree"<<endl;
        }

    }
    else
    {
        cout<< str<<": is not in trie Tree"<<endl;
    }

}
void trieTree::del(Trie_node root)      //�ͷ������ֵ���ռ�Ķѿռ�
{
    int i;
    if(root != NULL)
    {
        for(i = 0;i< MAX_CHILD;i++)
        {
            if(root->child[i]!= NULL)
            {
                del(root->child[i]);
            }

        }
        free(root);
    }

}
set<string>trieTree::readDictFile(const char *rFilebuff)
{
    string line;
    ifstream fin(rFilebuff,ios::in);
    if(!fin.is_open())
    {
        cout<<"open dict file error:"<<rFilebuff<<endl;
        exit(0);
    }
    while(!fin.eof() ) //���ļ���һ�ζ�ȡһ�У���������ֶ����ݣ�ֱ�������ļ�ĩβ��
    {
        //counts++;
        getline(fin, line);
        if(line.size() == 0 )
        {
            continue;
        }
        else
        {
            dictWords.insert(line);
        }

    }
    return dictWords;
}
Trie_node trieTree::constructTrieTree(const char *rFilebuff)
{
    char *wordPtr = NULL;
    set<string>words;
    words = readDictFile(rFilebuff);
    m_trieTreeRoot = CreateTrie();
    if(m_trieTreeRoot == NULL)
    {
        cout<<"create trieTree error:"<<endl;
        return NULL;
    }
    for(set<string>::iterator iter = words.begin(); iter!= words.end();++iter)
    {
        wordPtr = (char*)(*iter).c_str();
        insert_node(m_trieTreeRoot,wordPtr);
    }
    cout<<"Dict create finished:"<<endl;
    return m_trieTreeRoot;
}
Trie_node trieTree::getTrieTreeRoot()
{
    return m_trieTreeRoot;
}
trieTree::~trieTree()
{
    //cout<<"call trieTree deconstructor"<<endl;
    if(m_trieTreeRoot != NULL)
    {
        //cout << "tree root = " << m_trieTreeRoot << endl;
        del(m_trieTreeRoot);
    }

}
/*
int main()
{
    trieTree curTrieTee;
    Trie_node root = NULL;
    root = curTrieTee.constructTrieTree(DICT_FILE);
    curTrieTee.statisticsNgramsOccurenceTimes(root,"abc");

    return 0;


}
*/
