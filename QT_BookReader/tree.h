#ifndef TREE_H
#define TREE_H
#include "iostream"
#include<QDebug>

typedef struct Book
{
    char author[80];
    char name[80];
    char way[80];
    Book *Right;
    Book *Left;

}Book;

class Tree
{
public:
    Book * Root;
    Tree()
    {
        Root = NULL;
    }
    ~Tree()
    {
        DeleteTree(Root);
    }
    void Add(Book *B);
    void DeleteTree(Book *b);
    Book *Search(char _name[]);
    void FillTree();
    void Write(Book *B);

};

#endif // TREE_H
