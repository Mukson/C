#include "tree.h"
#include "iostream"
#include "fstream"
#include <QDebug>
#include "cstring"
#include"mainwindow.h"

using namespace std;

void Tree::Add(Book *B)
{
    if(Root == NULL)
    {
        Root = B;
        return;
    }
    else
    {
        Book * Current = Root;
        while(Current != NULL)
        {
            int Comp = strcmp(Current->name, B->name);
            if(Comp == -1)
            {
                if(Current->Right != NULL)
                {
                    Current = Current->Right;
                    continue;
                }
                Current->Right = B;
                break;
            }
            if(Comp == 1)
            {
                if(Current->Left != NULL)
                {
                    Current = Current->Left;
                    continue;
                }
                Current->Left = B;
                break;
            }
            if(Comp == 0)
                break;
        }
    }
}

Book *Tree::Search(char _name[])
{
    if(Root == NULL)
        qDebug()<<"Пустая библиотека" ;
    Book * Current = Root;
    while(Current != NULL)
    {
        int Comp = strcmp(Current->name, _name);
        if(Comp == -1)
        {
            Current = Current->Right;
            continue;
        }
        if(Comp == 1)
        {
            Current = Current->Left;
            continue;
        }
        if(Comp == 0)
            return Current;// надо как-то вернутть эту книгу

    }
    return NULL ;
}

void Tree::DeleteTree(Book *b)
{
  if(!b)
      return;
  DeleteTree(b->Left);
  DeleteTree(b->Right);
  delete b;
  b = NULL;

}

void Tree::Write(Book *B)
{
    ofstream n_file("D:\\books\\Print.txt",ios_base::app);
    if(!n_file.is_open())
    {
        qDebug() << "Ошибка чтения файла(7)";
        return; // если это сделать невозможно, то завершаем функцию
    }
    n_file << B->author <<" "<< B->name<<"\n";
}

void Tree::FillTree()
{
    ifstream file ("D:\\books\\test.txt");
    if(!file.is_open())
    {
        qDebug() << "Ошибка чтения файла(6)";
        return; // если это сделать невозможно, то завершаем функцию
    }
    char * author2 = new char [80];
    char *name2 = new char [80];
    char *way2 = new char [80];
    int i = 0;
    int flag = 0;

    while(!file.eof())
    {
         char c = file.get();
        if (c != '#' && flag == 0) // считывание автора книги
                {
                    author2[i] = c;
                    i++;
                }
                else if (c != '#'&& c != '$' && flag == 1)// считывание названия произведения
                {
                    name2[i] = c;
                    i++;
                }
                else if (c != '$'&& c != '\n' && flag == 2)// считывание расположения книги
                {
                    way2[i] = c;
                    i++;
                }
                else if (c == '#' || c == '$' || c == '\n')
                {
                    switch (flag)
                    {
                    case 0:
                    {
                        author2[i] = '\0';// последний элемент массива
                        flag = 1;
                        break;
                    }
                    case 1:
                    {
                        name2[i] = '\0';
                        flag = 2;
                        break;
                    }
                    case 2:
                    {
                        way2[i] = '\0';
                        flag = 0;
                        Book *B = new Book;
                        strcpy(B->author, author2);
                        strcpy(B->name, name2);
                        strcpy(B->way,way2);
                        Add(B);
                        Write(B);
                        break;
                    }
                    default:
                    {
                        break;
                    }
                    }
                     i = 0;
                }
    }
    delete [] author2;
    delete [] name2;
    delete [] way2;
    file.close();
    return;
}
