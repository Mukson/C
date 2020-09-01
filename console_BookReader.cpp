#include "stdafx.h"
#include<stdlib.h>
#include<string.h>

typedef struct Book // структура для книги
{
	char author[80];
	char name[80];
	char way[80];
	Book *Right;
	Book *Left;
}Book;

void initbook(Book *c)// инициализация книги
{
	c->Right = NULL;
	c->Left = NULL;
	return;
}

typedef struct BOOK_TREE// структура для дерева
{
	Book *Root;
}BOOK_TREE;

void INIT_TREE(BOOK_TREE *Q)// инициализация дерева
{
	Q->Root = NULL;
}

void ADD_TO_TREE(BOOK_TREE *Q, Book *P) // добавление в дерево(по автору)
{
	if (Q == NULL)	return;
	if (Q->Root == NULL)
	{
		Q->Root = P;
		return;
	}
	Book *CURRENT = Q->Root;
	while (CURRENT != NULL)
	{
		int comp = strcmp(CURRENT->author, P->author);
		if (comp == -1)
		{
			if (CURRENT->Right != NULL)
			{
				CURRENT = CURRENT->Right;
				continue;
			}
			CURRENT->Right = P;
			break;
		}
		if (comp == 1)
		{
			if (CURRENT->Left != NULL)
			{
				CURRENT = CURRENT->Left;
				continue;
			}
			CURRENT->Left = P;
			break;
		}
		if (comp == 0) break;
	}
}

void ADD_TO_TREE_2(BOOK_TREE *Q, Book *P) // добавление в дерево(по Названию книги)
{
	if (Q == NULL)	return;
	if (Q->Root == NULL)
	{
		Q->Root = P;
		return;
	}
	Book *CURRENT = Q->Root;
	while (CURRENT != NULL)
	{
		int comp = strcmp(CURRENT->name, P->name);
		if (comp == -1)
		{
			if (CURRENT->Right != NULL)
			{
				CURRENT = CURRENT->Right;
				continue;
			}
			CURRENT->Right = P;
			break;
		}
		if (comp == 1)
		{
			if (CURRENT->Left != NULL)
			{
				CURRENT = CURRENT->Left;
				continue;
			}
			CURRENT->Left = P;
			break;
		}
		if (comp == 0) break;
	}
}
void CreateBook(Book*e, BOOK_TREE *Birch, BOOK_TREE *Pine) // формирование данных о книге     
{
	char *author2; author2 = (char*)malloc(sizeof(char) * 80);
	char *name2; name2 = (char*)malloc(sizeof(char) * 80);
	char *way2; way2 = (char*)malloc(sizeof(char) * 80);
	INIT_TREE(Birch); INIT_TREE(Pine);
	FILE* fp;
	if (fopen_s(&fp, "D:\\test.txt", "r"))
	{
		printf("error: file couldn't be opened1\n");///////
	}
	int i = 0, flag = 0;
	char c;

	while ((c = getc(fp)) != EOF)
	{
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
				Book* e = (Book*)malloc(sizeof(Book)); initbook(e);     // выделение памяти для книги и ее инициализация
				strcpy_s(e->author, author2); strcpy_s(e->name, name2); strcpy_s(e->way, way2);
				ADD_TO_TREE(Birch, e); ADD_TO_TREE_2(Pine, e);              // добавление книги в деревья	
				FILE *for_print;
				if (fopen_s(&for_print, "D:\\for print.txt", "a")) printf_s("error: file couldn't be opened1\n");
				fprintf_s(for_print, "%s: %s\n", e->author, e->name);    //запись для вывода списка доступных книг
				fclose(for_print);
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
	free(author2); free(name2);
	fclose(fp);
	return;
}

Book *Author_Search(BOOK_TREE *Q, char author3[]) // поиск по автору
{
	if (Q == NULL) printf_s("Empty Library\n");
	Book *CURRENT = Q->Root;
	while (CURRENT != NULL)
	{
		int k = strcmp(CURRENT->author, author3);
		if (k == -1)
		{
			CURRENT = CURRENT->Right;
			continue;
		}
		if (k == 1)
		{
			CURRENT = CURRENT->Left;
			continue;
		}
		if (k == 0) return CURRENT;
	}
	return NULL;
}

Book *Name_Search(BOOK_TREE *Q, char name3[]) // поиск по названию произведения
{
	if (Q == NULL) printf_s("Empty Library\n");
	Book *CURRENT = Q->Root;
	while (CURRENT != NULL)
	{
		int k = strcmp(CURRENT->name, name3);
		if (k == -1)
		{
			CURRENT = CURRENT->Right;
			continue;
		}
		if (k == 1)
		{
			CURRENT = CURRENT->Left;
			continue;
		}
		if (k == 0) return CURRENT;
	}
	return NULL;
}

void Save_Book(Book *e, int  page[], int bookmarks[]) // сохранение книги
{
	FILE *sb;
	int i = 0;
	if (fopen_s(&sb, "D:\\saved book.txt", "w")) printf_s("Error:file couldn't be opened2");
	fprintf_s(sb, "%d", page[0]);
	fputs(e->way, sb);   fputs("\n", sb);
	while (1)
	{
		if (bookmarks[i] == '\0')
		{
			bookmarks[i] = 0; fprintf_s(sb, "%d", bookmarks[i]);
			break;
		}
		fprintf_s(sb, "%d", bookmarks[i]);  fputs("\n", sb);
		i++;
	}
	fclose(sb);
}

Book *Load_Book(Book *e, int  page[], int bookmarks[]) // загрузка книги
{
	char b, l[100];
	FILE *lb;
	int i = 0;
	if (fopen_s(&lb, "D:\\saved book.txt", "r")) printf_s("Error:file couldn't be opened3");
	if (lb != NULL)
	{
		fscanf_s(lb, "%d", &page[0]);
		while (1)
		{
			b = fgetc(lb);
			if (b == '\n')
			{
				l[i] = '\0';
				break;
			}
			l[i] = b;
			i++;
		}
		strcpy_s(e->way, l);
		i = 0;
		while (1)
		{
			fscanf_s(lb, "%d", &bookmarks[i]);
			if (bookmarks[i] == 0) break;
			i++;
		}
	}
	fclose(lb);
	return e;
}

void READING(Book *e, int param, int  page[], int bookmarks[])  // чтение книги
{
	char c[100];
	FILE *fp;
	if (fopen_s(&fp, e->way, "r")) printf_s("Error:file couldn't be opened4");
	if (fp != NULL)
	{
		int p = param, nline = 1, max = 25, i = 0, sym;
		char *str;
		while (1)
		{
			while (nline <param*max)
			{
				str = fgets(c, sizeof(c), fp);
				if (str == NULL)// проверяем ,закончился файл или ошибка при чтении
				{
					if (feof(fp) != 0)// закончился файл
					{
						printf_s("\n\t\t\tEnd of book\n");
						printf_s("1.Look throught the library\n2.Search by name\n3.Search by author\n4.Continue reading\n5.Your bookmarks\n6.Exit\n");//////////////
						fclose(fp);
						return;
					}
					else//ошибка при чтении
					{
						printf("Error: reading's impossible");
						return;
					}
				}
				puts(str);
				nline++;
			}
			printf("\n\t\t\tpage %d", p);
			printf_s("\nReference:\t touch 1 next page ,2 last reading place, 0 make a bookmark\n");
			nline = 0;
			param = 1;
			scanf_s("%d", &sym);
			switch (sym)
			{
			case 1: 	break; // переход на след. страницу
			case 2: // сохранение послед.страницы
			{
				page[0] = p;
				Save_Book(e, page, bookmarks);
				break;
			}
			case 0:// закладки
			{
				bookmarks[i] = p;
				bookmarks[i + 1] = '\0';
				i++;
				break;
			}
			default:
			{
				printf_s("Incorrect value\n");
				scanf_s("%d", &sym);
				break;
			}
			}
			if (sym == 2) break; // выход в главное меню
			p++;
		}
	}
	fclose(fp);
	return;
}

void Continue(Book *e, int param, int  page[], int bookmarks[])// продолжение чтения 
{
	Load_Book(e, page, bookmarks);
	param = page[0];
	READING(e, param, page, bookmarks);
}

void Bookmarks(Book *e, int page[], int bookmarks[]) // просмотр закладок
{
	int nline2 = 1, max2 = 25, i = 0, j = 1, u;
	char *str, z[100];
	FILE *bm;
	Load_Book(e, page, bookmarks);
	if (fopen_s(&bm, e->way, "r"))  printf_s("Error:file couldn't be opened5");
	if (bm != NULL)
	{
		while (bookmarks[i] != 0)
		{
			while (nline2 < bookmarks[i] * max2)
			{
				str = fgets(z, sizeof(z), bm);
				if (str == NULL)// проверяем ,закончился файл или ошибка при чтении
				{
					if (feof(bm) != 0)// закончился файл
					{
						printf_s("\n\t\t\tEnd of book\n");
						fclose(bm);
						return;
					}
					else//ошибка при чтении
					{
						printf("Error: reading's impossible");
						return;
					}
				}
				puts(str);
				nline2++;
				if (nline2 % max2 == 0)
				{
					printf_s("\t\t\tpage %d\n", j);
					j++;
				}
			}
			printf_s("\nReference: touch 1. Next bookmark\t2.Exit\n");
			scanf_s("%d", &u);
			if (u == 1)i++;
			if (u == 2)break;
		}
	}
}
int main()
{
	Book e; BOOK_TREE Tree; BOOK_TREE Tree2;
	Book *book = &e;
	BOOK_TREE *Birch = &Tree; BOOK_TREE *Pine = &Tree2;
	CreateBook(book, Birch, Pine);
	FILE *cleaning;
	int page[1], bookmarks[80], param = 1;
	char author3[80], name3[80],str2;
	printf_s("\t\t\t\tWelcome!\nChoose your next action\n");
	printf_s("1.Look throught the library\n2.Search by name\n3.Search by author\n4.Continue reading\n5.Your bookmarks\n6.Exit\n");

	int s;
	while (1)// основное меню
	{
		scanf_s("%d", &s);
		switch (s)
		{
		case 1: // вывод всех доступных книг
		{
			if (fopen_s(&cleaning, "D:\\for print.txt", "r")) printf_s("error: file couldn't be opened1\n");
			while ((str2 = getc(cleaning)) != EOF) putchar(str2);
			fclose(cleaning);
			break;
		}
		case 2: // поиск по названию книги
		{
			system("cls");
			printf_s("Enter the name\n (For example:War and peace)\n");
			getchar();
			gets_s(name3, 79);
			book = Name_Search(Pine, name3);
			READING(book, param, page, bookmarks);
			break;
		}
		case 3: // поиск по автору
		{
			system("cls");
			printf_s("Enter the writer\n (For example: O.Wild)\n");
			getchar();
			gets_s(author3, 79);
			book = Author_Search(Birch, author3);
			READING(book, param, page, bookmarks);
			break;
		}
		case 4: // продолжить чтение с последнего места
		{
			system("cls");
			Continue(book, param, page, bookmarks);
			break;
		}
		case 5: // посмотреть сделанные закладки
		{
			system("cls");
			Bookmarks(book, page, bookmarks);
			break;
		}
		case 6:// выход изглавного меню
		{
			if (fopen_s(&cleaning, "D:\\for print.txt", "w"))printf_s(" Error:file couldn't be opened");
			fclose(cleaning);// очистка файла for print.txt
			break;
		}
		default:
		{
			printf_s("Incorrect value\n");
			break;
		}
		}
		if (s == 6) break;// выход из программы
		printf_s("\n1.Look throught the library\n2.Search by name\n3.Search by author\n4.Continue reading\n5.Your bookmarks\n6.Exit\n");
	}
	return 0;
}