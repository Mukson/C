#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "dialog.h"
#include "mark.h"
#include"filename.h"
#include"tree.h"
#include "fstream"
#include<QFile>
#include<QTextStream>

using namespace std;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    Tree A;
    A.FillTree();
    ui->setupUi(this);
    ui->prev_btn->setEnabled(false); //делаем кнопки вперед-назад неактивными
    ui->next_btn->setEnabled(false);
    ui->PageNumber->hide();
    ui->label->hide();
    ui->DesiredPage->setEnabled(false);
    ui->open_book->setEnabled(false);
    ui->MakeMark->setEnabled(false);
    ui->SeeMarks->setEnabled(false);


//    Коннекторы связывают кнопки и другие действия с функциями
   connect(ui->open_book,SIGNAL(triggered()),this,SLOT(book_open())); //при нажатии пункта меню Открыть книгу сработает функция book_open
   connect(ui->prev_btn,SIGNAL(clicked()),this,SLOT(prev_page())); //настроим функции при нажатии на кнопки вперед-назад
   connect(ui->next_btn,SIGNAL(clicked()),this,SLOT(next_page()));
   connect(ui->DesiredPage,SIGNAL(triggered()),this,SLOT(OpenMyPage()));
   connect(ui->MakeMark,SIGNAL(triggered),this,SLOT(MakeBookmark()));
   connect(ui->Library,SIGNAL(triggered()),this,SLOT(Printlib()));
   connect(ui->StopReading,SIGNAL(triggered()),this,SLOT(Close()));
   connect(ui->SeeMarks,SIGNAL(triggered()),this,SLOT(SeeBookmarks()));
   connect(ui->ContinueReading,SIGNAL(triggered()),this,SLOT(ContinueReading()));

}


MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::book_open()
{
    FileName * Search = new FileName ;
    connect(Search,SIGNAL(SendName(QString)),this,SLOT(FixName(QString)));
    Search->show();
}

void MainWindow::FixName(const QString &str)
{
    if(!str.isEmpty())
    {
    QString str2 = str;
    file_name = str2.prepend("D:\\books\\").append(".txt");
    qDebug()<<file_name ;
    if(!file_name.isEmpty()) OpenPage(1);
    }



}



void MainWindow::next_page()
{
    Page++; // увеличиваем номер страницы
    OpenPage(Page );
    ui->prev_btn->setEnabled(true);//доступна кнопка предыдущей страницы
}


void MainWindow::prev_page()
{
    Page--;// уменьшение номера страницы
    OpenPage(Page);
    ui->next_btn->setEnabled(true);
}


void MainWindow :: OpenMyPage()
{
    Dialog *mwd = new Dialog(this,&file_name); //передадим имя файла в диалог
    connect(mwd,SIGNAL(sendData(int)),this,SLOT(OpenPage(int))); //ловим сигнал обновления из диалога ввода и запускаем обработку данных
    mwd->show();
}


void MainWindow:: OpenPage(int num)
{
    qDebug() << num;
    Page = num;
    ui->PageNumber->setValue(num);// устанавливаем номер страницы в spinbox
    ui->book_text->clear();//очищаем поле вывода книг
    //делаем доступными для нажатия кнопки "сделать закладку" и "посмотреть закладки"
    ui->MakeMark->setEnabled(true);
    ui->SeeMarks->setEnabled(true);
    if(Page==0) OpenPage(1);// если пользователем введен 0 , то будет открыта первая страница

    QFile file(file_name); // создаем объект класса QFile
    if (!file.open(QIODevice::ReadOnly)) // проверяем, возможно ли открыть наш файл для чтения
    {
        qDebug() << "Ошибка чтения файла(5)";
        return; // если это сделать невозможно, то завершаем функцию
    }

    QTextStream stream(&file);
    QString str;
    int nline = 1; // номер строки

    if(num == 1 )
    {
        ui->prev_btn->setEnabled(false);
        while( nline <=  MaxLine )
        {
         str = stream.readLine(125);// считывание строки
         ui->book_text->append(str);// вывод строки на экран
                if(stream.atEnd())// если конец книги
                {
                    // то выводим "конец книги" на экран и делаем недоступной кнопку следующей страницы
                    ui->book_text->setTextColor(Qt::red);
                    ui->book_text->append( "Конец книги");
                    ui->book_text->setTextColor(Qt::black);
                    ui->next_btn->setEnabled(false);
                    break;
                }
            nline++;
        }
        ui->next_btn->setEnabled(true); //делаем активной кнопку вперед
        ui->label->show();
        ui->PageNumber->show();
        ui->DesiredPage->setEnabled(true);// кнопка открытия любой страницы доступна
        ui->PageNumber->setValue(Page);
    }
    while( nline <= Page * MaxLine )
    {
     str = stream.readLine(125);// считывание строки
     if(nline <= (Page - 1) * MaxLine )// игнорируем предыдущие страницы
     {
         nline++;
         continue;
     }
     ui->book_text->append(str);// вывод строки на экран
            if(stream.atEnd())
            {
                ui->next_btn->setEnabled(false);
                ui->book_text->setTextColor(Qt::red);
                ui->book_text->append( "Конец книги");
                ui->book_text->setTextColor(Qt::black);
                break;
            }
        nline++;
    }
    file.close(); // закрытие файла
}

void MainWindow::Printlib()
{
    char buff[50];
    ifstream stream("D:\\books\\Print.txt", ios_base::in);
    if(!stream.is_open())
    {
        qDebug() << "Ошибка чтения файла(8)";
        return; // если это сделать невозможно, то завершаем функцию
    }
    while(!stream.eof())
    {
        stream.getline(buff,50);
        ui->book_text->append(buff);

    }

    stream.close();
    ui->open_book->setEnabled(true);
}

void MainWindow:: MakeBookmark()
{
 BookMark[MarkN] = Page;
 BookMark[MarkN++] = '\0';
 MarkN++;
}


void MainWindow::Close()
{
    ofstream fl("D:\\books\\Print.txt",ios_base::trunc);
    if(!fl.is_open())
    {
        qDebug() << "Ошибка чтения файла(9)";
        return; // если это сделать невозможно, то завершаем функцию
    }
    fl.close();
    SaveBook();
    close();
}

void MainWindow::SaveBook()
{
    int i = 0;
    ofstream file("D:\\books\\saved.txt");
     if(!file.is_open())
    {
        qDebug() << "Ошибка чтения файла(10)";
        return; // если это сделать невозможно, то завершаем функцию
    }
    file<<Page<<'\n';
    while(1)
    {
        if(BookMark[i] == '\0')
        {
            BookMark[i] = 0;
            file<<(BookMark[i])<< '\n';
            break;
        }
        file<< BookMark[i]<<'\n';
        i++;
    }
    file.close();

}

void MainWindow::LoadBook()
{
    int i = 0;
    ifstream file("D:\\books\\saved.txt");
      if(!file.is_open())
    {
        qDebug() << "Ошибка чтения файла(11)";
        return; // если это сделать невозможно, то завершаем функцию
    }
    file >> Page;

    while(1)
    {
        file >> BookMark[i];
        if(BookMark[i] == 0)
            break;
        i++;
    }
    file.close();
}

void MainWindow::SeeBookmarks()
{
    Mark *M = new Mark(this,&file_name);
    M->show();
}

void MainWindow::ContinueReading()
{
    QFile file("D:\\books\\saved.txt");
    if(!file.open(QIODevice::ReadOnly))
    {
        qDebug() << "Ошибка чтения файла(14)";
        return; // если это сделать невозможно, то завершаем функцию
    }
    QTextStream stream(&file);
    stream>> Page;
    file.close();
    OpenPage(Page);
}
