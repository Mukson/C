#include "mark.h"
#include "ui_mark.h"
#include<QFile>
#include<QTextStream>
#include<QDebug>

Mark::Mark(QWidget *parent,QString *in_file_name) :
    QDialog(parent),
    ui(new Ui::Mark)
{
    Fopen = *in_file_name; //принимаем имя файла из главного окна
     qDebug() << Fopen;
    ui->setupUi(this);
    ui->NextM->setEnabled(false);
    ui->PrevM->setEnabled(false);
    ui->label->hide();
    ui->numMark->hide();
    connect(ui->NextM,SIGNAL(clicked()),this,SLOT(NextBm()));
    connect(ui->PrevM,SIGNAL(clicked()),this,SLOT(PrevBm()));
    ReadMark(mark[index]);
}

Mark::~Mark()
{
    delete ui;
}

void Mark::NextBm()
{
    index++;
    ui->PrevM->setEnabled(true);
    ReadMark(mark[index]);
}

void Mark::PrevBm()
{
    index--;
    ui->NextM->setEnabled(true);
    ReadMark(mark[index]);
}

void Mark::OpenMark()
{
    int i = 0,p;
    QFile file("D:\\books\\saved.txt");
    if(!file.open(QIODevice::ReadOnly))
    {
        qDebug() << "Ошибка чтения файла(12)";
        return; // если это сделать невозможно, то завершаем функцию
    }
    QTextStream stream(&file);
    stream >> p;
    stream >> Fopen;
    while(1)
    {
        stream >> mark[i];
        if(mark[i] == 0)
            break;
        i++;
    }
    file.close();
}

void Mark::ReadMark(int num)
{

    ui->numMark->setText(QString :: number(mark[0]) );
    QFile file(Fopen);
    if (!file.open(QIODevice::ReadOnly)) // проверяем, возможно ли открыть наш файл для чтения
    {
        qDebug() << "Ошибка чтения файла(13)";
        return; // если это сделать невозможно, то завершаем функцию
    }
    QTextStream stream(&file);
    QString str;
    int nline = 1;
    if(mark[index] == 1 )
    {
        ui->PrevM->setEnabled(false);
        while( nline <=  25 )
        {
         str = stream.readLine(125);// считывание строки
         ui->MarkText->append(str);// вывод строки на экран
                if(stream.atEnd())
                {
                    ui->MarkText->setTextColor(Qt::red);
                    ui->MarkText->append( "Конец книги");
                    ui->MarkText->setTextColor(Qt::black);
                    ui->MarkText->setEnabled(false);
                    break;
                }
            nline++;
        }
        ui->NextM->setEnabled(true); //делаем активной кнопку вперед
        ui->label->show();
        ui->numMark->show();
        ui->numMark->setText(QString::number(mark[index]));
    }
    while( nline <= mark[index] * 25 )
    {
     str = stream.readLine(125);// считывание строки
     if(nline <= (mark[index] - 1) * 25 )
     {
         nline++;
         continue;
     }
     ui->MarkText->append(str);// вывод строки на экран
            if(stream.atEnd())
            {
                ui->NextM->setEnabled(false);
                ui->MarkText->setTextColor(Qt::red);
                ui->MarkText->append( "Конец книги");
                ui->MarkText->setTextColor(Qt::black);
                break;
            }
        nline++;
    }
    file.close();
}
