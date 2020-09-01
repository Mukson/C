#include "dialog.h"
#include "ui_dialog.h"


int const MaxLine2 = 25;

Dialog::Dialog(QWidget *parent, QString *in_file_name) :
    QDialog(parent),
    ui2(new Ui::Dialog)
{
    file_name = *in_file_name; //принимаем имя файла из главного окна
     qDebug() << file_name;
    ui2->setupUi(this);
    connect(ui2->Close,SIGNAL(clicked()),this, SLOT (close()));
    connect(ui2->Ok,SIGNAL(clicked()),this,SLOT(SendPage()));

    CountPages();
}

Dialog::~Dialog()
{
    delete ui2;
}

void Dialog:: SendPage()
{

    emit sendData(ui2->spinBox->value());
    close();
}


void Dialog:: CountPages()
{
    QFile file(file_name); // создаем объект класса QFile
    if (!file.open(QIODevice::ReadOnly)) // проверяем, возможно ли открыть наш файл для чтения
    {
        qDebug() << "Ошибка чтения файла(4)";
        return; // если это сделать невозможно, то завершаем функцию
    }
    QTextStream stream(&file);
    QString str;
    int nline = 1, Pages = 1;
    while( !stream.atEnd() )
    {
     str = stream.readLine(125);// считывание строки
            if(stream.atEnd())   break;// завершаем цикл, если достигнут конец файла
     nline++;
    }
    file.close();
    if(nline % MaxLine2  != 0)
        Pages = (nline / MaxLine2) + 1;
    else
        Pages = nline / MaxLine2;
    ui2->AllPages->setText(QString :: number(Pages) );

}

