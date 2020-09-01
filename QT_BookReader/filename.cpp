#include "filename.h"
#include "ui_filename.h"

FileName::FileName(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::FileName)
{
    ui->setupUi(this);
    connect(ui->cancel,SIGNAL(clicked()),this,SLOT(close()));
    connect(ui->Ok,SIGNAL(clicked()),this,SLOT(OkClicked()));
}

FileName::~FileName()
{
    delete ui;

}

void FileName::OkClicked()
{
    emit SendName(ui->lineEdit->text());
    close();
}
