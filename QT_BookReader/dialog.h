#ifndef DIALOG_H
#define DIALOG_H
#include <QFileDialog>
#include <QDebug>
#include <QString>

namespace Ui {
class Dialog;
}

class Dialog : public QDialog
{
    Q_OBJECT

public:
    explicit Dialog(QWidget *parent = 0, QString *in_file_name = 0);
    ~Dialog();

private:
    QString file_name;
    Ui::Dialog *ui2;
     void CountPages(); // колличество страниц в книге
private slots:
    void SendPage();
signals:
    void sendData(int);

};

#endif // DIALOG_H
