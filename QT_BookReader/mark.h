#ifndef MARK_H
#define MARK_H
#include<QString>
#include <QDialog>

namespace Ui {
class Mark;
}

class Mark : public QDialog
{
    Q_OBJECT

public:
    explicit Mark(QWidget *parent = 0, QString *in_file_name = 0);
    ~Mark();
    int mark[200];
    int index = 0;
    QString Fopen;
private:
    Ui::Mark *ui;
    void OpenMark();
    void ReadMark(int num);
private slots:
    void NextBm();
    void PrevBm();
};

#endif // MARK_H
