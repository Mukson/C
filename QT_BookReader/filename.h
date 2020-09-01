#ifndef FILENAME_H
#define FILENAME_H
#include<QString>
#include <QDialog>

namespace Ui {
class FileName;
}

class FileName : public QDialog
{
    Q_OBJECT

public:
    explicit FileName(QWidget *parent = 0);
    ~FileName();

private:
    Ui::FileName *ui;
private slots:
    void OkClicked();

signals:
    void SendName(const QString &str);
};

#endif // FILENAME_H
