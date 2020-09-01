#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QDebug>
#include <QFile>
#include <QString>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    int Page = 1;
    int const MaxLine = 25;
    int MarkN = 1;
private:
    QString file_name; //имя открытого файла
    QString book_text; //текст открытой книги
    Ui::MainWindow *ui;
    int BookMark[200];
    void SaveBook();//  сохранение книги
    void LoadBook();// загрузка книги
    void MakeBookmark();

private slots:
    //void dir_open(); //функция открытия папки
    void book_open(); //функция открытия книги
    void prev_page(); //функции кнопок
    void next_page();
    void OpenPage(int num );
    void OpenMyPage();
    void Printlib();
    void Close();
    void FixName(const QString &str);
    void SeeBookmarks();// посмотреть закладки
    void ContinueReading();// продолжить чтение

};

#endif // MAINWINDOW_H
