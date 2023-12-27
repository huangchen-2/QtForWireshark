#ifndef WIRESHARK_H
#define WIRESHARK_H

#include <QWidget>
#include <pcap.h>
#include <QVector>
#include <QMap>

#include <QListWidgetItem>
#include <QtConcurrent>
#include <wiresharkselectui.h>
#include <Stuct.h>
#include <QVariant>
#include <QDebug>
#include <QFuture>
#include <QRegExp>
#include <stdio.h>
#include <QCloseEvent>
#include <QDateTime>
#include <QDir>
#include <QTextStream>
#include <QMessageBox>


namespace Ui {
class Wireshark;
}


class Wireshark : public QWidget
{
    Q_OBJECT

public:
    explicit Wireshark(QWidget *parent = nullptr);
    ~Wireshark();
    void initDevice();
    void OpenSelectDevice(pcap_if_t *);
    void ifprint(pcap_if_t *d);
    char * iptos(u_long in);
    char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
    void closeEvent(QCloseEvent *event) override;
    friend void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
    void labelSetToolTip();
    void writerToFile(const char* str, bool ok, QString filename)
    {
        QDateTime currentDate = QDateTime::currentDateTime();
        QString exceptionFilePath = QDir::currentPath() + QString("/%1/").arg(filename) + currentDate.toString("yyyy-MM-dd") + ".txt";
        QDir dmp;
        bool exist = dmp.exists(QDir::currentPath() + "/"+filename);
        qDebug()<<exceptionFilePath;
        if(!exist)
        {
            dmp.mkdir(QDir::currentPath() + "/"+filename);
        }
        QFile exceptionFile(exceptionFilePath);
        if (!exceptionFile.open(QIODevice::WriteOnly | QIODevice::Append))
        {
            qDebug() << "无法打开文件：" << exceptionFilePath;
        }
        QTextStream writer(&exceptionFile);
        writer << QString("%1,%2,%3 ").arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss")).arg(str).arg(ok)<<endl;
        exceptionFile.close();
    }
signals:
    void SendProto(QVariant var);
    void SendInitOk();
private slots:
    void on_listWidget_itemDoubleClicked(QListWidgetItem *item);

private:
    Ui::Wireshark *ui;
    QVector<pcap_if_t*> deviceList;
    QMap<QString, QString> deviceTranslationTable;
    QMap<QString ,DeviceInfo> deviceMap;
    WireSharkSelectUi * select;
    QList<QString> list;
    QFuture<void> future;
public:
    pcap_t *adhandle; //打开设备的指针
    bool bool_value = false ;
};

#endif // WIRESHARK_H
