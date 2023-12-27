#ifndef WIRESHARKSELECTUI_H
#define WIRESHARKSELECTUI_H

#include <QWidget>
#include <Stuct.h>
#include <QVariant>
#include <QMap>
#include <QTableWidgetItem>
#include <QTableWidget>
#include <QDebug>
#include <QTreeWidgetItem>
#include <QMouseEvent>

#include <document/qhexdocument.h>

namespace Ui {
class WireSharkSelectUi;
}

class WireSharkSelectUi : public QWidget
{
    Q_OBJECT

public:
    explicit WireSharkSelectUi(QWidget *parent = nullptr);
    ~WireSharkSelectUi();
    void initTreeList();

public slots:
    void getProto(QVariant var);
     void ChangeTreeItemText(int index);
private slots:
    void currentAddressChanged(qint64 address);
    void on_tableWidget_clicked(const QModelIndex &index);
    void on_treeWidget_itemClicked(QTreeWidgetItem *item, int column);

private:
    Ui::WireSharkSelectUi *ui;
    QMap<int,ProtoInfo> itemMapinfo;
    QList<QTreeWidgetItem*> itemlist;
    QMap<QPair<int,int>,QTreeWidgetItem*> byteTree;
    QByteArray byte ;
    QHexDocument* document;
public:
    QString current_name = "";

};

#endif // WIRESHARKSELECTUI_H
