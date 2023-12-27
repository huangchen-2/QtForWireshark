#include "wiresharkselectui.h"
#include "ui_wiresharkselectui.h"

#include <QTextBlock>

#include <document/buffer/qmemorybuffer.h>

//关于TCP协议。前14个字节为以太网帧头部，后二十个为IP头，再20为Tcp头，最后剩下的就是数据域


WireSharkSelectUi::WireSharkSelectUi(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::WireSharkSelectUi)
{
    ui->setupUi(this);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);    //x先自适应宽度
    //设定选择行为，按行选择
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    //设置选中行的背景色，必须要显示设置，即代码设置或者在ui文件的控件中设置，用系统默认的是无法代码选中高亮某行
    ui->tableWidget->setStyleSheet("selection-background-color:rgb(223,178,128)");
    //设置要选中高亮的行，这里会触发QTableWidget::itemClicked的信号
    initTreeList();
    byteTree.insert(QPair<int, int>(0, 13), itemlist.at(0));
    byteTree.insert(QPair<int,int>(32,35),itemlist.at(1));
    byteTree.insert(QPair<int, int>(0, 5), itemlist.at(2));
    byteTree.insert(QPair<int,int>(6,11),itemlist.at(3));
    byteTree.insert(QPair<int,int>(12,13),itemlist.at(4));
    byteTree.insert(QPair<int,int>(14,14),itemlist.at(5));
    byteTree.insert(QPair<int,int>(15,15),itemlist.at(6));
    byteTree.insert(QPair<int,int>(16,17),itemlist.at(7));
    byteTree.insert(QPair<int, int>(32,33), itemlist.at(8));
    byteTree.insert(QPair<int,int>(34,35),itemlist.at(9));
    ui->editor->setReadOnly(true);



}

WireSharkSelectUi::~WireSharkSelectUi()
{
    delete ui;
}

void WireSharkSelectUi::initTreeList()
{
    auto first = ui->treeWidget->topLevelItem(0);
    auto second = ui->treeWidget->topLevelItem(1);
    itemlist.append(first);
    itemlist.append(second);
    itemlist.append(first->child(0));
    itemlist.append(first->child(1));
    itemlist.append(first->child(2));
    itemlist.append(second->child(0));
    itemlist.append(second->child(1));
    itemlist.append(second->child(2));
    itemlist.append(second->child(3));
    itemlist.append(second->child(4));
}

void WireSharkSelectUi::ChangeTreeItemText(int index)
{
    auto header = ui->treeWidget->headerItem();
    header->setText(0,"信息");
    auto first = ui->treeWidget->topLevelItem(0);
    auto second = ui->treeWidget->topLevelItem(1);
    auto info = itemMapinfo.value(index);
    int len = info.array.size();
    QString str = QString("Frame 1: %1 bytes on wire (%2 bits), %3 bytes captured (%4 bits) on interface %5}")
                      .arg(len).arg(len*8).arg(len).arg(len*8).arg(current_name);
    QString str1 = QString("Internet Protocol Version 4, Src: %1, Dst: %2").arg(info.src).arg(info.dst);
    first->child(0)->setText(0,QString("Ethernet II, Src: %1").arg(info.src_mac.replace(QChar(' '), QChar(':'))));
    first->child(1)->setText(0,QString("Ethernet II, Dst: %1").arg(info.dst_mac.replace(QChar(' '), QChar(':'))));
    first->child(2)->setText(0,"Type:IPV4");

    QString hexString = info.array.toHex().mid(30, 2);

    QString total = info.array.toHex().mid(32,4);


    second->child(0)->setText(0,QString("header length: 20 byte"));
    second->child(1)->setText(0,QString("Differentiated Services Field: %1 (DSCP: %2, ECN: %3) ").arg(hexString).arg(info.dscp).arg(info.ecn));
    second->child(2)->setText(0,QString("Total length: %1").arg( total.toInt(nullptr, 16)));
    second->child(3)->setText(0,QString("Src Port: %1").arg(info.src_port));
    second->child(4)->setText(0,QString("Dst Port: %1").arg(info.dst_port));
    first->setText(0,str);
    second->setText(0,str1);

}


void WireSharkSelectUi::getProto(QVariant var)
{

    ProtoInfo info;
    info = var.value<ProtoInfo>();
    QString str = QString("%1 -> %2  ack:%3  seq:%4").arg(info.src_port).arg(info.dst_port).arg(info.ack).arg(info.seq);
    int row = ui->tableWidget->rowCount();
    ui->tableWidget->insertRow(row);
    ui->tableWidget->setItem(row,0,new QTableWidgetItem(info.time));
    ui->tableWidget->setItem(row,1,new QTableWidgetItem(info.src));
    ui->tableWidget->setItem(row,2,new QTableWidgetItem(info.dst));
    ui->tableWidget->setItem(row,3,new QTableWidgetItem(info.proto));
    ui->tableWidget->setItem(row,4,new QTableWidgetItem(QString::number(info.len)));
    ui->tableWidget->setItem(row,5,new QTableWidgetItem(str));
    itemMapinfo.insert(row,info);
}

void WireSharkSelectUi::currentAddressChanged(qint64 address)
{
    if(byteTree.isEmpty())
        return ;

    for(auto value : byteTree)
    {
        //字节不映射parent，只映射子节点,跳过parent节点
        if(nullptr == value->parent()) continue ;
        auto key = byteTree.key(value);
        if(address>=key.first&&address<=key.second)
        {
            for(auto item : itemlist)
            {
                item->setBackground(0,Qt::white);
            }
            value->setBackground(0,QColor(223,178,128));
            value->parent()->setExpanded(true);
            return ;
        }
    }
}


void WireSharkSelectUi::on_tableWidget_clicked(const QModelIndex &index)
{

    int row = index.row();

    byte = itemMapinfo.value(row).array;
    auto item = itemMapinfo.value(row);
    document = QHexDocument::fromMemory<QMemoryBuffer>(byte);
    ui->editor->setDocument(document);
    ChangeTreeItemText(row);

}




void WireSharkSelectUi::on_treeWidget_itemClicked(QTreeWidgetItem *item, int column)
{
    QHexMetadata* hexmetadata = document->metadata();
    QByteArray data ;
    document->cursor()->clearSelection();
    int low = 0 ;
    int high = 0;
    int col = 0 ;
    int row = 0 ;
    for(auto value : byteTree)
    {
        if(value == item)
        {
            auto key = byteTree.key(value);
            low = key.first;
            high = key.second;
            qDebug()<<low<<high;
            break;
        }
    }
    if(high==0) return ;
    col = high / 16; // 计算起始列
    row = low / 16;  // 计算起始行
    hexmetadata->clear();
    if(row == col)
    {
        hexmetadata->foreground(0,low, high-low+1, Qt::blue);
        return;
    }
    // 确保我们不会错过最后一个字节的高亮
    col = qMax(0, col);
    row = qMax(0, row);
    qDebug()<<col<<row;



    // 高亮从low到high的整个范围
    for (int i = row; i < row + (col - row + 1); ++i) {
        // 计算每行的起始和结束位置
        int start = i * 16;
        int length = qMin(16, high - start + 1); // 加1确保包括最后一个字节
        qDebug()<<"length"<<length;
        // 应用前景色
        if (i == row) {
            // 如果是第一行，则从low开始
            hexmetadata->foreground(i, low - start, length, Qt::blue);
        } else {
            // 否则，从上一行的结束位置开始
            hexmetadata->foreground(i, start, length, Qt::blue);
        }
    }

}

