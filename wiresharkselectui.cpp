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
    byteTree.insert(QPair<int,int>(14,33),itemlist.at(1));
    byteTree.insert(QPair<int, int>(0, 5), itemlist.at(2));
    byteTree.insert(QPair<int,int>(6,11),itemlist.at(3));
    byteTree.insert(QPair<int,int>(12,13),itemlist.at(4));
    byteTree.insert(QPair<int,int>(14,14),itemlist.at(5));
    byteTree.insert(QPair<int,int>(15,15),itemlist.at(6));
    byteTree.insert(QPair<int,int>(16,17),itemlist.at(7));
    byteTree.insert(QPair<int,int>(18,19),itemlist.at(8));
    byteTree.insert(QPair<int,int>(20,20),itemlist.at(9));
    byteTree.insert(QPair<int,int>(21,21),itemlist.at(10));
    byteTree.insert(QPair<int,int>(22,22),itemlist.at(11));
    byteTree.insert(QPair<int,int>(23,23),itemlist.at(12));
    byteTree.insert(QPair<int,int>(24,25),itemlist.at(13));
    byteTree.insert(QPair<int,int>(26,29),itemlist.at(14));
    byteTree.insert(QPair<int,int>(30,33),itemlist.at(15));
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
    itemlist.append(second->child(5));
    itemlist.append(second->child(6));
    itemlist.append(second->child(7));
    itemlist.append(second->child(8));
    itemlist.append(second->child(9));
    itemlist.append(second->child(10));

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

    QString Identification = info.array.toHex().mid(36,4);

    QByteArray array = info.array.mid(20, 2); // Assuming array is already defined
    QString value = array.toHex(); // Convert to hexadecimal string

    auto pair = GetBit(value);
    auto ThreebitString = pair.second.first;
    auto ThreebitInt = QString::number(pair.first.first,16);
    QString NO1 = ThreebitString.at(0)=='1'?"":"Don't Fragment";
    QString NO2 = ThreebitString.at(1)=='1'?"":"More Fragments";
    qDebug()<<ThreebitString.at(0)<<ThreebitString.at(1);
    QString flag1 = QString("%1 . .... = Flags : %2 ,%3").arg(ThreebitString).arg(ThreebitInt)
                        .arg(NO1+" "+NO2);

    auto SixteenString = pair.second.second;
    auto SixteenInt =  QString::number(pair.first.second,16);
    QString flag2 = QString("... %1 = Fragment Offset:%2").arg(SixteenString).arg(SixteenInt);

    QString time = info.array.toHex().mid(44,2);
    QString Protocol ;
    if(info.proto == "TCP") Protocol = "TCP (6)";
    else if(info.proto == "Udp") Protocol = "UDP (17)";

    QString crc = info.array.toHex().mid(48,4);

    second->child(0)->setText(0,QString("header length: 20 byte"));
    second->child(1)->setText(0,QString("Differentiated Services Field: %1 (DSCP: %2, ECN: %3) ").arg(hexString).arg(info.dscp).arg(info.ecn));
    second->child(2)->setText(0,QString("Total length: %1").arg( total.toInt(nullptr, 16)));
    second->child(3)->setText(0,QString("Identification: 0x%1 (%2)").arg(Identification).arg(Identification.toInt(nullptr, 16)));
    second->child(4)->setText(0,QString("%1").arg(flag1));
    second->child(5)->setText(0,QString("%1").arg(flag2));
    second->child(6)->setText(0,QString("Time To Live : %1").arg(time.toInt(nullptr,16)));
    second->child(7)->setText(0,QString("Protocol: %1").arg(Protocol));
    second->child(8)->setText(0,QString("Header Checksum: 0x%1 [validation disabled]").arg(crc));
    second->child(9)->setText(0,QString("Src Port: %1").arg(info.src_port));
    second->child(10)->setText(0,QString("Dst Port: %1").arg(info.dst_port));
    first->setText(0,str);
    second->setText(0,str1);

}

QPair<QPair<int, int>, QPair<QString, QString> > WireSharkSelectUi::GetBit(QString str)
{
    bool ok;
    int hexValue = str.toInt(&ok, 16); // Convert to integer
    QString value = QString::number(hexValue, 2).rightJustified(16, '0'); // Convert to binary string
    auto first = value.mid(0,3);
    auto second = value.mid(3,13);
    int value1 = first.toInt(nullptr,2);
    int value2 = second.toInt(nullptr,2);
    QPair<int,int> pair1(value1,value2);
    QPair<QString,QString> pair2(first,second);
    QPair<QPair<int, int>, QPair<QString, QString> > pair(pair1,pair2);
    return pair;

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
    for(auto value : byteTree)
    {
        if(value == item)
        {
            auto key = byteTree.key(value);
            low = key.first;
            high = key.second;
            break;
        }
    }
    if (high == 0) return;

    int max = high ;
    int col = low / 16 ; // 起始行数，从1开始计数
    int row = max / 16 ; // 总行数，包括最后一行
    int last = max % 16; // 最后一行的剩余位置
    hexmetadata->clear();

    // 高亮从low到high的整个范围
    for (int i = col; i <= row; ++i) {
        // 应用前景色
        int  a1 = low ;
        int  b1 = high ;
        if(low - i*16 <=0) a1 = 0 ;
        else a1 -= i*16;
        if(high - i*16 <=0) b1 = 0 ;
        else b1 -= i*16;
        qDebug()<<a1<<b1;
        hexmetadata->foreground(i, a1, b1-a1+1, Qt::blue);
    }


}

