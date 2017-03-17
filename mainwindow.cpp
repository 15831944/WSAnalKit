#pragma execution_character_set("UTF-8")

#include "mainwindow.h"
//ui_mainwindow.h必须放到mainwindow.h之下，否则编译报错
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QByteArray>
#include <QVector>

#include <QQuickWidget>
#include <QQuickView>
#include <QQmlEngine>
#include <QQmlContext>
#include <QQmlComponent>

#include "wsconstant.h"
#include "anakit.h"
#include "stores/waveanaldatamodel.h"

/**
 * 波形显示待办事项：
 * 1.波形颜色要区分
 * 2.波形可按一定比例放大
 * 3.波形要根据实际最大值设定XY显示比例
 * 4.增加竖线，要能定位当前选择采样点  OK
 * 5.增加右侧通道名称和相关数据展示
 * 6.针对开关量显示的特殊处理，要能明确显示出分合两种值
 */

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    m_qwWaveData(new WaveAnalDataModel)
{
    ui->setupUi(this);

    setupOtherUi();

    //隐藏左侧报文包信息树表头
    ui->treeAllMsg->header()->hide();

    //设置报文信息一览表表头
    ui->tbMsgInfo->setColumnCount(4);
    ui->tbMsgInfo->setHorizontalHeaderLabels(QStringList()<<"序号"<<"协议"<<"发送端"<<"接收端");

    ui->menu_2->addAction(ui->dockWidget->toggleViewAction());

    setWaveStyle();

    connect(ui->horizontalScrollBar, SIGNAL(valueChanged(int)), this, SLOT(horzScrollBarChanged(int)));
    connect(ui->verticalScrollBar, SIGNAL(valueChanged(int)), this, SLOT(vertScrollBarChanged(int)));
//    connect(ui->wdtWave->xAxis2, SIGNAL(rangeChanged(QCPRange)), this, SLOT(xAxisChanged(QCPRange)));
//    connect(ui->wdtWave->yAxis, SIGNAL(rangeChanged(QCPRange)), this, SLOT(yAxisChanged(QCPRange)));
    connect(ui->wdtWave,SIGNAL(mousePress(QMouseEvent*)), this, SLOT(mousePress(QMouseEvent*)));
    connect(ui->wdtWave,SIGNAL(mouseWheel(QWheelEvent*)),this, SLOT(mouseWheel(QWheelEvent*)));

    m_mouseGraph = NULL;
	m_anakit = NULL;

}

MainWindow::~MainWindow()
{
    delete ui;
    delete m_qwWaveData;
    delete m_qwWaveData2;
}

void MainWindow::setLogView(bool view)
{
}

/*
 * 生成 [ 0 - nMax ]范围内不重复的数据 nCount 个
 * 注意， nMax 不小于 nCount
 *
 */
QList<int> random(int nMax, int nCount)
{
    QList<int> intList;
    int   i=0, m=0;
    QTime time;
    for(i=0;;)
    {
        if (intList.count() > nCount)
            break;

        int     randn;
        time    = QTime::currentTime();
        qsrand(time.msec()*qrand()*qrand()*qrand()*qrand()*qrand()*qrand());
        randn   = qrand()%nMax;
        m=0;

        while(m<i && intList.at(m)!=randn)
            m++;

        if(m==i)            { intList.append(randn); i++;}
        else if(i==nMax)    break;
        else                continue;
    }

    return intList;
}

void MainWindow::setupOtherUi()
{
    QTabWidget *tabw = ui->tabWidget;

    connect(ui->tabWidget, SIGNAL(currentChanged(int)), this, SLOT(currentChanged(int)));

    // 波形图
    m_qwWaveAnal = new QQuickWidget();
    m_qwWaveAnal->setObjectName(QStringLiteral("qwWaveAnal"));
    m_qwWaveAnal->setResizeMode(QQuickWidget::SizeRootObjectToView );
    m_qwWaveAnal->setSource(QUrl("qrc:/quick/WSWaveChartAnal.qml"));
//    QQmlComponent *component = new QQmlComponent(m_qwWaveAnal->engine());
//    component->setData("import QtQuick 2.4\n import XjUi 1.0 \n WaveChartAnal{}", QUrl());
//    m_qwWaveAnal->setContent(QUrl(), component, component->create());
    m_qwWaveAnal->rootContext()->setContextProperty("waveModel", m_qwWaveData);

    tabw->addTab(m_qwWaveAnal, QStringLiteral("波形分析"));
}

void MainWindow::currentChanged(int index)
{
//    qDebug() << index;

//    if (m_qwWaveData->test() == "1")
//        m_qwWaveData->setTest("0");
//    else
//        m_qwWaveData->setTest("1");
}

/**
 * @brief 重画定位线
 * @param mousePos  传入鼠标点击位置的x轴坐标
 */
void MainWindow::refreshMouseLine(double mousePos)
{
    double upper = ui->wdtWave->yAxis->range().upper;
    QVector<double> x(2), y(2);
    x[0] = mousePos;
    y[0] = 0;
    x[1] = mousePos;
    y[1] = upper;

    if(m_mouseGraph == NULL)
        m_mouseGraph = ui->wdtWave->addGraph();
    m_mouseGraph->setData(x,y);
    ui->wdtWave->replot();
}

//设置左侧报文解析树的解析内容
void MainWindow::setTreeMessageAll(CCapPackagesMnger *pPackMnger)
{
    //设置根节点及协议树，第一列存描述、第二列存节点类型（目前分“ROOT” “PROTOCOL” “CONNECTION”），第三列存和节点类型相关的数据
    QTreeWidget *pTree = ui->treeAllMsg;
    pTree->clear();
    QTreeWidgetItem *pRoot = new QTreeWidgetItem(pTree, QStringList()<<"AllMessage"<<"ROOT");
    QTreeWidgetItem *pMMSRoot = new QTreeWidgetItem(pRoot, QStringList()<<"MMS"<<"PROTOCOL");
    QTreeWidgetItem *pGOOSERoot = new QTreeWidgetItem(pRoot, QStringList()<<"GOOSE"<<"PROTOCOL");
    QTreeWidgetItem *pSVRoot = new QTreeWidgetItem(pRoot, QStringList()<<"SV9-2"<<"PROTOCOL");
    QTreeWidgetItem *pPtpRoot = new QTreeWidgetItem(pRoot, QStringList()<<"PTP1588"<<"PROTOCOL");
    QTreeWidgetItem *pOtherRoot = new QTreeWidgetItem(pRoot, QStringList()<<"其他"<<"PROTOCOL");

    std::map <int, CAPCONNECTINFO* >::iterator iter;
    CAPCONNECTINFO* pConnection;
    QTreeWidgetItem *pMsgNode;
    QStringList content;
    char itemStr[128];
    for (iter = pPackMnger->m_mapcapconnectionfo.begin(); iter != pPackMnger->m_mapcapconnectionfo.end(); iter ++ )
    {
        pConnection = iter->second;
        if(pConnection == NULL)
            continue;
        content.clear();
        if(pConnection->nconnectapptype == PROTOAPPTYPE_SMV92)
        {
			sprintf(itemStr, "0x%04X %s",pConnection->ncapp_id, pConnection->csrc2_mac);
            content << itemStr << "CONNECTION" << QString::number(iter->first);
            pMsgNode = new QTreeWidgetItem(pSVRoot, content);
        }
        else if(pConnection->nconnectapptype == PROTOAPPTYPE_GOOSE)
        {
            sprintf(itemStr, "0x%04X %s",pConnection->ncapp_id, pConnection->csrc2_mac);
            content << itemStr << "CONNECTION" << QString::number(iter->first);
            pMsgNode = new QTreeWidgetItem(pGOOSERoot, content);
        }
        else if(pConnection->nconnectapptype == PROTOAPPTYPE_MMS)
        {
            sprintf(itemStr, "%s - %s",pConnection->csrc1_ip, pConnection->csrc2_ip);
            content << itemStr << "CONNECTION" << QString::number(iter->first);
            pMsgNode = new QTreeWidgetItem(pMMSRoot, content);

        }
        else if(pConnection->nconnectapptype == PROTOAPPTYPE_TIME1588)
        {
            sprintf(itemStr, "%s - %s",pConnection->csrc1_mac, pConnection->csrc2_mac);
            content << itemStr << "CONNECTION" << QString::number(iter->first);
            pMsgNode = new QTreeWidgetItem(pPtpRoot, content);
        }
        else
        {
            if(strlen(pConnection->csrc1_ip)>0)
                sprintf(itemStr, "%s - %s",pConnection->csrc1_ip, pConnection->csrc2_ip);
            else
                sprintf(itemStr, "%s - %s",pConnection->csrc1_mac, pConnection->csrc2_mac);
            content << itemStr << "CONNECTION" << QString::number(iter->first);
            pMsgNode = new QTreeWidgetItem(pOtherRoot, content);
        }

        pPackMnger->m_pcapconnectinfoTotal.nerrpackages += pConnection->nerrpackages;//总的错误包
	}

}

void MainWindow::on_actionLogView_triggered()
{

}


//“打开文件”点击事件处理
void MainWindow::on_actionOpen_triggered()
{
//    QString file_name = QFileDialog::getOpenFileName(this,
//            tr("Open File"), "", "",  0);
    QString file_name("example/sv/smv.pcap");
//    QString file_name("example/mms/D146_BRCB.pcap");

    if (!file_name.isNull() && file_name.endsWith(QString(".pcap")))
    {
        QByteArray ba = file_name.toLatin1();

        //测试代码，一次只打开一个文件进行解析，之前的释放掉
		if (m_anakit)
			delete m_anakit;
        m_anakit = new AnaKit();
        m_anakit->Initialize();

        logPrint("开始解析文件" + file_name + "...");
        bool ret = m_anakit->OpenCapFileAndParse(ba.data());
		if (ret)
		{
            logPrint("报文解析成功");
            setTreeMessageAll(&m_anakit->m_cappackagesmnger);
		}
		else
		{
            logPrint("报文解析失败");
		}

    }
    else{
        //点的是取消
        return;
    }
}

//左侧报文解析树鼠标点击事件处理
void MainWindow::on_treeAllMsg_clicked(const QModelIndex &index)
{
    CAPCONNECTINFO* pConnection;
    QTreeWidgetItem *pItem = ui->treeAllMsg->currentItem();

    if(pItem->text(1) != "CONNECTION")
    {
        ui->tbMsgInfo->clearContents();
        return;
    }

    int key = pItem->text(2).toInt(); //map中的key值

    pConnection = m_anakit->m_cappackagesmnger.m_mapcapconnectionfo[key];
    if(pConnection->nconnectapptype == PROTOAPPTYPE_SMV92)
    {
        //采样值链路处理
        logPrint("点击SV9-2链路 " + pItem->text(0));
        //绘制波形图
        drawSVWaveWindow(pConnection);
        drawSVWaveWindowByQml(pConnection);
        //填乱七八糟的采样数据表
    }
    else if(pConnection->nconnectapptype == PROTOAPPTYPE_GOOSE)
    {
        //GOOSE链路处理
        logPrint("点击GOOSE链路 " + pItem->text(0));
    }
    else if(pConnection->nconnectapptype == PROTOAPPTYPE_MMS)
    {
        //MMS链路处理
        logPrint("点击MMS链路 " + pItem->text(0));
    }
    else
    {
        //其他链路处理
        logPrint("点击其他链路 " + pItem->text(0));
    }

    fillMessageTable(pConnection);
}

//把链路中所有报文概要显示到表格中
void MainWindow::fillMessageTable(CAPCONNECTINFO* pConnection)
{
    MAP_CAPMSGINFO *pMapCapMsgInfo = &pConnection->map_capmsginfo;
    CAPMSGGININFO *pMsgInfo;

    logPrint("报文个数"+QString::number(pMapCapMsgInfo->size()));

    ui->tbMsgInfo->clearContents();
    ui->tbMsgInfo->setRowCount(pMapCapMsgInfo->size());

    int key, i=0;
    std::map <int, CAPMSGGININFO* >::iterator iter;
    for(iter = pMapCapMsgInfo->begin(); iter!=pMapCapMsgInfo->end();iter ++, i++)
    {
        pMsgInfo = iter->second;
        if(pMsgInfo == NULL)
            continue;

        key = iter->first;
        ui->tbMsgInfo->setItem(i,0, new QTableWidgetItem(QString::number(key)));
        if(strlen(pMsgInfo->csrc_ip)>0)
        {
            ui->tbMsgInfo->setItem(i,2, new QTableWidgetItem(pMsgInfo->csrc_ip));
            ui->tbMsgInfo->setItem(i,3, new QTableWidgetItem(pMsgInfo->cdst_ip));
        }
        else
        {
            ui->tbMsgInfo->setItem(i,2, new QTableWidgetItem(pMsgInfo->csrc_mac));
            ui->tbMsgInfo->setItem(i,3, new QTableWidgetItem(pMsgInfo->cdst_mac));
        }

        switch(pMsgInfo->napptype)
        {
            case PROTOAPPTYPE_MMS:
                ui->tbMsgInfo->setItem(i,1, new QTableWidgetItem("MMS"));
                ui->tbMsgInfo->setItem(i,2, new QTableWidgetItem(pMsgInfo->csrc_ip));
                ui->tbMsgInfo->setItem(i,3, new QTableWidgetItem(pMsgInfo->cdst_ip));
                break;
            case PROTOAPPTYPE_SMV92:
                ui->tbMsgInfo->setItem(i,1, new QTableWidgetItem("SMV"));
                ui->tbMsgInfo->setItem(i,2, new QTableWidgetItem(pMsgInfo->csrc_mac));
                ui->tbMsgInfo->setItem(i,3, new QTableWidgetItem(pMsgInfo->cdst_mac));
                break;
            case PROTOAPPTYPE_GOOSE:
                ui->tbMsgInfo->setItem(i,1, new QTableWidgetItem("GOOSE"));
                ui->tbMsgInfo->setItem(i,2, new QTableWidgetItem(pMsgInfo->csrc_mac));
                ui->tbMsgInfo->setItem(i,3, new QTableWidgetItem(pMsgInfo->cdst_mac));
                break;
            default:
                ui->tbMsgInfo->setItem(i,1, new QTableWidgetItem("OTHER"));
                ui->tbMsgInfo->setItem(i,2, new QTableWidgetItem(pMsgInfo->csrc_mac));
                ui->tbMsgInfo->setItem(i,3, new QTableWidgetItem(pMsgInfo->cdst_mac));
                break;
        }

     }
}


//设置波形展示样式
void MainWindow::setWaveStyle()
{
    //显示采样数据的波形
    //设置波形属性：可缩放、移动等
//    ui->wdtWave->setInteractions(QCP::iRangeDrag | QCP::iRangeZoom | QCP::iSelectAxes |
//                                 QCP::iSelectLegend | QCP::iSelectPlottables);
    //ui->wdtWave->xAxis->setLabel("X");
    //ui->wdtWave->yAxis->setLabel("Y");
//    ui->wdtWave->legend->setVisible(true);

//    ui->wdtWave->setInteractions(QCP::iRangeZoom);

    //隐藏坐标轴上的刻度值
    //ui->wdtWave->yAxis->setTickLabels(false);

    //设置在上部显示x轴
    ui->wdtWave->xAxis2->setVisible(true);
    ui->wdtWave->xAxis->setVisible(false);

    //设置y轴坐标反转
    ui->wdtWave->yAxis->setRangeReversed(true);

    //设置坐标轴显示范围,否则我们只能看到默认的范围
    ui->wdtWave->xAxis->setRange(0,ui->wdtWave->width());
    ui->wdtWave->xAxis2->setRange(0,ui->wdtWave->width());
    ui->wdtWave->yAxis->setRange(0,ui->wdtWave->height()*100);

    /* 测试划线
    QVector<double> z(2), w(2);
    z[0] = 0;
    z[1] = 100;
    w[0] = 4000;
    w[1] = 5000;
    ui->wdtWave->addGraph();
    ui->wdtWave->graph()->setData(z,w);
    */
}
void MainWindow::xAxisChanged(QCPRange range)
{
    logPrint(QString("xAxisChanged,size:%1").arg(range.size()));
//  ui->horizontalScrollBar->setValue(qRound(range.center()*100.0)); // adjust position of scroll bar slider
//  ui->horizontalScrollBar->setPageStep(qRound(range.size()*100.0)); // adjust size of scroll bar slider
}

void MainWindow::yAxisChanged(QCPRange range)
{
    logPrint(QString("yAxisChanged,size:%1").arg(range.size()));
//  ui->verticalScrollBar->setValue(qRound(-range.center()*100.0)); // adjust position of scroll bar slider
//  ui->verticalScrollBar->setPageStep(qRound(range.size()*100.0)); // adjust size of scroll bar slider
}

void MainWindow::horzScrollBarChanged(int value)
{
//    logPrint(QString("horzScrollBarChanged,value:%1").arg(value));
    double start = ui->wdtWave->width()*(value/100.0);//这个地方的width应该换成采样点的个数，一个采样点对应一个像素
    double end = start + ui->wdtWave->width();
    ui->wdtWave->xAxis2->setRange(start, end);
    ui->wdtWave->xAxis->setRange(start, end);
    ui->wdtWave->replot();
}

void MainWindow::vertScrollBarChanged(int value)
{
//    logPrint(QString("vertScrollBarChanged,value:%1").arg(value));
    double start = ui->wdtWave->height()*(value/100.0);//这个地方的height应换成各通道加起来的高度
    double end = start + ui->wdtWave->height();
    ui->wdtWave->yAxis->setRange(start*100, end*100);
    ui->wdtWave->replot();
}

//鼠标点击事件
void MainWindow::mousePress(QMouseEvent* event)
{
    double pos_x = ui->wdtWave->xAxis2->pixelToCoord(event->x());
    double pos_y = ui->wdtWave->yAxis->pixelToCoord(event->y());
    logPrint(QString("鼠标点击x:%1,y%2").arg(pos_x).arg(pos_y));
    refreshMouseLine(pos_x);
}

//鼠标滚轮事件
void MainWindow::mouseWheel(QWheelEvent* event)
{
    //logPrint(QString("鼠标滚轮").arg(pos_x).arg(pos_y));
}

//画采样值波形图
void MainWindow::drawSVWaveWindow(CAPCONNECTINFO* pConnection)
{
    //准备采样数据
    MAP_CAPMSGINFO *pMapCapMsgInfo = &pConnection->map_capmsginfo;
    int smpCount = pMapCapMsgInfo->size();
    QVector<double> x(smpCount), y(smpCount);
    SMV_INFO_STRUCT *pSMVInfo;
    ASDU_INFO_STRUCT *pAsdu;
    CAPMSGGININFO* pMsgInfo;
    std::map <int, CAPMSGGININFO* >::iterator iter;
    int smp_index=0; //采样点序号
    int chn_index=0; //通道序号
    int chn_count=0; //通道个数

    //获取通道个数
    iter = pMapCapMsgInfo->begin();
    if(iter == pMapCapMsgInfo->end())
        return;
    pMsgInfo = iter->second;
    pSMVInfo = (SMV_INFO_STRUCT*)(pMsgInfo->pparserdstruct);
    chn_count = pSMVInfo->p_asdu_info_struct->n_data_num;

    //画所有通道波形图
    for(chn_index = 0; chn_index < chn_count; chn_index++)
    {

        for(smp_index=0, iter = pMapCapMsgInfo->begin(); iter!=pMapCapMsgInfo->end();iter++, smp_index++)
        {
            pMsgInfo = iter->second;
            pSMVInfo = (SMV_INFO_STRUCT*)(pMsgInfo->pparserdstruct);
            pAsdu = pSMVInfo->p_asdu_info_struct;
            x[smp_index] = smp_index;
            y[smp_index] = pAsdu->p_smv_data_struct[chn_index].n_value/10.0 + chn_index*2000;
//            if(smp_index > ui->wdtWave->xAxis->range().upper)
//                break;
        }
        ui->wdtWave->addGraph();
        ui->wdtWave->graph()->setData(x,y,true);

    }
    ui->wdtWave->replot();


    //图上添加文字块
    QCPItemText *phaseTracerText = new QCPItemText(ui->wdtWave);//构造一个文本
    phaseTracerText->position->setType(QCPItemPosition::ptAxisRectRatio);//设置文本坐标解析方式，前文中有提到QCPItemPosition类的PositionType枚举
    phaseTracerText->setPositionAlignment(Qt::AlignRight | Qt::AlignBottom);//设置位置在矩形区域的位置
    phaseTracerText->position->setCoords(1.0, 0.95); // 设置位置，注意第三行代码的枚举类型和这儿的值解析方式有关系
    phaseTracerText->setText("Points of fixed\nphase define\nphase velocity vp");//文本描述
    phaseTracerText->setTextAlignment(Qt::AlignLeft);//设置文本在矩形区域的位置
    phaseTracerText->setFont(QFont(font().family(), 9));//设置文本的字体
    phaseTracerText->setPadding(QMargins(4, 4, 4, 4));//设置文本所在矩形的margins
    phaseTracerText->setPen(QPen(Qt::black));//设置
    ui->wdtWave->replot();
}

//画采样值波形图（Qml插件方式）
void MainWindow::drawSVWaveWindowByQml(CAPCONNECTINFO* pConnection)
{
    //准备采样数据
    MAP_CAPMSGINFO *pMapCapMsgInfo = &pConnection->map_capmsginfo;
    int smpCount = pMapCapMsgInfo->size();
    QVector<double> x(smpCount), y(smpCount);
    SMV_INFO_STRUCT *pSMVInfo;
    ASDU_INFO_STRUCT *pAsdu;
    CAPMSGGININFO* pMsgInfo;
    std::map <int, CAPMSGGININFO* >::iterator iter;
    int smp_index=0; //采样点序号
    int chn_index=0; //通道序号
    int chn_count=0; //通道个数

    //获取通道个数
    iter = pMapCapMsgInfo->begin();
    if(iter == pMapCapMsgInfo->end())
        return;
    pMsgInfo = iter->second;
    pSMVInfo = (SMV_INFO_STRUCT*)(pMsgInfo->pparserdstruct);
    chn_count = pSMVInfo->p_asdu_info_struct->n_data_num;

//    if (m_qwWaveData)
//        m_qwWaveData->reset();

    //画所有通道波形图
    for(chn_index = 0; chn_index < chn_count; chn_index++)
    {
        for(smp_index=0, iter = pMapCapMsgInfo->begin(); iter!=pMapCapMsgInfo->end();iter++, smp_index++)
        {

            pMsgInfo = iter->second;
            pSMVInfo = (SMV_INFO_STRUCT*)(pMsgInfo->pparserdstruct);
            pAsdu = pSMVInfo->p_asdu_info_struct;

            x[smp_index] = smp_index;
            qreal y_val = pAsdu->p_smv_data_struct[chn_index].n_value / 10.0;
            y[smp_index] = pAsdu->p_smv_data_struct[chn_index].n_value/10.0;// + chn_index*2000;

            m_qwWaveData->append_x(chn_index, smp_index);
            m_qwWaveData->append_y(chn_index, y_val);
        }
    }

    // 波形图
    QTabWidget *tabw = ui->tabWidget;
    int idxQuickWidget = -1;
    for (int i = 0; i < tabw->count(); i++){
        if (tabw->tabText(i) == "波形分析"){
            idxQuickWidget = i;
            break;
        }
    }
    if (!m_qwWaveAnal){
        m_qwWaveAnal = new QQuickWidget();
        m_qwWaveAnal->setObjectName(QStringLiteral("qwWaveAnal"));
        m_qwWaveAnal->setResizeMode(QQuickWidget::SizeRootObjectToView );
        m_qwWaveAnal->setSource(QUrl("qrc:/quick/WSWaveChartAnal.qml"));
        m_qwWaveAnal->rootContext()->setContextProperty("waveModel", m_qwWaveData);
    }
    if (idxQuickWidget < 0)
        idxQuickWidget = tabw->addTab(m_qwWaveAnal, QStringLiteral("波形分析"));

    tabw->setCurrentIndex(idxQuickWidget);
}

//输出日志到下面的日志窗口
void MainWindow::logPrint(const QString &logStr)
{
    ui->textLog->append(logStr);
}

//表格中某一条报文的点击事件处理，在报文解析窗口显示解析后的信息
void MainWindow::on_tbMsgInfo_clicked(const QModelIndex &index)
{
    //拿到报文序号
    QTableWidgetItem *pTblItem = ui->tbMsgInfo->item(index.row(), 0);
    int msgKey = pTblItem->text().toInt();

    //找到对应的链路
    CAPCONNECTINFO* pConnection;
    QTreeWidgetItem *pTreeItem = ui->treeAllMsg->currentItem();
    int conKey = pTreeItem->text(2).toInt(); //map中的key值
    pConnection = m_anakit->m_cappackagesmnger.m_mapcapconnectionfo[conKey];

    //找到之前解析的结果
    CAPMSGGININFO *pMsgInfo = pConnection->map_capmsginfo[msgKey];

    //输出解析内容
    QString parseInfo;
    MMS_INFO_STRUCT *pmmsInfo;
    SMV_INFO_STRUCT *psmvInfo;
    GOOSE_INFO_STRUCT* pGOOSEInfo;
    switch(pMsgInfo->napptype)
    {
    case PROTOAPPTYPE_MMS:
        pmmsInfo = (MMS_INFO_STRUCT*)pMsgInfo->pparserdstruct;
        parseInfo.sprintf("src ip: %s \ndst ip:%s \ninvokeid: %d \n类型: %s \nmms服务: %s\n",
                    pMsgInfo->csrc_ip, //pInfo中的ip没有赋值，只能用上一层pMsgInfo中的地址
                    pMsgInfo->cdst_ip,
                    pmmsInfo->n_invoke_id,
                    pmmsInfo->c_pdu_type,
                    pmmsInfo->c_service_type);
        break;
    case PROTOAPPTYPE_SMV92:
        psmvInfo = (SMV_INFO_STRUCT*)pMsgInfo->pparserdstruct;
        parseInfo.sprintf("src mac: %s \ndst mac:%s \nAPPID: %04X \nSVID:%s\n采样序号: %d \n",
                    pMsgInfo->csrc_mac,
                    pMsgInfo->cdst_mac,
                    psmvInfo->n_app_id,
                    psmvInfo->p_asdu_info_struct->c_svID,
                    psmvInfo->p_asdu_info_struct->n_smpCnt);

        break;
    case PROTOAPPTYPE_GOOSE:
        pGOOSEInfo = (GOOSE_INFO_STRUCT*)pMsgInfo->pparserdstruct;
        parseInfo.sprintf("src mac: %s \ndst mac:%s \nAPPID: %04X \nGOID: %s \nstNum:%d \nsqNum:%d \n",
                    pMsgInfo->csrc_mac,
                    pMsgInfo->cdst_mac,
                    pGOOSEInfo->n_app_id,
                    pGOOSEInfo->c_goID,
                    pGOOSEInfo->n_stNum,
                    pGOOSEInfo->n_sqNum);
        break;
    default:
        parseInfo.append("暂不支持");
        break;
        //其他协议暂不显示
    }

    ui->textMsgInfo->clear();
    ui->textMsgInfo->append(parseInfo);
}

