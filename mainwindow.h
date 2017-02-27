#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "anakit.h"

#include "qcustomplot.h"

namespace Ui {
class MainWindow;
}

class QQuickWidget;
class WaveAnalDataModel;
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    void setTreeMessageAll(CCapPackagesMnger *pPackMnger);

    //输出日志到下面的日志窗口
    void logPrint(const QString &logStr);

    //把链路中所有报文概要显示到表格中
    void fillMessageTable(CAPCONNECTINFO* pConnection);


private slots:
    void setLogView(bool view);

    void on_actionLogView_triggered();

    void on_actionOpen_triggered();

    void on_treeAllMsg_clicked(const QModelIndex &index);

    void drawSVWaveWindow(CAPCONNECTINFO* pConnection);

    void drawSVWaveWindowByQml(CAPCONNECTINFO* pConnection);

    void on_tbMsgInfo_clicked(const QModelIndex &index);

    void xAxisChanged(QCPRange range);

    void yAxisChanged(QCPRange range);

    void horzScrollBarChanged(int value);

    void vertScrollBarChanged(int value);

    void mousePress(QMouseEvent* event);

    void mouseWheel(QWheelEvent* event);

private:

    //重画定位线，传入鼠标点击位置的x轴坐标
    void refreshMouseLine(double mousePos);

    void setupOtherUi();

    QCPGraph *m_mouseGraph; //鼠标点击位置的定位线

    QQuickWidget *m_qwWaveAnal; // Qml波形分析图
    WaveAnalDataModel *m_qwWaveData; // Qml波形分析数据

    double m_SampleNum;  //采样点个数
    double m_chnlNum;   //通道个数
    double m_maxSampleVal;  //所有通道中的最大采样点值，用于设置显示比例

    void setWaveStyle();

    Ui::MainWindow *ui;

	AnaKit *m_anakit;
};

#endif // MAINWINDOW_H
