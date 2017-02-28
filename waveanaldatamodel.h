#ifndef WAVEANALDATAMODEL_H
#define WAVEANALDATAMODEL_H

#include <QDate>
#include <QObject>

class WaveAnalDataModel : public QObject
{
    Q_OBJECT
    QString m_test;

    Q_PROPERTY(QString test READ test WRITE setTest NOTIFY testChanged)

public:
    explicit WaveAnalDataModel(QObject *parent = 0);

    QString test() const
    {
        return m_test;
    }

    Q_INVOKABLE void reset();

    Q_INVOKABLE QList<qreal> x_data(int idx);
    Q_INVOKABLE void append_x(int idx, qreal x);

    Q_INVOKABLE QList<qreal> y_data(int idx);
    Q_INVOKABLE void append_y(int idx, qreal y);

    Q_INVOKABLE int chn_count() { return m_x.count(); }

    Q_INVOKABLE int rows() { return m_x.count(); }

    Q_INVOKABLE int data_length() { if (m_x.count() > 0) return m_x.at(0).length(); else return 0; }

    Q_INVOKABLE int cols() { if (m_x.count() > 0) return m_x.at(0).length(); else return 0; }

    QList<int> random(int nMax, int nCount);
    Q_INVOKABLE void buildData(int rows, int nMaxValue, int samplePoints);

    Q_INVOKABLE void queenNewData(int nMaxValue, int samplePoints);

signals:
    void testChanged(QString arg);
    void xChanged(QList<QList<qreal> > &arg);
    void yChanged(QList<QList<qreal> > &arg);

public slots:
    void setTest(QString arg)
    {
        if (m_test != arg) {
            m_test = arg;
            emit testChanged(arg);
        }
    }

private:
    QList<QList<qreal> > m_x;
    QList<QList<qreal> >m_y;

};

#endif // WAVEANALDATAMODEL_H
