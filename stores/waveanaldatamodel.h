#ifndef WAVEANALDATAMODEL_H
#define WAVEANALDATAMODEL_H

#include <QDate>
#include <QObject>

#define QML_PROPERTY(type, name, \
    READ, getter, \
    WRITE, setter, \
    NOTIFY, notifyer\
    )  \
    type m_##name; \
    Q_PROPERTY(type name READ getter WRITE setter NOTIFY notifyer) \
    public: type getter##() const { return m_##name; } \
    public Q_SLOTS: void setter##(type arg) { if (m_##name != arg) {m_##name = arg; emit notifyer##(arg);}} \
    Q_SIGNALS:  \
        void notifyer##(type arg); \
    private:

// //////////////////
/// \brief The WaveAnalDataModel class
///
///
///

class WaveAnalDataModel : public QObject
{
    Q_OBJECT

    QML_PROPERTY(QString, test, READ, test, WRITE, setTest, NOTIFY, testChanged)
    QML_PROPERTY(QString, mac2, READ, mac2, WRITE, setMac2, NOTIFY, mac2Changed)
    QML_PROPERTY(QString, ip2, READ, ip2, WRITE, setIp2, NOTIFY, ip2Changed)
    QML_PROPERTY(QString, appid, READ, appid, WRITE, setAppid, NOTIFY, appidChanged)

public:
    explicit WaveAnalDataModel(QObject *parent = 0);

    Q_INVOKABLE void reset();

    Q_INVOKABLE QList<qreal> x_data(int idx);
    Q_INVOKABLE QList<qreal> y_data(int idx);
    Q_INVOKABLE void append_x(int idx, qreal x);
    Q_INVOKABLE void append_y(int idx, qreal y);

    Q_INVOKABLE int chn_count() { return m_x.count(); }
    Q_INVOKABLE int data_length() { if (m_x.count() > 0) return m_x.at(0).length(); else return 0; }

    Q_INVOKABLE int rows() { return m_x.count(); }
    Q_INVOKABLE int cols() { if (m_x.count() > 0) return m_x.at(0).length(); else return 0; }

    Q_INVOKABLE void buildData(int rows, int nMaxValue, int samplePoints);
    Q_INVOKABLE void queenNewData(int nMaxValue, int samplePoints);

    Q_INVOKABLE QList<int> random(int nMax, int nCount);

signals:
    void xChanged(QList<QList<qreal> > &arg);
    void yChanged(QList<QList<qreal> > &arg);

private:
    QList<QList<qreal> > m_x;
    QList<QList<qreal> >m_y;

};

#endif // WAVEANALDATAMODEL_H
