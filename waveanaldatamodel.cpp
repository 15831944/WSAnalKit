#include "waveanaldatamodel.h"

WaveAnalDataModel::WaveAnalDataModel(QObject *parent)
    : QObject(parent), m_test(QStringLiteral("mac address"))
{

}

void WaveAnalDataModel::reset()
{
    m_x.clear();
    m_y.clear();
}

QList<qreal> WaveAnalDataModel::x_data(int idx)
{
    return m_x.at(idx);
}

void WaveAnalDataModel::append_x(int idx, qreal value)
{
    if (idx + 1 > m_x.count())
    {
        for (int i = m_x.count(); i < idx + 1; ++i)
            m_x.push_back(QList<qreal>());
    }
    m_x[idx].append(value);
    emit xChanged(m_x);
}

QList<qreal> WaveAnalDataModel::y_data(int idx)
{
    return m_y.at(idx);
}

void WaveAnalDataModel::append_y(int idx, qreal value)
{
    if (idx + 1 > m_y.count())
    {
        for (int i = m_y.count(); i < idx + 1; ++i)
            m_y.push_back(QList<qreal>());
    }
    m_y[idx].append(value);
    emit yChanged(m_y);
}
