#define LOG_MODULE PacketLogModuleGtpv1Layer

#include "Gtpv1Layer.h"
#include "UdpLayer.h"
#include "IpUtils.h"
#include "PayloadLayer.h"
#include "DnsLayer.h"
#include "DhcpLayer.h"
#include "VxlanLayer.h"
#include "SipLayer.h"
#include "Logger.h"
#include <string.h>
#include <sstream>

namespace pcpp
{

Gtpv1Layer::Gtpv1Layer(uint8_t type, uint16_t length, uint32_t teid)
{
	m_DataLen = sizeof(gtpv1hdr);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	gtpv1hdr* gtpv1Hdr = (gtpv1hdr*)m_Data;
  gtpv1Hdr->version = 1;
  gtpv1Hdr->pt = 1;
	gtpv1Hdr->type = type;
	gtpv1Hdr->length = htons(length);
	gtpv1Hdr->teid = htonl(teid);
	m_Protocol = GTPv1;
}

void Gtpv1Layer::parseNextLayer()
{
	if (m_DataLen <= getHeaderLen())
		return;

	m_NextLayer = new PayloadLayer(m_Data + getHeaderLen(),  m_DataLen - getHeaderLen(), this, m_Packet);
}

void Gtpv1Layer::computeCalculateFields()
{
  ((void)0);
}


std::string Gtpv1Layer::toString()
{
	std::ostringstream ss;
	ss << "GTPv1 layer, Version: " << (getGtpv1Header()->version);
	ss << ", Type: " << (uint32_t)getGtpv1Header()->type;
	ss << ", Length: " << ntohs(getGtpv1Header()->length);
  ss << ", TEID: " << ntohl(getGtpv1Header()->teid);
	return ss.str();
}

} // namespace pcpp
