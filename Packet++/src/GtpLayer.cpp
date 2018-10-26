#define LOG_MODULE PacketLogModuleGtpLayer

#include "GtpLayer.h"
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

GtpLayer::GtpLayer(uint8_t flags, uint8_t type, uint16_t length, uint32_t teid, uint32_t seq)
{
	bool hasTeid = (flags & 0x8) != 0;
	if (hasTeid){
		m_DataLen = sizeof(gtphdr_teid);
		m_Data = new uint8_t[m_DataLen];
		memset(m_Data, 0, m_DataLen);
		gtphdr_teid* gtpHdr = (gtphdr_teid*)m_Data;
		gtpHdr->flags = flags;
		gtpHdr->type = type;
		gtpHdr->length = htons(length);
		gtpHdr->teid = htonl(teid);
		gtpHdr->seq = htonl(seq);
	}else{
		m_DataLen = sizeof(gtphdr);
		m_Data = new uint8_t[m_DataLen];
		memset(m_Data, 0, m_DataLen);
		gtphdr* gtpHdr = (gtphdr*)m_Data;
		gtpHdr->flags = flags;
		gtpHdr->type = type;
		gtpHdr->length = htons(length);
		//gtpHdr->teid = htonl(teid);
		gtpHdr->seq = htonl(seq);
	}
	m_Protocol = GTP;
}

void GtpLayer::parseNextLayer()
{
	if (m_DataLen <= getHeaderLen())
		return;

	m_NextLayer = new PayloadLayer(m_Data + getHeaderLen(),  m_DataLen - getHeaderLen(), this, m_Packet);
}

void GtpLayer::computeCalculateFields()
{
	gtphdr* gtpHdr = getGtpHeader();
    // length excluding the first 4 bytes
	gtpHdr->length = htons(m_DataLen - 4);
}

bool GtpLayer::hasTeid()
{
       return (getGtpHeader()->flags & 0x08) != 0; 
}

std::string GtpLayer::toString()
{
	std::ostringstream ss;
	ss << "GTP layer, Version: " << (getGtpHeader()->flags >> 5);
	ss << ", P: " << (((getGtpHeader()->flags & 0x10) == 0) ? false : true);
	ss << ", T: " << hasTeid();
	ss << ", Type: " << (uint32_t)getGtpHeader()->type;
	ss << ", Length: " << ntohs(getGtpHeader()->length);
	if (hasTeid()){
		ss << ", TEID: " << ntohl(getGtpteidHeader()->teid);
		ss << ", Sequence number: " << ntohl(getGtpteidHeader()->seq);
	}else{
		ss << ", Sequence number: " << ntohl(getGtpHeader()->seq);
	}
	return ss.str();
}

} // namespace pcpp
