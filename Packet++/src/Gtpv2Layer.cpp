#define LOG_MODULE PacketLogModuleGtpv2Layer

#include "Gtpv2Layer.h"
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

Gtpv2Layer::Gtpv2Layer(uint8_t flags, uint8_t type, uint16_t length, uint32_t teid, uint32_t seq)
{
	bool hasTeid = (flags & 0x8) != 0;
	if (hasTeid){
		m_DataLen = sizeof(gtpv2hdr_teid);
		m_Data = new uint8_t[m_DataLen];
		memset(m_Data, 0, m_DataLen);
		gtpv2hdr_teid* gtpv2Hdr = (gtpv2hdr_teid*)m_Data;
		gtpv2Hdr->flags = flags;
		gtpv2Hdr->type = type;
		gtpv2Hdr->length = htons(length);
		gtpv2Hdr->teid = htonl(teid);
		gtpv2Hdr->seq = htonl(seq);
	}else{
		m_DataLen = sizeof(gtpv2hdr);
		m_Data = new uint8_t[m_DataLen];
		memset(m_Data, 0, m_DataLen);
		gtpv2hdr* gtpv2Hdr = (gtpv2hdr*)m_Data;
		gtpv2Hdr->flags = flags;
		gtpv2Hdr->type = type;
		gtpv2Hdr->length = htons(length);
		//gtpv2Hdr->teid = htonl(teid);
		gtpv2Hdr->seq = htonl(seq);
	}
	m_Protocol = GTPv2;
}

void Gtpv2Layer::parseNextLayer()
{
	if (m_DataLen <= getHeaderLen())
		return;

	m_NextLayer = new PayloadLayer(m_Data + getHeaderLen(),  m_DataLen - getHeaderLen(), this, m_Packet);
}

void Gtpv2Layer::computeCalculateFields()
{
	gtpv2hdr* gtpv2Hdr = getGtpv2Header();
    // length excluding the first 4 bytes
	gtpv2Hdr->length = htons(m_DataLen - 4);
}

bool Gtpv2Layer::hasTeid()
{
       return (getGtpv2Header()->flags & 0x08) != 0; 
}

std::string Gtpv2Layer::toString()
{
	std::ostringstream ss;
	ss << "GTPv2 layer, Version: " << (getGtpv2Header()->flags >> 5);
	ss << ", P: " << (((getGtpv2Header()->flags & 0x10) == 0) ? false : true);
	ss << ", T: " << hasTeid();
	ss << ", Type: " << (uint32_t)getGtpv2Header()->type;
	ss << ", Length: " << ntohs(getGtpv2Header()->length);
	if (hasTeid()){
		ss << ", TEID: " << ntohl(getGtpv2teidHeader()->teid);
		ss << ", Sequence number: " << ntohl(getGtpv2teidHeader()->seq);
	}else{
		ss << ", Sequence number: " << ntohl(getGtpv2Header()->seq);
	}
	return ss.str();
}

} // namespace pcpp
