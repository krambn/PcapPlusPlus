#define LOG_MODULE PacketLogModuleStreamLayer

#include "StreamLayer.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "ArpLayer.h"
#include "VlanLayer.h"
#include "PPPoELayer.h"
#include "MplsLayer.h"
#include "Logger.h"
#include <string.h>
#include <sstream>
#if defined(WIN32) || defined(WINx64) || defined(PCAPPP_MINGW_ENV)
#include <winsock2.h>
#elif LINUX
#include <in.h>
#elif MAC_OS_X
#include <arpa/inet.h>
#endif

namespace pcpp
{

StreamLayer::StreamLayer(uint16_t streamId, uint16_t etherType) : Layer()
{
	m_DataLen = sizeof(streamhdr);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	streamhdr* streamHdr = (streamhdr*)m_Data;
	streamHdr->streamId = htons(streamId);
	streamHdr->etherType = htons(etherType);
	m_Protocol = STREAM;
}

void StreamLayer::parseNextLayer()
{
	if (m_DataLen <= sizeof(streamhdr))
		return;

	streamhdr* streamHder = getStreamHeader();
	uint16_t streamId = ntohs(streamHder->streamId);
	uint16_t etherType = ntohs(streamHder->etherType);

	switch (etherType)
	{
	case PCPP_ETHERTYPE_IP:
		m_NextLayer = new IPv4Layer(m_Data + sizeof(streamhdr), m_DataLen - sizeof(streamhdr), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_IPV6:
		m_NextLayer = new IPv6Layer(m_Data + sizeof(streamhdr), m_DataLen - sizeof(streamhdr), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_ARP:
		m_NextLayer = new ArpLayer(m_Data + sizeof(streamhdr), m_DataLen - sizeof(streamhdr), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_VLAN:
		m_NextLayer = new VlanLayer(m_Data + sizeof(streamhdr), m_DataLen - sizeof(streamhdr), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_PPPOES:
		m_NextLayer = new PPPoESessionLayer(m_Data + sizeof(streamhdr), m_DataLen - sizeof(streamhdr), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_PPPOED:
		m_NextLayer = new PPPoEDiscoveryLayer(m_Data + sizeof(streamhdr), m_DataLen - sizeof(streamhdr), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_MPLS:
		m_NextLayer = new MplsLayer(m_Data + sizeof(streamhdr), m_DataLen - sizeof(streamhdr), this, m_Packet);
		break;
	default:
		m_NextLayer = new PayloadLayer(m_Data + sizeof(streamhdr), m_DataLen - sizeof(streamhdr), this, m_Packet);
	}
}

void StreamLayer::computeCalculateFields()
{
	if (m_NextLayer == NULL)
		return;

	switch (m_NextLayer->getProtocol())
	{
		case IPv4:
			getStreamHeader()->etherType = htons(PCPP_ETHERTYPE_IP);
			break;
		case IPv6:
			getStreamHeader()->etherType = htons(PCPP_ETHERTYPE_IPV6);
			break;
		case ARP:
			getStreamHeader()->etherType = htons(PCPP_ETHERTYPE_ARP);
			break;
		case VLAN:
			getStreamHeader()->etherType = htons(PCPP_ETHERTYPE_VLAN);
			break;
		default:
			return;
	}
}

std::string StreamLayer::toString()
{
	std::ostringstream srcPortStream;
	srcPortStream << ntohs(getStreamHeader()->streamId);
	std::ostringstream dstPortStream;
	dstPortStream << ntohs(getStreamHeader()->etherType);

	return "STREAM Layer, Stream Id: " + srcPortStream.str() + ", Ether Type: " + dstPortStream.str();
}

} // namespace pcpp
