#define LOG_MODULE PacketLogModuleStreamLayer

#include "ArpCpuLayer.h"
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

ArpCpuLayer::ArpCpuLayer(uint16_t port_num, uint16_t ether_type) : Layer()
{
	m_DataLen = sizeof(arpcpuhdr);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	arpcpuhdr* arpcpu_hdr = (arpcpuhdr*)m_Data;
	arpcpu_hdr->port_num = htons(port_num);
	arpcpu_hdr->ether_type = htons(ether_type);
	m_Protocol = ARPCPU;
}

void ArpCpuLayer::parseNextLayer()
{
	if (m_DataLen <= sizeof(arpcpuhdr))
		return;

	arpcpuhdr* arpcpu_hdr = getArpCpuHeader();
	uint16_t port_num = ntohs(arpcpu_hdr->port_num);
	uint16_t ether_type = ntohs(arpcpu_hdr->ether_type);

	switch (ether_type)
	{
	case PCPP_ETHERTYPE_IP:
		m_NextLayer = new IPv4Layer(m_Data + sizeof(arpcpuhdr), m_DataLen - sizeof(arpcpuhdr), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_IPV6:
		m_NextLayer = new IPv6Layer(m_Data + sizeof(arpcpuhdr), m_DataLen - sizeof(arpcpuhdr), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_ARP:
		m_NextLayer = new ArpLayer(m_Data + sizeof(arpcpuhdr), m_DataLen - sizeof(arpcpuhdr), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_VLAN:
		m_NextLayer = new VlanLayer(m_Data + sizeof(arpcpuhdr), m_DataLen - sizeof(arpcpuhdr), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_PPPOES:
		m_NextLayer = new PPPoESessionLayer(m_Data + sizeof(arpcpuhdr), m_DataLen - sizeof(arpcpuhdr), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_PPPOED:
		m_NextLayer = new PPPoEDiscoveryLayer(m_Data + sizeof(arpcpuhdr), m_DataLen - sizeof(arpcpuhdr), this, m_Packet);
		break;
	case PCPP_ETHERTYPE_MPLS:
		m_NextLayer = new MplsLayer(m_Data + sizeof(arpcpuhdr), m_DataLen - sizeof(arpcpuhdr), this, m_Packet);
		break;
	default:
		m_NextLayer = new PayloadLayer(m_Data + sizeof(arpcpuhdr), m_DataLen - sizeof(arpcpuhdr), this, m_Packet);
	}
}

void ArpCpuLayer::computeCalculateFields()
{
	if (m_NextLayer == NULL)
		return;

	switch (m_NextLayer->getProtocol())
	{
		case IPv4:
			getArpCpuHeader()->ether_type = htons(PCPP_ETHERTYPE_IP);
			break;
		case IPv6:
			getArpCpuHeader()->ether_type = htons(PCPP_ETHERTYPE_IPV6);
			break;
		case ARP:
			getArpCpuHeader()->ether_type = htons(PCPP_ETHERTYPE_ARP);
			break;
		case VLAN:
			getArpCpuHeader()->ether_type = htons(PCPP_ETHERTYPE_VLAN);
			break;
		default:
			return;
	}
}

std::string ArpCpuLayer::toString()
{
	std::ostringstream port_num_ostream;
	port_num_ostream << ntohs(getArpCpuHeader()->port_num);
	std::ostringstream ether_type_ostream;
	ether_type_ostream << ntohs(getArpCpuHeader()->ether_type);

	return "ARPCPU Layer, Port Num: " + port_num_ostream.str() + ", Ether Type: " + ether_type_ostream.str();
}

} // namespace pcpp
