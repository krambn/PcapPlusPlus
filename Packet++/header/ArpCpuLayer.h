#ifndef PACKETPP_ARPCPU_LAYER
#define PACKETPP_ARPCPU_LAYER

#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @struct arpcpuhdr
	 * Represents an ARPCPU protocol header
	 */
#pragma pack(push,1)
	struct arpcpuhdr {
		/** port number */
		uint16_t port_num;
		/** EtherType */
		uint16_t ether_type;
	};
#pragma pack(pop)


	/**
	 * @class StreamLayer
	 * Represents an STREAM (Stream) protocol layer
	 */
	class ArpCpuLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to ether_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		ArpCpuLayer(uint8_t* data, size_t dataLen, Packet* packet) : Layer(data, dataLen, NULL, packet) { m_Protocol = ARPCPU; }

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to ether_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		ArpCpuLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = ARPCPU; }

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref arpcpuhdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
//		StreamLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = STREAM; }

		/**
		 * A constructor that allocates a new STREAM header with source and destination ports
		 * @param[in] portSrc Source STREAM port address
		 * @param[in] portDst Destination STREAM port
		 */
		ArpCpuLayer(uint16_t port_num, uint16_t ether_type);

    ~ArpCpuLayer() {}

		/**
		 * Get a pointer to the STREAM header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref arpcpuhdr
		 */
		inline arpcpuhdr* getArpCpuHeader() { return (arpcpuhdr*)m_Data; };

		// implement abstract methods

		/**
		 * Currently identifies the following next layers: DnsLayer, DhcpLayer, VxlanLayer, SipRequestLayer, SipResponseLayer.
		 * Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of @ref arpcpuhdr
		 */
		inline size_t getHeaderLen() { return sizeof(arpcpuhdr); }

		/**
		 * Calculate @ref arpcpuhdr#headerChecksum field
		 */
		void computeCalculateFields();

		std::string toString();

		OsiModelLayer getOsiModelLayer() { return OsiModelNetworkLayer; }
	};

} // namespace pcpp

#endif /* PACKETPP_ARPCPU_LAYER */
