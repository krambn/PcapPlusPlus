#ifndef PACKETPP_STREAM_LAYER
#define PACKETPP_STREAM_LAYER

#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @struct streamhdr
	 * Represents an STREAM protocol header
	 */
#pragma pack(push,1)
	struct streamhdr {
		/** Stream */
		uint16_t streamId;
		/** EtherType */
		uint16_t etherType;
	};
#pragma pack(pop)


	/**
	 * @class StreamLayer
	 * Represents an STREAM (Stream) protocol layer
	 */
	class StreamLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to ether_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		StreamLayer(uint8_t* data, size_t dataLen, Packet* packet) : Layer(data, dataLen, NULL, packet) { m_Protocol = STREAM; }

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to ether_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		StreamLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = STREAM; }

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref streamhdr)
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
		StreamLayer(uint16_t streamId, uint16_t etherType);

    ~StreamLayer() {}

		/**
		 * Get a pointer to the STREAM header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref streamhdr
		 */
		inline streamhdr* getStreamHeader() { return (streamhdr*)m_Data; };

		// implement abstract methods

		/**
		 * Currently identifies the following next layers: DnsLayer, DhcpLayer, VxlanLayer, SipRequestLayer, SipResponseLayer.
		 * Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of @ref streamhdr
		 */
		inline size_t getHeaderLen() { return sizeof(streamhdr); }

		/**
		 * Calculate @ref streamhdr#headerChecksum field
		 */
		void computeCalculateFields();

		std::string toString();

		OsiModelLayer getOsiModelLayer() { return OsiModelNetworkLayer; }
	};

} // namespace pcpp

#endif /* PACKETPP_STREAM_LAYER */
