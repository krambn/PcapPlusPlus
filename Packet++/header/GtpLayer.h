#ifndef PACKETPP_GTP_LAYER
#define PACKETPP_GTP_LAYER

#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @struct gtphdr
	 * Represents an GTP protocol header
	 */
#pragma pack(push,1)
	struct gtphdr {
		/** 3 bit Version piggybacking flag, TEID flag, Spare */
		uint8_t flags;
		/** Message type */
		uint8_t type;
		/** Message length */
		uint16_t length;
		/** Sequence number 24 bits*/
		uint32_t seq;
	};

	struct gtphdr_teid {
		/** 3 bit Version piggybacking flag, TEID flag, Spare */
		uint8_t flags;
		/** Message type */
		uint8_t type;
		/** Message length */
		uint16_t length;
		/** only present if TEID flag = 1 */
		uint32_t teid;
		/** Sequence number 24 bits*/
		uint32_t seq;
	};
#pragma pack(pop)


	/**
	 * @class GtpLayer
	 * Represents an UDP (User Datagram Protocol) protocol layer
	 */
	class GtpLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref gtphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GtpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet){}

		/**
		 * A constructor that allocates a new UDP header with source and destination ports
		 * @param[in] flags version and flags
		 * @param[in] type message type
		 * @param[in] length message length
		 * @param[in] teid TEID if T flag is set 
		 * @param[in] seq Sequence number 
		 */
		GtpLayer(uint8_t flags, uint8_t type, uint16_t length, uint32_t teid, uint32_t seq);

		/**
		 * Get a pointer to the GTP header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref gtphdr
		 */
		inline gtphdr* getGtpHeader() { return (gtphdr*)m_Data; };
		inline gtphdr_teid* getGtpteidHeader() { return (gtphdr_teid*)m_Data; };

		bool hasTeid();

		// implement abstract methods

		/**
		 * Currently identifies the following next layers: DnsLayer, DhcpLayer, VxlanLayer, SipRequestLayer, SipResponseLayer.
		 * Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of @ref gtphdr
		 */
		inline size_t getHeaderLen() {
			if (hasTeid()) {
				return sizeof(gtphdr_teid);
			}else{
				return sizeof(gtphdr);
			}
		}

		/**
		 * Calculate @ref gtphdr#headerChecksum field
		 */
		void computeCalculateFields();

		std::string toString();

		OsiModelLayer getOsiModelLayer() { return OsiModelTransportLayer; }
	};

} // namespace pcpp

#endif /* PACKETPP_GTP_LAYER */
