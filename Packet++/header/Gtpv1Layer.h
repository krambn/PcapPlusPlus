#ifndef PACKETPP_GTPV1_LAYER
#define PACKETPP_GTPV1_LAYER

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
	struct gtpv1hdr {
#if (BYTE_ORDER == LITTLE_ENDIAN)
    uint8_t pn:1,
            s:1,
            e:1,
            rsvd:1,
            pt:1,
            version:3;
#else
    uint8_t version:3,
            pt:1,
            rsvd:1,
            e:1,
            s:1,
            pn:1;
#endif
		/** Message type */
		uint8_t type;
		/** Message length */
		uint16_t length;
		/** TEID 32 bits*/
		uint32_t teid;
	};

#pragma pack(pop)


	/**
	 * @class Gtpv1Layer
	 * Represents an UDP (User Datagram Protocol) protocol layer
	 */
	class Gtpv1Layer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref gtpv1hdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		Gtpv1Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet){}

		/**
		 * A constructor that allocates a new UDP header with source and destination ports
		 * @param[in] type message type
		 * @param[in] teid TEID if T flag is set 
		 */
		Gtpv1Layer(uint8_t type, uint16_t length, uint32_t teid);

		/**
		 * Get a pointer to the GTPv1 header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref gtpv1hdr
		 */
		inline gtpv1hdr* getGtpv1Header() { return (gtpv1hdr*)m_Data; };


		// implement abstract methods

		/**
		 * Currently identifies the following next layers: DnsLayer, DhcpLayer, VxlanLayer, SipRequestLayer, SipResponseLayer.
		 * Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of @ref gtpv1hdr
		 */
		inline size_t getHeaderLen() {
			return sizeof(gtpv1hdr);
		}

		/**
		 * Calculate @ref gtpv1hdr fields
		 */
		void computeCalculateFields();

		std::string toString();

		OsiModelLayer getOsiModelLayer() { return OsiModelTransportLayer; }
	};

} // namespace pcpp

#endif /* PACKETPP_GTPV1_LAYER */
