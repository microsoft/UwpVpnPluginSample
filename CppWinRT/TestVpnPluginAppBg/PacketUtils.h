#pragma once
#include "pch.h"

const uint32_t VALID_LENGTH = 4 + 1;
const uint32_t VALID_LENGTH_V6 = 6 + 1;
const uint16_t IPV6_HEADER_LENGTH = 40;
const uint32_t PARTIAL_PACKET_SIZE = 64 * 1024 + 1;

enum class VPN_CONTROL
{
    VPN_CONTROL_PACKET = 0x1,
    VPN_CONTROL_DISCONNECT,
    VPN_CONTROL_KEEP_ALIVE,
    VPN_CONTROL_INVALID = -1
};

//
// Used by Decapsulate: The in6_addr structure represents an IPv6 Internet address
//
typedef struct in6_addr {
	union {
		UCHAR       Byte[16];
		USHORT      Word[8];
	} u;
} IN6_ADDR, * PIN6_ADDR, FAR* LPIN6_ADDR;

//
// Structure to represent a IPv4 header
//
typedef struct _IPV4_HEADER
{
	union
	{
		UINT8 VersionAndHeaderLength;

		// Version and header length.
		struct TagVersionAndHeaderLength
		{
			UINT8 HeaderLength : 4;
			UINT8 Version : 4;
		};
	};

	union
	{
		UINT8 TypeOfServiceAndEcnField;

		// Type of service & ECN (RFC 3168).
		struct TagTypeOfServiceAndEcnField
		{
			UINT8 EcnField : 2;
			UINT8 TypeOfService : 6;
		};
	};

	UINT16 TotalLength;
	// Total length of datagram.
	UINT16 Identification;

	union
	{
		UINT16 FlagsAndOffset;

		// Flags and fragment offset.
		struct TagFlagsAndOffset
		{
			UINT16 DontUse1 : 5;
			// High bits of fragment offset.
			UINT16 MoreFragments : 1;
			UINT16 DontFragment : 1;
			UINT16 Reserved : 1;
			UINT16 DontUse2 : 8;
			// Low bits of fragment offset.
		};
	};

	UINT8 TimeToLive;
	UINT8 Protocol;
	UINT16 HeaderChecksum;
	IN_ADDR SourceAddress;
	IN_ADDR DestinationAddress;
} IPV4_HEADER, * PIPV4_HEADER;

//
// IPV6_HEADER
//
// The structure for an IPv6 header.
//
typedef struct _IPV6_HEADER {
	UINT32 VersionClassFlow;// 4 bits Version, 8 Traffic Class, 20 Flow Label.
	UINT16 PayloadLength;   // Zero indicates Jumbo Payload hop-by-hop option.
	UINT8 NextHeader;       // Values are superset of IPv4's Protocol field.
	UINT8 HopLimit;
	IN6_ADDR SourceAddress;
	IN6_ADDR DestinationAddress;
} IPV6_HEADER, * PIPV6_HEADER;

//
// Structure to represent a TCP header
//
typedef struct _TCP_HEADER
{
	UINT16 sourcePort;
	UINT16 destinationPort;
	UINT32 sequenceNumber;
	UINT32 acknowledgementNumber;
	union
	{
		UINT8 dataOffsetReservedAndNS;
		struct
		{
			UINT8 nonceSum : 1;
			UINT8 reserved : 3;
			UINT8 dataOffset : 4;
		}dORNS;
	};
	union
	{
		UINT8 controlBits;
		struct
		{
			UINT8 FIN : 1;
			UINT8 SYN : 1;
			UINT8 RST : 1;
			UINT8 PSH : 1;
			UINT8 ACK : 1;
			UINT8 URG : 1;
			UINT8 ECE : 1;
			UINT8 CWR : 1;
		};
	};
	UINT16 window;
	UINT16 checksum;
	UINT16 urgentPointer;
	UINT8  pOptions[1]; // pointer to the first byte of the variable length Options
} TCP_HEADER, * PTCP_HEADER;

//
// Structure to represent a UDP header
//
typedef struct _UDP_HEADER  
{  
   UINT16 sourcePort;  
   UINT16 destinationPort;  
   UINT16 length;  
   UINT16 checksum;  
} UDP_HEADER, *PUDP_HEADER; 

//
// Structure to represent a ICMPv4 header
//
typedef struct _ICMP_HEADER_V4
{
	UINT8 type;
	UINT8 code;
	UINT16 checksum;
	// We don't use the full header, just enough to see what the ICMP packet is
} ICMP_HEADER_V4, * PICMP_HEADER_V4;

//
// Structure to represent a ICMPv6 header
//
typedef struct _ICMP_HEADER_V6
{
	UINT8 type;
	UINT8 code;
	UINT16 checksum;
	// We don't use the full header, just enough to see what the ICMP packet is
} ICMP_HEADER_V6, * PICMP_HEADER_V6;

//
// Structure to represent a "Full" packet header (e.g. control + IPv4 + TCP header)
//
typedef struct _FULL_HEADER_V4
{
	IPV4_HEADER ipv4Header;
	union
	{
		TCP_HEADER tcpHeader;
		UDP_HEADER udpHeader;
		ICMP_HEADER_V4 icmpV4Header;
	};
} FULL_HEADER_V4, * PFULL_HEADER_V4;

//
// Structure to represent a "Full" packet header (e.g. control + IPv6 + TCP header)
//
typedef struct _FULL_HEADER_V6
{
	IPV6_HEADER ipv6Header;
	union
	{
		TCP_HEADER tcpHeader;
		UDP_HEADER udpHeader;
		ICMP_HEADER_V6 icmpV6Header;
	};
} FULL_HEADER_V6, * PFULL_HEADER_V6;

typedef struct _FULL_CONTROL_HEADER_V4
{
	UINT8 ControlByte;
	FULL_HEADER_V4 fullHeader;
} FULL_CONTROL_HEADER_V4, * PFULL_CONTROL_HEADER_V4;

typedef struct _FULL_CONTROL_HEADER_V6
{
	UINT8 ControlByte;
	FULL_HEADER_V6 fullHeader;
} FULL_CONTROL_HEADER_V6, * PFULL_CONTROL_HEADER_V6;


