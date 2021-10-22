using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace SimpleVpnServer
{
    

    public enum VPN_CONTROL
    {
        VPN_CONTROL_PACKET = 0x1,
        VPN_CONTROL_DISCONNECT,
        VPN_CONTROL_KEEP_ALIVE
    };

    public struct PACKET_COUNTER
    {
        public int TotalReceivedFromClient; 
        public int TotalUDPReceivedFromClient;
        public int TotalTCPReceivedFromClient;
        public int TotalBytesReceivedFromClient;
        public int TotalOtherReceivedFromClient; //Non UDP/TCP received
        public int TotalControlMessagesReceivedFromClient;
        public int TotalForwardedBackToClient; //Since we only forward back UDP, only counter we need
    }
    /// <summary>
    /// Utilities for working with packets
    /// </summary>
    class PacketUtils
    {
        internal const int CONTROL_PACKET_LENGTH = 1;
        internal const int IPV4_HEADER_LENGTH = 20;
        internal const int UDP_HEADER_LENGTH = 8;

        public const int IPV4_TOTAL_LENGTH = CONTROL_PACKET_LENGTH + IPV4_HEADER_LENGTH + UDP_HEADER_LENGTH;


        [StructLayout(LayoutKind.Explicit)]
        public struct FULL_HEADER_V4
        {
            [FieldOffset(0)] internal CONTROL_HEADER ControlHeader;
            [FieldOffset(1)] internal IPV4_HEADER IpHeader;
            [FieldOffset(21)] internal IP_PROTOCOL_HEADER_V4 IpProtocolHeader;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CONTROL_HEADER
        {
            internal byte controlValue;
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct IP_PROTOCOL_HEADER_V4
        {
            [FieldOffset(0)]
            internal TCP_HEADER TcpHeader;
            [FieldOffset(0)]
            internal UDP_HEADER UdpHeader;
            [FieldOffset(0)]
            internal ICMP_HEADER_V4 IcmpV4Header;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct TCP_HEADER
        {
            internal ushort SourcePort;
            internal ushort DestinationPort;
            internal uint SequenceNumber;
            internal uint AcknowledgementNumber;
            internal byte DataOffsetReservedAndNS;
            internal byte ControlBits;
            internal ushort Window;
            internal ushort Checksum;
            internal ushort UrgentPointer;
            internal byte POptions;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct UDP_HEADER
        {
            internal ushort SourcePort;
            internal ushort DestinationPort;
            internal ushort Length;
            internal ushort Checksum;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ICMP_HEADER_V4
        {
            internal byte Type;
            internal byte Code;
            internal ushort Checksum;
            // We don't specify the full header, just enough to see what the packet is
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct IPV4_HEADER
        {
            internal byte VersionHeaderLengthByte;     // Offset 0
            internal byte DifferentiatedServicesByte;  // Offset 1
            internal ushort TotalLengthBytes;          // Offset 2
            internal ushort Idenfication;              // Offset 4
            internal ushort FlagsAndOffset;            // Offset 6
            internal byte ttl;                         // Offset 8
            internal byte Protocol;                    // Offset 9
            internal ushort HeaderChecksumBytes;       // Offset 10
            internal uint SourceAddressBytes;          // Offset 12
            internal uint DestinationAddressBytes;     // Offset 16

            internal ushort HeaderLength
            {
                get
                {
                    byte headerLength = VersionHeaderLengthByte;
                    headerLength <<= 4;
                    headerLength >>= 4;
                    headerLength *= 4;

                    return Convert.ToUInt16(headerLength);
                }
            }

            internal byte Version
            {
                get
                {
                    return (byte)(VersionHeaderLengthByte >> 4);
                }
            }

            internal string SourceAddress
            {
                get
                {
                    return String.Join(".", BitConverter.GetBytes(SourceAddressBytes));
                }
            }

            internal string DestinationAddress
            {
                get
                {
                    return String.Join(".", BitConverter.GetBytes(DestinationAddressBytes));
                }
            }
        }

        public static FULL_HEADER_V4 PinV4FullHeader(byte[] packetBytes)
        {
            GCHandle pinnedHeader = GCHandle.Alloc(packetBytes, GCHandleType.Pinned);
            FULL_HEADER_V4 header;

            header = (FULL_HEADER_V4)Marshal.PtrToStructure(pinnedHeader.AddrOfPinnedObject(), typeof(FULL_HEADER_V4));
            pinnedHeader.Free();
            
            return header;
        }

        public static UInt16 ReverseByteOrder(UInt16 value)
        {
            byte[] bytes = BitConverter.GetBytes(value);
            byte tempByte = bytes[0];
            bytes[0] = bytes[1];
            bytes[1] = tempByte;
            return BitConverter.ToUInt16(bytes, 0);
        }

        internal static void ReadPacket(Client client, FULL_HEADER_V4 fullHeader)
        {
            string strPacket = "";

            // Now we can see what type of packet this is and output it accordingly

            strPacket += ":: Control= " + fullHeader.ControlHeader.controlValue;
            
            // Check IP packet version
            if (fullHeader.IpHeader.Version == 4)
            {
                // This is a IPv4 packet
                strPacket += " :: Version=4";

                // Source and Destination
                strPacket += " :: Src=" + fullHeader.IpHeader.SourceAddress;
                strPacket += " :: Dst=" + fullHeader.IpHeader.DestinationAddress;

                // Determine protocol and output packet header accordingly
                switch (fullHeader.IpHeader.Protocol)
                {
                    case 1: // icmpv4

                        strPacket += " :: Protocol=icmpv4";
                        strPacket += " :: Type=" + fullHeader.IpProtocolHeader.IcmpV4Header.Type.ToString();
                        strPacket += " :: Code=" + fullHeader.IpProtocolHeader.IcmpV4Header.Code.ToString();
                        break;

                    case 6: // tcp

                        strPacket += " :: Protocol=tcp";
                        strPacket += " :: SrcPort=" + ReverseByteOrder(fullHeader.IpProtocolHeader.TcpHeader.SourcePort).ToString();
                        strPacket += " :: DstPort=" + ReverseByteOrder(fullHeader.IpProtocolHeader.TcpHeader.DestinationPort).ToString();
                        break;

                    case 17: // udp

                        strPacket += " :: Protocol=udp";
                        strPacket += " :: SrcPort=" + ReverseByteOrder(fullHeader.IpProtocolHeader.UdpHeader.SourcePort).ToString();
                        strPacket += " :: DstPort=" + ReverseByteOrder(fullHeader.IpProtocolHeader.UdpHeader.DestinationPort).ToString();
                        break;

                    default: // unhandled protocol

                        strPacket += " :: Protocol=" + fullHeader.IpHeader.Protocol.ToString();
                        break;
                }

                strPacket += " :: Length=" + ReverseByteOrder(fullHeader.IpHeader.TotalLengthBytes).ToString();
            }
            else
            {
                // This is not a IPv4 packet, so it's not supported at the moment
                strPacket += " :: Version=" + fullHeader.IpHeader.Version.ToString() + " :: WARNING - Non-IPv4 packet received";
            }

            client.LogMessage(Logger.MessageType.Received, "Packet: {0}", strPacket);
        }

        public static ushort ComputeIPHeaderChecksum(byte[] packet, int headerLength) {
            ushort words;
            long sum = 0;

            for (int i = CONTROL_PACKET_LENGTH; i < headerLength; i+=2) //don't want include the control packet in the checksum
            {
                words = (ushort) ((packet[i] << 8) + packet[i+1]);
                sum += (long) words;
            }

            while ((sum >> 16) != 0) 
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            sum = ~sum;

            return  (ushort) sum;
        }

        public static void makeHeader(int readLength, byte[] srcEndPoint, byte[] destAddress, ushort srcPort, ushort destPort, out byte[] packet) 
        {
            packet = new Byte[readLength + IPV4_TOTAL_LENGTH];

            packet[0] = (byte) VPN_CONTROL.VPN_CONTROL_PACKET;

            //Building the Header
            //Start with IP Header
            //Byte 0 is version and internal header length
            packet[0 + CONTROL_PACKET_LENGTH] = ((4 << 4) + 5); //ipv4, shift to first 4 bits. add 5 for internal header length

            //Byte 1 is DifferentiatedServiceBytes, keep 0

            //Byte 2 and 3 is total length
            UInt16 totalLength = PacketUtils.ReverseByteOrder((ushort) (20 + 8 + readLength)); //IpHeader Size + UDP header size + data length
            Array.Copy(BitConverter.GetBytes(totalLength), 0, packet, 2 + CONTROL_PACKET_LENGTH, 2);

            //Byte 4 and 5 is Identifcation, should be okay to keep 0

            //Byte 6 and 7 is Flags + Fragment Offset, should be okay to keep 0

            //Byte 8 is Time to live
            packet[8 + CONTROL_PACKET_LENGTH] = 40;

            //Byte 9 is Protocol
            packet[9 + CONTROL_PACKET_LENGTH] = 17;

            //Byte 10 and 11 is header checksum, we will compute later

            //Byte 12 through 15 is the Source IP address
            Array.Copy(srcEndPoint, 0, packet, 12 + CONTROL_PACKET_LENGTH, 4);

            //Byte 16 through 19 is the Destination IP Address
            Array.Copy(destAddress, 0, packet, 16 + CONTROL_PACKET_LENGTH, 4);

            //Now Starting UDP Header
            //Bytes 20 and 21 is Source Port
            UInt16 srcPortBytes = PacketUtils.ReverseByteOrder(srcPort);
            Array.Copy(BitConverter.GetBytes(srcPortBytes), 0, packet, 20 + CONTROL_PACKET_LENGTH, 2);

            //Bytes 22 and 23 is Destination Port
            Array.Copy(BitConverter.GetBytes(destPort), 0, packet, 22 + CONTROL_PACKET_LENGTH, 2);

            //Bytes 24 and 25 is UDP packetLength
            UInt16 udpPacketLength = PacketUtils.ReverseByteOrder((ushort) (readLength + 8));
            Array.Copy(BitConverter.GetBytes(udpPacketLength), 0, packet, 24 + CONTROL_PACKET_LENGTH, 2);

            //Bytes 26 and 27 is Checksum, okay to leave 0 for same reason as above

            //Now we compute IpHeader check sum
            byte[] checkSum = BitConverter.GetBytes(PacketUtils.ReverseByteOrder(PacketUtils.ComputeIPHeaderChecksum(packet, IPV4_HEADER_LENGTH + CONTROL_PACKET_LENGTH)));
            Array.Copy(checkSum, 0, packet, 10 + CONTROL_PACKET_LENGTH, 2);
        }
    }
}