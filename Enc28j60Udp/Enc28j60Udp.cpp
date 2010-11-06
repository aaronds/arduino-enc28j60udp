#include "Enc28j60Udp.h"

Enc28j60Udp::Enc28j60Udp(){
	first = NULL;
	state = NOT_CONFIGURED;
}

/**
 * Connect a socket and send arp request
 */

void Enc28j60Udp::connect(Enc28j60UdpSocket *sock){
	memset(sock->remoteMac,0,MAC_SIZE);
	if(first){
		sock->next = first;
	}

	first = sock;

	sock->parent = this;

	arpResolveAddress(sock);
}

/**
 * Remove socket from list of active sockets
 */

void Enc28j60Udp::disconnect(Enc28j60UdpSocket *sock){
	Enc28j60UdpSocket *sck = first;

	sock->parent = NULL;

	if(sck == sock){
		first = sock->next;
		return;
	}

	while(sck){
		if(sck->next == sock){
			sck->next = sock->next;
			return;
		}
		sck = sck->next;
	}
}

void Enc28j60Udp::init(){
	/*Setup Enc28j60*/
	enc28j60Init(localMac);
	enc28j60clkout(2);
  	enc28j60PhyWrite(PHLCON,0x476);
}

/**
 * Mostly copied from EtherShield/ip_arp_udp_tcp.c
 */

void Enc28j60Udp::arpResolveAddress(Enc28j60UdpSocket *sock){
	memset(buffer + ETH_DST_MAC,0xff,MAC_SIZE);
	memcpy(buffer + ETH_SRC_MAC,localMac,MAC_SIZE);
		
	buffer[ ETH_TYPE_H_P ] = ETHTYPE_ARP_H_V;
	buffer[ ETH_TYPE_L_P ] = ETHTYPE_ARP_L_V;
	
	buffer[ARP_OPCODE_H_P]=ARP_OPCODE_REQUEST_H_V;
	buffer[ARP_OPCODE_L_P]=ARP_OPCODE_REQUEST_L_V;
	
	// setup hardware type to ethernet 0x0001
	buffer[ ARP_HARDWARE_TYPE_H_P ] = ARP_HARDWARE_TYPE_H_V;
	buffer[ ARP_HARDWARE_TYPE_L_P ] = ARP_HARDWARE_TYPE_L_V;

	// setup protocol type to ip 0x0800
	buffer[ ARP_PROTOCOL_H_P ] = ARP_PROTOCOL_H_V;
	buffer[ ARP_PROTOCOL_L_P ] = ARP_PROTOCOL_L_V;

	// setup hardware length to 0x06
	buffer[ ARP_HARDWARE_SIZE_P ] = ARP_HARDWARE_SIZE_V;

	// setup protocol length to 0x04
	buffer[ ARP_PROTOCOL_SIZE_P ] = ARP_PROTOCOL_SIZE_V;

	//arp desitination and source mac address.

	memset(buffer + ARP_DST_MAC_P,0,MAC_SIZE);
	memcpy(buffer + ARP_SRC_MAC_P,localMac,MAC_SIZE);

	//arp desitination and source ip address.
	memcpy(buffer + ARP_DST_IP_P,sock->remoteIp,IP_SIZE);
	memcpy(buffer + ARP_SRC_IP_P,localIp,IP_SIZE);

	enc28j60PacketSend(42,buffer);
}

void Enc28j60Udp::poll(){

	size_t packetLength = enc28j60PacketReceive(ENC28_BUFFER_SIZE,buffer);
	
	if(packetLength > 0){
		/* ARP */

		if(buffer[ETH_TYPE_H_P] == ETHTYPE_ARP_H_V && buffer[ETH_TYPE_L_P] == ETHTYPE_ARP_L_V){
			/* Addressed to my IP */
			if(memcmp(buffer + ETH_ARP_DST_IP_P,localIp,IP_SIZE) == 0){
				if(buffer[ARP_OPCODE_H_P] == ARP_OPCODE_REPLY_H_V && buffer[ARP_OPCODE_L_P] == ARP_OPCODE_REPLY_L_V){
					/* A reply to one of our requests*/
					setSocketMacAddress();
				}else if(buffer[ARP_OPCODE_H_P] == ARP_OPCODE_REQUEST_H_V && buffer[ARP_OPCODE_L_P] == ARP_OPCODE_REQUEST_L_V){
					/* A request */
					sendArpReply();
				}
			}
		}else if(packetLength > 42 && buffer[ETH_TYPE_H_P] == ETHTYPE_IP_H_V && buffer[ETH_TYPE_L_P] == ETHTYPE_IP_L_V && buffer[IP_HEADER_LEN_VER_P] ){
			if(buffer[IP_PROTO_P] == IP_PROTO_UDP_V){
				/* UDP packet */
				dispatchDataToSocket();
			}
		}
	}
}

void Enc28j60Udp::setEthernetMacAndType(uint8_t *dest,uint8_t typeHigh,uint8_t typeLow){
	memcpy(buffer + ETH_DST_MAC,dest,MAC_SIZE);
	memcpy(buffer + ETH_SRC_MAC,localMac,MAC_SIZE);
	buffer[ETH_TYPE_H_P] = typeHigh;
	buffer[ETH_TYPE_L_P] = typeLow;
}

/**
 * Cycle through all sockets setting the mac address where the ip addresses match.
 */

void Enc28j60Udp::setSocketMacAddress(){
	Enc28j60UdpSocket *sck = first;

	while(sck){
		if(memcmp(sck->remoteIp,buffer + ETH_ARP_SRC_IP_P,IP_SIZE) == 0){
			memcpy(sck->remoteMac,buffer + ETH_ARP_SRC_MAC_P,MAC_SIZE);
		}
		sck = sck->next;
	}
}

/**
 * Send a reply to an arp request.
 */

void Enc28j60Udp::sendArpReply(){
	setEthernetMacAndType(buffer + ETH_ARP_SRC_MAC_P,ETHTYPE_ARP_H_V,ETHTYPE_ARP_L_V);
	memcpy(buffer + ETH_ARP_DST_IP_P,buffer + ETH_ARP_SRC_IP_P,IP_SIZE);
	memcpy(buffer + ETH_ARP_SRC_IP_P,localIp,IP_SIZE);
	enc28j60PacketSend(42,buffer);
}

/**
 * Cycle through all sockets try to match the incoming packet.
 */

void Enc28j60Udp::dispatchDataToSocket(){
	Enc28j60UdpSocket *sck = first;
	uint16_t localPort = (buffer[UDP_DST_PORT_H_P] << 8) + buffer[UDP_DST_PORT_L_P];
	uint16_t remotePort = (buffer[UDP_SRC_PORT_H_P] << 8) + buffer[UDP_SRC_PORT_L_P];
	uint16_t dataLength = (buffer[UDP_LEN_H_P] << 8) + buffer[UDP_LEN_L_P];

	while(sck){
		if(sck->remotePort == remotePort && sck->localPort == localPort && memcmp(buffer + IP_SRC_IP_P,sck->remoteIp,IP_SIZE) == 0 && sck->handler){

			sck->handler->serviceUdp(buffer + UDP_DATA_P,dataLength);
			return;
		}
		sck = sck->next;
	}
}

Enc28j60UdpSocket::Enc28j60UdpSocket(){
	parent = NULL;
	next = NULL;
}

/**
 * Pass the data up to the interface for sending.
 */
void Enc28j60UdpSocket::send(uint8_t *data,uint16_t size){
	parent->send(this,data,size);
}

/**
 * Mostly coppied from etherShield
 */

void Enc28j60Udp::send(Enc28j60UdpSocket *sock,uint8_t *data,uint16_t size){
	uint16_t csum = 0;
	uint16_t length = 0;
	
	setEthernetMacAndType(sock->remoteMac,ETHTYPE_IP_H_V,ETHTYPE_IP_L_V);
	/* Type */
	buffer[IP_P] = IP_V4_V | IP_HEADER_LENGTH_V;
	
	/* TOS */
	buffer[IP_TOS_P] = 0x00;
	
	/* Sequence */
	buffer[IP_ID_H_P] = (ipSequence >> 8) & 0xff;
	buffer[IP_ID_L_P] = ipSequence & 0xff;
	ipSequence++;

	/* Fragment flags */
	buffer[IP_FLAGS_H_P] = 0x40; // don't fragment
	buffer[IP_FLAGS_L_P] = 0x00;

	/* TTL */
	buffer[IP_TTL_P] = 128;

	/*Ip Addresses*/
	memcpy(buffer + IP_SRC_P,localIp,IP_SIZE);
	memcpy(buffer + IP_DST_P,sock->remoteIp,IP_SIZE);

	/*UDP*/
	buffer[IP_PROTO_P] = IP_PROTO_UDP_V;

	length = IP_HEADER_LEN + UDP_HEADER_LEN + size;
	
	/*IP length*/
	buffer[IP_TOTLEN_H_P] = (length >> 8) & 0xff;
	buffer[IP_TOTLEN_L_P] = length & 0xff;

	/*Reset checksum*/
	buffer[IP_CHECKSUM_H_P] = 0;
	buffer[IP_CHECKSUM_L_P] = 0;
	
	/*Ip Checksum*/
	csum = checksum(buffer + IP_P,IP_HEADER_LEN,0);
	buffer[IP_CHECKSUM_H_P] = (csum >> 8) & 0xff;
	buffer[IP_CHECKSUM_L_P] = csum & 0xff;
	
	/*Source Port*/
	buffer[UDP_SRC_PORT_H_P] = (sock->localPort >> 8) & 0xff;
	buffer[UDP_SRC_PORT_L_P] = (sock->localPort & 0xff);

	/*Destination Port*/
	buffer[UDP_DST_PORT_H_P] = (sock->remotePort >> 8) & 0xff;
	buffer[UDP_DST_PORT_L_P] = (sock->remotePort & 0xff);

	/*Udp Length*/
	length = UDP_HEADER_LEN + size;
	buffer[UDP_LEN_H_P] = length >> 8;
	buffer[UDP_LEN_L_P] = length & 0xff;

	/*Reset udp checksum*/
	buffer[UDP_CHECKSUM_H_P] = 0;
	buffer[UDP_CHECKSUM_L_P] = 0;

	csum = checksum(buffer + IP_SRC_P,16 + size,1);
	buffer[UDP_CHECKSUM_H_P] = csum >> 8;
	buffer[UDP_CHECKSUM_L_P] = csum & 0xff;

	memcpy(buffer + UDP_DATA_P,data,size);
	enc28j60PacketSend(UDP_HEADER_LEN + IP_HEADER_LEN + ETH_HEADER_LEN + size,buffer);
} 
// The Ip checksum is calculated over the ip header only starting
// with the header length field and a total length of 20 bytes
// unitl ip.dst
// You must set the IP checksum field to zero before you start
// the calculation.
// len for ip is 20.
//
// For UDP/TCP we do not make up the required pseudo header. Instead we 
// use the ip.src and ip.dst fields of the real packet:
// The udp checksum calculation starts with the ip.src field
// Ip.src=4bytes,Ip.dst=4 bytes,Udp header=8bytes + data length=16+len
// In other words the len here is 8 + length over which you actually
// want to calculate the checksum.
// You must set the checksum field to zero before you start
// the calculation.
// len for udp is: 8 + 8 + data length
// len for tcp is: 4+4 + 20 + option len + data length
//
// For more information on how this algorithm works see:
// http://www.netfor2.com/checksum.html
// http://www.msc.uky.edu/ken/cs471/notes/chap3.htm
// The RFC has also a C code example: http://www.faqs.org/rfcs/rfc1071.html
uint16_t Enc28j60Udp::checksum(uint8_t *buf, uint16_t len,uint8_t type){
        // type 0=ip 
        //      1=udp
        //      2=tcp
        uint32_t sum = 0;

        //if(type==0){
        //        // do not add anything
        //}
        if(type==1){
                sum+=IP_PROTO_UDP_V; // protocol udp
                // the length here is the length of udp (data+header len)
                // =length given to this function - (IP.scr+IP.dst length)
                sum+=len-8; // = real tcp len
        }
        if(type==2){
                sum+=IP_PROTO_TCP_V; 
                // the length here is the length of tcp (data+header len)
                // =length given to this function - (IP.scr+IP.dst length)
                sum+=len-8; // = real tcp len
        }
        // build the sum of 16bit words
        while(len >1){
                sum += 0xFFFF & (*buf<<8|*(buf+1));
                buf+=2;
                len-=2;
        }
        // if there is a byte left then add it (padded with zero)
        if (len){
                sum += (0xFF & *buf)<<8;
        }
        // now calculate the sum over the bytes in the sum
        // until the result is only 16bit long
        while (sum>>16){
                sum = (sum & 0xFFFF)+(sum >> 16);
        }
        // build 1's complement:
        return( (uint16_t) sum ^ 0xFFFF);
}
