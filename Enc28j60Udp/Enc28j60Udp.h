/**
 * A UDP Library for ENC28j60 as found on the EtherShield
 *
 * Most of the code was borrowed from the etherShield library:
 *
 * http://www.nuelectronics.com/estore/?p=14
 */

#ifndef __ENC28J60_UDP
#define __ENC28J60_UDP

#define IP_SIZE 4
#define MAC_SIZE 6
#define ENC28_BUFFER_SIZE 500

extern "C" {
	#include <inttypes.h>
	#include <stdlib.h>
	#include <string.h>
	#include <enc28j60.h>
	#include <net.h>
}

/**
 * A virtual class for anything responding to udp socket activity
 */

class Enc28j60UdpSocketHandler {
	public:
		/**
		 * serviceUdp is called by the interface when data
		 * arrives for a socket.
		 */
		virtual void serviceUdp(uint8_t *data,uint16_t length);
};

class Enc28j60Udp;

/**
 * Class for each socket
 */

class Enc28j60UdpSocket {

	public:
		Enc28j60UdpSocket();
		uint8_t remoteIp[IP_SIZE];
		uint8_t remoteMac[MAC_SIZE];

		uint16_t remotePort;
		uint16_t localPort;

		Enc28j60Udp *parent;

		Enc28j60UdpSocket *next;

		Enc28j60UdpSocketHandler *handler;

		void send(uint8_t *data,uint16_t size);
};

class Enc28j60Udp {

	public:
		Enc28j60Udp();
		uint8_t localIp[IP_SIZE];
		uint8_t localMac[MAC_SIZE];
		uint8_t gatewayIp[IP_SIZE];

		/**
		 * The first socket in the list of sockets.
		 */
	
		Enc28j60UdpSocket *first;

		/**
		 * A large buffer for creating the packets in.
		 */
		
		uint8_t buffer[ENC28_BUFFER_SIZE];

		/**
		 * Add a socket
		 */

		void connect(Enc28j60UdpSocket *sock);

		/**
		 * Remove socket
		 */
		void disconnect(Enc28j60UdpSocket *sock);

		void init();
		void poll();

		/**
		 * Set the MAC address of all sockets matching the current ARP response.
		 */

		void setSocketMacAddress();

		void setEthernetMacAndType(uint8_t *dest,uint8_t typeHigh,uint8_t typeLow);

		/**
		 * Reply to arp.
		 */

		void sendArpReply();

		/**
		 * Find an ip address
		 */

		void arpResolveAddress(Enc28j60UdpSocket *sock);

		/**
		 * Handel incoming upd data.
		 */

		void dispatchDataToSocket();

		/**
		 * Send data from a socket
		 */

		void send(Enc28j60UdpSocket *socket,uint8_t *data,uint16_t size);

		static const int NOT_CONFIGURED = 0;
		static const int CONFIGURED = 1;

		uint8_t state;
		uint16_t ipSequence;

		/**
		 * Compute the IP / UDP checksums
		 *
		 * Stolen from the etherShield library.
		 */

		uint16_t checksum(uint8_t *buf,uint16_t len,uint8_t type);
};

#endif
