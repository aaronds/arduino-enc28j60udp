/**
 * Example for Enc28j60 UDP driver
 *
 * This is work in progress, it nearly works. I have to ping the Arduino before the computer will recognise the packets.
 * 
 * To test:
 * Change ip addresses
 * Upload to arduino
 * Ping the arduino
 * Listen on udp port 444 for example with netcat: ‘nc -4 -u -l 4444’
 */

#include <enc28j60.h>
#include <net.h>
#include <Enc28j60Udp.h>

/* Mac Address */
static uint8_t macAddr[6] = {0x54,0x55,0x58,0x10,0x00,0x33}; 

/* Ip Address CHANGE ME */
static uint8_t ipAddress[] = {192,168,2,2};  

/* Server Address CHANGE ME*/
static uint8_t serverAddress[] = {192,168,2,1};

/* The Driver */
Enc28j60Udp udp;

/* A Socket */
Enc28j60UdpSocket sock;

unsigned long time = 0;

void setup(){
  Serial.begin(9600);
  /* Copy the addresses to the driver and socket */
  memcpy(udp.localMac,macAddr,MAC_SIZE);
  memcpy(udp.localIp,ipAddress,IP_SIZE);
  memcpy(udp.gatewayIp,serverAddress,IP_SIZE);
  memcpy(sock.remoteIp,serverAddress,IP_SIZE);
  
  /* Set the ports */
  sock.remotePort = 4444;
  sock.localPort = 2020;
  
  udp.init();
  udp.connect(&sock);
  
  Serial.println("Init Done");
  time = millis();
}

void loop(){
  
  if((millis() - time) > 1000){
    time = millis();
    sock.send((uint8_t *)"Hello World\n",strlen("Hello World\n"));
  }   
  
  udp.poll();
}
