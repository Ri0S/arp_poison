#include <pcap.h>
#define MACSIZE 18
#define MACASIZE 6
#define MTUSIZE 1500
#define IPSIZE 16
#define TIMEOUT 1000
#define PROMISC 1
#define NONPROMISC 0
int getMIPAddress(char *dev, u_char *buf);
int getMMACAddress(char *dev, u_char *buf);
int getGIPAddress(char *dev, u_char *buf);
int getGMACAddress(u_char *g_ip, u_char *buf);
