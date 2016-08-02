#include <pcap/pcap.h>

int gett_mac(const u_char *packet, u_char *t_mac, u_char* t_ip);
int packetrelay(pcap_t *pcd, char *dev, u_char *packet, u_char *g_ip, u_char *s_mac, u_char *t_ip, u_char *t_mac, u_char *g_mac);
