#include <pcap.h>

#define ARP_HRD_ETHER 0x01
#define ARP_PRO_IP 0x0800
#define ARP_PLN_IP_V4 0x04
#define ARP_OPER_REQ 0x01
#define ARP_OPER_REP 0x02
void makearprep(char *dev, u_char *packet, u_char *s_ip, u_char *s_mac, u_char *t_ip, u_char *t_mac);
void makearpreq(char *dev, u_char *packet, u_char *t_ip);
int sendarpreq(pcap_t *pcd, char *dev, u_char *packet, u_char *t_ip);
int sendarprep(pcap_t *pcd, char *dev, u_char *packet, u_char *s_ip, u_char *s_mac, u_char *t_ip, u_char *t_mac);
