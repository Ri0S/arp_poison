#define ARP_HRD_ETHER 0x01
#define ARP_PRO_IP 0x0800
#define ARP_PLN_IP_V4 0x04
#define ARP_OPER_REQ 0x01
#define ARP_OPER_REP 0x02
void makearprep(char *dev, char *packet, char *d_ip, char *t_mac);
void makearpreq(char *dev, char *packet, char *d_ip);
