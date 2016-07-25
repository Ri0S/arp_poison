#include <sys/time.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include "networkinfo.h"
#include "arp.h"
void makearprep(char *dev, char *packet, char *t_ip, char *t_mac){
    char g_ip[IPSIZE];
    char *cp;
    u_char s_mac[MACASIZE];
    struct ether_header etheh;

    getGIPAddress(dev, g_ip);
    getMMACAddress(dev, s_mac);

    cp = packet;

    memcpy(etheh.ether_dhost, t_mac, MACASIZE);
    memcpy(etheh.ether_shost, s_mac, MACASIZE);
    etheh.ether_type = htons(ETHERTYPE_ARP);
    memcpy(cp, &etheh, sizeof(struct ether_header));
    cp += sizeof(struct ether_header);

    struct ether_arp arph;
    memcpy(arph.arp_sha, s_mac, MACASIZE);
    inet_aton(g_ip, &(arph.arp_spa));
    memcpy(arph.arp_tha, t_mac, MACASIZE);
    inet_aton(t_ip, &(arph.arp_tpa));
    arph.ea_hdr.ar_hln = MACASIZE;
    arph.ea_hdr.ar_hrd = htons(ARP_HRD_ETHER);
    arph.ea_hdr.ar_pln = ARP_PLN_IP_V4;
    arph.ea_hdr.ar_pro = htons(ARP_PRO_IP);
    arph.ea_hdr.ar_op = htons(ARP_OPER_REP);
    memcpy(cp, &arph, sizeof(struct ether_arp)); //arp 패킷 세팅
}

void makearpreq(char *dev, char *packet, char *t_ip){
    char s_ip[IPSIZE];
    char *cp;
    u_char s_mac[MACASIZE], t_mac[MACASIZE] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    struct ether_header etheh;

    getMIPAddress(dev, s_ip);
    getMMACAddress(dev, s_mac);

    cp = packet;

    memcpy(etheh.ether_dhost, t_mac, MACASIZE);
    memcpy(etheh.ether_shost, s_mac, MACASIZE);
    etheh.ether_type = htons(ETHERTYPE_ARP);
    memcpy(cp, &etheh, sizeof(struct ether_header));
    cp += sizeof(struct ether_header);

    struct ether_arp arph;
    memcpy(arph.arp_sha, s_mac, MACASIZE);
    inet_aton(s_ip, &(arph.arp_spa));
    memcpy(arph.arp_tha, t_mac, MACASIZE);
    inet_aton(t_ip, &(arph.arp_tpa));
    arph.ea_hdr.ar_hln = MACASIZE;
    arph.ea_hdr.ar_hrd = htons(ARP_HRD_ETHER);
    arph.ea_hdr.ar_pln = ARP_PLN_IP_V4;
    arph.ea_hdr.ar_pro = htons(ARP_PRO_IP);
    arph.ea_hdr.ar_op = htons(ARP_OPER_REQ);
    memcpy(cp, &arph, sizeof(struct ether_arp)); //arp 패킷 세팅
}

