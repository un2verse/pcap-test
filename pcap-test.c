#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <time.h>

void p_packetcapture(const u_char *packet);
void p_payload(const u_char *payload);
void p_port(const u_char *port);
void p_mac(const u_char *mac);
void p_ip(const u_char *ip);
void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void p_mac(const u_char *mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void p_ip(const u_char *ip)
{
    printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
}
void p_port(const u_char *port)
{
    printf("%d\n", ((port[1] & 0xFF00 >> 8) | (port[0] & 0x00FF) << 8));
}

void p_payload(const u_char *payload)
{
    for (int i = 0; i < 8; i++)
    {
        printf("%02x ", payload[i]);
    }
    printf("\n");
}


void p_packetcapture(const u_char *packet)
{
    if ((packet[12] << 8 | packet[13]) == 2048 || packet[23] == 6)
    {
    printf("%d %d\n", (packet[12] << 8 | packet[13]), packet[12]);
        return;
    }

}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        //printf("%u bytes captured\n", header->caplen);
        p_packetcapture(packet);
        time_t t = time(NULL);
        struct tm tm = *localtime(&t);
        printf("\n========packet capture info========\n\n");
        printf("capture time : %d-%d-%d %d:%d:%d\n",
               tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
               tm.tm_hour, tm.tm_min, tm.tm_sec);
        printf("src mac : ");
        p_mac(&packet[0]);
        printf("dst mac : ");
        p_mac(&packet[6]);
        printf("scr ip : ");
        p_ip(&packet[12]);
        printf("dst ip : ");
        p_ip(&packet[26]);
        printf("src port : ");
        p_port(&packet[30]);
        printf("dst port : ");
        p_port(&packet[36]);
        printf("payload : ");
        p_payload(&packet[54]);

    }

    pcap_close(pcap);
}



