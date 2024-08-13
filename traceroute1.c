#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

#define MAX_HOPS 30
#define PACKET_SIZE 64
#define ICMP_HDR_SIZE 8
#define IP_PACKET 1024

unsigned short in_cksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return (answer);
}

int setup_socket()
{
    int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (raw_socket < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    return raw_socket;
}

void set_socket_options(int raw_socket, int ttl)
{
    if (setsockopt(raw_socket, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
}

void send_icmp_packet(int raw_socket, struct sockaddr_in *server_addr, int seq)
{
    struct icmphdr icmp_hdr;
    char sendbuf[PACKET_SIZE];

    memset(sendbuf, 0, sizeof(sendbuf));

    icmp_hdr.type = ICMP_ECHO;
    icmp_hdr.code = 0;
    icmp_hdr.checksum = 0;
    icmp_hdr.un.echo.id = getpid() & 0xFFFF;
    icmp_hdr.un.echo.sequence = seq;

    memcpy(sendbuf, &icmp_hdr, ICMP_HDR_SIZE);

    icmp_hdr.checksum = in_cksum((unsigned short *)&icmp_hdr, ICMP_HDR_SIZE);
    memcpy(sendbuf, &icmp_hdr, ICMP_HDR_SIZE);

    if (sendto(raw_socket, sendbuf, sizeof(sendbuf), 0, (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0)
    {
        perror("sendto");
        exit(EXIT_FAILURE);
    }
}

void receive_icmp_reply(int raw_socket, int ttl)
{
   fd_set read_fds;
    struct timeval timeout;
    char recvbuf[IP_PACKET];
    struct sockaddr_in recv_addr;
    socklen_t addr_len = sizeof(recv_addr);
    struct timeval start_time, end_time;

    FD_ZERO(&read_fds);
    FD_SET(raw_socket, &read_fds);

    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    gettimeofday(&start_time, NULL);

    int select_ret = select(raw_socket + 1, &read_fds, NULL, NULL, &timeout);
    if (select_ret < 0)
    {
        perror("select");
        exit(EXIT_FAILURE);
    }
    else if (select_ret > 0)
    {
        ssize_t recv_len = recvfrom(raw_socket, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *)&recv_addr, &addr_len); // чтения данных из сокета. Если данные доступны, они считываются в буфер recvbuf, а информация о происхождении данных (адрес отправителя) записывается в структуру recv_addr.
        if (recv_len < 0)
        {
            perror("recvfrom");
            exit(EXIT_FAILURE);
        }
        gettimeofday(&end_time, NULL);
        double rtt = (end_time.tv_sec - start_time.tv_sec) * 1000.0 + (end_time.tv_usec - start_time.tv_usec) / 1000.0;

        struct iphdr *ip_hdr = (struct iphdr *)recvbuf;
        struct icmphdr *icmp_reply = (struct icmphdr *)(recvbuf + (ip_hdr->ihl * 4));

        if (icmp_reply->type == ICMP_TIME_EXCEEDED)
        {
            printf("%d\t%s\t%.2f мс\n", ttl, inet_ntoa(recv_addr.sin_addr), rtt);
        }
        else if (icmp_reply->type == ICMP_ECHOREPLY)
        {
            printf("%d\t%s\t%.2f мс\n", ttl, inet_ntoa(recv_addr.sin_addr), rtt);
         
        }
    }
    else
    {
        printf("%d\t*\n", ttl);
    }
}
void traceroute(const char *hostname)
{
    struct sockaddr_in server_addr;
    struct hostent *host;
    int ttl = 1;
    int raw_socket;
    int seq = 0;

    raw_socket = setup_socket();

    host = gethostbyname(hostname);
    if (host == NULL)
    {
        fprintf(stderr, "Unknown host: %s\n", hostname);
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr = *(struct in_addr *)host->h_addr_list[0];

    while (ttl <= MAX_HOPS)
    {
        set_socket_options(raw_socket, ttl);
        send_icmp_packet(raw_socket, &server_addr,seq++);
        receive_icmp_reply(raw_socket, ttl);
        ttl++;
    }
    close(raw_socket);
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <hostname>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    traceroute(argv[1]);
    return 0;
}
