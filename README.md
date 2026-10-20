# ARPSPOOFER

Ferramenta experimental em C para estudar pacotes ARP em redes Ethernet Linux.

## Aviso de uso

Use apenas em redes próprias ou em ambientes onde tenha autorização explícita. O uso de ARP spoofing contra terceiros pode interromper comunicações e ser ilegal.

## Requisitos

- Linux
- GCC
- Privilégios de administrador para criar raw sockets
- Uma interface Ethernet ativa

## Compilar

```bash
gcc -Wall -Wextra ARPSPOOFER.c -o arpspoof
```

## Executar

```bash
sudo ./arpspoof <INTERFACE> <IP_DO_ALVO> <IP_DO_ROUTER>
```

Exemplo de laboratório:

```bash
sudo ./arpspoof eth0 192.168.1.20 192.168.1.1
```

Pressione `Ctrl+C` para interromper. O programa tenta enviar anúncios ARP de restauração antes de sair.

## Limitações

- Funciona apenas em Linux e redes Ethernet compatíveis.
- Requer que os endereços IP estejam na mesma rede local.
- Deve ser testado somente em máquinas virtuais, redes isoladas ou ambientes autorizados.
