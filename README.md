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

Com o `Makefile`:

```bash
make
```

O binário gerado é `./arpspoof`. Para remover os artefactos de compilação:

```bash
make clean
```

Também é possível compilar diretamente:

```bash
gcc -Iinclude -Wall -Wextra -O2 src/main.c -o arpspoof
```

## Instalação opcional

O alvo `install` instala o binário em `/usr/local/bin` e configura a
capacidade `cap_net_raw`:

```bash
sudo make install
```

Use esta opção apenas numa máquina de laboratório ou num ambiente autorizado.

## Executar

```bash
sudo ./arpspoof <INTERFACE> <IP_DO_ALVO> <IP_DO_ROUTER>
```

Exemplo de laboratório:

```bash
sudo ./arpspoof eth0 192.168.1.20 192.168.1.1
```

Pressione `Ctrl+C` para interromper. O programa tenta enviar anúncios ARP de restauração antes de sair.

Também é possível terminar com `SIGTERM`; em ambos os casos a restauração é
executada no fluxo normal do programa. Os endereços do alvo e do router devem
ser IPv4 válidos e a interface deve estar ativa.

## Limitações

- Funciona apenas em Linux e redes Ethernet compatíveis.
- Requer que os endereços IP estejam na mesma rede local.
- Não atravessa routers nem VLANs; ARP é limitado ao domínio Ethernet local.
- Deve ser testado somente em máquinas virtuais, redes isoladas ou ambientes autorizados.
