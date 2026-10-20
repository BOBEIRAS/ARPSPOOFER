# ARPSPOOFER

Ferramenta experimental em C para estudar pacotes ARP em redes Ethernet Linux,
com suporte a restauração das entradas ARP e encaminhamento opcional no
laboratório.

## Aviso de uso

Use apenas em redes próprias ou em ambientes onde tenha autorização explícita. O uso de ARP spoofing contra terceiros pode interromper comunicações e ser ilegal.

## Requisitos

- Linux com uma interface Ethernet ativa.
- GCC, `make` e `libcap2-bin` (`setcap`).
- Acesso à rede própria ou autorização explícita para o teste.

O programa cria raw sockets. Depois da instalação, o `Makefile` atribui apenas
a capacidade Linux `cap_net_raw` ao binário, permitindo executá-lo sem `sudo`.
O `sudo` continua a ser necessário uma vez para instalar o binário e definir
essa capacidade.

Para verificar a capacidade atribuída:

```bash
getcap "$(command -v arpspoof)"
```

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

Para instalar em `/usr/local/bin` e configurar `cap_net_raw`:

```bash
sudo make install
```

Depois da instalação, execute sem `sudo`:

```bash
arpspoof <INTERFACE> <IP_DO_ALVO> <IP_DO_ROUTER>
```

Para remover a instalação:

```bash
sudo setcap -r /usr/local/bin/arpspoof
sudo rm /usr/local/bin/arpspoof
```

Se o shell não encontrar o comando instalado, abra um novo terminal ou use:

```bash
/usr/local/bin/arpspoof <INTERFACE> <IP_DO_ALVO> <IP_DO_ROUTER>
```

## Executar

Depois de `sudo make install`, execute sem `sudo`:

```bash
arpspoof <INTERFACE> <IP_DO_ALVO> <IP_DO_ROUTER>
```

Sem instalação, o binário local normalmente precisa de privilégios para abrir
raw sockets:

```bash
sudo ./arpspoof <INTERFACE> <IP_DO_ALVO> <IP_DO_ROUTER>
```

Exemplo de laboratório:

```bash
./arpspoof eth0 192.168.1.20 192.168.1.1
```

Argumentos:

| Argumento | Descrição |
| --- | --- |
| `INTERFACE` | Interface Ethernet, por exemplo `eth0` |
| `IP_DO_ALVO` | IPv4 do dispositivo de laboratório |
| `IP_DO_ROUTER` | IPv4 do router no mesmo domínio Ethernet |

Pressione `Ctrl+C` para interromper. O programa tenta enviar anúncios ARP de
restauração antes de sair. Durante a execução, pressione `T` para alternar o
encaminhamento de pacotes no modo de laboratório. `SIGTERM` também inicia o
encerramento.

Para descobrir os valores locais:

```bash
ip -br addr
ip route
ip neigh show dev eth0
```

Também é possível terminar com `SIGTERM`; em ambos os casos a restauração é
iniciada antes de sair. Os endereços do alvo e do router devem ser IPv4 válidos
e a interface deve estar ativa.

## Limitações

- Funciona apenas em Linux e redes Ethernet compatíveis.
- Requer que os endereços IP estejam na mesma rede local.
- Não atravessa routers nem VLANs; ARP é limitado ao domínio Ethernet local.
- A capacidade `cap_net_raw` não concede privilégios administrativos gerais.
- A restauração não substitui a verificação manual da tabela de vizinhos.
- Deve ser testado somente em máquinas virtuais, redes isoladas ou ambientes
  autorizados.

## Estrutura do projeto

```text
.
├── Makefile
├── README.md
└── src/
    └── main.c
```

## Limpeza e recuperação

Para parar um processo em execução e limpar a cache de vizinhos da interface:

```bash
pgrep -a arpspoof
sudo kill -TERM <PID>
sudo ip neigh flush dev eth0
```

Use o PID apresentado por `pgrep`; não termine processos de outros programas.
