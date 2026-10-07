# Arquitetura do laboratório

## Princípio

Laboratório pequeno, mas coerente: cada componente tem **uma função clara** e corresponde a uma categoria que existe em um SOC real. A ordem de prioridade é **clareza → aprendizado → realismo → documentação → portfólio**.

## Redes (VMware)

| Rede VMware | Segmento | Sub-rede | Gateway | Função |
|---|---|---|---|---|
| VMnet8 (NAT) | WAN | 192.168.252.0/24 | — | Saída para a internet; único segmento que o HOST enxerga |
| VMnet2 (host-only) | CLIENTS | 10.0.1.0/24 | 10.0.1.1 | Estações de trabalho |
| VMnet3 (host-only) | SERVERS | 10.0.2.0/24 | 10.0.2.1 | DC e SIEM |
| VMnet4 (host-only) | ATTACKER | 10.0.3.0/24 | 10.0.3.1 | Máquina de ataque isolada |

As redes host-only **não têm adaptador virtual do HOST** ("Connect a host virtual adapter" desmarcado) e não usam o DHCP do VMware. Todo o tráfego entre segmentos passa obrigatoriamente pelo pfSense, que filtra e registra.

## Ativos

| Host | Segmento | IP | Papel |
|---|---|---|---|
| pfSense | todos | .1 de cada rede | Firewall, NAT, DHCP, DNS para a rede ATTACKER |
| DC01 | SERVERS | 10.0.2.10 | AD DS e DNS do domínio `meulab.local` |
| Ubuntu (Splunk) | SERVERS | 10.0.2.20 | Splunk Enterprise (Web 8000, recepção 9997, syslog 5140/udp) |
| CLI-TI-01 (WIN10) | CLIENTS | 10.0.1.101 (DHCP) | Endpoint com Sysmon e Universal Forwarder |
| Kali | ATTACKER | 10.0.3.100 (DHCP) | Simulação de ataques |

## Acesso administrativo a partir do HOST

O HOST só alcança a WAN do pfSense. O acesso aos serviços internos é feito por port forward, **restrito ao alias `HOST_ANALISTA`**:

| Porta na WAN | Destino | Uso |
|---|---|---|
| 443 | pfSense | Painel web |
| 8000 | 10.0.2.20:8000 | Splunk Web |
| 2222 | 10.0.2.20:22 | SSH no Ubuntu |
| 2223 | 10.0.2.10:22 | SSH no DC01 (OpenSSH Server) |

Em um ambiente corporativo, isso corresponde a uma **estação administrativa dedicada** acessando servidores por canais controlados, em vez de administração pelo console.

## Fluxo de logs

```
WIN10 ── Security/System/Application ──┐
WIN10 ── Sysmon/Operational ───────────┼── Universal Forwarder ──TCP 9997──► Splunk (10.0.2.20)
                                       │
pfSense ── filterlog (syslog UDP 5140) ─────────────────────────────────────► Splunk
DC01 ── (planejado) Universal Forwarder ────────────────────────────────────► Splunk
```

## Organização no Splunk

| Index | Conteúdo | Sourcetype |
|---|---|---|
| `windows` | Security, System, Application do WIN10 | `XmlWinEventLog` |
| `sysmon` | Microsoft-Windows-Sysmon/Operational | `XmlWinEventLog` |
| `pfsense_logs` | Firewall de rede | `pfsense` |

Critério: **separar por retenção e por quem acessa**, não por tipo de log. Poucos indexes, cada um com motivo. Detalhes no [projeto 03](../projetos/03-onboarding-splunk/).

## Hardware e alocação de recursos

Todo o laboratório roda em um único PC, que também é a estação do analista.

| Componente | Especificação |
|---|---|
| CPU | AMD Ryzen 7 5800X3D (8 núcleos / 16 threads) |
| RAM | 32 GB |
| Armazenamento | SSD NVMe 2 TB |
| GPU | AMD Radeon RX 7600 (não utilizada pelo lab) |
| Virtualização | VMware Workstation |

### Alocação por VM

| VM | Função | RAM | vCPU | Disco | Rede(s) |
|---|---|---|---|---|---|
| pfSense | Firewall / gateway | 2 GB | 2 | 20 GB | VMnet8, 2, 3, 4 |
| Windows Server 2022 (DC01) | AD DS + DNS | 4 GB | 2 | 60 GB | VMnet3 |
| Ubuntu Server | Splunk Enterprise | 6 GB | 4 | 80 GB | VMnet3 |
| Windows 10 (CLI-TI-01) | Endpoint | 6 GB | 4 | 60 GB | VMnet2 |
| Kali Linux | Atacante | 2 GB | 2 | 80 GB | VMnet4 |
| **Total** | | **~20 GB** | **14** | **300 GB** | |

### Planejamento de capacidade

- **Memória é o recurso limitante.** Com as 5 VMs ligadas, sobram cerca de 12 GB para o Windows 11 HOST (navegador com o Splunk Web, ferramentas de análise).
- **vCPU:** 14 vCPUs alocadas para 16 threads físicas. Não há sobrealocação, e como as VMs raramente usam CPU ao mesmo tempo, o HOST continua responsivo.
- **Splunk** é a VM que mais cresce com o volume de dados (indexação e buscas). Próximo ajuste: 8 GB, ainda deixando ~10 GB livres para o HOST.
- **Disco:** os 300 GB alocados são o limite máximo dos discos virtuais; o espaço real ocupado é menor, porque os discos crescem conforme o uso.
- Nem todas as VMs precisam estar ligadas sempre: o Kali só é ligado durante simulações de ataque.

<!-- Foto do PC (opcional): salve como docs/img/pc-host.jpg, remova os metadados e descomente a linha abaixo.
![PC que hospeda o laboratório](img/pc-host.jpg)
-->

## Divisão de responsabilidades

| Camada | Ferramenta |
|---|---|
| SIEM | Splunk |
| EDR | LimaCharlie (planejado) |
| Antivírus | Microsoft Defender |
| Telemetria de endpoint | Sysmon |
| Firewall de rede | pfSense |
| Firewall de host | Windows Defender Firewall (gerenciado por GPO) |
| Identidade | Active Directory |
