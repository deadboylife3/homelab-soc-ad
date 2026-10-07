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
