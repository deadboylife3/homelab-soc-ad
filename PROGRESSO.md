# Diário do laboratório

## Sessão 04/10/2026 — Topologia v2
- [x] Migração da rede plana para a topologia segmentada (CLIENTS, SERVERS, ATTACKER).
- [x] DC01 em 10.0.2.10, forwarder DNS apenas para o pfSense.
- [x] Caso de troubleshooting: erro 1789 no WIN10 (DNS manual apontando para o IP antigo do DC).
- [x] Logs do WIN10 e do pfSense chegando no Splunk.

## Sessão 05/10/2026 — Segmentação e GPO
- [x] Kali movido para VMnet4 (10.0.3.100), sem host adapter. Isolamento validado.
- [x] OpenSSH Server no DC01. NAT WAN:2223 → 10.0.2.10:22.
- [x] OUs criadas: LAB\Workstations. CLI-TI-01 movido.
- [x] GPO "WS - Firewall - SMB e Logging": SMB-In 445 (Domain), 3 perfis ligados, log de drops.
- [x] Validado: nc do Kali → 10.0.1.101:445 open.
- Lição: verificar firewall efetivo com -PolicyStore ActiveStore.
- Lição: hibernação do endpoint invalida testes e cria buraco de telemetria.

## Sessão 06/10/2026 — Onboarding do Splunk e ruído
- [x] outputs.conf do WIN10 verificado com btool: único destino 10.0.2.20:9997.
- [x] Saúde do forwarder validada via index=_internal (metrics.log).
- [x] CLIENTS: Default allow IPv4 (sombreada) e IPv6 (bypass) desativadas.
- [x] Indexes windows e sysmon criados (pfsense_logs mantido).
- [x] App lab_inputs_windows: Security/System/Application → windows, Sysmon → sysmon, todos renderXml=1.
- [x] Validado com canary event (eventcreate ID 999).
- [x] Macro sysmon_sem_uf. Exclusão na origem adiada (amostra enviesada; criaria ponto cego).
- [x] Broadcast na WAN: atribuído ao VMware, investigação mostrou SignalRGB (portas 12345, 1982, 5555).
      Assinatura válida. Alias BROADCAST_HOST + regra de bloqueio sem log.
- [x] CORREÇÃO: NAT 2223 (SSH DC01) estava com source "*". Restrito a HOST_ANALISTA.
- [x] CORREÇÃO: sshd do DC01 estava em Manual. Ajustado para Automatic.
- [x] NAT 2222 e 8000 confirmados restritos a HOST_ANALISTA.

## Pendências
### Segurança e estabilidade
- [ ] Snapshot de todas as VMs (v2.3-onboarding-splunk).
- [ ] ufw no Ubuntu (22, 8000, 9997/tcp, 5140/udp).
- [ ] Desativar a Anti-Lockout Rule da CLIENTS.
- [ ] Desativar hibernação do WIN10 via GPO.

### Splunk
- [ ] Medir ruído do Sysmon em regime normal.
- [ ] Add-on de parsing do pfSense.
- [ ] Ajustar host do pfSense (aparece como 10.0.2.1).
- [ ] Verificar e remover o index antigo "pfsense".
- [ ] Coletar pfirewall.log do WIN10.
- [ ] Zona de pesquisa reversa 10.0.2.x no DNS do DC (opcional).

### Telemetria
- [ ] Universal Forwarder no DC01 + auditoria avançada (4624, 4625, 4768, 4769, 4720, 5136/5137).
- [ ] Religar o Defender no WIN10 e coletar Windows Defender/Operational.
- [ ] LimaCharlie (EDR) no WIN10.

### Higiene
- [ ] Desabilitar a conta teste_sysmon.
- [ ] Limpar arquivos acidentais na pasta do Administrator do DC (ipconfig, IPv4, Subnet...).
- [ ] Trocar a senha padrão do admin do pfSense.
- [ ] Fixar o IP da WAN do pfSense (DHCP static mapping do VMware).
