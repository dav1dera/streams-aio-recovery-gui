# Due VM di prova su Proxmox · Ubuntu 26.04

Usa `ubuntu-26.04.1-live-server-amd64.iso` già caricata nello storage `local`. La GUI Recovery **v0.3.1 o successiva** accetta Ubuntu 26.04.x e 24.04.x amd64. Non serve scaricare Ubuntu 24.04 per questa prova.

## 1. Creare le VM

Puoi usare **Create VM** due volte dalla GUI Proxmox. Seleziona la ISO Ubuntu caricata, un disco su uno storage per immagini VM, controller **VirtIO SCSI**, rete **VirtIO** e il bridge della LAN. Usa nuovi VM ID assegnati da Proxmox.

| VM nuova | Nome suggerito | Risorse iniziali per la prova | Utente Ubuntu |
| --- | --- | --- | --- |
| Stack | `streams-aio-dr-test` | 4 core, 8 GiB RAM, 80 GiB disco | `pi` |
| Infisical | `infisical-dr-test` | 2 core, 4 GiB RAM, 32 GiB disco | `infiscal` |

Sono allocazioni iniziali, da adattare alle risorse libere del nodo e al carico delle applicazioni. Controlla RAM e disco prima di avviare entrambe.

Se preferisci la shell, apri **pve → Shell**. Controlla storage e bridge:

```bash
pvesm status
ip -br link show type bridge
free -h
```

Nel blocco seguente `local-lvm` e `vmbr0` sono esempi: imposta i nomi effettivi mostrati dai controlli. `pvesh` sceglie gli ID liberi; il blocco crea soltanto le due nuove VM e non avvia o arresta quelle esistenti. Non rilanciarlo per avviare VM già create, altrimenti ne creeresti altre.

```bash
(
set -euo pipefail
DISK_STORAGE=local-lvm
LAN_BRIDGE=vmbr0
ISO_VOLUME=local:iso/ubuntu-26.04.1-live-server-amd64.iso

test -d "/sys/class/net/$LAN_BRIDGE/bridge"
pvesm status --storage "$DISK_STORAGE"
test -s "$(pvesm path "$ISO_VOLUME")"

VM_STACK=$(pvesh get /cluster/nextid)
qm create "$VM_STACK" --name streams-aio-dr-test \
  --ostype l26 --cpu host --cores 4 --memory 8192 \
  --scsihw virtio-scsi-pci --scsi0 "$DISK_STORAGE:80" \
  --ide2 "$ISO_VOLUME,media=cdrom" \
  --net0 "virtio,bridge=$LAN_BRIDGE" --boot 'order=ide2;scsi0'

VM_INFISICAL=$(pvesh get /cluster/nextid)
qm create "$VM_INFISICAL" --name infisical-dr-test \
  --ostype l26 --cpu host --cores 2 --memory 4096 \
  --scsihw virtio-scsi-pci --scsi0 "$DISK_STORAGE:32" \
  --ide2 "$ISO_VOLUME,media=cdrom" \
  --net0 "virtio,bridge=$LAN_BRIDGE" --boot 'order=ide2;scsi0'

printf 'VM_STACK=%s\nVM_INFISICAL=%s\n' "$VM_STACK" "$VM_INFISICAL"
qm start "$VM_STACK"
qm start "$VM_INFISICAL"
)
```

Annota gli ID stampati. Se il blocco si ferma, controlla l’elenco VM prima di riprovare: non cancella automaticamente quanto è già stato creato.

## 2. Installare Ubuntu

Apri **Console** per ciascuna nuova VM e completa l’installazione Ubuntu Server:

1. Usa hostname distinti, per esempio quelli della tabella.
2. Assegna IP diversi dalle VM operative; DHCP va bene per la prova, purché il PC raggiunga entrambe via SSH.
3. Crea `pi` sullo stack e `infiscal` su Infisical come primi utenti: devono avere UID/GID 1000 e sudo.
4. Seleziona **Install OpenSSH server**. Usa password SSH oppure una chiave già gestita sul PC.
5. Completa l’installazione sul disco della VM. Docker e gli strumenti di ripristino li installa il programma.
6. Al riavvio imposta **Hardware → CD/DVD → Do not use any media** e **Options → Boot Order** con il disco `scsi0` per primo.

In alternativa, dopo l’installazione imposta l’avvio dal disco dalla shell PVE, sostituendo gli ID annotati:

```bash
qm set ID_STACK --boot order=scsi0
qm set ID_INFISICAL --boot order=scsi0
```

## 3. Verificare e aprire Recovery

Sulla console di ciascuna VM nuova:

```bash
. /etc/os-release
printf 'Ubuntu %s / %s\n' "$VERSION_ID" "$VERSION_CODENAME"
id -u
id -g
sudo -v
hostname -I
systemctl is-active ssh.service --no-pager
```

Per la ISO indicata il sistema riporta `26.04 / resolute`; UID e GID devono essere `1000`, SSH `active`. Annota i due IP.

Apri l’eseguibile **v0.3.4**, inserisci accessi, token GitHub, chiave age ed export AIO, premi **Verifica** e segui la [guida completa](USAGE.md#3-compilare-il-programma-esempio-completo). La VM stack deve raggiungere la VM Infisical via SSH e le nuove VM devono avere accesso a Internet.

Per la prima prova lascia TLS e automazioni di pubblicazione disattivati. Al termine verifica login Infisical, Agent/tunnel, NPM e le applicazioni prima di passare alle nuove VM.
