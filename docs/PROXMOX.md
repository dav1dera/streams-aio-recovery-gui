# Due VM di prova su Proxmox · Recovery 0.4.0 preview

La nuova dashboard accetta **Ubuntu Server 26.04 o 24.04 amd64**, con i rispettivi codename `resolute` e `noble`. Per la prova puoi usare `ubuntu-26.04.1-live-server-amd64.iso` già caricata nello storage `local`; se il nome effettivo è diverso, sostituiscilo nei comandi sotto.

Questa guida prepara due destinazioni pulite. Il recupero completo della 0.4.0, compresi AIO automatico, domini e CometNet pubblico, deve ancora essere collaudato sulle VM. Creare le VM non attesta l’equivalenza funzionale allo stack originale.

## 1. Creare le VM

Puoi usare **Create VM** due volte dalla GUI Proxmox. Seleziona la ISO Ubuntu caricata, un disco su uno storage per immagini VM, controller **VirtIO SCSI**, rete **VirtIO** e il bridge della LAN. Usa nuovi VM ID assegnati da Proxmox.

| VM nuova | Nome suggerito | Risorse iniziali per la prova | Esempio di utente Ubuntu |
| --- | --- | --- | --- |
| Stack | `streams-aio-dr-test` | 4 core, 8 GiB RAM, 80 GiB disco | `test` |
| Infisical | `infisical-dr-test` | 2 core, 4 GiB RAM, 32 GiB disco | `test2` |

Sono allocazioni iniziali, da adattare alle risorse libere del nodo e al carico delle applicazioni. Controlla RAM e disco prima di avviare entrambe. I nomi utente sono esempi: il nuovo profilo operativo usa l’identità SSH effettiva, con UID/GID 1000.

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
3. Crea il primo utente su ciascuna VM con UID/GID 1000 e sudo. Puoi usare `test` e `test2`, oppure altri nomi. Il recupero usa la home effettiva dell’utente SSH; non è legato a `/home/test` o a una release storica.
4. Seleziona **Install OpenSSH server**. Usa password SSH oppure una chiave già gestita sul PC.
5. Completa l’installazione sul disco della VM. Docker e gli strumenti di ripristino li installa il programma.
6. Al riavvio imposta **Hardware → CD/DVD → Do not use any media** e **Options → Boot Order** con il disco `scsi0` per primo.

In alternativa, dopo l’installazione imposta l’avvio dal disco dalla shell PVE, sostituendo gli ID annotati:

```bash
qm set ID_STACK --boot order=scsi0
qm set ID_INFISICAL --boot order=scsi0
```

## 3. Verificare le destinazioni

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

Per la ISO indicata il sistema riporta `26.04 / resolute`; con Ubuntu 24.04 riporta `24.04 / noble`. UID e GID devono essere `1000`, SSH `active`. Annota i due IP e verifica che siano diversi dagli originali e tra loro.

Il PC Windows deve raggiungere entrambe via SSH. La VM stack deve raggiungere la VM Infisical via SSH; le nuove VM devono avere accesso a Internet per scaricare repository, immagini e dipendenze.

Prima del primo recupero puoi creare uno snapshot Proxmox delle due installazioni pulite. Per ripetere una simulazione da zero torna a quegli snapshot o crea nuove VM di test. **Crea da zero** nella GUI non cancella container, volumi o dati estranei e non reinstalla Ubuntu.

## 4. Preparare il percorso dei domini

La 0.4.0 usa NPM, HTTPS e il dominio reale di CometNet. La raggiungibilità SSH delle VM non dimostra che i domini puntino alla destinazione corretta.

| Modalità della GUI | Preparazione della rete |
| --- | --- |
| **Prova affiancata alle VM operative** | Mantieni operative le VM originali e prepara un instradamento DNS del test verso le nuove VM. Deve essere visibile anche a Comet attraverso Gluetun/VPN. DDNS, Watchtower e Deunhealth restano esclusi. |
| **Recupero della produzione** | Prepara DNS e port forwarding del router verso le VM sostitutive. I controller pubblici vengono attivati per ultimi, dopo i controlli dei domini. |

Modificare soltanto il file hosts di Windows non cambia la risoluzione dei contenitori o della VPN. Un certificato valido servito dal server originale non basta: il recupero deve raggiungere il nuovo NPM dal percorso usato da CometNet. La prova P2P da Internet va verificata separatamente.

La GUI non configura Proxmox, DNS o router. Il campo **Indirizzo IP previsto per i domini** registra la destinazione scelta; non crea il relativo instradamento. Per una prova affiancata non spostare il traffico pubblico della produzione solo per superare un controllo.

## 5. Aprire Recovery

Apri la **0.4.0 preview** e seleziona **Accessi e backup**:

1. Inserisci i due accessi SSH e il token GitHub con Contents: Read sui repository dello stack e DR.
2. Premi **Carica backup** e scegli una release completa schema 2, con snapshot AIO nativo. Il commit associato viene letto dal manifest.
3. Seleziona il file della identity age privata PRIMARY o RECOVERY compatibile con quel backup. Non serve caricare export JSON AIO nel percorso normale.
4. Scegli la modalità di recupero e l’indirizzo previsto per i domini.
5. Torna a **Panoramica**: premi **Crea da zero** per le due VM pulite, oppure **Rileva e continua** per un tentativo compatibile già presente.

Segui la [guida completa](USAGE.md). Prima di considerare terminata la prova, verifica login, profili AIO, Agent/tunnel, NPM/HTTPS, OAuth e CometNet, poi riavvia entrambe le VM e ripeti i controlli. [Elenco del collaudo finale](USAGE.md#collaudo-finale).
