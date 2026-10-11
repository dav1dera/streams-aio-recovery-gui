<div align="center">

# Streams AIO Recovery

### Dal backup a due VM operative, con un pulsante.

GUI Windows per recuperare Infisical e lo stack Streams AIO, con configurazioni AIO, Agent, NPM, HTTPS e dominio CometNet.

**v0.4.8 · [Scarica la GUI](https://github.com/dav1dera/streams-aio-recovery-gui/releases/tag/v0.4.8) · [Guida dettagliata](docs/USAGE.md) · [Note della versione](docs/RELEASE-NOTES-v0.4.8.md)**

</div>

![Panoramica: Crea da zero e Rileva e continua](docs/screenshots/00-dashboard-v040.png)

## Come ottenere il recupero one click

Il pulsante **Crea da zero** esegue il recupero completo dopo aver preparato le due VM, gli accessi e l’instradamento. Serve un backup completo esistente: il programma ricostruisce il tuo stack dal punto scelto. Non crea le VM in Proxmox e non installa Ubuntu o configura il router.

### 1. Scarica il programma

Accedi a GitHub con un account autorizzato alla repo privata e apri la [release v0.4.8](https://github.com/dav1dera/streams-aio-recovery-gui/releases/tag/v0.4.8).

Scarica **StreamsAIO-Recovery.exe** e **SHA256SUMS**, confronta il checksum e avvia l’eseguibile su Windows. Python, SSH e gli strumenti della GUI sono inclusi; non serve installare Python sul PC. L’eseguibile non ha firma Authenticode.

<details>
<summary>Controllare il checksum in PowerShell</summary>

Nella cartella dei file scaricati:

```powershell
Get-FileHash .\StreamsAIO-Recovery.exe -Algorithm SHA256
Get-Content .\SHA256SUMS
```

L’hash deve corrispondere alla riga di `StreamsAIO-Recovery.exe`. Ogni build ha il proprio checksum: usa quello della stessa release.

</details>

### 2. Prepara due VM Ubuntu vuote

| Destinazione | Sistema e accessi | Risorse iniziali consigliate |
| --- | --- | --- |
| **Stack** | Ubuntu Server 24.04 o 26.04 **amd64**, OpenSSH, utente con sudo e UID/GID 1000 | 4 core, 8 GiB RAM, 80 GiB disco |
| **Infisical** | Ubuntu Server 24.04 o 26.04 **amd64**, OpenSSH, utente con sudo e UID/GID 1000 | 2 core, 4 GiB RAM, 32 GiB disco |

Usa indirizzi distinti e raggiungibili dal PC. I nomi utente possono essere diversi sulle due VM. **Docker viene installato dalla GUI**: puoi partire da Ubuntu con SSH, senza container, volumi o dati di un precedente stack. Dimensiona le risorse secondo il carico e lascia spazio libero per download e ripristino.

La [guida Proxmox](docs/PROXMOX.md) spiega come preparare le VM. Per ripetere una simulazione usa destinazioni nuove o uno snapshot realmente pulito delle sole VM di test. **Crea da zero non cancella un recupero esistente.**

Le nuove VM possono avere IP diversi dalle precedenti: inserisci quelli attuali nella GUI. Se una VM ricreata riutilizza un IP già conosciuto, la **0.4.7 mostra l’impronta SSH precedente e quella nuova**. Confronta la nuova impronta con quella visibile dalla console della VM e accetta solo se corrisponde. La GUI salva la nuova identità dopo l’autenticazione riuscita e aggiorna soltanto quella destinazione. [Verifica dell’impronta](docs/USAGE.md#vm-ricreata-o-indirizzo-ip-diverso).

### 3. Compila «Accessi e backup»

| Campo | Cosa inserire |
| --- | --- |
| **VM Stack e VM Infisical** | IP SSH, utente e password, oppure chiave SSH. Compila sudo o passphrase separati solo se necessari. |
| **Token GitHub** | Token fine-grained con **Contents: Read** su `dav1dera/streams-aio-dr` e `dav1dera/streams-aio-sanitized`. Per il recupero non serve scrittura. |
| **Backup pubblicato** | Premi **Carica backup** e scegli una release completa **schema 2**. Il commit dello stack viene compilato dal manifest: non sostituirlo con un commit scelto a caso. |
| **File della chiave privata age** | Seleziona il file **PRIMARY oppure RECOVERY** compatibile con quel backup. Contiene `AGE-SECRET-KEY-1…`; le stringhe pubbliche `age1…` non decifrano. |
| **Destinazione del recupero** | Scegli la modalità spiegata nel passo successivo. |
| **Indirizzo IP previsto per i domini** | L’indirizzo che i domini devono raggiungere per arrivare alle nuove VM; può essere diverso dall’IP SSH. |

**Non selezionare JSON AIOStreams, JSON AIOMetadata, payload privati o file integrativi per un backup completo schema 2.** Le configurazioni AIO e le credenziali Infisical necessarie sono nel backup; non devi ricopiarle a mano. Se hai già compilato gli input legacy, rimuovili dalle opzioni avanzate prima di iniziare.

Il punto completo contiene questi otto file:

```text
aio-state.tar.gz.age
infisical-agent-infisical-agent.tar.gz.age
infisical-config.tar.gz.age
infisical-postgres-globals.sql.age
infisical-postgres.dump.age
npm-database.sqlite.age
manifest.json
SHA256SUMS
```

### 4. Prepara i domini e scegli la modalità

| Modalità | Quando usarla | Cosa predisporre |
| --- | --- | --- |
| **Prova affiancata alle VM operative** | Le originali restano in funzione | Instradamento dedicato alla prova, usando i nomi del backup. DDNS, Watchtower e Deunhealth restano esclusi. |
| **Recupero della produzione** | Le nuove VM sostituiscono quelle perdute | DNS e router devono portare il traffico alle nuove destinazioni. I controller pubblici vengono attivati per ultimi. Evita due istanze concorrenti dei controller originali. |

Nel campo **Indirizzo IP previsto per i domini** inserisci la destinazione effettiva del loro instradamento. Se i domini passano da Internet normalmente sarà l’IP pubblico previsto; l’IP LAN della VM è corretto soltanto se il percorso dei domini della prova raggiunge davvero quella destinazione. Non copiarci automaticamente l’IP SSH.

NPM, HTTPS e CometNet mantengono i domini del backup. Il loro percorso deve funzionare anche dalla VM e dal container Comet attraverso Gluetun/VPN: modificare solo il file `hosts` del PC non basta. Devono essere disponibili DNS, provider ACME/Cloudflare e le connessioni richieste dalle applicazioni. La GUI verifica la nuova destinazione con una risposta temporanea univoca, evitando di confonderla con il server originale.

### 5. Premi «Crea da zero»

Torna in **Panoramica** e premi **Crea da zero**. Da questo momento la GUI esegue e verifica il percorso:

1. Installa Docker e dipendenze sulle nuove VM.
2. Verifica release, checksum, commit e decifratura.
3. Ripristina database/configurazione Infisical e controlla l’API.
4. Genera configurazioni private, directory e permessi dello stack.
5. Ripristina NPM e i database SQLite nativi di AIOStreams/AIOMetadata.
6. Installa Agent continuo e tunnel SSH permanente.
7. Prepara immagini e avvia i servizi secondo le dipendenze.
8. Configura NPM, certificati, HTTPS e dominio CometNet e verifica la destinazione.
9. Esegue i controlli finali e attiva i controller previsti dalla modalità scelta.

Attendi l’esito senza avviare contemporaneamente altri restore o comandi di modifica sulle VM. **Salva esiti** esporta il registro dei controlli, senza i valori dei secret.

### Se si interrompe: «Rileva e continua»

Conserva lo stato delle VM, riapri gli accessi e premi **Rileva e continua**. La GUI verifica entrambe le destinazioni e riconosce backup, commit e instradamento del tentativo presente; riprende i passi compatibili senza azzerare i dati. Il backup più recente non sostituisce automaticamente quello con cui è iniziato un recupero.

Un rifiuto di proprietà, identity o checkpoint richiede di correggere la causa indicata. Non cancellare file o falsificare marker per superarlo. Per iniziare una nuova simulazione completa prepara nuovamente due destinazioni pulite.

## Quali dati ritrovi

| Componente | Recupero |
| --- | --- |
| **Infisical** | Database, ruoli, configurazione privata, secret e impostazioni catturati nel punto scelto. |
| **AIOStreams / AIOMetadata** | Snapshot SQLite nativi: identità, profili, configurazioni, hash delle password e record collegati. Immagini e chiavi applicative devono corrispondere al backup. |
| **NPM** | Database, utenti, access list e routing; collegamenti alle nuove VM e verifica TLS/HTTPS. |
| **Agent** | Configurazione e bootstrap privato, Agent continuo e tunnel verso Infisical. |
| **Stack** | Compose e configurazioni del commit associato, immagini fissate, directory e permessi. |
| **Comet / CometNet / StremThru e cache escluse** | Configurazioni e credenziali recuperate; database ricostruibili inizializzati vuoti. Scraping e cache ripartono. |

I dispositivi esterni puntati da NPM non vengono creati dal recupero delle due VM. Una route verso un dispositivo spento può restare come avviso con configurazione conservata. Lo snapshot AIO non comprende tutti i volumi Docker né l’intero PostgreSQL applicativo. Token scaduti o revocati presso servizi esterni possono richiedere riautorizzazione.

## Dopo il recupero

Accedi a Infisical, NPM, AIOStreams e AIOMetadata; confronta profili, URL addon e integrazioni. Prova CometNet anche dall’esterno e riavvia entrambe le VM per verificare la persistenza. Il completamento dei controlli automatici non sostituisce queste prove d’uso.

**Backup futuri:** il coordinatore sull’host originale cattura ogni giorno alle **04:30 Europe/Rome**, con ritardo fino a 10 minuti, e conserva **cinque release verificate**. Ogni cattura sincronizza prima la configurazione pubblica e salva lo stato Infisical e i database AIO presenti in quel momento. Le release esistenti non cambiano quando modifichi lo stack.

La GUI **non reinstalla automaticamente il coordinatore dei backup sul nuovo host**. Dopo una sostituzione definitiva segui il [README DR](https://github.com/dav1dera/streams-aio-dr#install-on-docker-stack), ripristina timer e accessi di scrittura e verifica una nuova pubblicazione. Un nuovo servizio richiede anche una scelta esplicita per il suo database e un contratto di recupero compatibile.

## Cosa salvare per cambiare PC o affrontare un guasto

Conserva fuori dal PC, in copie protette:

- **Entrambi i file privati age PRIMARY e RECOVERY**; basta uno compatibile per decifrare, ma perdere entrambi rende inutilizzabili i backup cifrati.
- GUI, checksum e questa guida; le chiavi age sono portabili e non sono legate a Windows.
- Una copia completa degli otto file di una release verificata, con il riferimento al commit pubblico associato.
- Accesso all’account GitHub e recupero MFA, accessi alle nuove VM e accesso a DNS/router/provider TLS. Un token GitHub può essere ricreato.

Il kit contiene materiale privato: non caricarlo nei repository. La GUI scarica da GitHub; la copia locale cifrata è un fallback per il recupero tecnico, **non un import offline supportato dalla GUI**. Il kit non include tutte le immagini Docker e i pacchetti necessari a un’installazione senza Internet.

## Stato delle verifiche

Il report della **0.4.5 del 10 ottobre 2026** ha completato tutte le fasi di bootstrap e i controlli di Infisical, AIO nativo, Agent, servizi, NPM, TLS e dominio CometNet sulle due VM di recupero, in modalità produzione; resta un avviso per un upstream esterno non raggiungibile. La release `dr-20261009T194149Z` usata nella prova ha superato inventario, SHA256 e decifratura di tutti i sei artifact con PRIMARY e RECOVERY.

La baseline Ubuntu appena reinstallata senza Docker non è confermata. Login/profili, integrazioni esterne, P2P pubblico e persistenza dopo riavvio restano da collaudare. [Checklist finale](docs/USAGE.md#collaudo-finale).

## Guide e sviluppo

[Uso dettagliato](docs/USAGE.md) · [Preparazione Proxmox](docs/PROXMOX.md) · [Note 0.4.8](docs/RELEASE-NOTES-v0.4.8.md)

Il programma usa Python/Tk e SSH. Per una build locale usa `build.ps1`; i test Python sono in `tests/`. La pipeline GitHub esegue controlli di sicurezza, compatibilità Ubuntu e self-test dell’eseguibile Windows prima della pubblicazione. Le versioni delle applicazioni devono restare compatibili con il backup e con il profilo verificato.

## Configurazione locale e segreti

Dalla 0.4.6 i backup possono contenere anche la configurazione ordinaria salvata
sulla VM stack: indirizzi interni, sottoreti, nomi e URL senza credenziali.
Password, token, chiavi applicative e stringhe di connessione con password
restano in Infisical. Il recupero legge entrambi dal backup selezionato;
non devi aggiungere file integrativi alla GUI.

I backup con configurazione locale richiedono **GUI 0.4.6 o successiva**.
La 0.4.6 continua a leggere anche i backup precedenti. Le cartelle AIO con
segreti vengono ancora lette dinamicamente; un valore locale in conflitto con
un valore remoto ferma il recupero.

Il confronto temporaneo dei 20 output Agent e i test automatici verificano
la nuova separazione. Il collaudo completo su due nuove VM resta da eseguire:
le precedenti VM di test non sono più disponibili.
