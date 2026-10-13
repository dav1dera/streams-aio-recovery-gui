# Creare un setup come questo, da zero

Questa guida spiega come organizzare due VM, tenere i segreti in Infisical e conservare su GitHub ciò che serve al recupero. Per ripristinare un backup già esistente usa invece il [README della Recovery GUI](../README.md).

**Il progetto attuale è adattato allo stack di riferimento.** La GUI usa i repository `dav1dera/streams-aio-sanitized` e `dav1dera/streams-aio-dr`; anche gli strumenti di pubblicazione hanno percorsi, utenti e repository prestabiliti. Un'altra persona può riprodurre questa architettura, ma deve adattare gli strumenti ai propri repository e creare i propri segreti, mapping e backup. La GUI non è un installatore universale che crea un progetto Infisical nuovo.

## 1. Capire dove va ogni cosa

| Componente | Dove si trova | A cosa serve |
| --- | --- | --- |
| VM stack | Ubuntu con Docker Compose | Esegue i servizi, Nginx Proxy Manager e l'Agent Infisical. |
| VM Infisical | VM separata | Conserva i segreti; il deployment comprende backend, PostgreSQL e Redis. |
| Repository pubblico sanitizzato | GitHub | Conserva Compose, impostazioni pubbliche, template e istruzioni per ricreare lo stack. |
| Repository DR privato | GitHub | Conserva gli strumenti DR e le release con i backup cifrati. |
| Chiavi private age | Copie protette fuori dalle VM e dai repository | Permettono di decifrare i backup anche dopo aver perso VM e PC. |
| AdGuard/DNS e router | Dispositivi esterni | Portano i domini e il traffico HTTPS alla VM stack. |

Nel setup di riferimento lo stack originale usa `.11`, Infisical `.28`. Sono indirizzi di esempio: per le nuove VM inserisci gli IP corretti nella GUI. Il nome HTTPS di Infisical arriva prima a NPM sulla VM stack, che inoltra alla VM Infisical.

## 2. Preparare le due VM e i propri repository

Per destinazioni compatibili con la Recovery GUI prepara due VM **Ubuntu Server 24.04 o 26.04 amd64**, distinte, con OpenSSH, un utente con sudo e UID/GID 1000. Il nome utente può essere diverso sulle due VM. Riserva gli IP nel DHCP o assegna indirizzi stabili. Vedi la [guida Proxmox](PROXMOX.md).

Le risorse dipendono dai servizi. Come punto di partenza: stack con 4 core, 8 GiB RAM e 80 GiB disco; Infisical con 2 core, 4 GiB RAM e 32 GiB disco. Mantieni spazio libero per immagini, staging e backup. La GUI installa Docker durante il recupero; la creazione iniziale delle VM e di Ubuntu rimane esterna.

Per un setup personale crea un repository per la configurazione pubblica e uno **privato** per il DR. Configura l'accesso GitHub separando gli usi:

- **Pubblicazione e backup automatici:** il processo sulla VM stack deve poter scrivere nei propri repository. Git e GitHub CLI devono funzionare senza richieste interattive per l'utente del servizio.
- **Recupero dalla GUI:** basta un token con **Contents: Read** sui due repository previsti dal programma.

Le credenziali GitHub non vanno in Compose, nelle unità systemd, nei commit o nella documentazione. Le chiavi SSH per Git non sostituiscono automaticamente l'accesso alle API GitHub Releases.

Per cambiare proprietario/repository occorre adattare almeno il backend della GUI e gli strumenti `sync-public-stack.py`, `dr-releases.py` e `update-dr.sh`, oltre al profilo e alle verifiche che li accompagnano. Nel coordinatore di riferimento sono prestabiliti anche l'host e l'utente Infisical, i percorsi e la chiave SSH del backup. Un fork da solo non li cambia.

## 3. Installare Infisical e collegare l'Agent

Per il **primo setup**, installa Infisical sulla sua VM e crea il tuo amministratore, progetto, ambiente e cartelle dei segreti. Configura un'identità applicativa con accesso alle sole cartelle necessarie all'Agent. La GUI recupera questi elementi da un backup completo; non li inventa quando il backup non esiste.

Il profilo di recupero incluso prevede Infisical in `/opt/infisical`, servizi `backend`, `db` e `redis`, immagini fissate e PostgreSQL 14. Un'installazione iniziale diversa deve essere resa compatibile con quel profilo e con i produttori di backup prima di affidarsi al recupero automatico.

Sulla VM stack configura l'Agent Infisical con i propri accessi privati e con i **mapping**: ogni mapping dice quale segreto leggere e in quale file scriverlo. Conserva la configurazione dell'Agent e i suoi accessi di bootstrap nel percorso privato previsto dal backup. Non metterli nel repository pubblico.

Nel recupero la GUI installa e abilita `infisical-agent.service` e `streams-aio-infisical-tunnel.service`. Il tunnel SSH fornisce all'Agent un collegamento permanente all'API della nuova VM Infisical. I due servizi ripartono con Ubuntu; la GUI Windows non deve restare aperta. Nel primo setup questi collegamenti e permessi vanno invece predisposti e verificati.

## 4. Separare impostazioni pubbliche e segreti

**Pubblico** significa un'impostazione che hai deciso di rendere visibile: ad esempio porte, numero di worker, subnet Docker e indirizzi dei container. **Privato** significa password, token, chiavi applicative, credenziali e URL che contengono una password. Un parametro non diventa pubblico solo perché ha un nome innocuo.

Esempio per un servizio nuovo:

```text
streams-aio/
├── docker-compose.yml
├── data/nuovo-servizio/.env       impostazioni pubbliche
└── .secrets/nuovo-servizio.env    segreti generati dall'Agent
```

Nel Compose il servizio legge prima il file pubblico e poi quello privato:

```yaml
env_file:
  - ./data/nuovo-servizio/.env
  - ./.secrets/nuovo-servizio.env
```

Un valore ripetuto nel secondo file prevale sul primo; una voce in `environment:` prevale sugli env file. Evita quindi duplicati che sovrascrivano involontariamente il valore privato. Dopo una modifica alle variabili, il container può richiedere una ricreazione per usarle.

I file misti YAML/JSON/TOML richiedono template e associazioni esplicite dei campi privati. Le configurazioni gestite e riscritte dalle applicazioni devono essere inizializzate senza sovrascriverle continuamente con l'Agent. Il repository pubblico contiene il piano di rendering e le associazioni approvate; non contiene i valori dei segreti.

La sanitizzazione applica regole su percorsi, tipi di file, variabili e valori privati conosciuti. **Non riconosce infallibilmente ogni segreto possibile.** Controlla ciò che dichiari pubblico. Un file escluso dal repository pubblico, inoltre, non entra automaticamente nel backup cifrato.

## 5. Attivare la sincronizzazione pubblica

La sincronizzazione segue **VM stack → GitHub**: registra le modifiche locali consentite. Non scarica modifiche GitHub per distribuirle ai container e non avvia un servizio appena aggiunto.

Questi sono i comandi del **deployment di riferimento**, con utente `pi` e stack in `/home/pi/streams-aio`. Per un altro setup adatta prima repository, percorsi, utenti e unità. Non eseguirli su un host diverso pensando che configurino automaticamente un fork personale.

Il worker usa una cartella separata dallo stack. Richiede Git, GitHub CLI autenticata, Python 3.11+ con venv e accesso a Docker/Compose per l'utente del servizio. Per una prima installazione, la cartella `tooling` deve essere nuova:

```bash
SYNC_HOME=/home/pi/.local/share/streams-aio-public-sync
sudo apt-get install -y git gh python3-venv
mkdir -p "$SYNC_HOME"
git clone --depth 1 https://github.com/dav1dera/streams-aio-sanitized.git "$SYNC_HOME/tooling"
python3 -m venv "$SYNC_HOME/venv"
"$SYNC_HOME/venv/bin/python" -m pip install -r "$SYNC_HOME/tooling/scripts/requirements-public-sync.txt"
```

Autentica `gh` come utente del servizio, ad esempio con `gh auth login --hostname github.com`. Controlla prima senza pubblicare:

```bash
"$SYNC_HOME/venv/bin/python" -B "$SYNC_HOME/tooling/scripts/sync-public-stack.py" \
  --source /home/pi/streams-aio --seamless
```

Dopo `PUBLIC_SYNC_CHECK PASS`, installa la policy e il timer. Il verificatore finale esegue una pubblicazione reale:

```bash
"$SYNC_HOME/venv/bin/python" -B "$SYNC_HOME/tooling/scripts/install-public-sync-policy.py" \
  --source /home/pi/streams-aio
sudo install -m 644 "$SYNC_HOME/tooling/systemd/streams-aio-public-sync.service" /etc/systemd/system/
sudo install -m 644 "$SYNC_HOME/tooling/systemd/streams-aio-public-sync.timer" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now streams-aio-public-sync.timer
sudo -v
"$SYNC_HOME/tooling/scripts/verify-public-sync-systemd.sh"
```

Il timer controlla circa ogni **15 minuti**, con un ritardo casuale fino a un minuto; il primo controllo avviene circa cinque minuti dopo l'avvio. Pubblica un commit solo quando cambia qualcosa e verifica la rilettura. Se un controllo fallisce, la pubblicazione si ferma. Dettagli e aggiornamento del worker: [README dello stack sanitizzato](https://github.com/dav1dera/streams-aio-sanitized#attivare-la-sincronizzazione).

## 6. Preparare le chiavi age e il backup privato

Per un setup nuovo crea **due identità age indipendenti**, PRIMARY e RECOVERY, su un dispositivo fidato. `age-keygen -o primary.agekey` e `age-keygen -o recovery.agekey` sono esempi di generazione: non sovrascrivere chiavi esistenti e non rigenerarle per recuperare backup vecchi.

Conserva entrambi i file **privati** fuori dalle VM e dai repository, con copie protette recuperabili anche perdendo il PC. I produttori di backup ricevono solo le corrispondenti chiavi **pubbliche** `age1…` e cifrano per entrambe. Un file privato compatibile basta per decifrare; perdere entrambi rende inutilizzabili i backup.

Il coordinatore DR sulla VM stack richiede:

- il worker pubblico già funzionante;
- il produttore locale per NPM e configurazione/bootstrap Agent;
- il produttore remoto per database, ruoli e configurazione Infisical;
- il produttore per gli snapshot SQLite nativi AIOStreams e AIOMetadata;
- SSH non interattivo e chiavi host verificate verso Infisical, permessi sudo limitati ai wrapper previsti e GitHub CLI con accesso alle Releases private.

**La sola clonazione del repository DR non installa tutti questi prerequisiti.** I wrapper locale e remoto devono essere già predisposti. La [procedura DR](https://github.com/dav1dera/streams-aio-dr#install-on-docker-stack) documenta l'installazione del produttore AIO e delle unità; conserva anche gli strumenti e la configurazione necessari a riprodurre i produttori del tuo setup. Non sostituire questo passaggio con un semplice `git push` della cartella dello stack.

Nel riferimento, il coordinatore è `/home/pi/streams-aio-dr/scripts/update-dr.sh`. Esegue prima la sincronizzazione pubblica, associa il relativo commit al backup, cattura i componenti, cifra prima dell'upload e verifica inventario e checksum rileggendo da GitHub. Solo dopo la pubblicazione verificata applica la retention.

Il timer `streams-aio-dr.timer` parte ogni giorno alle **04:30 nel fuso della VM**, con ritardo fino a dieci minuti e recupero dell'avvio perso se la VM era spenta. Nel riferimento il fuso è `Europe/Rome`. Conserva le **cinque release verificate** più recenti; anche i backup manuali usano questa retention. La sincronizzazione pubblica ogni 15 minuti non rende altrettanto frequente il backup privato.

## 7. Verificare il primo backup e quelli successivi

Non considerare conclusa la configurazione perché il timer è presente. Avvia e verifica una cattura reale:

```bash
sudo systemctl start streams-aio-public-sync.service
sudo systemctl start streams-aio-dr.service
systemctl list-timers streams-aio-public-sync.timer streams-aio-dr.timer --no-pager --full
systemctl show streams-aio-public-sync.service streams-aio-dr.service \
  -p Id -p Result -p ExecMainStatus -p ExecMainExitTimestamp
```

Un servizio `oneshot` può tornare `inactive` dopo il successo: controlla `Result=success`, `ExecMainStatus=0`, la data dell'ultima esecuzione e il timer attivo. Controlla che su GitHub compaia davvero una nuova release completa schema 2 con sei artifact cifrati, manifest e checksum. Il manifest deve indicare il commit pubblico associato.

Una prova su **due VM di test vuote**, usando le tue chiavi e la GUI, verifica il percorso che i soli timer non provano. Completa anche login, profili AIO, addon in Stremio, integrazioni e riavvio delle VM. Non usare le originali come destinazioni vuote e non mettere due controller di produzione concorrenti online.

Quando cambi segreti, profili AIO o configurazioni, la release precedente resta invariata: il nuovo stato entra nel prossimo backup riuscito. Dopo modifiche importanti avvia un backup manuale. Conserva anche una copia protetta di una release completa e il riferimento al suo commit pubblico. La GUI scarica da GitHub: la copia locale non è un import offline supportato e non include tutte le immagini Docker o i pacchetti necessari.

## 8. Aggiungere servizi e mantenere il recupero funzionante

Per un nuovo servizio applica questa sequenza:

1. Aggiungi Compose, impostazioni pubbliche e directory locali.
2. Se servono segreti, creali in Infisical e aggiungi i mapping dell'Agent.
3. Prepara dipendenze, utenti/database, permessi e controlli di salute. Se cambia il contratto di recupero, aggiorna anche template e bootstrap.
4. Decidi quali dati possono ripartire vuoti e quali devono essere salvati. Per questi ultimi serve una cattura e un ripristino dedicati.
5. Applica e verifica il servizio locale, controlla la pubblicazione sanitizzata e crea un nuovo backup completo.

La pubblicazione conserva le modifiche consentite, ma non può inventare un inizializzatore o il backup di un'applicazione nuova. Comet, StremThru, Redis e le altre cache dichiarate ricostruibili non hanno lo stesso recupero dei database nativi AIO.

## 9. Dopo una sostituzione definitiva delle VM

Adatta manualmente DNS rewrite in AdGuard/DNS locale e inoltri del router TCP **80/443** alla nuova VM stack. Verifica anche il percorso dei domini da Windows, telefono e dalle applicazioni: il DNS del solo PC non basta. I dispositivi esterni referenziati da NPM restano esterni al recupero.

La GUI riattiva Agent e tunnel, ma **non reinstalla automaticamente il coordinatore dei backup e i timer di pubblicazione sul nuovo host**. Ripristina tooling, produttori, destinatari age pubblici, accessi GitHub di scrittura e SSH del backup; verifica una nuova release completa. Evita due VM che pubblicano contemporaneamente gli stessi backup.

Per l'uso della GUI, la scelta tra prova e produzione e gli errori recuperabili: [README](../README.md) e [guida d'uso](USAGE.md).
