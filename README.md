# Streams AIO Recovery

Un programma Windows per preparare una **VM nuova** e ricostruire lo stack dai repository GitHub, dai secret Infisical e dagli export AIO. La repository è privata. Codice e programma non contengono credenziali o backup reali.

## Ripristino delle due VM · versione 0.2

Il pulsante **Ripristina entrambe le VM** controlla le due destinazioni prima di modificarle, installa Docker e dipendenze, recupera la release privata verificando SHA256, ripristina il server Infisical e legge i segreti dal server appena recuperato. Poi prepara lo stack, recupera NPM e gli export AIO, installa l’Agent continuo e avvia i servizi per dipendenze. L’opzione TLS richiama la riemissione/verifica NPM esistente.

Il deployment Infisical originale è stato identificato su Fedora 44: `/opt/infisical`, servizi Compose `backend`, `db`, `redis`, database/utente/proprietario `infisical`, porta API 80. Le **nuove destinazioni** richiedono entrambe Ubuntu Server 24.04 amd64. Il restore usa i digest confermati di Infisical `v0.165.16`, PostgreSQL `14.24` e Redis, senza dipendere da tag mobili. `ENCRYPTION_KEY`, `AUTH_SECRET` e connessioni vengono conservati dal backup cifrato; non vengono rigenerati.

La preparazione e il semplice stato running/healthy **non certificano** login, enrollment Headscale/Headplane, raggiungibilità degli upstream, compatibilità delle immagini o funzionamento AIO. Nessuna prova DR completa con backup reali è stata eseguita per questa versione. L’app indica separatamente preparazione e avvio, senza dichiarare un ripristino completo.

## Aprire il programma

Scarica `StreamsAIO-Recovery.exe` e `SHA256SUMS` dalla [release privata v0.2.0](https://github.com/dav1dera/streams-aio-recovery-gui/releases/tag/v0.2.0), accedendo con il tuo account GitHub. Le compilazioni sono anche disponibili in **Actions → Safety tests and Windows app → Artifacts**. L’eseguibile comprende Python e SSH; non richiede Python installato sul PC. È privo di firma Authenticode: verifica provenienza e SHA256 del file scaricato.

Per eseguire il sorgente con Python 3.11+:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

Per compilare su Windows: `./build.ps1`. I file in `dist/` e `build/` sono esclusi da Git. Il workflow non usa secret reali né contatta le VM di produzione.

## Cosa inserire

1. **VM docker-stack nuova:** host/IP, utente, password SSH oppure chiave SSH. Questa versione richiede Ubuntu Server 24.04 amd64, utente UID/GID 1000 e sudo. Attiva SSH durante l’installazione Ubuntu. Gli host con container/volumi o stack preesistente vengono rifiutati, anche se i container sono spenti.
2. **GitHub:** fine-grained token con `Contents: Read` sulle repository `streams-aio-dr` e `streams-aio-sanitized`. Il programma non crea token né modifica i permessi dell’account. `Carica release` mostra i tag pubblicati e risolve il commit pubblico attuale: scegli un punto coerente con la release, senza presumere un accoppiamento atomico tra i due repository.
3. **age identity:** scegli dal PC il file PRIMARY o RECOVERY recuperabile fuori dalle VM. La chiave viene trasferita sulla VM selezionata via SSH in un’area privata esterna ai clone; non viene committata né inviata a GitHub. L’app non gestisce automaticamente identity cifrate con passphrase o hardware token.
4. **AIO:** scegli gli export JSON logici AIOStreams 2.35.3 / AIOMetadata 3.3.0, oppure un `PRIVATE_DR_PAYLOAD` completo. I binding UUID/password devono esistere in `/dr/AIO_PROFILE_BINDINGS` in Infisical. Le release DR automatiche non contengono questi export. SQLite grezzi, archivi e versioni diverse non vengono convertiti implicitamente.
5. **Nuova VM Infisical:** host/IP, porta e credenziali SSH/sudo, oppure chiave SSH. Anche qui l’utente deve avere UID/GID 1000. Per il pulsante unico non serve inserire un endpoint API: il programma crea il collegamento SSH sicuro. Progetto/ambiente e Universal Auth provengono dal backup Agent. I campi avanzati servono per la modalità di solo stack o per un bootstrap diverso.

Al primo accesso confronta l’impronta SSH con quella della VM tramite la console. Una chiave già nota e cambiata blocca l’accesso: non viene accettata automaticamente.

## Percorso operativo

**Verifica** controlla accesso GitHub, SSH, sudo, sistema e destinazioni nuove. Non installa software né avvia container. Quando è indicata la seconda VM, la verifica anche come destinazione Infisical. Due indirizzi che puntano alla stessa macchina vengono rifiutati dal pulsante unico.

**Ripristina entrambe le VM** esegue questo ordine:

```text
Controlli delle due VM → installazione sulla nuova VM Infisical
Release scelta → SHA256/manifest/age → configurazione privata
PostgreSQL isolato → ruoli originali → database con owner/grant originali
Infisical con le chiavi recuperate → controllo /api/status
Tunnel SSH temporaneo via Windows → login Universal Auth sul nuovo Infisical
Preparazione dello stack → NPM + import AIO → preflight
Agent nativo 0.43.137 + tunnel SSH permanente tra le VM
Avvio per dipendenze → eventuale TLS → test funzionali da eseguire
```

La fase PostgreSQL usa un utente bootstrap distinto e casuale, per restaurare i ruoli senza ignorare collisioni o errori SQL. Globals e dump vengono applicati con arresto al primo errore e transazioni; il dump deve essere di `infisical`, PostgreSQL 14. L’utente bootstrap viene poi disabilitato per il login. Redis riparte vuoto. La configurazione accetta soltanto `.env` e `docker-compose.prod.yml` nelle due strutture di archivio riconosciute, senza symlink, file extra, bind host, database esterni o esposizione delle porte PostgreSQL/Redis. Un deployment diverso richiede aggiornare il contratto esplicitamente.

**Prepara stack** resta disponibile se Infisical è già recuperato e raggiungibile via HTTPS. Mostra host, release e commit prima di scrivere. Trasferisce il runner e gli input in `~/.local/share/streams-aio-recovery/upload-<id>/`, installa Docker dal repository APT ufficiale e usa un venv separato per le dipendenze. Quindi:

```text
GitHub → clone pubblico sul commit scelto + manager DR separato
Release pubblicata → inventario esatto + SHA256 + manifest + envelope age
age → plaintext privato esterno ai clone
Agent cifrato → bootstrap Universal Auth, se la struttura è riconosciuta
Infisical → snapshot privati → renderer fresh → env/config e directory
NPM SQLite → preparazione proxy/TLS
Export AIO → nuovi SQLite mediante l’importatore esistente
Preflight reale + Compose → PREPARED
```

Il manager del repo privato effettua gli stessi controlli fail-closed della pubblicazione: sette asset esatti, checksum, manifest coerente e artifact age con recipient PRIMARY/RECOVERY. Nessun cleanup remoto, retention, upload Release o push Git viene avviato dall’app. La versione del manager privato viene registrata nel checkpoint.

I sette file sono `npm-database.sqlite.age`, `infisical-agent-infisical-agent.tar.gz.age`, `infisical-config.tar.gz.age`, `infisical-postgres.dump.age`, `infisical-postgres-globals.sql.age`, `manifest.json`, `SHA256SUMS`. Gli archivi vengono estratti solo come file/directory regolari in storage privato, senza symlink, traversal, ownership esterna o esecuzione di hook. Il materiale server resta sotto `~/.local/share/streams-aio-infisical-recovery/`; il deployment recuperato è `/opt/infisical` con configurazione privata e `recovery-compose.json` con immagini bloccate per digest.

**Avvia servizi** richiede un checkpoint di preparazione riuscita sullo stesso host, ripete il preflight e aspetta i servizi per ogni onda del manifest. Rifiuta container di altri deployment e non abilita Watchtower, Cloudflare DDNS o deunhealth. Non installa timer pubblici/privati. L’opzione TLS richiama i helper NPM esistenti; può usare Cloudflare/ACME reali e richiede upstream/DNS funzionanti.

Il clone pubblico resta sul commit scelto, con HEAD detached. L’app non sincronizza verso GitHub e non va usata per aggiornare uno stack esistente. I timer di pubblicazione e backup, i producer privati esterni e i controller DDNS/Watchtower/deunhealth restano disattivati sulla prova: si attivano soltanto quando questa VM diventa quella operativa, con credenziali GitHub di scrittura e connessioni ai producer configurate. Il token di lettura del ripristino non abilita push o pubblicazione Release.

## Agent continuo e API protetta

Con l'Agent continuo attivo, progetto/ambiente e Universal Auth devono provenire dal backup originale: lascia vuoti i quattro campi avanzati. Un override viene rifiutato prima di modificare le VM, per evitare che il renderer e l'Agent leggano scope diversi. Per un bootstrap diverso usa la preparazione del solo stack e configura separatamente l'Agent dopo il collaudo.

L’opzione Agent è attiva per il pulsante unico. Installa la CLI `0.43.137` dall’artifact ufficiale `cli_0.43.137_linux_amd64.tar.gz` dopo aver controllato il SHA256 fissato nel codice. Il servizio `infisical-agent.service` gira come utente deployment, con umask 0077 e output escluso dal journal; aggiorna i mapping privati `.secrets` recuperati dall’archivio ogni 60 secondi. La copertura degli env del piano deve essere completa. Honey, Seanime, Headscale e altre configurazioni mutable vengono inizializzate una sola volta. I comandi `execute.command` recuperati restano nell’archivio privato e vengono rimossi dalla configurazione attivata durante il test. Un secret aggiornato non ricrea automaticamente il container: gli hook si rivedono dopo il collaudo.

`streams-aio-infisical-tunnel.service` collega solo `127.0.0.1:18180` sulla VM stack alla porta API locale del nuovo Infisical. Il collegamento prosegue senza Windows. La chiave Ed25519 viene generata sulla VM stack e resta fuori da Git; sull’altra VM viene creato un account dedicato `streams-aio-tunnel`, limitato a quell’API, senza shell, terminale, agent forwarding o forwarding remoto. Il server è autenticato con la stessa chiave pubblica SSH già verificata dalla GUI: nessun `StrictHostKeyChecking=no` e nessun `ssh-keyscan` accettato alla cieca. Questo tunnel non modifica DNS o routing pubblico.

## Compatibilità e casi che richiedono intervento

- Il bootstrap Agent riconosce un solo `agent-config.yaml/yml/json` Universal Auth, riferimenti assoluti recuperati esattamente nell’archivio e un solo progetto/ambiente. Non cerca credenziali per basename o su host diversi.
- Gli import Infisical con precedenza ambigua vengono rifiutati. Nessun segreto mascherato può diventare un input del renderer.
- Gli export AIO vengono associati agli UUID dei binding; per un singolo profilo senza UUID si usa quell’unico profilo. Profili mancanti, duplicati o ambigui richiedono un payload esplicito. OAuth e account collegati richiedono le normali riautorizzazioni; l’app non elimina campi per far passare l’importazione.
- NPM e importer AIO restano legati ai contratti del repo pubblico: NPM 2.16.0, AIOStreams 2.35.3, AIOMetadata 3.3.0. Il digest aggiornato non dimostra la compatibilità del helper. Verifica le immagini durante la prova prima del passaggio in produzione.
- Se un passo non atomico viene interrotto dopo aver scritto configurazioni/database, la ripresa si blocca per revisione. Non cancellare marker/checkpoint né rinominare database per aggirare il controllo. Download, decifratura e raccolta input usano staging privato e conservano copie fallite.

## Credenziali e log

Password SSH/sudo, passphrase e token GitHub non vengono salvati sul PC. Il solo dato persistente locale dell’app è `known_hosts` con chiavi **pubbliche** SSH, sotto `%LOCALAPPDATA%/StreamsAIORecovery/`. Il token arriva alle due destinazioni tramite stdin delle connessioni SSH e resta in memoria; è passato soltanto ai processi Git/gh che leggono GitHub, mai all’ambiente dei processi Docker. Non viene creato un file contenente il token. Il helper GitHub per Git viene configurato sull’utente deployment; il token non viene inserito negli URL o argomenti dei processi.

Le chiavi age, gli export e i file Universal Auth trasferiti restano in storage privato sulla VM per la prova e l’eventuale diagnosi. Le directory sono 700, i file privati 600, gli output del renderer seguono il loro contratto UID/GID/ACL. Non sono cancellati automaticamente a fine prova. Dopo il collaudo gestisci quel materiale secondo la tua custodia operativa.

L’app scarta stdout/stderr grezzi di APT, Docker e script. Mostra eventi strutturati con passi/esiti/codici, senza valori dei file. `Salva esiti` salva soltanto questi eventi, senza host, percorsi, token o credenziali. `Interrompi` interrompe la connessione, non annulla il lavoro già fatto sulla VM: verifica il checkpoint prima di riprendere.

## Verifiche

I test sintetici controllano log, credenziali, archivi, release, configurazioni Infisical, immagini, ruoli, tunnel, ordine dei passi e mapping Agent. La CI Linux include un round trip reale PostgreSQL 14 con ruoli/database e dati sintetici in container usa e getta; verifica owner, contenuto e disabilitazione dell’utente bootstrap. Il job Windows compila e controlla l’apertura dell’eseguibile senza input privati. Nessun test usa credenziali reali o contatta le VM di produzione.

```powershell
python -m pip install -r requirements.txt PyYAML
python -B -m unittest discover -s tests -v
```

La prova successiva necessaria è su **due VM nuove** con una release reale: login GUI Infisical e lettura dei segreti, compatibilità dei helper NPM/AIO, primo rendering e aggiornamento Agent, enrollment, accessi applicativi e routing/HTTPS. Mantieni le VM originali intatte fino alla riuscita. Controlla un aggiornamento di secret non critico senza stampare il valore; ricrea esplicitamente il suo container quando necessario. Non riattivare i timer di push sulla VM di prova mentre la VM operativa continua a pubblicare.

Riferimenti: [runbook dello stack](https://github.com/dav1dera/streams-aio-sanitized/blob/main/docs/DISASTER-RECOVERY.md), [backup privati](https://github.com/dav1dera/streams-aio-dr/releases), [Docker Ubuntu APT](https://docs.docker.com/engine/install/ubuntu/), [SDK Infisical](https://infisical.com/docs/sdks/languages/python), [SSH host key checking](https://docs.paramiko.org/en/stable/api/client.html).
