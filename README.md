# Streams AIO Recovery

Un programma Windows per preparare una **VM nuova** e ricostruire lo stack dai repository GitHub, dai secret Infisical e dagli export AIO. La repository è privata. Codice e programma non contengono credenziali o backup reali.

## Stato della prima versione

La versione 0.1 automatizza installazione Docker/dipendenze, accesso GitHub in sola lettura, recupero e verifica della release DR, decifratura age privata, input Infisical, rendering fresh, directory, NPM e import AIO. Un’azione distinta avvia i servizi per dipendenze e può richiedere la riemissione/verifica TLS NPM.

**Infisical deve già essere disponibile. Il restore del server Infisical su una seconda VM non è ancora automatizzato.** L’accesso SSH opzionale a quella VM è un controllo host; non ripristina PostgreSQL/config. La struttura del deployment privato, le versioni e le chiavi applicative devono essere recuperate secondo la [guida principale](https://github.com/dav1dera/streams-aio-sanitized/blob/main/docs/DISASTER-RECOVERY.md#3-ripristinare-prima-infisical).

La preparazione e il semplice stato running/healthy **non certificano** login, enrollment Headscale/Headplane, raggiungibilità degli upstream, compatibilità delle immagini o funzionamento AIO. Nessuna prova DR completa con backup reali è stata eseguita per questa versione. L’app indica separatamente preparazione e avvio, senza dichiarare un ripristino completo.

## Aprire il programma

Usa `StreamsAIO-Recovery.exe` prodotto dal job Windows in **Actions → Safety tests and Windows app → Artifacts**. L’eseguibile comprende Python e SSH; non richiede Python installato sul PC. È privo di firma Authenticode: non modificare le protezioni Windows per eseguirlo, e verifica provenienza e SHA256 del file scaricato.

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
5. **Infisical:** se il backup Agent è riconosciuto, progetto/ambiente e file Universal Auth sono recuperati dall’archivio. Puoi indicare un nuovo endpoint HTTPS. Per strutture diverse fornisci i due file Universal Auth, progetto, ambiente ed endpoint nei campi avanzati. L’app legge i secret esistenti; non li crea o modifica.

Al primo accesso confronta l’impronta SSH con quella della VM tramite la console. Una chiave già nota e cambiata blocca l’accesso: non viene accettata automaticamente.

## Percorso operativo

**Verifica** controlla accesso GitHub, SSH, sudo, sistema e assenza di runtime sul nuovo docker-stack. Non installa software né avvia container. La connessione Infisical opzionale controlla soltanto host/SSH.

**Prepara ripristino** mostra host, release e commit prima di scrivere. Trasferisce il runner e gli input in `~/.local/share/streams-aio-recovery/upload-<id>/`, installa Docker dal repository APT ufficiale e usa un venv separato per le dipendenze. Quindi:

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

I sette file sono `npm-database.sqlite.age`, `infisical-agent-infisical-agent.tar.gz.age`, `infisical-config.tar.gz.age`, `infisical-postgres.dump.age`, `infisical-postgres-globals.sql.age`, `manifest.json`, `SHA256SUMS`. Il backup Infisical viene recuperato/decifrato ma **non applicato a PostgreSQL** da questa versione. Gli archivi Agent vengono estratti solo come file/directory regolari in storage privato, senza symlink, traversal, ownership esterna o esecuzione di hook.

**Avvia servizi** richiede un checkpoint di preparazione riuscita sullo stesso host, ripete il preflight e aspetta i servizi per ogni onda del manifest. Rifiuta container di altri deployment e non abilita Watchtower, Cloudflare DDNS o deunhealth. Non installa timer pubblici/privati. L’opzione TLS richiama i helper NPM esistenti; può usare Cloudflare/ACME reali e richiede upstream/DNS funzionanti.

Il clone pubblico resta sul commit scelto, con HEAD detached. L’app non sincronizza verso GitHub e non va usata per aggiornare uno stack esistente. Dopo il collaudo si installano Agent continuo e le automazioni seguendo la guida dello stack; il programma non ricrea i producer privati esterni installati fuori Git.

## Compatibilità e casi che richiedono intervento

- Il bootstrap Agent riconosce un solo `agent-config.yaml/yml/json` Universal Auth, riferimenti assoluti recuperati esattamente nell’archivio e un solo progetto/ambiente. Non cerca credenziali per basename o su host diversi.
- Gli import Infisical con precedenza ambigua vengono rifiutati. Nessun segreto mascherato può diventare un input del renderer.
- Gli export AIO vengono associati agli UUID dei binding; per un singolo profilo senza UUID si usa quell’unico profilo. Profili mancanti, duplicati o ambigui richiedono un payload esplicito. OAuth e account collegati richiedono le normali riautorizzazioni; l’app non elimina campi per far passare l’importazione.
- NPM e importer AIO restano legati ai contratti del repo pubblico: NPM 2.16.0, AIOStreams 2.35.3, AIOMetadata 3.3.0. Il digest aggiornato non dimostra la compatibilità del helper. Verifica le immagini durante la prova prima del passaggio in produzione.
- Se un passo non atomico viene interrotto dopo aver scritto configurazioni/database, la ripresa si blocca per revisione. Non cancellare marker/checkpoint né rinominare database per aggirare il controllo. Download, decifratura e raccolta input usano staging privato e conservano copie fallite.

## Credenziali e log

Password SSH/sudo, passphrase e token GitHub non vengono salvati sul PC. Il solo dato persistente locale dell’app è `known_hosts` con chiavi **pubbliche** SSH, sotto `%LOCALAPPDATA%/StreamsAIORecovery/`. Il token è inviato soltanto a GitHub e alla VM scelta per leggere il backup; sul runner arriva tramite stdin cifrato dalla connessione SSH e resta in memoria durante la preparazione. Non viene creato un file contenente il token. Il helper GitHub per Git viene configurato sull’utente deployment; il token non viene inserito negli URL o argomenti dei processi.

Le chiavi age, gli export e i file Universal Auth trasferiti restano in storage privato sulla VM per la prova e l’eventuale diagnosi. Le directory sono 700, i file privati 600, gli output del renderer seguono il loro contratto UID/GID/ACL. Non sono cancellati automaticamente a fine prova. Dopo il collaudo gestisci quel materiale secondo la tua custodia operativa.

L’app scarta stdout/stderr grezzi di APT, Docker e script. Mostra eventi strutturati con passi/esiti/codici, senza valori dei file. `Salva esiti` salva soltanto questi eventi, senza host, percorsi, token o credenziali. `Interrompi` interrompe la connessione, non annulla il lavoro già fatto sulla VM: verifica il checkpoint prima di riprendere.

## Verifiche

I test sintetici controllano filtri dei log, credenziali escluse dalle rappresentazioni, selezione release, URL Infisical, snapshot, archivi ostili, decifratura parziale e associazione profili AIO. La CI Linux verifica i permessi POSIX reali delle fixture; il job Windows compila e controlla anche l’apertura dell’eseguibile senza input privati; sul PC Windows i test dei file Linux simulano esclusivamente quei bit di permesso. Nessun test usa credenziali reali.

```powershell
python -m pip install -r requirements.txt PyYAML
python -B -m unittest discover -s tests -v
```

La prova successiva necessaria è su VM nuove: preparazione con una release reale, compatibilità dei helper, Agent continuo, enrollment, accessi, routing/HTTPS e, separatamente, restore del server Infisical. Mantieni le VM originali intatte fino alla riuscita di quei controlli.

Riferimenti: [runbook dello stack](https://github.com/dav1dera/streams-aio-sanitized/blob/main/docs/DISASTER-RECOVERY.md), [backup privati](https://github.com/dav1dera/streams-aio-dr/releases), [Docker Ubuntu APT](https://docs.docker.com/engine/install/ubuntu/), [SDK Infisical](https://infisical.com/docs/sdks/languages/python), [SSH host key checking](https://docs.paramiko.org/en/stable/api/client.html).
