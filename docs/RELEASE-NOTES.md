# 0.4.17 · Recupero collaudato e guida italiana

Ordine OAuth2 Proxy/NPM corretto, attesa limitata dei proxy HTTPS,
collegamenti Headplane/Headscale e Tailscale sulle nuove VM, ripresa Agent
e guida italiana per setup, sincronizzazione e backup.

Il 14 ottobre 2026 il recupero applicativo su due VM svuotate ha completato
i controlli finali; Docker era già installato. AIOStreams e AIOMetadata
sono stati provati da Stremio sul telefono. Riavvio delle VM recuperate,
integrazioni esterne complete e P2P pubblico restano da collaudare.
[Note complete e checksum della build provata](RELEASE-NOTES-v0.4.17.md).

---

# v0.4.8 · Trasferimento sulle VM appena installate

Sulle VM nuove il trasferimento poteva fermarsi con `OPERATION_STOPPED`
prima del primo passo del recupero. Il programma creava `.local` e
`.local/share` come cartelle root con permessi `0700`; l’utente SSH non
poteva attraversarle per caricare i file.

Le nuove cartelle vengono ora create con proprietario UID/GID 1000.
La ripresa corregge anche le due cartelle lasciate dal vecchio uploader,
soltanto quando contengono esclusivamente la struttura del recupero.
Directory estranee, link e proprietà incompatibili vengono rifiutati prima
delle modifiche. Le directory dell’utente già valide conservano permessi
e contenuti.

Il registro mostra «Trasferimento file a Infisical» e «Trasferimento file
allo stack». I problemi del percorso o di SFTP hanno codici specifici;
gli errori non espongono credenziali o output privati.

I test Linux riproducono il difetto e verificano un vero processo UID 1000
che scrive nella cartella dopo la creazione e dopo la ripresa. Non
costituiscono un collaudo completo del ripristino sulle nuove VM.

Per continuare: apri la 0.4.8, conserva accessi, backup, commit e chiave age
e premi **Rileva e continua**. Non occorre azzerare nuovamente le VM.

---

# v0.4.7 · Collegamento alle VM ricreate

Una VM reinstallata genera nuove chiavi SSH. Se riutilizzava un indirizzo già conosciuto, la GUI precedente si fermava con `SSH_HOST_KEY_CHANGED` senza permettere di aggiornare l’identità.

La GUI ora mostra indirizzo e porta, impronta precedente e nuova impronta. Dopo il confronto con la console della VM, puoi approvare la nuova chiave e continuare. Il collegamento successivo verifica esattamente la chiave approvata; l’identità viene salvata solo dopo l’autenticazione riuscita. Rifiuto, annullamento, autenticazione fallita o un ulteriore cambio di chiave conservano l’identità precedente.

L’aggiornamento riguarda soltanto la destinazione selezionata. Le altre identità SSH e il file SSH di sistema restano conservati. Non vengono disattivati i controlli SSH. Un errore nel salvataggio locale viene segnalato con `SSH_HOST_KEY_STORE_FAILED`.

Per un nuovo recupero puoi usare VM vuote con IP diversi, compilando i campi della GUI con i nuovi indirizzi. Cambiare indirizzo a un recupero già preparato richiede invece la migrazione di checkpoint e collegamenti: questa versione non la esegue automaticamente.

La [guida](USAGE.md#vm-ricreata-o-indirizzo-ip-diverso) descrive il confronto delle impronte. Questa correzione non attesta un nuovo collaudo completo da due VM vuote; lo stato delle verifiche resta descritto nel [README](../README.md#stato-delle-verifiche).

---

# v0.4.6 · Configurazione locale nel backup

Il recupero supporta un file facoltativo di parametri ordinari nell’archivio
privato dell’Agent. I parametri vengono uniti ai segreti di Infisical; cartelle
interamente locali possono essere assenti dal server. Le esportazioni AIO
continuano a leggere i nuovi segreti aggiunti alle cartelle dinamiche.

File, permessi, riferimenti ammessi e duplicati JSON sono verificati. Duplicati
locali/remoti diversi fermano il recupero. Il nuovo Agent conserva configurazione
locale e provenienza dei template per i backup successivi. I backup precedenti
senza mappa locale mantengono il percorso originale.

Il rendering isolato sulla VM originale ha confrontato tutti i 20 output:
18 identici byte per byte e 2 AIO equivalenti per righe complete. Nessun servizio
è stato riavviato per questo controllo. Le due VM di test non sono più disponibili;
questa verifica non costituisce un nuovo collaudo completo da VM vuote.

Usare GUI 0.4.6 o successiva per i backup creati dopo la separazione dei parametri.
Conservare la GUI aggiornata nel kit offline insieme alle chiavi age private.

---

# v0.4.5 · Recupero automatico e guida one click

Questa versione riunisce le correzioni successive alla 0.4.0 e il percorso verificato sulle VM: ripristino AIO nativo con chiavi applicative coerenti, gestione NPM/Certbot, riconoscimento del backup e dell’instradamento già registrati e attesa del tempo residuo quando Compose segnala prematuramente un container non sano. Restano obbligatori i controlli finali; non vengono falsificate healthcheck o identità per superare un errore.

Il README spiega i preparativi, gli accessi, il backup schema 2 e il file age privato, la differenza fra IP SSH e destinazione dei domini, «Crea da zero» e «Rileva e continua». Non servono export JSON o payload integrativi per il recupero completo.

Il report 0.4.5 del 10 ottobre 2026 verifica bootstrap, Infisical, AIO, Agent, servizi, NPM, TLS e dominio CometNet, con un upstream esterno non raggiungibile conservato come avviso. La baseline Ubuntu appena reinstallata senza Docker non è confermata; login/profili, P2P pubblico e persistenza dopo riavvio restano da verificare.

Dettagli: [0.4.1](RELEASE-NOTES-v0.4.1.md), [0.4.2](RELEASE-NOTES-v0.4.2.md), [0.4.3](RELEASE-NOTES-v0.4.3.md), [0.4.4](RELEASE-NOTES-v0.4.4.md), [0.4.5](RELEASE-NOTES-v0.4.5.md).

Le note sotto sono lo storico delle versioni precedenti; i riferimenti a prove pendenti descrivono lo stato di quelle versioni.

## v0.4.0 preview · Recupero automatico con due azioni

La nuova dashboard riunisce lo stato di Infisical, Stack, AIO, Agent, Domini e Servizi. **Crea da zero** prepara due VM vuote; **Rileva e continua** controlla il punto di recupero su entrambe e riprende soltanto i passaggi compatibili. Gli errori indicano il campo o la fase da correggere. Gli screenshot nella guida mostrano l’applicazione Windows reale.

Il percorso normale usa backup schema 2: include gli snapshot SQLite nativi di AIOStreams e AIOMetadata, le identità, gli hash delle password e i collegamenti presenti. Non richiede di importare gli export JSON a mano. Immagini, chiavi di cifratura e commit dello stack vengono verificati insieme al backup. L’importazione tiene un registro privato per riconoscere una scrittura interrotta e conservare database estranei.

NPM viene preparato prima di CometNet. I collegamenti alle VM originali sono rimappati soltanto quando il backup ne prova la provenienza; i servizi interni e i server esterni mantengono le loro destinazioni. HTTPS e una risposta temporanea univoca verificano che i domini raggiungano il nuovo NPM. CometNet usa il dominio WSS reale; la modalità della prova precedente rimane disponibile soltanto per i suoi checkpoint storici.

Il **9 ottobre 2026** il timer DR della VM originale è stato aggiornato e verificato: tutti i giorni alle **04:30 nel fuso della VM**, ritardo casuale massimo di 10 minuti, avvio automatico dopo un’esecuzione persa. I servizi applicativi sono rimasti invariati. La politica conserva cinque punti di recupero verificati.

**Verifiche della preview:** test automatici Windows e controlli Linux del backup, del formato AIO e della ripresa superati. Il recupero completo della 0.4.0 da due VM vuote, i login AIO, il traffico pubblico CometNet e la ripartenza dopo riavvio restano da collaudare. Un avvio sano dei container non viene presentato come equivalenza funzionale con la produzione. Il nuovo backup completo deve essere pubblicato prima di usare il percorso automatico AIO.

## v0.3.17 · CometNet locale per la simulazione

Il controllo sulla VM ha identificato l'errore di CometNet: `ADVERTISE_REACHABILITY_FAILED` e `LIFESPAN_STARTUP_FAILED`, con database leggibile, immagine corretta e checkpoint invariato. L'indirizzo pubblico proveniente dal backup non è raggiungibile nella prova senza DNS/TLS riattivati. Non è un errore delle credenziali PostgreSQL.

Il nuovo profilo della prova usa `ws://127.0.0.1:8765`, rete privata con ID distinto e password casuale locale, liste iniziali di peer vuote, UPnP disattivato e directory temporanee dedicate per identità e pool. Mantiene i controlli dell'orologio, della raggiungibilità WebSocket e della salute HTTP. Non modifica healthcheck, tempi di attesa, immagini, secret Infisical o file gestiti dall'Agent. La password di isolamento resta in file privati sulla VM e non entra nei report o nei sorgenti.

Il codice del commit effettivo `f56677f05ed9a158f9a0338ad2f44d8efde35969` avvia il listener prima del controllo WebSocket. La separazione P2P richiede sia ID che password della rete; il solo flag di rete privata non basta. Fonti: [avvio e self-check](https://github.com/g0ldyy/comet/blob/f56677f05ed9a158f9a0338ad2f44d8efde35969/comet/cometnet/manager.py#L359), [autenticazione fra nodi](https://github.com/g0ldyy/comet/blob/f56677f05ed9a158f9a0338ad2f44d8efde35969/comet/cometnet/transport.py#L765), [stato dei peer salvati](https://github.com/g0ldyy/comet/blob/f56677f05ed9a158f9a0338ad2f44d8efde35969/comet/cometnet/manager.py#L1965).

**Ripresa del tentativo attuale:** inserisci soltanto l'accesso SSH/sudo stack nella 0.3.17. Lascia TLS e Ricomincia il test da zero disattivati, conferma la destinazione e premi **Avvia servizi**. Il programma accetta il profilo precedente soltanto dopo la sua validazione completa, verifica la proprietà delle risorse e registra una migrazione limitata al nodo CometNet. Conserva le fasi già completate e riprende i normali controlli di avvio. Dopo la migrazione usa la 0.3.17 anche per verifiche e riprese successive; una versione precedente rifiuterebbe il nuovo profilo.

La correzione è limitata al punto di recupero e all'utente della prova già documentati. Il profilo locale rifiuta TLS reale: collegare il nuovo nodo alla rete P2P pubblica richiede un passaggio separato.

**Collaudo reale del 9 ottobre:** l'utente ha eseguito l'helper che richiama la stessa azione SSH.start della GUI 0.3.17 sulla .29. Il registro conferma immagini PASS, controlli dei servizi PASS, avvio PASS e COMETNET_TRIAL_RESUME PASS. Il blocco di CometNet è superato nel tentativo corrente. Restano importazione manuale AIO, login, prova dopo riavvio e collegamenti esterni. Questa è una ripresa riuscita del recupero già preparato; una nuova simulazione da VM vuote interamente con la GUI 0.3.17 resta da collaudare. Il registro non include uno stage di migrazione CometNet, quindi non documenta quando quella migrazione sia stata registrata.

Suite Windows: 308 test totali, **279 PASS**, 29 verifiche Linux/Docker escluse, zero errori o fallimenti. I nuovi casi coprono migrazione del checkpoint precedente, nuova preparazione, password privata e permessi, idempotenza, risorse estranee o sostituite, deriva delle sorgenti, porte errate, modifica di secret o healthcheck rifiutata, rollback delle scritture e ripresa con i controlli di salute obbligatori. Gli overlay precedenti restano identici ai byte della build 0.3.16.

## v0.3.16 · Diagnosi automatica del gruppo fermato

Se un gruppo di servizi fallisce il controllo di avvio, il programma raccoglie lo stato di tutti i servizi mentre detiene ancora il lock del recupero. Ricontrolla la proprietà di container e volumi prima di mostrare nomi pubblici, salute, ultimo exit code della healthcheck, riavvii e indicatore OOM. La GUI mostra il gruppo fermato e un riepilogo; **Salva esiti** conserva il report completo. Non occorre una seconda connessione o password per questa diagnosi.

La raccolta è limitata a 20 secondi complessivi. Errori di lettura o risorse estranee producono solo UNAVAILABLE o OWNERSHIP_REFUSED; il codice originale APPLICATION_HEALTH_WAIT_FAILED viene conservato. Log grezzi, variabili, mount e valori delle credenziali restano fuori dal report. Non aggiunge retry, modifica delle healthcheck o avvio automatico dopo il fallimento. Include la correzione del trasporto SSH della 0.3.15.

La ripresa reale dalla GUI 0.3.14 del 9 ottobre ha raggiunto CometNet. La diagnosi successiva conferma 27 servizi attivi e CometNet con 9 riavvii e healthcheck fallita; la causa resta da accertare. Le pagine anonime Infisical, NPM, AIOStreams e AIOMetadata sono raggiungibili. Login e recupero funzionale completo non sono ancora certificati.

Suite Windows: 289 test totali, **260 PASS**, 29 verifiche Linux/Docker escluse, zero errori o fallimenti. I nuovi casi coprono un gruppo non sano, servizi mancanti, risorse estranee apparse dopo il fallimento, timeout, contenuto privato inatteso, preservazione del codice originale e assenza di riavvii automatici.

## v0.3.15 · Esito SSH completo e ripresa dell'avvio

La diagnosi reale del 9 ottobre conferma preparazione, profilo, Agent e immagini. I 27 servizi già creati sono in esecuzione, sani dove è prevista una healthcheck; CometNet non è ancora stato creato. Il checkpoint e la proprietà delle risorse sono validi e non è presente un processo di avvio attivo. StremThru ha un riavvio registrato, ma il dato da solo non dimostra la causa del precedente arresto.

La GUI prima interrompeva la lettura quando arrivava l'exit status e i buffer erano momentaneamente vuoti. SSH può inviare l'esito prima di aver terminato il flusso del processo: l'ultimo evento REFUSED poteva andare perso. Ora attende anche EOF o chiusura del canale e accetta un evento completo senza newline finale, con lo stesso schema chiuso. Conserva il primo errore specifico e distingue assenza di exit status, valore 137 e valore 143 senza dedurne automaticamente un problema di memoria. Output grezzo e credenziali restano fuori dal registro. Nessun retry automatico è stato aggiunto.

La correzione riguarda solo il trasporto e i messaggi della GUI. Gli strumenti remoti incorporati sono identici alla 0.3.14: non modifica immagini, avvio per dipendenze, tempi di attesa, healthcheck, profilo, checkpoint o dati applicativi.

**Ripresa del tentativo attuale:** apri 0.3.15, inserisci host stack, utente, password o chiave SSH e sudo se diverso. Mantieni TLS e Ricomincia il test da zero disattivati; conferma la destinazione nella schermata Ripristino e premi **Avvia servizi**. Il pulsante usa la preparazione già presente: per questa ripresa non serve ricompilare backup, token GitHub o accesso Infisical. I controlli di macchina, file, profilo e proprietà delle risorse restano attivi. Il recupero funzionale completo non è ancora certificato.

Suite Windows: 278 test totali, **249 PASS**, 29 verifiche Linux/Docker escluse, zero errori o fallimenti. I nuovi casi riproducono exit status prima dei dati finali, evento senza newline, errore specifico precedente e rifiuto di contenuto arbitrario. Sono fixture sintetiche, senza VM o daemon reali.

## v0.3.14 · Lettura dei metadati immagine

Il registro del 9 ottobre raggiunge tutti i PASS della preparazione di Infisical e dello stack fino a directory e permessi; la compatibilità del primo avvio si ferma con `RUNTIME_PROFILE_IMAGE_INSPECT_FAILED`.

La revisione ha individuato un difetto concreto nel template: `.Id` è il nome JSON, mentre il tipo Go di Docker espone `.ID`. La prima forma obbliga il formatter a ripiegare sul JSON grezzo; con `missingkey=error` fallisce quando `Config.User` vuoto viene omesso. La correzione usa `.ID`, conservando la stringa vuota e la chiave JSON `Id` attesa dai controlli. È compatibile anche con Docker precedente. Fonti: [formatter Docker](https://raw.githubusercontent.com/docker/cli/v29.8.2/cli/command/inspect/inspector.go), [tipo dei metadati](https://raw.githubusercontent.com/moby/moby/docker-v29.8.2/api/types/image/image_inspect.go), [campi opzionali della configurazione OCI](https://raw.githubusercontent.com/opencontainers/image-spec/v1.1.1/specs-go/v1/config.go).

Il runner distingue inoltre la lista restituita dall'ispezione JSON completa dall'oggetto restituito dal template e accetta il valore `null` di una healthcheck assente, che il controllo delle dipendenze continua a rifiutare quando è necessaria. Non cambia digest, piattaforma, account delle immagini, permessi o dati del recupero.

Le regressioni modellano i nomi dei campi Go e JSON e l'omissione dell'utente vuoto: riproducono il fallimento precedente e fanno passare il controllo completo delle quattro immagini e dei loro archivi. Verificano anche il rifiuto di ID, piattaforma e versione PostgreSQL errati, liste e JSON non validi. Questo test simula il formatter documentato; non esegue il motore Docker o le VM reali.

Suite Windows: **243 test PASS**, 29 verifiche Linux/Docker escluse, nessun errore. La revisione indipendente comprende la ripresa, NPM/AIO manuale, il passaggio all'Agent e le verifiche di avvio: non sono emersi altri blocchi deterministici nel codice. Non sostituisce il collaudo sulle VM. L'eseguibile è distribuito localmente e confrontato con i sorgenti per versione e tutti i file remoti incorporati.

**Per continuare:** apri 0.3.14 con gli stessi accessi, release, commit, identity e companion. Mantieni AIO manuale, Agent attivo e TLS disattivato. Lascia **Ricomincia il test da zero disattivato**, premi Verifica e Ripristina entrambe le VM. Il profilo non era ancora registrato e l'avvio non era stato tentato nel checkpoint attuale: le fasi precedenti restano utilizzabili. Il collaudo applicativo completo resta da eseguire.

## v0.3.13 · Immagini presenti e diagnosi del primo avvio

Il registro della prova con 0.3.12 conferma archiviazione e pulizia di entrambe le destinazioni, recupero completo del server Infisical e preparazione dello stack fino a directory e permessi. Il passo successivo si è fermato con `RUNTIME_PROFILE_COMMAND_FAILED`. Quel codice era condiviso da download delle immagini, Compose e controlli locali: il registro non permette di attribuire con certezza il guasto alla connessione.

La preparazione ora controlla le quattro immagini esatte del profilo PostgreSQL, DNSCrypt, OAuth2 Proxy e PgBouncer. Riutilizza quelle disponibili al digest previsto e scarica solo quelle mancanti. Un errore del daemon o di accesso non viene confuso con un'immagine assente. Restano obbligatori tutti i controlli di piattaforma, contenuto, identità degli utenti, file e permessi del profilo. Non vengono scelti tag o digest alternativi.

Il controllo degli archivi è stato adattato anche allo store containerd, predefinito nelle nuove installazioni Docker 29+. Il vecchio lettore richiedeva che l'ID ispezionato fosse il digest della configurazione, mentre lo store moderno usa il digest del manifest o dell'indice. Il percorso precedente conserva la verifica originale; quello moderno verifica ogni digest e dimensione nella catena indice/manifest/config della piattaforma Linux amd64, i blob dei layer e i rispettivi contenuti decompressi. Non avvia container per leggere gli utenti e non modifica lo store Docker. Questa incompatibilità è stata identificata nel codice e nei sorgenti ufficiali, non diagnosticata sulla VM dell'utente. [Store Docker](https://docs.docker.com/engine/storage/containerd/), [ispezione immagini Docker 29.8.2](https://raw.githubusercontent.com/moby/moby/docker-v29.8.2/daemon/containerd/image_inspect.go), [formato export](https://raw.githubusercontent.com/moby/moby/docker-v29.8.2/vendor/github.com/containerd/containerd/v2/core/images/archive/exporter.go).

Gli errori distinguono i quattro download, lettura delle immagini presenti, verifica e archiviazione delle immagini, configurazione/versione Compose, checkout Git e risorse Docker. La transazione conserva questi codici anche quando deve annullare una scrittura parziale del profilo. Output dei comandi, argomenti privati e credenziali non compaiono nel registro. I messaggi di completamento degli input spiegano inoltre il campo da correggere, invece di mostrare soltanto il codice.

**Per continuare il tentativo attuale:** apri 0.3.13 con le stesse VM, tag, commit, identity e companion, AIO manuale, Agent attivo e TLS disattivato. Lascia **Ricomincia il test da zero disattivato**: entrambe le pulizie sono già riuscite. Premi Verifica, poi Ripristina entrambe le VM. I checkpoint e gli archivi vengono conservati. La nuova versione elimina i download superflui e identifica il comando eventualmente ancora fallito; il recupero reale completo resta da collaudare.

Suite Windows: **237 test PASS**, 29 verifiche Linux/Docker escluse, nessun errore. I nuovi test verificano riuso senza rete, assenza reale rispetto a errori Docker, quattro download distinti, JSON malformato, riservatezza degli output e annullamento di una transazione parziale con conservazione di file e checkpoint. Coprono inoltre archivi OCI manifest/indice, gzip e tar, layer alterati, piattaforme ambigue, contenuti mancanti e preservazione del lettore precedente. Il supporto degli archivi è limitato a SHA256, schema 2, Linux amd64, tar/gzip, con limiti di dimensione e profondità; altri formati sono rifiutati. L'eseguibile viene confrontato con i sorgenti per versione e tutti i file remoti incorporati. La build è distribuita localmente; non attesta un nuovo collaudo sulle VM.

## v0.3.12 · Correzione dei mount nel nuovo test

La 0.3.11 fermava **Ricomincia il test da zero** con `TEST_RESET_BIND_SCOPE_REFUSED`: il controllo di tutti i servizi rifiutava `/dev/net/tun`, già dichiarato da Tailscale nel Compose del recupero. La 0.3.12 riconosce quel dispositivo, i device Tailscale/Gluetun, il socket Docker dei quattro servizi previsti e il tmpfs `/tmp` di Comet/CometNet. I percorsi, i destinatari dei mount e le opzioni devono corrispondere al modello scelto. Dispositivo e socket vengono verificati senza copiarli o rimuoverli.

Il confronto copre tutti i **31 servizi e sette volumi dichiarati** nel [Compose del commit della prova](https://github.com/dav1dera/streams-aio-sanitized/blob/28f6ca7cc6f5fd10418fc0af2926815927ef98c8/docker-compose.yml) e nel suo [overlay DR](https://github.com/dav1dera/streams-aio-sanitized/blob/28f6ca7cc6f5fd10418fc0af2926815927ef98c8/config/compose.dr.yaml). I test usano configurazioni pubbliche e risposte Docker sintetiche: comprendono entrambe le rappresentazioni del tmpfs, la normalizzazione del socket e il rifiuto di percorsi, dispositivi e opzioni diversi. È stato inoltre controllato il flusso dopo la pulizia: gli archivi conservati non interferiscono con il nuovo checkpoint o con la ripresa.

**Per continuare:** apri 0.3.12, conserva le stesse destinazioni, release, commit, identity age e companion. Usa AIO manuale, Agent attivo e TLS disattivato. Seleziona **Ricomincia il test da zero**, premi **Verifica**, poi **Ripristina entrambe le VM**. Il collaudo completo del nuovo recupero sulle due VM resta da eseguire.

Suite su Windows: **203 test PASS**, 29 verifiche Linux/Docker escluse, nessun errore. La build locale viene controllata per verificare che contenga la versione e tutti i file remoti aggiornati; nessuna operazione sulle VM è stata eseguita durante questa verifica.

## v0.3.11 · Ricominciare la prova dalla GUI

La scelta **Ricomincia il test da zero (.29/.30)** permette di archiviare il tentativo già avviato e ripristinare nuovamente Infisical e stack. È disattivata inizialmente e limitata a `test@192.168.178.29`, `test2@192.168.178.30`, tag `dr-20261006T210601Z`, commit `28f6ca7cc6f5fd10418fc0af2926815927ef98c8`, AIO manuale e TLS disattivato.

Il programma controlla GitHub e entrambe le VM prima di intervenire. Verifica checkpoint, macchina, risorse Compose, unità Agent/tunnel e spazio; ferma soltanto i componenti riconosciuti, copia e verifica tutti i volumi prima della rimozione e conserva cartelle e file privati in `/var/lib/streams-aio-test-reset/` su ciascuna VM. Le copie restano locali e non vengono pubblicate. Risorse estranee, mount non verificati e filesystem incompatibili vengono rifiutati.

Una volta completata la pulizia delle due destinazioni, la casella si disattiva automaticamente: una riprova riprende il nuovo recupero. Le interruzioni durante la pulizia conservano un registro privato e le copie; il passo può essere ripetuto con le stesse scelte. **Verifica** non pulisce le VM. I pulsanti separati **Prepara stack** e **Avvia servizi** non eseguono questa operazione.

Ubuntu, Docker e immagini già presenti vengono conservati. Per collaudare l'installazione su un sistema operativo nuovo occorrono VM nuove, reinstallate o uno snapshot precedente al primo recupero. Gli archivi non sono un clone completo delle VM e non comprendono i livelli scrivibili dei container. Il ripristino completo sulle VM reali resta da collaudare.

Verifica automatica su Windows: **197 test PASS**, 29 verifiche Linux/Docker escluse. I nuovi test coprono proprietà delle risorse, copie prima della rimozione, corruzione degli archivi, interruzioni e ripresa, controllo di entrambe le destinazioni e riprove senza una seconda pulizia.

## v0.3.10 · Ripresa prima dell’avvio

Il vecchio errore `RUNTIME_PROFILE_FRESH_HOST_REQUIRED` era usato anche per checkpoint già preparati, senza dati Docker. Ora NPM/AIO completati e preparazione PASS possono essere conservati durante la registrazione del profilo, purché l’avvio non sia mai stato tentato, non esistano container e gli eventuali volumi siano tutti vuoti e appartengano allo stack. Integrità, ambito e permessi restano obbligatori. Nessun database viene cancellato o ricreato da questa migrazione.

**Verifica** mostra i conteggi Docker e le fasi registrate. Un checkpoint che segnala un avvio precedente senza profilo riceve `RUNTIME_PROFILE_PRESTART_CHECKPOINT_REQUIRED`, prima di ripetere il recupero Infisical. Il codice `RUNTIME_PROFILE_FRESH_HOST_REQUIRED` resta dedicato al controllo fisico di container/volumi. Conserva i dati e usa la [guida corrente](USAGE.md) per distinguere ripresa e nuova simulazione.

Il controllo preliminare riconosce anche gli eventuali volumi vuoti appartenenti allo stesso recupero, senza crearli, modificarli o cancellarli. **Avvia servizi** richiede un profilo registrato e verificato: non salta la preparazione di compatibilità.

Verifica automatica su Windows: 163 test PASS, 28 controlli Linux/Docker esclusi. Il ripristino completo sulle VM reali resta da collaudare.

## v0.3.9 · Compatibilità del primo avvio

Profilo circoscritto al tag `dr-20261006T210601Z`, commit `28f6ca7cc6f5fd10418fc0af2926815927ef98c8` e utente stack `test`. Include layout PostgreSQL 18, lettura dei file privati DNS/OAuth/PgBouncer, ordine delle dipendenze, companion cifrato della lista email, AIO manuale, download delle immagini per digest e verifica finale dei servizi. Il commit pubblico e le VM originali restano fuori dalle modifiche del profilo locale.

## Correzioni precedenti incluse: v0.3.8

La v0.3.8 corregge `INFISICAL_DEPLOYMENT_PROFILE_CHANGED` nella ripresa dopo un aggiornamento del programma. Le vecchie build Windows contenevano il profilo JSON con terminatori CRLF, mentre la build locale usava LF: impostazioni identiche producevano impronte SHA256 diverse.

Il checkpoint ora lega database, ruolo PostgreSQL e immagini fissate a un’impronta canonica delle impostazioni. I due formati storici vengono riconosciuti soltanto se corrispondono al profilo già verificato: il checkpoint conserva l’impronta precedente e tutti i passi riusciti. Cambi reali al profilo e impronte sconosciute restano rifiutati. Il file del profilo viene inoltre distribuito sempre con righe LF. I controlli sui file installati, sul runtime, sulla release e sul materiale privato restano invariati.

**Per riprendere:** chiudi il vecchio programma e apri **v0.3.8**. Conserva VM, release DR, commit e chiave age; scegli AIO manuale, Agent attivo e TLS disattivato per la prova. Premi **Ripristina entrambe le VM**. Non cancellare checkpoint o database: il restore Infisical già completato viene riutilizzato.

I test riproducono entrambe le impronte dei programmi distribuiti, la ripresa senza rieseguire config/database, la seconda esecuzione senza riscritture e il rifiuto di cambi effettivi prima di modificare il checkpoint. Restano incluse le correzioni dell’Agent della v0.3.7. Il collaudo completo sulle VM reali resta da completare.

## Correzioni precedenti incluse: v0.3.7

La v0.3.7 corregge `PRIVATE_INPUT_REQUIRES_MODE_600` nel passaggio dai file dello stack all’Agent continuo. Il renderer del commit pubblico scelto crea gli env come `root:deployment-group 0640`; il programma precedente li sottoponeva al controllo `0600` delle chiavi private prima di poterli assegnare all’Agent.

Il programma verifica il piano pubblico, la ricevuta di render e il percorso dentro `.secrets`. Solo un env dichiarato e già generato può passare da `0640` a `0600`, con proprietario dell’Agent. Prima di modificare i permessi verifica l’intero insieme: proprietari o gruppi estranei, accesso pubblico, scrittura di gruppo, bit speciali e link restano rifiutati. I contenuti rimangono identici. Il controllo delle chiavi private resta invariato.

**Per riprendere:** apri **v0.3.7**, mantieni le stesse VM, release DR, commit e chiave age, scegli AIO manuale e Agent attivo, lascia TLS disattivato per la prova e premi **Ripristina entrambe le VM**. La preparazione completata e il tunnel già configurato vengono riutilizzati. Non cancellare checkpoint o database.

I test POSIX eseguono il vero renderer del commit fissato, verificano il passaggio `0640 → 0600` e la seconda esecuzione, conservano byte e ricevuta e controllano i rifiuti prima di qualsiasi modifica. Restano inclusi i test del tunnel, degli archivi e dell’importazione AIO manuale. Agent e servizi sulle VM reali restano da collaudare dopo la ripresa.

## Correzioni precedenti incluse: v0.3.6

La v0.3.6 corregge il blocco dell'Agent subito dopo **Preparazione completata · PASS**. OpenSSH restituisce la chiave pubblica insieme al commento `streams-aio-recovery-tunnel`; la versione precedente rifiutava quel formato e mostrava soltanto `REMOTE_OPERATION_FAILED`.

Il programma ora separa il commento dal materiale della chiave e verifica tipo Ed25519, codifica e struttura prima di inviarla alla seconda VM. La chiave privata già creata viene riutilizzata. Il registro mostra l'inizio del passo Agent e conserva il codice pubblico dell'errore anche nei comandi che restituiscono metadati; stderr, chiavi e output arbitrari restano fuori dai report.

**Per riprendere:** chiudi il vecchio programma e apri **v0.3.6**. Conserva le stesse VM, release DR, commit e chiave age. Mantieni la configurazione AIO manuale, l'Agent attivo e TLS disattivato nella prova, poi premi **Ripristina entrambe le VM**. Infisical, NPM e gli altri passi completati vengono verificati e riutilizzati.

I test includono una vera chiave OpenSSH con commento e la sua riutilizzazione su Linux, chiavi malformate, errori frammentati sul trasporto SSH e rifiuto di output estranei ai codici pubblici. Il collaudo completo sulle VM reali resta da completare.

## Correzioni precedenti incluse: v0.3.5

La v0.3.5 aggiunge la configurazione manuale di AIOStreams e AIOMetadata. Nel passo **02 · Backup** seleziona **Configurerò AIOStreams e AIOMetadata manualmente**: puoi lasciare vuoti gli export AIO e `PRIVATE_DR_PAYLOAD`. La chiave privata age resta necessaria.

Infisical, secret, stack, NPM e Agent seguono il recupero esistente. Le applicazioni AIO partono con database nuovi e le configuri o importi dalle loro interfacce dopo l'avvio. Il registro indica **DA IMPORTARE MANUALMENTE**, senza attestare un'importazione riuscita. I controlli sugli altri componenti restano attivi.

**Per riprendere da un errore AIO:** chiudi il vecchio programma, apri **v0.3.5**, conserva le stesse VM, release DR, commit e chiave age, seleziona la modalità manuale e premi **Ripristina entrambe le VM**. I passi completati vengono verificati e riutilizzati. Il cambio di modalità viene rifiutato se esistono già database AIO o un'importazione parziale: nessun database viene cancellato.

Gli upload privati usano nuove cartelle con proprietario e permessi verificati tramite sudo. La suite verifica il preflight originale del commit dello stack: soltanto l'importazione AIO esplicitamente rinviata può essere saltata; NPM, file sorgente, prerequisiti e altri blocchi mantengono il loro effetto. La compilazione Windows include un controllo dell'opzione manuale nella GUI.

Il collaudo completo sulle VM con i backup reali resta da completare. Dopo l'avvio verifica le due applicazioni e i loro collegamenti. [Guida completa](https://github.com/dav1dera/streams-aio-recovery-gui/blob/main/docs/USAGE.md).

## Correzioni precedenti incluse: v0.3.4

La v0.3.4 corregge `UNSAFE_AGENT_ARCHIVE` nel passo **Secret da Infisical** per il backup Agent creato dal produttore con percorsi assoluti Linux.

I file sotto `/etc/infisical`, `/etc/infisical-agent`, la unit `infisical-agent.service` e i suoi drop-in vengono ricostruiti nella cartella privata del recupero. Nessun percorso originale viene usato come destinazione host. Il lettore continua a rifiutare altri percorsi assoluti, link simbolici e hard link, device, attraversamenti, duplicati anche tra nomi assoluti/relativi e collisioni tra file e cartelle, prima di estrarre.

La suite comprende il layout completo dei sei file del produttore, il recupero Universal Auth e i casi di rifiuto. Il controllo locale sull'archivio cifrato reale ha verificato estrazione e riconoscimento del bootstrap senza pubblicare chiavi o contenuti; la copia temporanea privata e stata rimossa. La CI esegue anche questi test su Ubuntu 24.04 e 26.04 prima di compilare e verificare l'eseguibile Windows.

**Per riprendere:** chiudi il vecchio programma, apri **StreamsAIO-Recovery.exe v0.3.4** e mantieni le stesse VM, release DR, commit dello stack, chiave privata ed export JSON. Premi **Ripristina entrambe le VM**. Infisical gia ripristinato viene controllato e riutilizzato; il passo INPUTS incompleto puo ripartire se gli output non sono ancora installati. Non cancellare checkpoint e non rilanciare gli strumenti di reset usati prima della decifratura. Lascia TLS disattivato nella prima prova. La versione dei checkpoint resta invariata.

Restano incluse le correzioni delle identity Windows, dei permessi di download e del bootstrap PostgreSQL descritte sotto. Il recupero completo dei secret, dell'Agent continuo e delle applicazioni sulle VM resta soggetto al collaudo reale.

## Correzioni precedenti incluse: v0.3.3

La v0.3.3 gestisce i file della chiave age salvati su Windows in UTF-8 con BOM o UTF-16 con BOM, che prima potevano fermarsi su `AGE_DECRYPTION_FAILED` anche con una chiave corretta.

- Legge solo identity X25519 originali complete `AGE-SECRET-KEY-1…`, con commenti, righe vuote e CRLF. Non genera chiavi e non aggiunge prefissi a codici sconosciuti.
- Prepara una copia canonica in una cartella temporanea `0700`, file `0600`, esterna ai repository. Il file originale non viene modificato. La copia canonica viene eliminata alla fine del passo, anche in caso di rifiuto.
- Valida la chiave con `age-keygen` prima della decifratura. Distingue `AGE_PUBLIC_KEY_NOT_IDENTITY`, `AGE_PRIVATE_IDENTITY_REQUIRED`, `AGE_IDENTITY_INVALID` e `AGE_NO_MATCHING_RECIPIENT`, con spiegazioni in italiano nel registro.
- Nessuna chiave, public recipient o stderr dei processi viene mostrata negli esiti. L'errore di age viene convertito soltanto in codici fissi.
- SHA256, manifest, dimensioni degli asset, envelope age e rifiuto dei set parziali restano attivi. Restano incluse le correzioni dei permessi di download e dell'avvio PostgreSQL della v0.3.2.
- Test con vere chiavi PRIMARY/RECOVERY usa e getta: tutti e cinque gli artifact, UTF-8, BOM, UTF-16 LE/BE, CRLF e rifiuto di una terza identity valida ma estranea. Le prove sono obbligatorie su Ubuntu 24.04 e 26.04 prima della build Windows.

**Per riprovare:** annota il commit dello stack nella vecchia GUI, chiudila e scarica **StreamsAIO-Recovery.exe v0.3.3**. Mantieni le stesse VM, release DR e commit, seleziona il file della chiave privata originale e premi **Ripristina entrambe le VM**. Un arresto alla decifratura prima del restore config/database permette di riutilizzare i checkpoint. Per il primo collaudo lascia disattivata la riemissione TLS reale.

Una identity valida che non apre il backup richiede l'altra chiave originale PRIMARY/RECOVERY o una release cifrata per quella identity. Una chiave nuova non apre i backup precedenti. [Formato identity ufficiale age](https://github.com/FiloSottile/age/blob/main/parse.go).

La pubblicazione richiede inoltre test di sicurezza, round trip PostgreSQL 14 con dati sintetici, prove dei permessi di download, dipendenze su entrambi gli Ubuntu, avvio/navigazione dell'eseguibile Windows e verifica SHA256 degli asset riscaricati.

Il ripristino completo con i backup reali dell'utente resta da collaudare. Questa è una **prerelease**: i test automatici non attestano quel collaudo.
