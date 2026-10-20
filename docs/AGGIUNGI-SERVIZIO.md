# Aggiungi servizio — anteprima 0.5.0-dev.2

Questa scheda aggiunge **un servizio nuovo** a uno stack Streams AIO già configurato.
L’analisi iniziale funziona offline. La connessione diretta alla VM viene aperta solo
premendo **Verifica VM**; le modifiche richiedono **Aggiungi e verifica**.
Non occorre tenere aperto VS Code o permettere il controllo del desktop Windows.

## Collaudo su due VM Ubuntu vuote

Usa il riquadro **Collaudo su due VM vuote** della nuova scheda, senza premere
«Crea da zero» in Panoramica. Il normale recupero avvia lo stack completo e richiede
anche l’instradamento dei domini; questo laboratorio prepara soltanto file e Agent.

1. Crea uno snapshot delle due VM pulite. Devono avere OpenSSH attivo e un utente
   con sudo; non serve installare Docker a mano.
2. In **Accessi e backup** compila le due VM, il token GitHub con **Contents: Read**
   sui repository del recupero e il file della chiave age. Carica un backup completo.
   Per esempio: stack `test@192.168.178.30`, Infisical `test2@192.168.178.33`.
3. Torna in **Aggiungi servizio** e premi **Prepara le VM di collaudo**. Il programma
   controlla che entrambe siano vuote prima dei trasferimenti, ripristina Infisical,
   prepara lo stack e collega il suo Agent alla VM Infisical di prova tramite SSH.
   Non avvia l’intero stack e non installa i processi di pubblicazione automatica.
4. Mantieni selezionato **Solo collaudo locale** e prepara il nuovo servizio secondo
   i passaggi sotto. Un controllo protetto sulla VM impedisce di pubblicare dal
   laboratorio nei repository principali, anche se viene tolta la selezione.
5. L’esito locale verifica il servizio e il collegamento Agent. **GitHub e backup
   risultano esclusi**, non verificati. Il collaudo completo della pubblicazione
   richiede successivamente repository e processi di backup dedicati alla prova.

Puoi lasciare accese le VM principali. Non cambiare AdGuard, DNS di Ubuntu o porte
del router per questa preparazione. Se la preparazione viene interrotta dopo aver
iniziato a ripristinare dati, questa anteprima richiede di tornare agli snapshot
puliti per ripetere il pulsante di laboratorio; non cancella automaticamente le VM.

## Stato della versione

Il codice è in sviluppo e viene verificato con test simulati. Il collaudo su VM dedicate
e la verifica grafica dell’eseguibile restano da eseguire: non è una nuova versione
stabile da sostituire alla GUI di recupero già funzionante.

La prima versione gestisce servizi **senza dati persistenti propri** e impostazioni
espresse in Compose e file `.env`. Rifiuta mount `volumes`, inclusi quelli readonly,
e immagini che dichiarano volumi anonimi. Non aggiunge database al sistema di snapshot:
un nuovo backup con checksum corretti non dimostrerebbe di averne salvato i dati.
File di configurazione aggiuntivi, policy Infisical, socket Docker e proxy NPM automatici
richiedono un’estensione e un collaudo separati.

## Prima di iniziare

- La VM stack deve avere lo stack già funzionante in `/home/<utente>/streams-aio`.
- Per il percorso completo, Agent Infisical, worker pubblico con modalità `--seamless` e coordinatore DR devono
  essere installati e funzionanti secondo il setup di questo repository.
- Il client GitHub della VM deve avere accesso ai repository configurati. La scheda
  usa quelli del deployment di riferimento; non imposta un account GitHub nuovo.
- Per variabili private servono ID progetto, ambiente e un **access token** abilitato
  a leggere e creare cartelle e segreti nel progetto. Le API usano il tunnel locale
  dell’Agent quando riconosciuto; in sua assenza serve l’indirizzo **HTTPS** corretto.
  Le API richieste sono cartelle v2 e segreti v4. Un vecchio service token non va
  necessariamente bene: usa un access token valido per queste API.
- L’identità dell’Agent deve già poter leggere la cartella `/<nome-servizio>`.
  La scheda non amplia ruoli o permessi delle identità.
- Scegli un servizio con un controllo Docker HEALTHCHECK oppure predisponi un endpoint
  HTTP locale di salute su una porta pubblicata dal nuovo servizio.

## Procedura completa

1. In **Accessi e backup** inserisci IP, utente e accesso SSH della VM stack.
   La nuova scheda usa solo questi accessi: per aggiungere un servizio non richiede
   un backup selezionato né gli accessi SSH dell’altra VM.
2. Apri **Aggiungi servizio**, indica il percorso dello stack e incolla il blocco Compose
   di **un solo servizio** e il suo `.env`. Puoi usare un blocco `services:` completo
   oppure il singolo servizio. Usa un nome nuovo e l’immagine che vuoi eseguire.
   Non inserire `build`, `include`, `extends`, anchor YAML o volumi.
3. Premi **Analizza variabili**. Seleziona ciascuna variabile e conferma **Pubblica**
   oppure **Privata**. I nomi sospetti sono solo suggerimenti. Porte, IP interni,
   timezone e opzioni ordinarie restano pubblici; password, token e URL con credenziali
   vanno privati. Puoi inserire il valore privato nel campo mascherato e conservarlo
   in memoria con il pulsante dedicato.
4. Conferma di aver verificato le scelte e prepara il piano. La parte pubblica finisce
   in `data/<servizio>/.env`; l’Agent genera `.secrets/<servizio>.env` dai segreti
   `/<servizio>/<NOME_VARIABILE>`. Il file privato viene applicato per ultimo.
   I commenti dei file esistenti vengono conservati. L’export del piano contiene
   nomi, percorsi e riferimenti, senza valori.
5. Se ci sono segreti, compila progetto, ambiente e token Infisical nella scheda.
   Quando l’Agent usa un tunnel locale riconosciuto, la GUI instrada le API verso
   quel tunnel tramite la connessione SSH autenticata alla VM stack: puoi lasciare
   vuoto HTTPS. Questo evita di contattare l’Infisical principale durante la prova.
   In assenza di un tunnel riconosciuto serve l’indirizzo HTTPS dell’istanza corretta.
   Se l’immagine non ha HEALTHCHECK, indica l’URL di prova nel formato
   `http://127.0.0.1:<porta-pubblicata>/percorso`. Non sono ammessi URL con credenziali,
   host esterni o porte appartenenti ad altri servizi.
6. Premi **Verifica VM**. Il controllo legge lo stato e verifica eventuali conflitti
   con file, nomi o segreti già presenti. Un segreto esistente è riutilizzato solo
   quando il suo valore coincide; non viene sovrascritto. Controlla l’impronta SSH
   quando il programma te la presenta.
7. Premi **Aggiungi e verifica** e attendi. La procedura crea i segreti mancanti,
   aggiunge il nuovo servizio senza riscrivere quelli esistenti, collega l’Agent,
   verifica il valore generato e avvia soltanto il nuovo servizio. Poi richiede la
   sincronizzazione pubblica e un nuovo backup, ne rilegge gli allegati cifrati e
   verifica checksum, manifest e commit associato.
8. Considera conclusa l’operazione solo quando compaiono tutti i controlli verificati
   e il tag del nuovo backup. Apri anche l’applicazione e provane la funzione reale:
   un endpoint di salute non verifica ogni sua funzione.

## Password e file

Token, password SSH e valori privati restano nella memoria della sessione Windows.
I valori dei secret viaggiano verso Infisical attraverso HTTPS oppure dentro la
connessione SSH autenticata, fino al tunnel loopback dell’Agent. Non compaiono negli
argomenti dei comandi SSH. Il report non riporta credenziali o risposte del server.
Con l’Agent di produzione il file privato resta a `0640`, nella cartella privata
a `0750`. L’Agent installato dal recupero usa invece il proprietario dell’utente SSH,
file `0600` e cartella `0700` o `0750`: la scheda riconosce entrambi e non ne amplia
i permessi. Legge il percorso effettivo dalla configurazione del servizio Agent.
La VM conserva un registro protetto dell’operazione per evitare sovrascritture dopo
un’interruzione; può contenere copie della configurazione precedente ed è riservato
all’amministratore.

Per compatibilità con il formato Agent e il verificatore DR esistenti, questa
anteprima rifiuta valori privati con apostrofo, caratteri di controllo, righe multiple
o backslash finale. Il simbolo `$` è supportato. Il rifiuto avviene prima di creare
segreti: non alterare una password valida solo per aggirarlo; serve estendere e
collaudare insieme il formato Agent e il ripristino.

## Se si interrompe

- Una modifica ai campi annulla l’anteprima: prepara e verifica nuovamente il piano.
- Prima dell’avvio, il tool tenta di ripristinare solo i file che ha modificato e che
  non sono cambiati nel frattempo. Non elimina segreti già creati in Infisical.
- Dopo un tentativo di avvio conserva lo stato per la verifica, invece di cancellare
  container o dati. Un errore non viene convertito in un successo.
- Se manca soltanto la pubblicazione o il backup, nella **stessa sessione** puoi
  verificare e riprendere lo stesso piano senza aggiungere di nuovo il servizio.
  La ripresa automatica dopo la chiusura della GUI non è ancora disponibile.

## DNS, domini e altre dipendenze

AdGuard, DNS di Ubuntu, router e inoltri porte restano fuori dal tool. Per un nuovo
dominio configura tu DNS/rewrite, proxy NPM, certificato e accesso dall’esterno.
Se cambi VM durante un disaster recovery, ricorda di aggiornare rewrite locali e
inoltri verso gli IP nuovi prima di collaudare i domini. Non basta cambiare il campo
IP della GUI per modificare un apparato esterno.

## Riferimenti delle API

Il client usa i contratti ufficiali Infisical per [cartelle](https://infisical.com/docs/api-reference/endpoints/folders/create)
e [segreti](https://infisical.com/docs/api-reference/endpoints/secrets/create).
Non segue redirect con il token e non ripete automaticamente una creazione dopo
una risposta ambigua.
