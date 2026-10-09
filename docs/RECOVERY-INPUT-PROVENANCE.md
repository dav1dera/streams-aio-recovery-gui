# Provenienza degli input per il ripristino da zero

Gli input dello stack vengono letti dall'Infisical ripristinato, con la Universal Auth recuperata dal backup Agent. Il programma rifiuta secret nascosti, import ambigui e input obbligatori mancanti. Non sostituisce una credenziale e non inventa identità, password o autorizzazioni.

## AIO importato manualmente

Con la scelta **import manuale AIO**, il programma rinvia soltanto `/dr/AIO_PROFILE_BINDINGS`: il registro serve a ricostruire le identità applicative durante un import automatico. La stessa scelta vale sia per la lettura degli input sia per il rendering. Il piano pubblico e i suoi checksum restano invariati; la variante del contratto esiste soltanto in memoria.

Ogni altro input, compresa la lista delle email consentite di OAuth2 Proxy, resta obbligatorio. Il preflight finale continua a controllare lo stack, NPM e tutti i file richiesti; ammette soltanto le configurazioni utente AIO lasciate esplicitamente da importare manualmente.

## Companion cifrato per la lista email

La release `dr-20261006T210601Z` non contiene `/oauth2-proxy/ALLOWED_EMAILS` nel database Infisical. L'archivio Agent conserva configurazione, template e credenziali, e non costituisce un backup della lista email generata. La lista non può essere ricavata dal client secret OAuth o dagli account AIO.

Per questa release è disponibile il companion `missing-dr-inputs-20261007T002014Z-d2029b2e.age`, prodotto e verificato dal precedente controllo degli input. Selezionalo nel campo **File integrativo cifrato .age** della GUI. Usa una delle identity private che lo possono aprire, come per gli altri artifact age.

Il lettore accetta soltanto il formato del companion: `schema=1`, release e commit identici al punto di recupero selezionato, e un oggetto `request` contenente `allowed_emails`. Il commit associato al companion sopra è `28f6ca7cc6f5fd10418fc0af2926815927ef98c8`.

Viene utilizzata soltanto la lista email, e soltanto se questa manca in Infisical. Una lista presente in Infisical conserva la precedenza. Gli altri dati e il payload AIO nel companion non vengono importati da questa procedura. Sono richiesti indirizzi email espliciti, senza wildcard, duplicati o liste vuote. Il programma non scrive il fallback in Infisical.

Il file cifrato e le identity originali rimangono intatti. La copia decifrata temporanea resta nel deposito privato della VM ed è rimossa dopo la lettura. Il checkpoint registra solamente release, commit, SHA256 del companion e riferimento eventualmente applicato; non contiene email o credenziali.

## Controlli prima del primo avvio

Prima di installare NPM o avviare container applicativi, il recupero prepara il profilo di compatibilità della VM di test verificata: immagini bloccate, layout PostgreSQL 18, lettura delle configurazioni private da DNSCrypt/OAuth2 Proxy/PgBouncer e ordine delle dipendenze. L'override privato viene registrato insieme al suo checksum, senza cambiare i file pubblici né eliminare volumi. Una ripresa verifica il record esistente prima di riutilizzarlo.

La connessione CometNet deve inoltre corrispondere, per ruolo, password e database, a una connessione provisionata dal piano SQL. Il confronto resta privato; il programma rifiuta una connessione indipendente non provisionata invece di creare una nuova credenziale o correggere il secret implicitamente.

Questi controlli preparano un ripristino da zero. Il completamento operativo viene confermato dai controlli successivi all'avvio, non dalla sola preparazione.
