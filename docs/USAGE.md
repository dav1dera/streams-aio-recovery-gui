# Guida pratica · Streams AIO Recovery 0.4.0 preview

Questa guida segue la nuova dashboard: **Panoramica**, **Accessi e backup**, **Opzioni avanzate**. Il percorso recupera due VM e importa automaticamente i database AIO da un backup completo. È una preview con test locali: il collaudo completo da VM vuote e le prove applicative descritte in fondo sono ancora da eseguire.

## 1. Preparare le due VM

Usa **Ubuntu Server 26.04 o 24.04 amd64**, seleziona OpenSSH durante l’installazione e crea un primo utente con sudo. L’utente SSH deve avere UID/GID 1000. Il nome può essere diverso per le due VM; non deve necessariamente essere `test` o `test2`. [Preparazione in Proxmox](PROXMOX.md).

La GUI installa Docker e le dipendenze. Non crea le VM in Proxmox e non installa Ubuntu. Fedora sull’Infisical originale non significa che Fedora sia supportata come nuova destinazione della GUI.

Per la prova attuale le destinazioni sono:

| Ruolo | IP SSH | Utente della prova |
| --- | --- | --- |
| Stack | `192.168.178.29` | `test` |
| Infisical | `192.168.178.30` | `test2` |

Sono esempi della prova, non valori obbligatori del nuovo profilo operativo. Per **Crea da zero**, entrambe le VM devono essere vuote e distinte. Per un recupero già presente usa **Rileva e continua**.

Una reinstallazione cambia l’impronta SSH anche mantenendo lo stesso IP. Verifica l’impronta dalla console della VM prima di accettare la nuova chiave. Il programma non considera l’IP invariato una prova dell’identità della macchina.

## 2. Preparare gli accessi e la chiave

Apri **Accessi e backup** e compila le due schede VM.

![Schermata Accessi e backup della 0.4.0, con campi privati vuoti](screenshots/01-setup-v040.png)

| Campo | Valore da inserire |
| --- | --- |
| Indirizzo IP o nome host | Indirizzo raggiungibile dal PC Windows. |
| Utente SSH | L’utente Ubuntu creato su quella VM. |
| Password dell’utente SSH | La password di quell’utente Ubuntu. |
| Chiave SSH | In alternativa alla password, il file della chiave privata SSH autorizzata sulla VM. |

La password SSH non è il token GitHub, la password di Infisical o il suo client secret. Se sudo usa la stessa password SSH, lascia vuoto il relativo campo nelle **Opzioni avanzate**. Compila lì le porte diverse da 22 e le eventuali passphrase delle chiavi SSH.

Per GitHub usa un token fine-grained con accesso a `dav1dera/streams-aio-dr` e `dav1dera/streams-aio-sanitized`, permesso **Contents: Read**. Non occorre un token con accesso in scrittura per recuperare.

Nel campo **File della chiave privata age PRIMARY o RECOVERY** premi **Sfoglia** e scegli il file della identity compatibile con il backup. Il file contiene la riga originale `AGE-SECRET-KEY-1…`; può avere estensione `.txt`. PRIMARY e RECOVERY sono alternative se entrambe sono destinatarie del backup scelto.

Le stringhe `age1…` sono chiavi pubbliche: non permettono di ricostruire la chiave privata. Non cambiare un prefisso per trasformarle in identity. Conserva copie offline delle chiavi private e non inserirle in repository, screenshot o messaggi.

## 3. Scegliere un backup completo

Premi **Carica backup**, poi seleziona **Backup pubblicato**. Il campo **Commit associato al backup** viene compilato leggendo il manifest della release: per il nuovo flusso non scegliere a mano il `main` più recente al posto del commit registrato.

Un punto adatto al recupero automatico deve contenere:

| File della release privata | Contenuto |
| --- | --- |
| `manifest.json` con schema 2 | Identificativo del punto, commit dello stack e inventario degli artifact. |
| `SHA256SUMS` | Checksum del manifest e degli artifact pubblicati. |
| `infisical-config.tar.gz.age` | Configurazione privata Infisical. |
| `infisical-postgres.dump.age` e `infisical-postgres-globals.sql.age` | Database e ruoli Infisical. |
| `infisical-agent-infisical-agent.tar.gz.age` | Configurazione e credenziali dell’Agent. |
| `npm-database.sqlite.age` | Configurazione NPM prevista dal flusso di recupero. |
| `aio-state.tar.gz.age` | Snapshot nativi dei due database AIO, immagini associate e verifiche delle chiavi di cifratura. |

Il programma verifica release pubblicata, inventario, checksum, commit, identity e contratto dei dati prima di usare il contenuto. La presenza della release nell’elenco non dimostra da sola che sia completa o compatibile.

I backup precedenti senza `aio-state.tar.gz.age` non diventano completi aggiornando l’eseguibile. Possono essere riconosciuti per la compatibilità storica, ma il nuovo percorso automatico richiede un nuovo backup schema 2 prodotto e verificato dall’originale. I campi JSON, payload e companion delle **Opzioni avanzate** non sostituiscono questo requisito.

## 4. Scegliere la destinazione dei domini

Nella scheda **Domini e configurazioni AIO** scegli una modalità.

### Prova affiancata alle VM operative

Mantieni attive le VM originali e usa un instradamento DNS dedicato al test per portare i nomi del backup sulle nuove VM. DDNS, Watchtower e Deunhealth restano esclusi. Il recupero usa HTTPS e l’indirizzo CometNet reale: non ricrea il vecchio profilo locale della 0.3.17.

L’instradamento deve funzionare anche da Comet attraverso Gluetun/VPN, perché CometNet esegue lì il proprio controllo di raggiungibilità. Cambiare soltanto il file hosts di Windows non modifica la risoluzione dei contenitori. Un DNS dedicato visibile solo sulla LAN potrebbe non essere raggiungibile dalla VPN.

La prova affiancata può verificare HTTPS e la destinazione del recupero; la raggiungibilità P2P da Internet deve essere collaudata separatamente, perché i peer pubblici potrebbero raggiungere ancora la produzione.

### Recupero della produzione

Usala quando il traffico dei domini deve raggiungere le VM sostitutive. Prepara prima gli indirizzamenti DNS e il port forwarding del router verso NPM. La scelta abilita il completamento del recupero operativo e l’attivazione finale di Cloudflare DDNS, Watchtower e Deunhealth.

**La GUI non cambia DNS pubblici, router o port forwarding.** La scelta della modalità è esplicita, ma non effettua automaticamente il trasferimento del traffico. Per una simulazione con gli originali ancora operativi scegli la modalità affiancata.

### Indirizzo IP previsto per i domini

Inserisci l’IP previsto dall’instradamento dei domini, non necessariamente quello usato per SSH. In produzione può essere l’IP pubblico; in una prova può essere l’indirizzo della destinazione di test. Questo campo registra la destinazione scelta: non modifica il DNS e non sostituisce la prova effettiva del percorso HTTPS.

NPM deve già avere una route compatibile con l’upstream CometNet sul servizio Gluetun. Le route che puntano soltanto a un vecchio IP LAN richiedono una verifica e un adattamento esplicito: la preview non le riscrive indovinando la destinazione.

## 5. Avviare o riprendere

Torna alla **Panoramica**, controlla le due destinazioni e scegli:

![Panoramica della 0.4.0: Crea da zero, Rileva e continua e avanzamento](screenshots/00-dashboard-v040.png)

| Azione | Quando usarla |
| --- | --- |
| **Crea da zero** | Le due VM sono nuove, senza dati o risorse del precedente stack. |
| **Rileva e continua** | Esiste un tentativo del recupero scelto oppure vuoi rilevare e completare il suo avvio. |

Entrambe le azioni controllano backup e identità delle VM prima di preparare il recupero. **Rileva e continua esegue anche i passi mancanti:** non è un pulsante di sola diagnostica.

La ripresa verifica macchina, backup, commit, file, proprietà di container e volumi e stato registrato. Non basta che un container abbia un nome simile. Un checkpoint incompatibile o un’operazione ancora registrata come incompleta ferma la procedura, conservando lo stato da esaminare.

**Crea da zero non cancella risorse esistenti.** Per un nuovo collaudo completo ripristina uno snapshot pulito o crea nuove VM di test. Il vecchio reset circoscritto alle `.29/.30` non fa parte delle due azioni operative della dashboard.

Tieni il PC collegato e non avviare un secondo recupero o script di modifica in parallelo. Se interrompi, lascia terminare l’operazione corrente, conserva gli esiti e usa **Rileva e continua** con le stesse scelte. Non cancellare file di stato per far sparire un errore.

## 6. Cosa succede durante il recupero

1. **Infisical** — installazione delle dipendenze, controllo del punto scelto, decifratura e recupero di configurazione, ruoli, database e API.
2. **Stack** — lettura dei secret, generazione dei file, directory e permessi; verifica della compatibilità del primo avvio con le immagini previste.
3. **AIO e NPM** — recupero del database NPM e ripristino nativo di AIOStreams e AIOMetadata.
4. **Agent** — installazione dell’Agent continuo e del tunnel SSH permanente tra le nuove VM.
5. **Avvio per dipendenze** — verifica delle immagini e avvio dei servizi nell’ordine previsto.
6. **NPM prima di CometNet** — riemissione TLS e preparazione della route, quindi prova della destinazione HTTPS dal percorso Gluetun/VPN. Solo dopo viene avviato CometNet con il proprio indirizzo WSS reale.
7. **Verifica finale** — controllo degli upstream NPM e dei servizi. In produzione i tre controller pubblici vengono attivati per ultimi.

L’ordine NPM → HTTPS → CometNet evita che il controllo iniziale di CometNet fallisca mentre il suo proxy non è ancora pronto. Una risposta temporanea univoca inserita nella route NPM deve tornare dal nuovo server: il certificato valido del server originale non è sufficiente. La risposta viene poi rimossa e la configurazione NPM ripristinata.

I controlli applicativi automatici registrano l’infrastruttura e l’avvio. Non possono confermare da soli che ogni login, configurazione addon o autorizzazione esterna funzioni: servono le prove sotto.

## Dati conservati e dati ricostruibili

Gli snapshot AIO copiano i database SQLite nativi con la loro struttura, senza convertire un export JSON a una versione diversa. Conservano gli UUID, gli hash delle password, i profili e i record OAuth già presenti. Prima del ripristino vengono confrontati immagini applicative e collegamento alle chiavi di cifratura recuperate da Infisical.

Questo evita di creare nuove identità al posto di quelle originali. Non prolunga però la validità di un token già revocato o scaduto presso un servizio esterno: AniList, Trakt e gli altri collegamenti devono essere provati dopo il recupero.

| Dato | Trattamento |
| --- | --- |
| Infisical, chiavi applicative e credenziali Agent | Recuperati dagli artifact cifrati del punto scelto. |
| NPM, route e impostazioni TLS previste | Recuperati; certificati riemessi dal flusso previsto e HTTPS verificato. |
| Database SQLite AIOStreams e AIOMetadata | Recuperati automaticamente dalla capsule AIO coerente. |
| Configurazioni e credenziali Comet/StremThru | Ricostruite dai secret e dai template previsti. |
| Database e cache ricostruibili già esclusi, inclusi Comet, CometNet, StremThru e Redis | Ripartono vuoti; scraping e cache si ricostruiscono. |
| Cache AIO, Jackett e DNSCrypt dichiarate ricostruibili | Non incluse nella capsule AIO. |
| Stati opzionali di altri servizi, account locali e registrazioni dei nodi | Da riconciliare nell’inventario e verificare nelle applicazioni prima di dichiarare equivalenza alla produzione. |

Il recupero non svuota indiscriminatamente PostgreSQL condiviso o volumi sconosciuti. La compatibilità del primo avvio resta legata ai layout e ai digest verificati: un aggiornamento delle immagini può richiedere un nuovo controllo del profilo.

## Se compare un errore

Premi **Salva esiti** e conserva il registro. Risolvi la causa indicata, poi riprendi con gli stessi accessi, backup e destinazioni. I messaggi generici di arresto descrivono l’esito; il codice specifico del passo identifica il controllo che non è passato.

| Messaggio o situazione | Cosa controllare |
| --- | --- |
| `SSH_AUTH_FAILED` | Utente Ubuntu, password o chiave della VM corretta. |
| `SSH_CONNECTION_FAILED` | VM accesa, IP, porta SSH e raggiungibilità dal PC. |
| `SSH_HOST_KEY_CHANGED` | Impronta della nuova installazione verificata dalla console della VM. |
| `GITHUB_REPOSITORY_OR_RELEASE_UNAVAILABLE` | Token, repository selezionati e permesso Contents: Read. |
| `AGE_PUBLIC_KEY_NOT_IDENTITY` | È stato scelto un file pubblico `age1…`; occorre l’identity privata originale. |
| `AGE_NO_MATCHING_RECIPIENT` | Identity e release non appartengono allo stesso backup; scegli una PRIMARY/RECOVERY compatibile. |
| Backup AIO richiesto | Scegli un nuovo punto schema 2 con `aio-state.tar.gz.age`; la vecchia release non contiene lo snapshot nativo. |
| Collegamenti NPM assenti dal backup | Scegli un nuovo punto completo con la topologia NPM cifrata. Una vecchia copia non contiene la prova necessaria per adattare gli upstream alle due nuove VM. |
| Ricevuta AIO o NPM incompatibile | Conserva database, checkpoint ed esiti. La ripresa automatica richiede ricevute e copie corrispondenti; non eliminarle per forzare il passaggio. |
| Lista email OAuth assente | Completa l’input nell’Infisical originale e crea un nuovo backup. I vecchi tentativi possono usare un companion cifrato compatibile nelle Opzioni avanzate. |
| Commit del backup non coerente | Ricarica il punto scelto e usa il commit registrato nel suo manifest. |
| VM non vuota o risorse non riconosciute | Usa Rileva e continua per il tentativo compatibile; per un test nuovo usa VM pulite. |
| Checkpoint incompatibile o operazione incompleta | Conserva lo stato e il registro; non eliminare il checkpoint e non riavviare un reset alla cieca. |
| Errore dei domini, HTTPS o CometNet | DNS dal percorso VPN, destinazione del router, route/upstream NPM, certificato e WebSocket. |
| Immagine o layout non supportato | Confronta il punto di recupero con la versione della GUI e il profilo verificato. |

## Backup giornaliero

Il timer giornaliero è stato **installato e verificato sull’host originale il 9 ottobre 2026**: ogni giorno alle **04:30 nel fuso della VM**, con ritardo casuale fino a 10 minuti e recupero delle esecuzioni perse. Risultava attivo e abilitato, con prossima esecuzione il **10 ottobre 2026 alle 04:35:05 CEST**. Lo stato applicativo dell’originale è stato verificato invariato. Lock, verifica della pubblicazione e politica di conservazione restano parte del flusso: sono mantenute al massimo **cinque release verificate**. Un backup manuale aggiuntivo usa uno dei cinque punti disponibili.

**Stato attuale:** frequenza giornaliera confermata; pubblicazione e decifratura di un nuovo backup completo con snapshot AIO e topologia NPM ancora da confermare. Questa GUI non attiva automaticamente il coordinatore dei backup sull’originale.

Prima di affidarti alla pianificazione, verifica sull’host che coordina il backup:

- timer attivo e abilitato, calendario effettivamente giornaliero e prossima esecuzione corretta;
- nuova release pubblicata con manifest schema 2, commit coerente e capsule AIO;
- inventario e checksum completi, decifratura provata con PRIMARY e RECOVERY;
- input Infisical completi, inclusa la lista email OAuth precedentemente fornita dal companion;
- cinque punti verificati conservati e nessuna cancellazione di release estranee.

Questi controlli attestano il backup. Un ripristino completo su destinazioni pulite ne attesta l’utilizzabilità.

## Collaudo finale

Per dichiarare il risultato equivalente allo stack originale devono essere completate e registrate tutte queste prove. I test locali della preview e la prova storica 0.3.17 non le sostituiscono.

- [ ] Produrre sull’originale un backup completo schema 2 e verificarlo con entrambe le identity private.
- [ ] Eseguire **Crea da zero** su due VM pulite, usando soltanto la GUI.
- [ ] Interrompere in un punto controllato e completare con **Rileva e continua**, conservando dati e identità.
- [ ] Verificare Agent e tunnel, tutti i servizi previsti e le healthcheck definite.
- [ ] Accedere a Infisical e NPM; verificare route, certificati e domini sulla nuova destinazione.
- [ ] Accedere ad AIOStreams e AIOMetadata con le identità originali; confrontare profili, configurazioni e URL addon.
- [ ] Provare AniList, Trakt, provider e gestori esterni; registrare soltanto le riautorizzazioni realmente necessarie.
- [ ] Provare OAuth2 Proxy e la lista email consentite.
- [ ] Verificare CometNet WSS attraverso NPM e un collegamento P2P da un percorso esterno.
- [ ] Verificare che i database/cache esclusi si inizializzino e riprendano scraping o ricostruzione.
- [ ] Riconciliare gli stati opzionali con l’inventario dell’originale.
- [ ] In produzione, verificare i tre controller dopo il trasferimento del traffico.
- [ ] Riavviare entrambe le VM e ripetere le prove di accesso, Agent, HTTPS e servizi.
- [x] Confermare il timer giornaliero sull’originale (9 ottobre 2026).
- [ ] Confermare una successiva pubblicazione completa e la sua decifratura.

La prova del 9 ottobre con la 0.3.17 ha completato l’avvio dei 28 servizi della simulazione, con AIO manuale e CometNet locale. La nuova 0.4.0 estende il percorso; il suo esito completo deve ancora essere registrato.
