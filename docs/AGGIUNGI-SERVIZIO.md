# Aggiungi servizio — guida illustrata 0.5.0-dev.8

Scarica il programma dalla [release di anteprima 0.5.0-dev.8](https://github.com/dav1dera/streams-aio-recovery-gui/releases/tag/v0.5.0-dev.8). La stabile resta 0.4.19. [Prima di iniziare](PRIMA-DI-INIZIARE.md) · [Note e verifiche dell'anteprima](RELEASE-NOTES-v0.5.0-dev.8.md).

Questa scheda aggiunge **un servizio nuovo alla VM già operativa**, senza ripristinare
backup o database. I servizi esistenti sono conservati. Per ripristinare invece le
due VM o riprendere un recupero, consulta il [README](../README.md).

Il percorso è **Destinazione → Servizio → Segreti → Verifica**. Analisi e piano
sono locali; **Verifica VM** legge la VM e **Aggiungi e verifica** applica il piano.
Non occorre tenere aperto VS Code o consentire il controllo del desktop.

Le figure mostrano la UI attuale con dati e risposte dimostrative. Puntatori e stati
verdi spiegano i passaggi: non certificano operazioni sulle VM del lettore.
[Origine e indice delle immagini](screenshots/README.md).

## 1. Destinazione: stack operativo o laboratorio

![Stack esistente oppure Collaudo locale](screenshots/v050-dev8/09-destinazione.png)

| Modalità | Quando usarla | Controlli richiesti |
| --- | --- | --- |
| **Stack esistente** | Aggiungi un container alla VM operativa. | Servizio, Agent, GitHub e nuovo backup. |
| **Collaudo locale** | Prova il servizio su VM dedicate. | Servizio e Agent. GitHub e backup esclusi. |

Per lo **stack operativo**, in **Accessi e backup** bastano gli accessi SSH della VM
stack. Non servono backup selezionato, chiave age o accessi SSH della seconda VM.
Infisical deve essere raggiungibile dal tunnel Agent o dall’HTTPS alternativo.

Apri **Percorso dello stack e controllo di salute**. In **Cartella dello stack**
inserisci il percorso reale, per esempio `/home/pi/streams-aio`, appartenente all’utente
SSH. Se l’immagine non ha HEALTHCHECK, compila **Controllo HTTP locale**: il controllo
sarà eseguito **sulla VM stack**, non sul PC Windows.

Per **Stack esistente** devono già funzionare Agent, worker pubblico con modalità
`--seamless`, coordinatore DR e accessi GitHub della VM. La scheda li usa:
**non installa da zero i worker di pubblicazione e backup**, né configura un nuovo
account GitHub.

### Laboratorio: preparare le due VM

![Accessi, backup e chiave age per il laboratorio](screenshots/v050-dev8/01-accessi.png)

1. Prepara due VM Ubuntu dedicate, con OpenSSH e un utente con sudo. Conserva uno
   snapshot pulito. Non serve installare Docker a mano.
2. In **Accessi e backup** compila entrambe le VM, un token GitHub con **Contents:
   Read** sui repository del recupero e la chiave age privata. Scegli **File della
   chiave** oppure **Incolla chiave**. Serve `AGE-SECRET-KEY-1…`; la chiave pubblica
   `age1…` e l’etichetta «PRIMARY» non sono la chiave da incollare.
3. Premi **Carica backup** e scegli un backup completo: il commit è associato
   automaticamente. Nel test di riferimento: stack `test@192.168.178.30`,
   Infisical `test2@192.168.178.33`. Sostituiscili con le tue VM.
4. In **Aggiungi servizio → Destinazione → Collaudo locale**, premi **Prepara le VM
   di collaudo** e attendi l’esito nel riquadro del pulsante.
5. Dopo «File e Agent preparati», prosegui con il servizio qui sotto. Non premere
   **Crea da zero** per completare il laboratorio.

La preparazione ripristina e avvia **Infisical e i suoi container** sulla seconda VM.
Sulla VM stack prepara file e servizio di sistema Agent: **non avvia lo stack
applicativo completo**. Per questa prova le principali possono restare accese;
AdGuard, DNS di Ubuntu e inoltri router non devono essere modificati.

Per riprendere una preparazione interrotta, conserva lo stato, scegli **lo stesso
backup** e ripremi **Prepara le VM di collaudo**. La GUI controlla entrambe le VM,
identità, proprietà e checkpoint. Non adotta automaticamente un altro punto di
recupero, un’altra macchina o dati estranei.

Un contrassegno impedisce al laboratorio di pubblicare nei repository principali
e di avviare tutto lo stack. Per un successivo **recupero completo da zero**, usa altre
VM vuote o ripristina gli snapshot puliti delle sole VM di prova, poi segui il
[README](../README.md).

## 2. Servizio: Compose e variabili

![Nome, Compose e variabili del servizio](screenshots/v050-dev8/05-servizio.png)

In **Nome del servizio** scrivi `prova-agent`. In **Compose** incolla:

```yaml
services:
  prova-agent:
    image: traefik/whoami:v1.11.0
    restart: unless-stopped
    ports:
      - "127.0.0.1:18089:80"
```

In **Variabili del servizio** incolla:

```dotenv
WHOAMI_PORT_NUMBER=80
TEST_API_TOKEN=solo-collaudo-infisical
```

Il token è fittizio. Il container non ha dati persistenti ed espone la porta solo
sul loopback della VM. Nel passo **Destinazione**, dentro **Percorso dello stack
e controllo di salute**, inserisci in **Controllo HTTP locale**:

```text
http://127.0.0.1:18089/health
```

È la porta **del servizio sulla VM stack**, dopo l’avvio. Non è il pannello Infisical
e non va aperta nel browser Windows: lì `127.0.0.1` indica il PC Windows.
L’esempio [whoami v1.11.0](https://github.com/traefik/whoami/tree/v1.11.0) offre `/health`.

Premi **Analizza variabili** per passare a **Segreti**. Per altri servizi usa un nome,
una porta liberi e il loro vero endpoint di salute.

## 3. Segreti: classificazione e collegamento Infisical

![Scelta pubblico o privato e accesso Infisical](screenshots/v050-dev8/06-segreti.png)

| Variabile | Scelta | Destinazione |
| --- | --- | --- |
| `WHOAMI_PORT_NUMBER` | **Pubblica** | `data/prova-agent/.env` |
| `TEST_API_TOKEN` | **Infisical** (privata) | Infisical `prod`, cartella `/prova-agent`; Agent → `.secrets/prova-agent.env` |

Verifica ogni proposta. Porte, IP locali, timezone e opzioni ordinarie sono pubblici;
password, token e URL con credenziali sono privati. Il nome da solo non dimostra la
natura del valore. Se un valore privato manca, seleziona la variabile, inseriscilo
nel campo mascherato e premi **Imposta valore**.

In **Collega Infisical** inserisci **ID del progetto**, **Ambiente** (per esempio
`prod`) e **Token Infisical con permessi di scrittura**. Serve un access token:
**non il token GitHub né il Client Secret**. Se il tunnel Agent è riconosciuto,
lascia vuoto **Accesso HTTPS alternativo → Indirizzo HTTPS**: la GUI segue l’istanza
collegata alla VM stack. Altrimenti serve l’HTTPS diretto con certificato valido.

### Ottenere progetto e token senza modificare l’Agent

Apri il pannello dell’istanza Infisical che stai usando. Per trovare la porta,
sulla VM Infisical leggi:

```bash
sudo docker ps --format 'table {{.Names}}\t{{.Ports}}'
```

Nel test riportato, `infisical-backend` pubblicava `0.0.0.0:80->8080/tcp` e il
pannello era `http://192.168.178.33/`. È solo l’esempio del laboratorio: non una porta
garantita per tutte le installazioni. L’istanza ripristinata conserva gli account
presenti nel backup; accedi con quell’account verificando l’indirizzo del pannello.

1. Nel progetto **streams-aio → Settings**, copia il **Project ID** nella GUI.
2. Nell’organizzazione apri **Access Control → Machine Identities → Create**. Crea
   una nuova identità, per esempio `recovery-gui-lab`, con ruolo organizzazione
   **No Access**, se disponibile. Non modificare l’identità dell’Agent.
3. Sulla nuova identità configura **Authentication → Token Auth**. Se presenta
   Universal Auth predefinito, sostituiscilo soltanto su questa nuova identità.
4. Premi **Add Token** e copia il token nella Recovery GUI. Il Client Secret di
   Universal Auth non è il valore richiesto.
5. Nel progetto apri **Access Control → Machine Identities → Add Machine Identity
   to Project → Assign Existing**, scegli l’identità e assegna **Member**. Con ruoli
   personalizzati servono lettura e creazione di cartelle e segreti nell’ambiente scelto.

Riferimento: [guida ufficiale Token Auth](https://infisical.com/docs/documentation/platform/identities/token-auth).
Se scade, genera un token nuovo. Non incollarlo in chat o file pubblici.

Le API richieste sono cartelle v2 e segreti v4; un vecchio service token potrebbe
non funzionare. L’identità **dell’Agent** deve già poter leggere la cartella
`/<nome-servizio>`: la funzione aggiunge il template e non amplia ruoli o permessi.

Conferma **Ho verificato la scelta pubblico/privato delle variabili** e premi
**Prepara il piano**.

## 4. Verifica: controllare e aggiungere

![Piano, controlli e pulsanti di esecuzione](screenshots/v050-dev8/07-verifica.png)

1. Controlla nome, immagine, VM e modalità nella parte alta.
2. Premi **Verifica VM**: controlla percorso, Agent, immagine, porta, file e conflitti.
   Verifica l’impronta SSH se viene richiesta.
3. Con verifica riuscita, premi **Aggiungi e verifica** e attendi. Non occorre aprire
   il link `/health` nel browser.

La procedura crea i segreti mancanti, aggiunge il servizio, collega il template
Agent, rilegge il file privato e avvia **soltanto il nuovo container**. Non riscrive
l’intero Compose e non ripristina database esistenti. Un segreto presente è riusato
solo se il valore coincide; un valore diverso è conservato e segnala un conflitto.

Il file pubblico è `data/<servizio>/.env`; l’Agent genera `.secrets/<servizio>.env`,
applicato per ultimo. I commenti dei file esistenti sono conservati. Il piano
esportabile contiene nomi e riferimenti senza valori.

## 5. Esito: cosa è stato verificato

![Esito locale: servizio e Agent verificati, GitHub e backup esclusi](screenshots/v050-dev8/08-esito-locale.png)

**Collaudo locale completato** verifica servizio e Agent. Gli altri container
dello stack non sono avviati dalla preparazione; Infisical sulla seconda VM è attivo.
**GitHub e backup restano esclusi**: il verde locale non ne prova la pubblicazione.

In **Stack esistente**, dopo servizio e Agent il tool richiede pubblicazione
sanitizzata e nuovo backup ai worker già installati. Rilegge allegati, manifest,
checksum e commit. Il percorso è completo solo con **Servizio aggiunto e verificato**,
tutti i controlli richiesti e il tag del backup. Prova anche la funzione reale dell’app.

**Stato della 0.5.0-dev.8:** l’utente ha completato preparazione del laboratorio
`.30/.33` e aggiunta di `prova-agent`, con servizio e Agent verificati. Pubblicazione
GitHub, nuovo backup e recupero completo dello stack con questa anteprima restano da
collaudare. La 0.5 è un’anteprima, non una nuova release stabile dichiarata equivalente
alla GUI già usata per il recupero precedente.

## 6. Interruzioni e limiti

- Cambiare campi annulla il piano: preparalo e verificalo di nuovo.
- Prima dell’avvio sono ripristinati soltanto i propri file non modificati nel
  frattempo, quando possibile. I segreti già creati non vengono eliminati.
- Dopo un tentativo di avvio, stato e registro sono conservati. Non cancellare
  checkpoint per eliminare un errore.
- Se manca solo GitHub o backup, nella **stessa sessione** puoi verificare e riprendere
  lo stesso piano. La ripresa dopo la chiusura della GUI non è ancora disponibile.
- Solo servizi **senza nuovi dati persistenti**: sono rifiutati mount `volumes`,
  anche readonly e socket Docker, e immagini con volumi anonimi. Nuovi database
  richiedono prima una copertura di backup e recupero collaudata.
- File aggiuntivi `.conf`/`.toml`/`.json`, proxy NPM e nuovi permessi Infisical non
  sono creati automaticamente. Nel Compose non usare `build`, `include`, `extends`
  o anchor YAML.
- Valori privati con apostrofo, caratteri di controllo, righe multiple o backslash
  finale sono rifiutati prima di creare segreti. `$` è supportato. Non cambiare una
  password valida per aggirare il limite: serve estendere il formato.

### SSH e immagini del backup

Gli errori SSH indicano **VM stack** oppure **VM Infisical**. Controlla IP, utente
e porta. Con password lascia vuoto il campo chiave SSH: la chiave age serve al backup.
La porta 22 aperta non dimostra autenticazione e impronta corrette. Salva gli esiti,
conserva checkpoint e VM e riprendi dopo aver risolto.

Il laboratorio usa immagini immutabili del backup scelto, incrociando
`config/image-lock.json`, `config/compose.dr.yaml` e Compose del commit verificato.
Un digest aggiornato non richiede di tornare alle vecchie immagini. Restano i
controlli Linux amd64, repository, PostgreSQL 18, account, permessi e valori privati.
Non migra automaticamente database tra versioni principali; Infisical ha un proprio
profilo compatibile.

## 7. Credenziali e apparati esterni

Password, token e valori privati restano nella memoria della sessione Windows.
**Incolla chiave** non crea file temporanei Windows: trasferisce direttamente via
SFTP in un file remoto a `0600`. Piano ed esiti non contengono la chiave. Chiudendo
la GUI va reinserita: conserva separatamente una copia protetta.

Le API transitano via HTTPS o dentro SSH fino al tunnel loopback Agent. I valori
non entrano negli argomenti SSH. Sono riconosciuti file privati di produzione a
`0640` e del recupero a `0600`, senza ampliare i permessi. Il registro remoto
protetto può conservare copie precedenti delle configurazioni.

AdGuard, DNS di Ubuntu, router e inoltri restano fuori dal progetto. Per nuovi
domini configura DNS/rewrite, NPM e certificati. In un recupero su nuovi IP aggiorna
rewrite e inoltri verso la VM corretta, incluso il dominio del controller Headscale.
Il campo IP nella GUI non modifica gli apparati. Per il servizio loopback non serve
cambiare nulla.

## Riferimenti tecnici

- [Aspetto dell’interfaccia](UI-DESIGN.md)
- [API Infisical: cartelle](https://infisical.com/docs/api-reference/endpoints/folders/create)
- [API Infisical: segreti](https://infisical.com/docs/api-reference/endpoints/secrets/create)

Il client non segue redirect con il token e non ripete automaticamente una creazione
dopo una risposta ambigua.
