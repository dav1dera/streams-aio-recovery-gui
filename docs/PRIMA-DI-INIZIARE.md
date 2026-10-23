# Prima di iniziare — Streams AIO Recovery 0.5.0-dev.8

Questa è un'**anteprima**, con interfaccia scura e scheda **Aggiungi servizio**. La versione stabile resta **0.4.19**. Scegli il percorso adatto prima di usare le VM.

- [Release 0.5.0-dev.8 e download](https://github.com/dav1dera/streams-aio-recovery-gui/releases/tag/v0.5.0-dev.8)
- [Guida illustrata completa](https://github.com/dav1dera/streams-aio-recovery-gui/blob/v0.5.0-dev.8/README.md)
- [Guida Aggiungi servizio](https://github.com/dav1dera/streams-aio-recovery-gui/blob/v0.5.0-dev.8/docs/AGGIUNGI-SERVIZIO.md)
- [Note e verifiche dell'anteprima](https://github.com/dav1dera/streams-aio-recovery-gui/blob/v0.5.0-dev.8/docs/RELEASE-NOTES-v0.5.0-dev.8.md)

## 1. Scarica e apri il programma

Nella release scarica **StreamsAIO-Recovery.exe**, **SHA256SUMS** e questo documento. **streams-aio-recovery-gui-source.zip** contiene i sorgenti; non serve per usare l'eseguibile.

Serve Windows con **Microsoft Edge WebView2 Runtime**. Python non è richiesto. Se WebView2 manca, installa il runtime ufficiale Microsoft prima di aprire la GUI.

Nella cartella dei file, verifica il checksum in PowerShell:

```powershell
Get-FileHash .\StreamsAIO-Recovery.exe -Algorithm SHA256
Get-Content .\SHA256SUMS
```

Confronta l'hash con la riga di **StreamsAIO-Recovery.exe** nello stesso file **SHA256SUMS** della release. L'eseguibile non è firmato con Authenticode. Chiudi la GUI precedente e apri questa versione manualmente.

**Password, token e chiavi si inseriscono soltanto nei campi della GUI.** Restano nella memoria della sessione; dopo averla chiusa vanno reinseriti. Non scriverli in questo documento, nei piani esportati, negli env pubblici o nei messaggi GitHub.

## 2. Scegli il percorso

| Cosa vuoi fare | Percorso |
| --- | --- |
| Ripristinare l'intero ambiente su due VM vuote | **Panoramica → Crea da zero**. Servono il backup completo e la preparazione della rete. |
| Riprendere un recupero interrotto | **Panoramica → Rileva e continua**, sulle stesse VM e con lo stesso backup del tentativo. |
| Provare l'aggiunta di un servizio su due VM dedicate | **Aggiungi servizio → Destinazione → Collaudo locale → Prepara le VM di collaudo**. |
| Aggiungere un servizio a una VM già operativa | **Aggiungi servizio → Destinazione → Stack esistente**. Non ripristinare un backup e non preparare il laboratorio. |

Per recupero completo e laboratorio servono **due VM Ubuntu Server 24.04 o 26.04 amd64**, IP distinti, OpenSSH e utenti sudo con UID/GID 1000. La GUI installa Docker se manca; non crea le VM. Conserva uno snapshot Ubuntu pulito delle VM di prova.

Lo **Stack esistente** deve già avere Agent, worker della pubblicazione sanitizzata e coordinatore DR funzionanti. La scheda non installa questi worker da zero e non configura un account GitHub.

## 3. Compila Accessi e backup

Per recupero completo o laboratorio:

1. Inserisci IP attuali, utenti e porte SSH della VM **stack** e della VM **Infisical**. Con password lascia vuoto il campo della chiave SSH. Compila sudo o passphrase soltanto quando necessari.
2. Inserisci un token GitHub con **Contents: Read** sui due repository di recupero.
3. Premi **Carica backup**, scegli un punto completo e lascia il commit associato automaticamente. Per una ripresa scegli **lo stesso punto del tentativo fermato**.
4. Per age scegli **File della chiave** oppure **Incolla chiave**. Serve la chiave privata compatibile `AGE-SECRET-KEY-1…`. Non aggiungere la parola PRIMARY e non usare la chiave pubblica `age1…`.
5. Quando richiesto, confronta l'impronta SSH con la console della VM. Una VM ricreata può avere una chiave nuova anche mantenendo lo stesso IP.

La chiave age incollata viene trasferita direttamente via SFTP a un file remoto privato `0600`, senza file temporaneo Windows. Conserva comunque una copia protetta della chiave fuori dal PC.

Per **aggiungere un servizio allo stack attivo** bastano gli accessi SSH della VM stack e, se ci sono valori privati, l'accesso API Infisical: non servono backup selezionato, chiave age o accessi SSH della seconda VM.

## 4. Prova locale o recupero completo

Il **Collaudo locale** ripristina e avvia Infisical sulla seconda VM; sulla VM stack prepara file e Agent. **Non avvia l'intero stack**. Dopo la preparazione puoi aggiungere un servizio di prova: viene avviato soltanto quel servizio. GitHub e backup restano esclusi, e le originali possono restare accese.

Il **recupero completo** avvia invece le applicazioni previste. Prima prepara manualmente DNS/rewrite e inoltri del router verso le VM di destinazione. Per sostituire le originali, spegnile ed evita istanze concorrenti. **Crea da zero richiede destinazioni vuote**; non cancella installazioni presenti. Su un tentativo riconosciuto usa **Rileva e continua**.

Il laboratorio non si trasforma in un recupero completo premendo Crea da zero. Per quella prova usa altre VM vuote oppure ripristina gli snapshot puliti delle sole VM di laboratorio.

## 5. Infisical per aggiungere un servizio

Nella scheda **Segreti**, verifica quali valori sono pubblici e quali privati. Porte e IP locali ordinari restano nei file pubblici; password, token e URL con credenziali vanno in Infisical.

Per i valori privati inserisci **Project ID**, ambiente (per esempio `prod`) e un **access token Infisical** con lettura e creazione di cartelle e segreti. **Non è il token GitHub e non è il Client Secret di Universal Auth.**

Puoi creare un'identità dedicata nell'organizzazione, configurare **Token Auth → Add Token** e assegnarla al progetto con ruolo **Member**, oppure un ruolo personalizzato equivalente. Non modificare l'identità dell'Agent. Quest'ultima deve già poter leggere la cartella del nuovo servizio: la GUI non ne amplia i permessi. La guida illustrata mostra tutti i passaggi.

Se il tunnel Agent è riconosciuto, lascia vuoto l'HTTPS alternativo: la GUI usa l'istanza collegata alla VM stack. Nel laboratorio usa l'Infisical ripristinato sulla VM di prova.

Un URL di salute come `http://127.0.0.1:18089/health` va nel campo **Controllo HTTP locale** della GUI. Il controllo viene eseguito **sulla VM stack**, non nel browser Windows e non sul pannello Infisical.

## 6. DNS, AdGuard e router restano manuali

La GUI adatta i collegamenti interni dello stack; **non modifica AdGuard, i DNS di sistema Ubuntu o il router**.

Per il recupero completo controlla:

- I domini delle applicazioni e del controller Headscale devono raggiungere la nuova VM stack, dove gira NPM. Anche il dominio HTTPS di Infisical passa da NPM, che inoltra alla VM Infisical separata.
- I record espliciti possono prevalere sui wildcard. Verifica la risoluzione da client, VM e container, non soltanto da Windows.
- Inoltra **TCP 80 e 443 alla VM stack** e adegua separatamente le altre porte necessarie. Il campo IP nella GUI verifica la destinazione attesa; non crea gli inoltri.
- Dopo una prova, spegni le VM recuperate e ripristina DNS e router prima di tornare alle originali.

Per il servizio di prova su loopback non serve cambiare AdGuard o router.

## 7. Cosa è già provato e cosa resta da provare

**Prova reale completata:** preparazione del laboratorio sulle VM `.30` e `.33`, poi aggiunta di `prova-agent` con segreto Infisical, file generato dall'Agent e risposta HTTP verificati.

**Ancora da collaudare con questa anteprima:** un nuovo recupero dell'intero stack da VM pulite, pubblicazione GitHub e nuovo backup del percorso Aggiungi servizio, e funzionamento dopo riavvio delle due VM. I test automatici non sostituiscono queste prove.

Sono supportati nuovi servizi **senza dati persistenti propri**. Mount, socket Docker, immagini con volumi anonimi, nuovi database e configurazioni aggiuntive richiedono un percorso dedicato. Non considerare coperti dati nuovi soltanto perché il container parte.

Se una fase fallisce, salva gli esiti, conserva VM e checkpoint e segui il messaggio. Non cancellare database o checkpoint per aggirare un controllo.
