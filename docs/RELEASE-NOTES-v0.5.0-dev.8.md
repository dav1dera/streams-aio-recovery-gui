# Streams AIO Recovery 0.5.0-dev.8 — anteprima

Questa anteprima introduce l'interfaccia scura e la scheda **Aggiungi servizio**, con passaggi **Destinazione → Servizio → Segreti → Verifica**. La versione stabile resta **0.4.19**: pubblicare l'anteprima non dichiara completati i collaudi ancora mancanti.

[Download della prerelease](https://github.com/dav1dera/streams-aio-recovery-gui/releases/tag/v0.5.0-dev.8) · [Prima di iniziare](PRIMA-DI-INIZIARE.md) · [README illustrato](../README.md) · [Guida Aggiungi servizio](AGGIUNGI-SERVIZIO.md)

## Interfaccia e aggiunta di servizi

- Interfaccia WebView2 con barra laterale, avanzamento a passi, esiti e piani senza valori privati. Richiede Edge WebView2 Runtime; l'eseguibile non richiede Python.
- Aggiunta di un servizio alla **VM già operativa**, senza ripristinare un backup sui database. Il percorso conserva i servizi esistenti e avvia soltanto il nuovo container.
- Analisi delle variabili con conferma pubblico/privato, creazione dei segreti mancanti in Infisical e collegamento al template Agent. Le API usano il tunnel riconosciuto oppure un HTTPS alternativo valido.
- Controllo di VM, nomi, porte, file, immagini e salute prima di considerare riuscita l'aggiunta. Un segreto presente viene riusato soltanto se coincide; non è sovrascritto con un valore diverso.
- In **Stack esistente**, richiesta di pubblicazione sanitizzata e nuovo backup ai worker già installati, con rilettura di manifest, commit e allegati. Se manca soltanto questa parte, lo stesso piano può essere ripreso nella stessa sessione.

Il percorso **Collaudo locale** prepara due VM dedicate: avvia Infisical sulla seconda e prepara file e Agent sulla VM stack. Non avvia l'intero stack applicativo e non pubblica GitHub o backup. La successiva aggiunta avvia soltanto il servizio di prova.

## Chiave age, SSH e profili del laboratorio

La chiave age privata può essere scelta da file oppure incollata in un campo mascherato. L'incollata viene trasferita direttamente via SFTP a un file remoto privato, senza file temporaneo Windows e senza inserirla negli esiti. Age e chiave SSH restano credenziali distinte.

La diagnostica SSH distingue la **VM stack** dalla **VM Infisical** e le principali cause di collegamento: rete, autenticazione, protocollo, chiave privata, trasporto e archivio delle impronte. Un'impronta viene salvata soltanto con trasporto attivo e autenticazione completa; le approvazioni restano richieste e un'impronta cambiata non è accettata automaticamente.

Il primo avvio del laboratorio verifica identità della macchina, utente, permessi e punto di recupero. Il profilo usa le immagini immutabili associate al backup scelto, incrociando image lock, Compose DR e commit verificato. Un digest aggiornato non impone di tornare alle immagini di una vecchia prova; repository, architettura e compatibilità restano controllati. Non è una migrazione automatica tra versioni principali di database.

## Documentazione distribuita

Il README in italiano presenta recupero da zero, ripresa e aggiunta di servizi con **nove schermate annotate**. Le figure mostrano la vera interfaccia con dati dimostrativi: i loro stati verdi spiegano i comandi e non attestano un'esecuzione remota per ciascuna immagine.

La release distribuisce **StreamsAIO-Recovery.exe**, **streams-aio-recovery-gui-source.zip**, **PRIMA-DI-INIZIARE.md** e **SHA256SUMS**. Usare il tag dell'anteprima per il download: la voce «Latest» può continuare a indicare la stabile 0.4.19.

## Verifiche automatiche e prova reale

| Verifica | Esito e significato |
| --- | --- |
| Suite locale sui sorgenti dev.8 | **1108 casi raccolti: 1059 riusciti, 49 esclusi su Windows.** Le esclusioni includono controlli che richiedono Linux. |
| GitHub Actions sui sorgenti dev.8 | Controlli Linux, Ubuntu 24.04/26.04 e Windows riusciti, compresi i self-test della finestra Windows con collegamenti remoti disabilitati. [Esecuzione dei controlli](https://github.com/dav1dera/streams-aio-recovery-gui/actions/runs/39487412597). |
| Scansione segreti sui sorgenti dev.8 | [Riuscita](https://github.com/dav1dera/streams-aio-recovery-gui/actions/runs/39487412696). |
| Interfaccia documentale | Rendering con browser headless, API simulata e richieste HTTP bloccate. Verifica l'interfaccia, non le VM. |
| Prova reale dell'utente | Preparazione del laboratorio `.30/.33` e aggiunta di **prova-agent**, con segreto Infisical, file generato dall'Agent e risposta HTTP verificati. **GitHub e backup erano esclusi dal collaudo locale.** |

Le esecuzioni CI collegate attestano i sorgenti dev.8 controllati in quelle esecuzioni; non rappresentano un nuovo collaudo delle VM e non attestano automaticamente un successivo pacchetto pubblicato. I checksum della release identificano i file effettivamente distribuiti.

## Collaudi mancanti e limiti

Con questa anteprima restano da completare **un nuovo recupero integrale da due VM pulite**, **pubblicazione GitHub e nuovo backup nel percorso Aggiungi servizio** e **persistenza dopo riavvio delle due VM**. L'esito locale non prova questi percorsi.

- Sono ammessi nuovi servizi senza dati persistenti propri. Mount, socket Docker, immagini con volumi anonimi, `build`, `include`, `extends` e anchor YAML vengono rifiutati.
- Nuovi database, file `.conf`/`.toml`/`.json`, proxy NPM e permessi Infisical aggiuntivi non vengono configurati automaticamente.
- I valori privati con apostrofo, righe multiple, caratteri di controllo o backslash finale vengono rifiutati; `$` è supportato. Non cambiare una credenziale valida per aggirare il limite.
- La ripresa dell'aggiunta dopo la chiusura della GUI non è ancora disponibile. Password e token restano solo nella memoria della sessione.
- **AdGuard, DNS di sistema Ubuntu e router restano manuali.** Prima di recuperare su nuovi IP aggiornare rewrite e inoltri, incluso il dominio Headscale. Il campo IP della GUI verifica la destinazione attesa e non modifica gli apparati.
- Agent e tunnel del recupero sono preparati dalla GUI; i worker di sincronizzazione sanitizzata e backup DR richiedono installazione e verifica separate dopo una sostituzione definitiva.

Conserva checkpoint ed esiti in caso di errore. La GUI rifiuta uno stato estraneo invece di adottarlo o cancellarlo automaticamente.
