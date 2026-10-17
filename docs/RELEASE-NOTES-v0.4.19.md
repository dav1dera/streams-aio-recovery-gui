# Streams AIO Recovery 0.4.19

Un nuovo servizio può richiedere un file `.secrets/servizio.env` che il piano pubblico precedente non conosce. La GUI ora usa il template Agent esplicito conservato nel backup cifrato per generarlo prima del primo controllo Compose. Il percorso standard `data/servizio/.env` pubblico più `.secrets/servizio.env` privato non richiede l'aggiunta manuale di mapping su GitHub.

La configurazione Agent determina esattamente sorgenti e destinazioni. Il recupero riusa la versione CLI verificata, esegue i template selezionati in un'area privata e rimuove i comandi di esecuzione associati ai template. Installa i file soltanto dopo aver verificato tutti gli output. Dopo la preparazione resta previsto l'Agent continuo per gli aggiornamenti dei secret.

La ripresa conserva una verifica privata del rendering pubblico e della generazione degli env nuovi. Se l'interruzione avviene durante la loro installazione, riusa un risultato completo verificato oppure ricrea soltanto la generazione parziale di cui può dimostrare la proprietà. File estranei, contenuti modificati o ricevute incompatibili fermano la ripresa senza autorizzare la loro rimozione. Un semplice marker del renderer non basta per ripetere un passo incompleto.

I percorsi espliciti di un Agent già recuperato vengono riconosciuti anche se l'utente della VM precedente era diverso; template che indicano stack originali diversi vengono rifiutati. I nuovi errori arrivano alla GUI con spiegazioni italiane specifiche.

## Percorso quotidiano e limiti

- Modifica Compose e gli env pubblici locali; inserisci i secret nella GUI Infisical e mantieni il template Agent con la destinazione privata esatta. Attendi la sincronizzazione pubblica e un nuovo backup DR verificato, successivo alle modifiche. Le vecchie release non si aggiornano.
- Sono supportati gli env pubblici `data/servizio/.env` e gli env privati obbligatori `.secrets/*.env` dei servizi dichiarati direttamente in `docker-compose.yml`. Gli env del servizio non alimentano l'interpolazione `${VAR}` o `$VAR` del Compose: una nuova variabile obbligatoria non prevista dai binding del `.env` principale produce un errore esplicito. I binding già previsti per il file principale restano conservati. Anche `include` e `extends` richiedono una verifica dedicata e vengono rifiutati.
- Un nuovo env non aggiunge il backup del database del servizio. Dati persistenti, file misti YAML/JSON e nuove dipendenze richiedono un contratto di ripristino adeguato.
- La correzione delle schede Honey appartiene al worker pubblico aggiornato sulla VM: le associazioni seguono schede riconosciute da riferimenti univoci, anziché l'indice. Riferimenti ambigui o la perdita di una scheda con binding fermano la sincronizzazione. L'eseguibile della GUI non installa quel worker.

La [guida in sei passaggi](../README.md#aggiungere-un-container-sei-passaggi) descrive il flusso completo e i controlli prima di fare affidamento sul nuovo backup.

## Verifiche

Suite locale su Windows: **790 test raccolti, 741 eseguiti con successo, 49 saltati**, senza errori o fallimenti. I 15 test del nuovo percorso coprono l'ordine prima di Compose, template e percorsi espliciti, conservazione degli env pubblici, errori di mapping, output incompleti, interruzione della seconda installazione, fallimento del checkpoint finale, ripresa verificata e rifiuto di file o sorgenti modificati. I test dei messaggi verificano anche il trasporto dei codici senza aprire l'elenco a stringhe arbitrarie.

Le credenziali e il trasporto CLI dei test sono sintetici. Su Windows i controlli di proprietà e permessi del nuovo percorso sono simulati; le prove POSIX o d'integrazione che richiedono Linux vengono saltate. Queste verifiche dei sorgenti non attestano un nuovo recupero completo o un riavvio delle due VM. Lo storico della prova applicativa precedente resta nelle [note 0.4.17](RELEASE-NOTES-v0.4.17.md).
