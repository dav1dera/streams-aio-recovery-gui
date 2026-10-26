# 0.5.0-dev.11

L’aggiunta di un servizio non deve richiedere correzioni manuali sulla VM dopo ogni tentativo. Questa versione controlla il Compose, le immagini, le porte e la futura esportazione pubblica prima di scrivere la configurazione dell’applicazione.

- La GUI ritrova operazioni compatibili già avviate dopo una chiusura e offre **Riprendi verifiche**, senza reinstallare i container.
- **Prepara strumenti VM** aggiorna i checkout degli strumenti e, quando manca, installa il produttore di backup verificato; non aggiorna il sistema operativo.
- I segreti nuovi vengono creati o verificati in Infisical. L’Agent deve renderli correttamente e il contenuto viene verificato prima di scrivere i file dell’applicazione e avviarla. Le stringhe `${…}` restano letterali.
- Gli errori riportano fase, file e righe consentite. Password, valori privati, contenuti remoti e output grezzi non entrano nei rapporti.
- La verifica dell’esportazione usa un overlay in memoria, conservando il corpus privato. I titoli software pubblici completi dei file YAML gestiti sono distinti da descrizioni e alias privati.

Per riprendere Homepage già avviato, aprire questa versione, reinserire gli accessi e importare lo stesso pacchetto. Preparare il piano e verificare la VM. Se richiesto, usare **Prepara strumenti VM**, poi verificare di nuovo e riprendere.

La validazione comprende test unitari, trasporto reale dei moduli, interfaccia nel browser e una prova isolata con Infisical, Agent e Docker reali. L’esito finale delle verifiche è registrato nella pull request; questa nota non attesta un nuovo ripristino completo delle VM dell’utente.
