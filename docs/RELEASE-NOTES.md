Corretto il blocco `DR_DOWNLOAD_FAILED` durante il recupero della release cifrata.

Il bootstrap crea la cartella temporanea come root, mentre GitHub CLI scarica come utente della VM. La cartella viene ora assegnata all'utente UID/GID 1000 mantenendo i permessi privati `0700`. La correzione si applica al recupero Infisical e al recupero dello stack.

- Il token resta su stdin SSH e nell'ambiente dei soli processi Git/GitHub CLI; non entra negli argomenti, nei log o in Docker.
- SHA256, manifest, dimensioni degli asset ed envelope age continuano a essere verificati prima dell'utilizzo del bundle.
- I checkpoint restano compatibili. I tentativi falliti vengono conservati; la ripresa del download usa una nuova cartella, senza sovrascrivere bundle esistenti.
- Nuovo codice `DR_DOWNLOAD_DIRECTORY_FAILED` se la cartella privata non può essere preparata.
- Test di regressione con un vero processo UID 1000 avviato da root su Ubuntu 24.04 e 26.04, oltre ai controlli di rifiuto e ripresa del download.
- Il restore PostgreSQL attende ora il server definitivo, dopo il server temporaneo usato dall'immagine ufficiale durante l'inizializzazione. Questo evita avvii prematuri del restore durante il riavvio iniziale; la prova PostgreSQL usa lo stesso controllo. Nessuna porta aggiuntiva viene esposta. [Entrypoint ufficiale PostgreSQL](https://github.com/docker-library/postgres/blob/master/docker-entrypoint.sh).

**Per riprovare:** chiudi la v0.3.1, scarica **StreamsAIO-Recovery.exe v0.3.2**, mantieni le stesse VM, release DR e commit dello stack, reinserisci gli accessi e premi **Ripristina entrambe le VM**. Se il blocco era al download prima del restore config/database, non serve ricreare le VM. Per il primo collaudo lascia disattivata la riemissione TLS reale.

La pubblicazione richiede test di sicurezza, round trip PostgreSQL 14 con dati sintetici, prove dei permessi e dipendenze su entrambi gli Ubuntu, avvio/navigazione dell'eseguibile Windows e verifica SHA256 degli asset riscaricati.

Il ripristino completo con i backup reali dell'utente resta da collaudare. Questa è una **prerelease**: i test automatici non attestano quel collaudo.
