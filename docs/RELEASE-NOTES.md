Interfaccia Windows rinnovata e guida illustrata per il ripristino su due VM nuove.

- Navigazione in cinque passi, schede più leggibili, pagine scorrevoli e pulsanti persistenti.
- Riepilogo delle destinazioni e dello snapshot prima del ripristino; stato separato per Infisical, stack, Agent e servizi.
- README con screenshot reali e guida completa in `docs/USAGE.md`.
- Il motore di recupero, i controlli dei backup e la gestione privata delle credenziali restano quelli della v0.2.

Scarica **StreamsAIO-Recovery.exe**. Non serve installare Python. `SHA256SUMS` permette di verificare l'eseguibile e l'archivio del sorgente.

La pubblicazione passa dai test di sicurezza, dal round trip PostgreSQL 14 con dati sintetici e dal test di avvio/navigazione dell'eseguibile Windows. Gli asset vengono riscaricati e verificati prima di rendere pubblicata la prerelease nel repository privato.

Il ripristino completo con i backup reali dell'utente su due VM nuove resta da collaudare. Questa è una **prerelease**: i test automatici non attestano quel collaudo.
