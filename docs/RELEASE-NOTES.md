Supporto Ubuntu Server **26.04 LTS amd64**, comprese le ISO 26.04.x, per entrambe le nuove VM. Ubuntu 24.04 resta supportato.

- Il controllo SSH e il bootstrap condividono la stessa policy di compatibilità.
- Docker viene installato dal repository della VM: `resolute` su 26.04, `noble` su 24.04. Nessun fallback a pacchetti di un’altra distribuzione.
- GUI e messaggi di verifica mostrano le versioni supportate e la versione effettiva della VM.
- README e guida aggiornati, con istruzioni Proxmox per la ISO già caricata.
- Test aggiuntivi per Ubuntu 24.04/26.04, dipendenze del bootstrap e rifiuto di versioni/codename incoerenti.

Scarica **StreamsAIO-Recovery.exe** e **SHA256SUMS**. La v0.3.0 continua a richiedere Ubuntu 24.04: aggiorna l’eseguibile per usare 26.04.

La pubblicazione richiede test di sicurezza, round trip PostgreSQL 14 con dati sintetici, controlli delle dipendenze su entrambi gli Ubuntu e avvio/navigazione dell’eseguibile Windows. Gli asset vengono riscaricati e verificati prima della pubblicazione nel repository privato.

Il ripristino completo con i backup reali dell'utente su due VM nuove resta da collaudare. Questa è una **prerelease**: i test automatici non attestano quel collaudo.
