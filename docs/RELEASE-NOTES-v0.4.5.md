# 0.4.5 — Attesa del primo avvio

Docker Compose può terminare `up --wait` appena un container diventa `unhealthy`, anche prima del limite di cinque minuti. Nel collaudo da VM vuote Comet è stato segnalato non sano, poi è diventato sano senza modifiche o riavvii.

Se Compose restituisce esattamente quell'errore, il recupero controlla i container del gruppo fino alla scadenza originale. Non ripete l'avvio e non modifica healthcheck, configurazioni, immagini o database. Controlla proprietà, immagini fissate, salute e identità dei container; arresti, riavvii, sostituzioni, errori di lettura e scadenza restano fallimenti. Gli altri errori Compose fermano subito il recupero. La verifica finale di tutti i servizi resta obbligatoria.

La versione mantiene la ripresa automatica dal backup e dall'instradamento registrati sulle VM. Il report del 10 ottobre 2026 ha completato tutte le fasi di bootstrap, AIO, Agent, servizi, HTTPS e dominio CometNet sulle due VM di recupero. La baseline Ubuntu senza Docker non è confermata; login applicativi, P2P pubblico e persistenza dopo riavvio restano da verificare. Il report conserva un avviso per un upstream NPM su un dispositivo esterno non raggiungibile.
