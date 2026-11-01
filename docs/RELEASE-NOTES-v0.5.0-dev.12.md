# 0.5.0-dev.12

La GUI può aggiornare i file pubblici di configurazione di servizi già installati, conservando Compose, variabili, risorse, Agent e dati. La nuova modalità **Aggiorna file di configurazione** controlla i file attuali, la futura esportazione pubblica e la salute del servizio prima di applicare la modifica; aggiorna anche le impronte dell’inventario e verifica la pubblicazione GitHub e un nuovo backup cifrato.

La prima versione supporta pacchetti pubblici con gli stessi percorsi e permessi. Le modifiche a Compose, variabili private e risorse richiedono un percorso distinto. Il registro delle aggiunte precedenti viene conservato; un aggiornamento interrotto è riprendibile e le modifiche estranee sono preservate per revisione.

Il tema Homepage corretto usa lo sfondo approvato nel componente nativo, contenuto limitato a1560pixel, schede compatte traslucide, loghi a colori, sezioni più ordinate e cinque righe di consumi reali. I valori Proxmox non collegati non vengono simulati.

La pubblicazione è subordinata ai test della GUI, alla prova reale Infisical/Agent/Docker con aggiornamento di una configurazione esistente, e a una prova con Homepage v2.7.0 e Chromium a1280,1600,2560 e390pixel. Le schermate di collaudo utilizzano dati sintetici isolati.
