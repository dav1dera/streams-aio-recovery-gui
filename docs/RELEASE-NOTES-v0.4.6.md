# v0.4.6 · Configurazione locale nel backup

Il recupero supporta un file facoltativo di parametri ordinari nell’archivio
privato dell’Agent. I parametri vengono uniti ai segreti di Infisical; cartelle
interamente locali possono essere assenti dal server. Le esportazioni AIO
continuano a leggere i nuovi segreti aggiunti alle cartelle dinamiche.

File, permessi, riferimenti ammessi e duplicati JSON sono verificati. Duplicati
locali/remoti diversi fermano il recupero. Il nuovo Agent conserva configurazione
locale e provenienza dei template per i backup successivi. I backup precedenti
senza mappa locale mantengono il percorso originale.

Il rendering isolato sulla VM originale ha confrontato tutti i 20 output:
18 identici byte per byte e 2 AIO equivalenti per righe complete. Nessun servizio
è stato riavviato per questo controllo. Le due VM di test non sono più disponibili;
questa verifica non costituisce un nuovo collaudo completo da VM vuote.

Usare GUI 0.4.6 o successiva per i backup creati dopo la separazione dei parametri.
Conservare la GUI aggiornata nel kit offline insieme alle chiavi age private.
