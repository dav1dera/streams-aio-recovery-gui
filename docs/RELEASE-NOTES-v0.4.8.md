# v0.4.8 · Trasferimento sulle VM appena installate

Sulle VM nuove il trasferimento poteva fermarsi con `OPERATION_STOPPED`
prima del primo passo del recupero. Il programma creava `.local` e
`.local/share` come cartelle root con permessi `0700`; l’utente SSH non
poteva attraversarle per caricare i file.

Le nuove cartelle vengono ora create con proprietario UID/GID 1000.
La ripresa corregge anche le due cartelle lasciate dal vecchio uploader,
soltanto quando contengono esclusivamente la struttura del recupero.
Directory estranee, link e proprietà incompatibili vengono rifiutati prima
delle modifiche. Le directory dell’utente già valide conservano permessi
e contenuti.

Il registro mostra «Trasferimento file a Infisical» e «Trasferimento file
allo stack». I problemi del percorso o di SFTP hanno codici specifici;
gli errori non espongono credenziali o output privati.

I test Linux riproducono il difetto e verificano un vero processo UID 1000
che scrive nella cartella dopo la creazione e dopo la ripresa. Non
costituiscono un collaudo completo del ripristino sulle nuove VM.

Per continuare: apri la 0.4.8, conserva accessi, backup, commit e chiave age
e premi **Rileva e continua**. Non occorre azzerare nuovamente le VM.
