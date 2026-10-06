La v0.3.3 gestisce i file della chiave age salvati su Windows in UTF-8 con BOM o UTF-16 con BOM, che prima potevano fermarsi su `AGE_DECRYPTION_FAILED` anche con una chiave corretta.

- Legge solo identity X25519 originali complete `AGE-SECRET-KEY-1…`, con commenti, righe vuote e CRLF. Non genera chiavi e non aggiunge prefissi a codici sconosciuti.
- Prepara una copia canonica in una cartella temporanea `0700`, file `0600`, esterna ai repository. Il file originale non viene modificato. La copia canonica viene eliminata alla fine del passo, anche in caso di rifiuto.
- Valida la chiave con `age-keygen` prima della decifratura. Distingue `AGE_PUBLIC_KEY_NOT_IDENTITY`, `AGE_PRIVATE_IDENTITY_REQUIRED`, `AGE_IDENTITY_INVALID` e `AGE_NO_MATCHING_RECIPIENT`, con spiegazioni in italiano nel registro.
- Nessuna chiave, public recipient o stderr dei processi viene mostrata negli esiti. L'errore di age viene convertito soltanto in codici fissi.
- SHA256, manifest, dimensioni degli asset, envelope age e rifiuto dei set parziali restano attivi. Restano incluse le correzioni dei permessi di download e dell'avvio PostgreSQL della v0.3.2.
- Test con vere chiavi PRIMARY/RECOVERY usa e getta: tutti e cinque gli artifact, UTF-8, BOM, UTF-16 LE/BE, CRLF e rifiuto di una terza identity valida ma estranea. Le prove sono obbligatorie su Ubuntu 24.04 e 26.04 prima della build Windows.

**Per riprovare:** annota il commit dello stack nella vecchia GUI, chiudila e scarica **StreamsAIO-Recovery.exe v0.3.3**. Mantieni le stesse VM, release DR e commit, seleziona il file della chiave privata originale e premi **Ripristina entrambe le VM**. Un arresto alla decifratura prima del restore config/database permette di riutilizzare i checkpoint. Per il primo collaudo lascia disattivata la riemissione TLS reale.

Una identity valida che non apre il backup richiede l'altra chiave originale PRIMARY/RECOVERY o una release cifrata per quella identity. Una chiave nuova non apre i backup precedenti. [Formato identity ufficiale age](https://github.com/FiloSottile/age/blob/main/parse.go).

La pubblicazione richiede inoltre test di sicurezza, round trip PostgreSQL 14 con dati sintetici, prove dei permessi di download, dipendenze su entrambi gli Ubuntu, avvio/navigazione dell'eseguibile Windows e verifica SHA256 degli asset riscaricati.

Il ripristino completo con i backup reali dell'utente resta da collaudare. Questa è una **prerelease**: i test automatici non attestano quel collaudo.
