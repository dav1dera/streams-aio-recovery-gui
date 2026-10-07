La v0.3.6 corregge il blocco dell'Agent subito dopo **Preparazione completata · PASS**. OpenSSH restituisce la chiave pubblica insieme al commento `streams-aio-recovery-tunnel`; la versione precedente rifiutava quel formato e mostrava soltanto `REMOTE_OPERATION_FAILED`.

Il programma ora separa il commento dal materiale della chiave e verifica tipo Ed25519, codifica e struttura prima di inviarla alla seconda VM. La chiave privata già creata viene riutilizzata. Il registro mostra l'inizio del passo Agent e conserva il codice pubblico dell'errore anche nei comandi che restituiscono metadati; stderr, chiavi e output arbitrari restano fuori dai report.

**Per riprendere:** chiudi il vecchio programma e apri **v0.3.6**. Conserva le stesse VM, release DR, commit e chiave age. Mantieni la configurazione AIO manuale, l'Agent attivo e TLS disattivato nella prova, poi premi **Ripristina entrambe le VM**. Infisical, NPM e gli altri passi completati vengono verificati e riutilizzati.

I test includono una vera chiave OpenSSH con commento e la sua riutilizzazione su Linux, chiavi malformate, errori frammentati sul trasporto SSH e rifiuto di output estranei ai codici pubblici. Il collaudo completo sulle VM reali resta da completare.

## Correzioni precedenti incluse: v0.3.5

La v0.3.5 aggiunge la configurazione manuale di AIOStreams e AIOMetadata. Nel passo **02 · Backup** seleziona **Configurerò AIOStreams e AIOMetadata manualmente**: puoi lasciare vuoti gli export AIO e `PRIVATE_DR_PAYLOAD`. La chiave privata age resta necessaria.

Infisical, secret, stack, NPM e Agent seguono il recupero esistente. Le applicazioni AIO partono con database nuovi e le configuri o importi dalle loro interfacce dopo l'avvio. Il registro indica **DA IMPORTARE MANUALMENTE**, senza attestare un'importazione riuscita. I controlli sugli altri componenti restano attivi.

**Per riprendere da un errore AIO:** chiudi il vecchio programma, apri **v0.3.5**, conserva le stesse VM, release DR, commit e chiave age, seleziona la modalità manuale e premi **Ripristina entrambe le VM**. I passi completati vengono verificati e riutilizzati. Il cambio di modalità viene rifiutato se esistono già database AIO o un'importazione parziale: nessun database viene cancellato.

Gli upload privati usano nuove cartelle con proprietario e permessi verificati tramite sudo. La suite verifica il preflight originale del commit dello stack: soltanto l'importazione AIO esplicitamente rinviata può essere saltata; NPM, file sorgente, prerequisiti e altri blocchi mantengono il loro effetto. La compilazione Windows include un controllo dell'opzione manuale nella GUI.

Il collaudo completo sulle VM con i backup reali resta da completare. Dopo l'avvio verifica le due applicazioni e i loro collegamenti. [Guida completa](https://github.com/dav1dera/streams-aio-recovery-gui/blob/main/docs/USAGE.md).

## Correzioni precedenti incluse: v0.3.4

La v0.3.4 corregge `UNSAFE_AGENT_ARCHIVE` nel passo **Secret da Infisical** per il backup Agent creato dal produttore con percorsi assoluti Linux.

I file sotto `/etc/infisical`, `/etc/infisical-agent`, la unit `infisical-agent.service` e i suoi drop-in vengono ricostruiti nella cartella privata del recupero. Nessun percorso originale viene usato come destinazione host. Il lettore continua a rifiutare altri percorsi assoluti, link simbolici e hard link, device, attraversamenti, duplicati anche tra nomi assoluti/relativi e collisioni tra file e cartelle, prima di estrarre.

La suite comprende il layout completo dei sei file del produttore, il recupero Universal Auth e i casi di rifiuto. Il controllo locale sull'archivio cifrato reale ha verificato estrazione e riconoscimento del bootstrap senza pubblicare chiavi o contenuti; la copia temporanea privata e stata rimossa. La CI esegue anche questi test su Ubuntu 24.04 e 26.04 prima di compilare e verificare l'eseguibile Windows.

**Per riprendere:** chiudi il vecchio programma, apri **StreamsAIO-Recovery.exe v0.3.4** e mantieni le stesse VM, release DR, commit dello stack, chiave privata ed export JSON. Premi **Ripristina entrambe le VM**. Infisical gia ripristinato viene controllato e riutilizzato; il passo INPUTS incompleto puo ripartire se gli output non sono ancora installati. Non cancellare checkpoint e non rilanciare gli strumenti di reset usati prima della decifratura. Lascia TLS disattivato nella prima prova. La versione dei checkpoint resta invariata.

Restano incluse le correzioni delle identity Windows, dei permessi di download e del bootstrap PostgreSQL descritte sotto. Il recupero completo dei secret, dell'Agent continuo e delle applicazioni sulle VM resta soggetto al collaudo reale.

## Correzioni precedenti incluse: v0.3.3

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
