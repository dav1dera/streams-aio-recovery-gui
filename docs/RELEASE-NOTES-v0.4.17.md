# Streams AIO Recovery 0.4.17

Questa versione raccoglie le correzioni collaudate dopo la 0.4.8 e aggiorna la guida italiana per setup, backup e recupero delle due VM.

## Cosa cambia

- Avvio ordinato di OAuth2 Proxy, NPM, Headplane, Tailscale e CometNet. OAuth2 Proxy viene creato prima che Nginx ne richieda il nome, evitando il blocco circolare con Headplane.
- Attesa limitata dopo il reload di Nginx: la prova HTTPS accetta soltanto la risposta univoca attesa dal nuovo server. TLS e verifica della destinazione restano obbligatori.
- Collegamento Headplane al nuovo Headscale, con verifica della chiave API e preparazione di una nuova chiave privata locale quando necessario.
- Adattamento degli IP locali di Headscale e dei collegamenti del pannello alle nuove VM; controllo del controller prima della registrazione Tailscale.
- Ripresa dell'installazione Agent/tunnel e autorizzazione della propria chiave dedicata dopo i controlli di proprietà.
- Riquadro dei domini prima dell'avvio, stato delle operazioni più chiaro e rimozione dei selettori JSON AIO non necessari ai backup completi.
- AdGuard resta esterno al progetto. La GUI non cambia DNS rewrite, resolver Ubuntu o inoltri router: i preparativi sono documentati nel README.

## Prove eseguite

Il 14 ottobre 2026 il recupero con `dr-20261013T023710Z` ha completato tutte le fasi automatiche su due VM svuotate di dati e risorse applicative precedenti. Docker e cache immagini erano già presenti. Sono passati Infisical, AIO, Agent/tunnel, Headplane/Headscale, Tailscale, NPM, HTTPS, CometNet, controller di produzione e verifiche finali. Un upstream esterno non raggiungibile è rimasto come avviso.

AIOStreams e AIOMetadata sono stati confermati funzionanti in Stremio dal telefono. Il problema osservato sul PC riguardava la risoluzione DNS del client. Non sono stati completati nella stessa prova il riavvio delle VM recuperate, tutte le integrazioni esterne o il P2P pubblico.

Suite locale: 769 test, nessun errore o fallimento, 49 controlli POSIX saltati su Windows. Self-test dell'eseguibile e verifica delle risorse incluse superati.

L'eseguibile distribuito è la build locale usata nel collaudo, SHA256:

```text
8acb82845ce037d9d4d32df5d630e4483423608757039c6c776add9d52343414
```

## Come usarla

Per un tentativo compatibile già iniziato usa **Rileva e continua**, conservando backup e destinazioni originali del tentativo. Per un nuovo recupero prepara due destinazioni pulite e usa **Crea da zero**.

Prima dell'avvio predisponi DNS/AdGuard e porte del router verso la nuova VM stack. Dopo una sostituzione definitiva reinstalla e verifica anche i timer di sincronizzazione pubblica e backup DR: la GUI non installa quei due coordinatori.

[README](../README.md) · [Setup iniziale](SETUP-DA-ZERO.md) · [Uso della GUI](USAGE.md)
