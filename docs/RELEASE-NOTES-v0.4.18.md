# Streams AIO Recovery 0.4.18

La GUI riconosce WUD come servizio automatico che può aggiornare i container. I backup precedenti con Watchtower restano supportati.

## Cosa cambia

- In **Prova affiancata**, WUD resta escluso dall'avvio, come Watchtower, Cloudflare DDNS e Deunhealth.
- In **Recupero della produzione**, WUD viene avviato soltanto dopo i controlli HTTPS e della destinazione recuperata. Un controllo fallito interrompe il percorso prima del suo avvio.
- Gli esiti della GUI riconoscono anche WUD e mostrano il suo stato quando un gruppo di servizi non diventa pronto, senza esporre configurazioni private.
- Il programma non richiede Watchtower nei backup che contengono soltanto WUD.

## Verifiche

Sono passati 66 test mirati, senza errori o test saltati: avvio produzione dopo HTTPS, esclusione nella prova, blocco della destinazione errata, diagnostica, avvio a freddo e integrazioni Headplane/Tailscale.

Questi controlli verificano la logica della GUI. Il recupero completo da due VM pulite con WUD e il successivo riavvio delle VM non sono stati ripetuti per questa versione. Il collaudo applicativo della 0.4.17 resta descritto nelle [note precedenti](RELEASE-NOTES-v0.4.17.md).

## Aggiornamento

Usa l'eseguibile 0.4.18 per recuperare un backup che include WUD: la 0.4.17 contiene i moduli precedenti. Su un tentativo compatibile già presente scegli **Rileva e continua**; su due destinazioni pulite scegli **Crea da zero**.

AdGuard, DNS e porte del router restano preparativi manuali esterni alla GUI. L'aggiornamento non modifica le impostazioni di WUD salvate nel backup e non configura nuove regole di aggiornamento dei container.

[README](../README.md) · [Uso della GUI](USAGE.md)
