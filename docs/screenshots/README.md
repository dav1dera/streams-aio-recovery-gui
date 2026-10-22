# Immagini della guida

## Interfaccia attuale — 0.5.0-dev.8

Le figure in [v050-dev8](v050-dev8) sono catture dell’interfaccia HTML, CSS e
JavaScript inclusa nel programma. Sono renderizzate in un browser senza finestra
visibile, con risposte dimostrative del collegamento alla GUI e dati di esempio.
Non collegano VM, non leggono credenziali e non eseguono un recupero.

I puntatori numerati sono annotazioni per la documentazione. Campi mascherati,
esiti verdi, tag e avanzamenti spiegano i passaggi: **non sono prove di esecuzione
di quelle operazioni sulle VM del lettore**. I campi privati non contengono
credenziali reali. La disposizione può cambiare con la dimensione della finestra;
alcune pagine e riquadri sono scorrevoli.

| Figura | Pagina e contenuto | Uso |
| --- | --- | --- |
| [01-accessi.png](v050-dev8/01-accessi.png) | Accessi e backup: due VM, backup e chiave age. | Dati iniziali e preparazione laboratorio. |
| [02-domini.png](v050-dev8/02-domini.png) | Domini e instradamento. | Indirizzo atteso, DNS e router gestiti manualmente. |
| [03-crea-da-zero.png](v050-dev8/03-crea-da-zero.png) | Panoramica, Crea da zero. | Recupero completo su VM vuote. |
| [04-riprendi.png](v050-dev8/04-riprendi.png) | Panoramica, Rileva e continua. | Ripresa dello stesso tentativo. |
| [05-servizio.png](v050-dev8/05-servizio.png) | Aggiungi servizio → Servizio. | Nome, Compose e variabili di prova-agent. |
| [06-segreti.png](v050-dev8/06-segreti.png) | Aggiungi servizio → Segreti. | Pubblico/privato e accesso Infisical. |
| [07-verifica.png](v050-dev8/07-verifica.png) | Aggiungi servizio → Verifica. | Piano, Verifica VM, Aggiungi e verifica. |
| [08-esito-locale.png](v050-dev8/08-esito-locale.png) | Esempio di collaudo locale completato. | Servizio/Agent verificati; GitHub/backup esclusi. |
| [09-destinazione.png](v050-dev8/09-destinazione.png) | Aggiungi servizio → Destinazione. | Modalità, cartella ed endpoint HTTP. |

Il collaudo effettivamente riportato dall’utente sulla 0.5.0-dev.8 ha completato
preparazione delle VM .30/.33 e aggiunta locale di prova-agent. Gli stati dimostrativi
delle altre figure non estendono il risultato a recupero completo, pubblicazione
GitHub o nuovo backup.

[README principale](../../README.md) · [Guida Aggiungi servizio](../AGGIUNGI-SERVIZIO.md)

## Immagini delle versioni precedenti

Le catture storiche fuori da v050-dev8 appartengono all’interfaccia classica e non
rappresentano il nuovo percorso scuro a quattro passi.

- Le catture v0.3.0 mostrano l’eseguibile Windows con campi privati vuoti, senza
  connessioni alle VM o backup reali.
- 02-backup-v039.jpg mostra la v0.3.9 con AIO manuale e campo companion cifrato.
  È un riferimento storico, non un passaggio richiesto dal backup completo attuale.
