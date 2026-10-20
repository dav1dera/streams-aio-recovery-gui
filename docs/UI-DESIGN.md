# Interfaccia desktop: progetto e riferimenti

La nuova interfaccia usa HTML, CSS e JavaScript locali nella finestra desktop
pywebview con il motore Edge WebView2. Le operazioni restano affidate al backend
Python esistente. Il precedente frontend Tk è mantenuto soltanto come percorso
di compatibilità esplicito.

Il tema scelto per questa versione è **scuro**. Non sono necessari CDN, font web,
immagini remote o librerie JavaScript scaricate all'avvio. Il font usa la famiglia
di sistema disponibile, con Segoe UI su Windows. La visualizzazione locale non
deve richiedere accesso a GitHub, alle VM o a Infisical.

## Riferimento visivo e provenienza

Il riferimento è il frontend pubblico di
[Viren070/AIOStreams, commit `6ca32ed21e3036d87c35c49b24f2cf507d065ed1`](https://github.com/Viren070/AIOStreams/tree/6ca32ed21e3036d87c35c49b24f2cf507d065ed1).
I collegamenti sono fissati a quel commit per rendere verificabile il riferimento.

- [Tema condiviso](https://github.com/Viren070/AIOStreams/blob/6ca32ed21e3036d87c35c49b24f2cf507d065ed1/packages/ui/theme.css): palette, font e raggi.
- [Preset](https://github.com/Viren070/AIOStreams/blob/6ca32ed21e3036d87c35c49b24f2cf507d065ed1/packages/ui/tailwind-preset.ts): colori semantici e dimensioni.
- [Pagina di configurazione](https://github.com/Viren070/AIOStreams/blob/6ca32ed21e3036d87c35c49b24f2cf507d065ed1/packages/frontend/src/app/configure/page.tsx)
  e [sidebar](https://github.com/Viren070/AIOStreams/blob/6ca32ed21e3036d87c35c49b24f2cf507d065ed1/packages/frontend/src/app/configure/main-sidebar.tsx): separazione tra navigazione, contenuti e azioni.
- [Menu verticale](https://github.com/Viren070/AIOStreams/blob/6ca32ed21e3036d87c35c49b24f2cf507d065ed1/packages/ui/src/vertical-menu/vertical-menu.tsx),
  [card](https://github.com/Viren070/AIOStreams/blob/6ca32ed21e3036d87c35c49b24f2cf507d065ed1/packages/ui/src/card/card.tsx)
  e [pulsanti](https://github.com/Viren070/AIOStreams/blob/6ca32ed21e3036d87c35c49b24f2cf507d065ed1/packages/ui/src/button/button.tsx): gerarchia e stati dei controlli.

Questa implementazione è originale: non incorpora componenti React, fogli di stile,
icone, loghi o altri asset copiati da AIOStreams. Riprende la direzione visiva scura,
l'accento viola e la gerarchia dei controlli, mantenendo l'identità Streams AIO
Recovery. Il repository di riferimento dichiara
[AGPL-3.0](https://github.com/Viren070/AIOStreams/blob/6ca32ed21e3036d87c35c49b24f2cf507d065ed1/LICENSE);
questo riferimento non autorizza a importarne in futuro codice o asset senza
valutarne licenza e attribuzioni.

## Palette e dimensioni

Questi sono i valori di riferimento, non un vincolo su ogni singolo pixel.
Gli stati devono distinguersi anche attraverso testo e icone, oltre al colore.

| Ruolo | Riferimento |
| --- | --- |
| Sfondo | `#070707` |
| Card | `#0B0B0B` |
| Superficie secondaria | `#101010` / `#1C1C1C` |
| Testo | `#D1D1D1` |
| Testo secondario | `#8F8F8F` |
| Bordo discreto | bianco al 10% |
| Azione primaria | `#6152DF` |
| Azione primaria, interazione | `#5243CB` |
| Accento testuale su scuro | `#C7C2FF` |
| Verificato | `#68B695` |
| Da controllare | `#E4AD81` |
| Errore | `#E48181` |
| Raggio controlli / card | 8 / 12 px |
| Altezza normale dei controlli | circa 40 px |
| Passi di spaziatura | 8, 16, 24, 32 px |

Nel riferimento il font è Inter e la sidebar desktop usa una barra di sole icone.
Qui si preferiscono font locali e **icone accompagnate da etichette italiane**:
un utente che esegue un recupero deve riconoscere subito la destinazione di ogni
azione. Lo stato attivo usa una superficie leggermente più chiara; il viola resta
riservato alle azioni e agli elementi che richiedono attenzione.

## Percorsi e stati dell'operazione

I due percorsi principali hanno finalità e accessi distinti:

1. **Recupero dello stack** usa due VM e un backup selezionato. Mantiene le azioni
   esistenti di creazione e ripresa, con i controlli del backend.
2. **Aggiunta di un servizio** usa uno stack già preparato. Analisi, anteprima,
   verifica della VM e applicazione sono azioni separate. Il laboratorio su due
   VM vuote appartiene a questo percorso e non avvia lo stack completo.

Il percorso selezionato, gli indirizzi delle VM e il tipo di verifica devono essere
leggibili prima dell'azione. **Collaudo locale** e **verifica completa con GitHub e
backup** non devono apparire equivalenti. Nel collaudo locale GitHub e backup sono
esclusi, non verificati; l'esito non deve suggerire un disaster recovery completo.
Una pagina visualizzata senza backend deve dichiararsi anteprima e non mostrare
connessioni, servizi sani o operazioni concluse come se fossero stati controllati.

L'avanzamento e gli errori appartengono al riquadro che ha avviato l'operazione e
restano visibili durante il lavoro. Un clic non deve sembrare ignorato mentre si
attende la rete. Un'attività occupata impedisce di iniziarne un'altra sulle stesse
risorse; cambiare pagina non avvia, annulla o duplica un lavoro.

Ogni stato positivo deve derivare da un esito esplicito del backend. Un container
in esecuzione non prova da solo che l'applicazione funzioni; un trasferimento di
file non prova che esista un backup valido. Un errore conserva il codice tecnico
e offre una spiegazione breve e un'azione coerente con lo stato conservato.

## Dati privati e confine con il backend

Gli asset non eseguono richieste HTTP proprie: comunicano attraverso il bridge
desktop. Password e token sono campi mascherati; gli input e i valori privati non
devono essere salvati in localStorage, sessionStorage, cookie o IndexedDB, né
inviati a servizi di analisi. I report restano privi di credenziali. Il contenuto
inserito dall'utente si mostra tramite nodi testuali, mai come HTML eseguibile.

Per la chiave age si distinguono **File** e **Incolla**. La seconda modalità usa
un campo mascherato e conserva il testo soltanto nella sessione; non crea un file
temporaneo Windows. Il backend trasferisce i byte direttamente via SFTP autenticato
a un file remoto privato `0600`, conservando i controlli di decifratura esistenti.
La chiave incollata non fa parte di impostazioni restituite al frontend,
metadati, report, piani esportati o storage del browser.

Il cambio di frontend non deve modificare conferma dell'impronta SSH,
classificazione esplicita dei valori privati, confini di autorizzazione, protezione
dei file, controlli di salute o verifica della pubblicazione. AdGuard, DNS del
sistema e router rimangono esterni al progetto: valgono le istruzioni manuali
del README.

## Verifica

`tests/test_web_assets.py` controlla offline integrità dei riferimenti locali e
assenza di canali browser per rete, persistenza o inserimento HTML dei dati.
Non usa il desktop, non apre una WebView e non contatta VM o servizi esterni.
Questi controlli statici non sostituiscono il collaudo delle operazioni Python,
la verifica grafica nella WebView o una prova completa su VM dedicate.
