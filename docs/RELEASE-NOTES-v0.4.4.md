# 0.4.4 — Ripresa dal tentativo rilevato

«Rileva e continua» legge il punto di recupero e l’instradamento già salvati sulle due VM. Un backup più recente selezionato nella GUI, o la modalità produzione selezionata per errore durante una prova affiancata, non sostituiscono il tentativo esistente.

La lettura richiede checkpoint privati di root, macchina e destinazione corrispondenti. I punti delle due VM devono essere coerenti. La release rilevata viene verificata nuovamente su GitHub, compresi commit e snapshot AIO. I controlli completi su container, volumi e fasi interrotte restano obbligatori prima di continuare. Il rilevamento non modifica checkpoint o servizi.

Il punto e la modalità rilevati vengono mostrati in «Accessi e backup» e registrati come informazioni pubbliche nel pannello attività. I dati e le credenziali private non entrano nel registro.

La versione conserva le correzioni HTTPS della 0.4.3. Il collaudo dal vivo della nuova selezione automatica, della ripartenza da VM vuote e dei login applicativi resta da completare.
