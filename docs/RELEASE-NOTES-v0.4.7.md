# v0.4.7 · Collegamento alle VM ricreate

Una VM reinstallata genera nuove chiavi SSH. Se riutilizzava un indirizzo già conosciuto, la GUI precedente si fermava con `SSH_HOST_KEY_CHANGED` senza permettere di aggiornare l’identità.

La GUI ora mostra indirizzo e porta, impronta precedente e nuova impronta. Dopo il confronto con la console della VM, puoi approvare la nuova chiave e continuare. Il collegamento successivo verifica esattamente la chiave approvata; l’identità viene salvata solo dopo l’autenticazione riuscita. Rifiuto, annullamento, autenticazione fallita o un ulteriore cambio di chiave conservano l’identità precedente.

L’aggiornamento riguarda soltanto la destinazione selezionata. Le altre identità SSH e il file SSH di sistema restano conservati. Non vengono disattivati i controlli SSH. Un errore nel salvataggio locale viene segnalato con `SSH_HOST_KEY_STORE_FAILED`.

Per un nuovo recupero puoi usare VM vuote con IP diversi, compilando i campi della GUI con i nuovi indirizzi. Cambiare indirizzo a un recupero già preparato richiede invece la migrazione di checkpoint e collegamenti: questa versione non la esegue automaticamente.

La [guida](USAGE.md#vm-ricreata-o-indirizzo-ip-diverso) descrive il confronto delle impronte. Questa correzione non attesta un nuovo collaudo completo da due VM vuote; lo stato delle verifiche resta descritto nel [README](../README.md#stato-delle-verifiche).
