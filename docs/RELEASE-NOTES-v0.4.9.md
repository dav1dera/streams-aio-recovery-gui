# v0.4.9 · File integrativi soltanto quando servono

La GUI elimina i selettori degli export JSON AIOStreams/AIOMetadata e del
payload privato AIO. Il percorso automatico ripristina già i database nativi
inclusi nel backup completo; quei selettori non erano usati dal percorso.

Il file integrativo cifrato compare nelle Opzioni avanzate solo dopo un errore
che ne richiede l'uso, per esempio una lista email OAuth assente. La selezione
vale soltanto per lo stesso backup e commit; viene rimossa al loro cambio,
anche quando la ripresa rileva un punto diverso sulle VM. I campi nascosti
non aggiungono file privati alla richiesta di recupero.

La chiave privata age PRIMARY o RECOVERY resta in Accessi e backup. Le
modalità di prova affiancata e recupero della produzione restano disponibili.
Questa modifica dell'interfaccia non costituisce un nuovo collaudo sulle VM
né una prova del trasferimento reale del traffico in produzione.
