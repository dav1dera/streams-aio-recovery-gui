# Servizi con configurazioni e dati — anteprima 0.5.0-dev.9

L'aggiunta accetta gruppi Compose, file pubblici e montaggi. Il piano elenca ogni servizio, immagine, file, volume, dato da conservare e risorsa della VM. Importa un pacchetto JSON da **Aggiungi servizio → Servizio → Importa pacchetto**, poi analizza e controlla il riepilogo.

I file pubblici vanno sotto `data/<servizio>/public/`, montati in sola lettura. Password e token restano nelle variabili private: la GUI li invia a Infisical e l'Agent prepara un file separato per ciascun servizio. Il rapporto esportato contiene soltanto metadati.

Le cartelle dati sotto lo stack e i volumi Docker locali hanno politica `stopped_archive`: il backup arresta i container dello stack che possono scriverli, crea l'archivio e riavvia gli stessi container, anche se la cattura fallisce. L'archivio viene cifrato con i due destinatari age già configurati. Socket Docker, `/proc`, `/sys`, tmpfs e altri collegamenti alla VM vengono ricreati e controllati sulla destinazione.

Il nuovo asset facoltativo è `services-state.tar.gz.age`. La release resta schema 2, legata all'esatto commit pubblico e all'hash dell'inventario `config/service-resources.json`. I vecchi backup rimangono leggibili. Il ripristino usa destinazioni vuote, prepara tutti i dati prima di installarli e conserva un checkpoint privato per le interruzioni.

## Aggiornamento coordinato sulla VM

Prima della prova completa servono i tre componenti aggiornati:

1. Questa GUI.
2. Il worker di sincronizzazione pubblica, con il nuovo `scripts/public_export.py` in `streams-aio-sanitized`.
3. Il coordinatore DR e il nuovo produttore in `streams-aio-dr`. Il suo `scripts/install-service-resources.sh`, eseguito come amministratore dopo la revisione, installa soltanto i file del produttore e una regola sudo per il punto d'ingresso con argomenti controllati.

La GUI controlla la disponibilità del produttore prima di aggiungere dati persistenti. Non dichiara completata la prova se manca il backup cifrato e il suo riscontro su GitHub. La modalità laboratorio conserva l'esito distinto `PASS_LOCAL`, senza attestare pubblicazione o backup.

## Ambito di questa anteprima

Sono gestiti bind, volumi locali, tmpfs, reti e configurazioni Compose. Volumi esterni o con driver specifici richiedono una procedura di recupero esterna dichiarata. Dati con collegamenti simbolici/fisici e sorgenti dati sovrapposte sono rifiutati; non vengono copiati in modo ambiguo. Build, include/extends e file Compose secret arbitrari restano fuori da questo percorso.

Le verifiche automatiche comprendono pianificazione, instradamento di segreti omonimi, transazioni, rollback, pubblicazione simulata, archivi reali su filesystem e interfaccia. Docker e age sono simulati nei test locali. Un recupero completo sulle VM reali deve ancora essere collaudato prima di considerare questa anteprima stabile.