"""Desktop dashboard entry point and public presentation text."""
import json
from pathlib import Path
import queue
import re
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import webbrowser

from .backend import (Failure, GitHub, Host, SSH, SHA, TAG, require, restore_all, check_first_boot_resume,
                      validate_test_reset_choice, inspect_test_reset, test_reset_recovery_point)
from .codes import ERROR_CODES
from .startup_diagnostic import lines as startup_diagnostic_lines
from . import __version__

TEXT = {
    'DEPENDENCIES': 'Docker e dipendenze', 'CLONES': 'Repository e commit scelto',
    'DOWNLOAD': 'Release e verifica SHA256', 'DECRYPT': 'Decifratura privata age',
    'INITIALIZE': 'Destinazione vuota', 'INPUTS': 'Secret da Infisical',
    'RENDER': 'Configurazioni dello stack', 'EMPTY_STATE': 'Directory e permessi',
    'NPM': 'Database NPM', 'AIO': 'Configurazioni AIO', 'PREFLIGHT': 'Controlli finali',
    'PREPARED': 'Preparazione completata', 'STARTED': 'Avvio dei servizi', 'TLS': 'Certificati e HTTPS',
    'REFUSED': 'Procedura fermata',
    'INFISICAL_CONFIG': 'Configurazione privata Infisical',
    'INFISICAL_DATABASE': 'Ruoli e database Infisical',
    'INFISICAL_SERVER': 'Avvio e controllo API Infisical',
    'NATIVE_AGENT': 'Agent continuo e tunnel SSH permanente',
    'RUNTIME_PROFILE': 'Compatibilità del primo avvio',
    'COMETNET_TRIAL': 'CometNet locale per la simulazione',
    'IMAGES': 'Immagini Docker del backup',
    'APPLICATION_CHECKS': 'Verifica dei servizi avviati',
    'TEST_RESET_STACK': 'Nuova simulazione: archiviazione e pulizia dello stack di test',
    'TEST_RESET_INFISICAL': 'Nuova simulazione: archiviazione e pulizia Infisical di test',
}
ERRORS = {
    'NPM_TOPOLOGY_BACKUP_REQUIRED': 'Questo backup non include i collegamenti verificati di NPM alle due VM. Scegli un nuovo backup completo; il programma conserva il tentativo presente.',
    'NPM_TOPOLOGY_ADDRESS_INVALID': 'Un indirizzo dei collegamenti NPM non è valido. Controlla gli indirizzi delle due VM in Accessi e backup; i domini e gli accessi restano conservati.',
    'NPM_TOPOLOGY_TARGET_INVALID': 'NPM richiede due destinazioni distinte e valide per stack e Infisical. Controlla gli indirizzi delle VM in Accessi e backup.',
    'NPM_TOPOLOGY_SOURCE_INVALID': 'Il backup dei collegamenti NPM non corrisponde allo stack di origine. Serve un nuovo punto di recupero completo verificato.',
    'NPM_TOPOLOGY_INVALID': 'La copia dei collegamenti NPM non supera il controllo di formato, commit o integrità. Seleziona un backup completo coerente.',
    'NPM_TOPOLOGY_DATABASE_INVALID': 'Il database NPM non è leggibile nel formato previsto. Il programma lo conserva e ferma il ripristino dei collegamenti.',
    'NPM_TOPOLOGY_DATABASE_IDENTITY_REQUIRED': 'Proprietà o permessi del database NPM non corrispondono all’utente previsto. Il programma conserva il database e ferma l’adattamento dei collegamenti.',
    'NPM_TOPOLOGY_SCHEMA_UNSUPPORTED': 'Questa versione del database NPM non è compatibile con i collegamenti registrati nel backup. Serve un backup e una versione della GUI compatibili.',
    'NPM_TOPOLOGY_ENDPOINT_UNPROVEN': 'Una destinazione NPM non è associabile con certezza a un servizio del backup. Il programma conserva la route e richiede un backup verificato.',
    'NPM_TOPOLOGY_SERVICE_UNPROVEN': 'Un servizio indicato da NPM non è riconosciuto nel punto di recupero. Il programma conserva i collegamenti e ferma l’adattamento.',
    'NPM_TOPOLOGY_UNCLASSIFIED_REFERENCE': 'Una configurazione personalizzata NPM contiene un indirizzo che richiede una verifica esplicita. Non viene sostituito automaticamente.',
    'NPM_TOPOLOGY_ALREADY_MOUNTED': 'Un container sta già usando il database NPM. I collegamenti non vengono modificati durante l’uso: conserva il tentativo e consulta gli esiti.',
    'NPM_TOPOLOGY_SOURCE_DRIFT': 'Le route NPM sono cambiate rispetto alla copia verificata. Il programma conserva database e ricevute; non sostituisce le modifiche presenti.',
    'NPM_TOPOLOGY_EVIDENCE_REQUIRED': 'La ricevuta dei collegamenti NPM è assente o non corrisponde al checkpoint. Conserva il tentativo per verificarlo prima della ripresa.',
    'NPM_TOPOLOGY_JOURNAL_INVALID': 'La ricevuta del passaggio NPM interrotto non è compatibile con questo recupero. Database e copie precedenti restano conservati.',
    'NPM_TOPOLOGY_APPLY_FAILED': 'I collegamenti NPM non hanno superato il controllo dopo l’adattamento. Salva gli esiti e conserva il tentativo prima di continuare.',
    'NPM_TOPOLOGY_PATH_INVALID': 'Un file NPM è un collegamento o non rispetta il percorso previsto. Il programma conserva lo stato e ferma il recupero.',
    'NPM_TOPOLOGY_PRIVATE_FILE_REQUIRED': 'I permessi di un file privato NPM non corrispondono a quelli previsti. Il programma conserva i dati e ferma il recupero.',
    'OPERATIONAL_DEPLOYMENT_REFUSED': 'Destinazione, modalità o checkpoint non corrispondono al recupero scelto. Controlla Accessi e backup e conserva gli esiti del passaggio interrotto prima di riprendere.',
    'PUBLIC_DOMAIN_TARGET_MISMATCH': 'Il dominio raggiunge una destinazione diversa dalla VM recuperata. Controlla DNS, inoltro porte e instradamento del test: un pannello originale raggiungibile non prova il recupero.',
    'PUBLIC_DOMAIN_CONFIGURATION_REQUIRED': 'Controlla in Accessi e backup l’indirizzo previsto per i domini. Il recupero richiede anche la configurazione pubblica CometNet, il suo indirizzo WSS e la route NPM corrispondente nel backup.',
    'PUBLIC_DOMAIN_PROBE_FAILED': 'Il dominio non ha superato la verifica HTTPS sulla VM recuperata. Controlla instradamento, NPM e certificati; il controllo di raggiungibilità resta attivo.',
    'PUBLIC_DOMAIN_PROBE_CLEANUP_REQUIRED': 'Il controllo del dominio richiede di verificare la rimozione del marcatore temporaneo NPM. Il recupero si ferma per conservare lo stato.',
    'PUBLIC_CONTROLLER_CUTOVER_REQUIRED': 'I controller che aggiornano DNS e immagini richiedono la modalità Recupero della produzione. Nella prova affiancata restano esclusi.',
    'OPERATIONAL_TLS_REQUIRED': 'Il recupero completo richiede HTTPS. Riprendi dalla GUI aggiornata, che esegue la verifica TLS prima di avviare CometNet pubblico.',
    'OPERATIONAL_PROFILE_TRANSACTION_FAILED': 'L’applicazione del profilo di recupero si è interrotta. Il programma conserva il checkpoint e le copie precedenti: controlla gli esiti prima di riprendere.',
    'AIO_SNAPSHOT_REQUIRED': 'Questo backup non include le configurazioni AIO automatiche. Seleziona un backup completo recente; gli export singoli non sostituiscono la copia verificata richiesta dal recupero operativo.',
    'AIO_SNAPSHOT_BACKUP_REQUIRED': 'La release selezionata non contiene la copia cifrata AIO richiesta. Scegli un backup completo recente prima di iniziare il recupero.',
    'DR_STACK_COMMIT_MISMATCH': 'Il commit inserito non è quello associato al backup. Ricarica il punto di recupero in Accessi e backup per usare il commit verificato dalla release.',
    'DR_BUNDLE_VERIFICATION_FAILED': 'Il backup non ha superato il controllo del manifest e delle impronte dei file. Ricarica il punto selezionato; il materiale già presente resta conservato.',
    'AIO_SNAPSHOT_ENCRYPTION_KEY_MISMATCH': 'La chiave applicativa recuperata non corrisponde alla copia AIO. Il database viene conservato e il recupero si ferma per evitare profili illeggibili.',
    'AIO_SNAPSHOT_EXISTING_DATABASE_REFUSED': 'Sono già presenti dati AIO senza una ricevuta di importazione compatibile. Il programma li conserva e non li sovrascrive.',
    'AIO_SNAPSHOT_SCHEMA_UNSUPPORTED': 'Lo schema della copia AIO non corrisponde alle applicazioni previste dal backup. Serve un punto di recupero compatibile.',
    'AIO_SNAPSHOT_SOURCE_CHANGED': 'Le applicazioni AIO sono cambiate durante la creazione della copia. Serve un nuovo backup completo verificato prima del recupero.',
    'AIO_SNAPSHOT_IMAGE_MISMATCH': 'Le immagini AIO della copia non corrispondono a quelle fissate nel backup. Seleziona un backup completo coerente; i database presenti vengono conservati.',
    'AIO_SNAPSHOT_MARKER_INVALID': 'La ricevuta AIO non corrisponde ai dati recuperati. Il programma conserva i database e ferma l’importazione per verificarne lo stato.',
    'AIO_SNAPSHOT_JOURNAL_INVALID': 'La ricevuta dell’importazione AIO interrotta non corrisponde alla copia verificata. I database presenti restano conservati; salva gli esiti prima di riprendere.',
    'AIO_SNAPSHOT_ARCHIVE_INVALID': 'La copia AIO non è leggibile come backup nativo. Seleziona un punto completo verificato; i dati presenti restano conservati.',
    'AIO_SNAPSHOT_ARCHIVE_UNSAFE': 'La copia AIO contiene file o collegamenti fuori dal formato previsto. Il recupero si ferma prima di installarli.',
    'AIO_SNAPSHOT_DIGEST_MISMATCH': 'Un database AIO non corrisponde all’impronta registrata nel backup. Seleziona una copia completa verificata.',
    'AIO_SNAPSHOT_MANIFEST_INVALID': 'L’inventario interno della copia AIO non rispetta il formato previsto. Seleziona un backup completo compatibile.',
    'AIO_SNAPSHOT_DATABASE_MISMATCH': 'Schema o contenuto del database AIO non corrispondono all’inventario verificato. La copia non viene installata.',
    'AIO_SNAPSHOT_RESTORED_DATABASE_CHANGED': 'Un database AIO è cambiato prima dell’avvio previsto. Il programma conserva i dati e ferma la ripresa per verificarli.',
    'AIO_SNAPSHOT_DATABASE_OWNER_CHANGED': 'La proprietà dei database AIO è cambiata. Il programma conserva i file e ferma la verifica.',
    'AIO_SNAPSHOT_TARGET_MOUNTED': 'Un container sta già usando i database AIO. Il ripristino non li sostituisce durante l’uso; conserva il tentativo e consulta gli esiti.',
    'AIO_SNAPSHOT_INSTALL_FAILED': 'L’installazione AIO si è interrotta. Il programma conserva le copie e la ricevuta; Rileva e continua verifica se il tentativo può riprendere.',
    'SELECT_GITHUB_RECOVERY_POINT': 'Apri Accessi e backup, carica i backup e seleziona un punto di recupero. Il commit viene associato alla release verificata.',
    'AGE_IDENTITY_FILE_REQUIRED': 'Apri Accessi e backup e scegli con Sfoglia il file della chiave privata PRIMARY o RECOVERY. Non incollare la chiave nel campo del percorso.',
    'SSH_ADDRESS_REQUIRED': 'Apri Accessi e backup e completa indirizzo, utente e accesso SSH di entrambe le VM. La porta SSH è nelle opzioni avanzate.',
    'GITHUB_TOKEN_REQUIRED': 'Apri Accessi e backup e inserisci il token GitHub con permesso Contents: Read sui due repository del recupero.',
    'FOREIGN_RECOVERY_STATE': 'Il recupero presente non corrisponde alla VM, al backup o al commit selezionato. Seleziona il punto originale del tentativo; i dati vengono conservati.',
    'FOREIGN_CONTAINER_REFUSED': 'La VM contiene container che non appartengono al recupero verificato. Usa la destinazione corretta: il programma conserva le risorse esistenti.',
    'FOREIGN_VOLUME_REFUSED': 'La VM contiene volumi che non appartengono al recupero verificato. I dati esistenti vengono conservati.',
    'COMETNET_TRIAL_SCOPE_REFUSED': 'La modalità locale CometNet richiede il checkpoint della prova previsto. Conserva lo stato per verificarlo.',
    'COMETNET_TRIAL_TLS_REFUSED': 'Questa simulazione usa CometNet locale. Lascia disattivata la casella dei certificati e HTTPS; il passaggio ai domini pubblici richiede una verifica separata.',
    'COMETNET_TRIAL_TRANSACTION_FAILED': 'La registrazione di CometNet locale è fallita. Il checkpoint precedente e le copie vengono conservati.',
    'AGE_IDENTITY_FILE_INVALID': 'Il file scelto come chiave è un collegamento o supera 64 KiB. Nel campo Chiave age seleziona il file di testo della identity privata; il file integrativo .age va nel suo campo separato.',
    'AGE_IDENTITY_ENCODING_INVALID': 'Salva la chiave privata originale in un file di testo UTF-8 o UTF-16.',
    'AGE_PRIVATE_IDENTITY_REQUIRED': 'Serve la chiave privata originale completa AGE-SECRET-KEY-1…, salvata in un file. Non aggiungere il prefisso a un altro codice.',
    'AGE_PUBLIC_KEY_NOT_IDENTITY': 'Il file contiene una chiave pubblica age1…. Seleziona il file della chiave privata PRIMARY o RECOVERY.',
    'AGE_IDENTITY_INVALID': 'La chiave privata age non è valida: controlla che la copia sia completa e senza caratteri modificati.',
    'AGE_NO_MATCHING_RECIPIENT': 'La chiave è valida ma non apre questo backup. Seleziona l’altra identity PRIMARY/RECOVERY originale o una release compatibile.',
    'AGE_DECRYPTION_FAILED': 'age non ha completato la decifratura. Il materiale e i checkpoint restano conservati.',
    'SSH_AUTH_FAILED': 'Accesso SSH rifiutato. Controlla utente, password o chiave.',
    'SSH_CONNECTION_FAILED': 'La VM non risponde via SSH.',
    'SSH_HOST_KEY_CHANGED': 'La chiave SSH è cambiata: verifica la VM dalla console prima di aggiornare known_hosts.',
    'FRESH_DOCKER_HOST_REQUIRED': 'Sono presenti container o volumi. Usa una VM nuova.',
    'EXISTING_STACK_REFUSED': 'È presente un tentativo di recupero. Scegli Rileva e continua per verificarlo e riprendere; Crea da zero richiede destinazioni vuote.',
    'INCOMPLETE_STEP_REQUIRES_REVIEW': 'Un passo di scrittura è rimasto incompleto e non può essere ripetuto automaticamente. Conserva lo stato e consulta gli esiti per verificare quel passaggio prima della ripresa.',
    'RECOVERY_OPERATION_INCOMPLETE': 'Il checkpoint registra un’operazione ancora incompleta. Il programma conserva lo stato e richiede di verificarla prima di proseguire.',
    'AGENT_BOOTSTRAP_CONFIG_NOT_UNIQUE': 'Bootstrap Agent non riconosciuto. Usa i campi avanzati per i file Universal Auth.',
    'AGENT_CREDENTIAL_PATH_UNSUPPORTED': 'Il backup Agent usa percorsi non supportati. Fornisci i due file Universal Auth.',
    'AGENT_TUNNEL_PUBLIC_KEY_INVALID': 'Il controllo della chiave SSH del tunnel è fallito. Conserva i checkpoint e usa la versione aggiornata della GUI.',
    'AGENT_PRIVATE_OUTPUT_INVALID': 'Una destinazione privata dell’Agent non è un file regolare isolato nello stack. Conserva i checkpoint per il controllo.',
    'AGENT_PRIVATE_OUTPUT_PERMISSIONS_INVALID': 'I permessi o il proprietario di un file dell’Agent non corrispondono al piano di ripristino. Nessun permesso più aperto è stato accettato.',
    'AGENT_RENDER_MARKER_INVALID': 'La ricevuta dei file generati non corrisponde allo stack recuperato. Conserva i checkpoint per il controllo.',
    'PRIVATE_INPUT_FILE_REQUIRED': 'Un file privato richiesto manca nel materiale recuperato.',
    'HTTPS_INFISICAL_ORIGIN_REQUIRED': 'Serve l’endpoint HTTPS Infisical raggiungibile dalla VM.',
    'INFISICAL_SNAPSHOT_FAILED': 'Autenticazione o lettura Infisical fallita. Nessun valore è stato registrato.',
    'INFISICAL_DEPLOYMENT_PROFILE_CHANGED': 'Il profilo Infisical non corrisponde al checkpoint. La versione aggiornata riconosce i vecchi formati LF/CRLF; un cambio reale di immagini o database resta bloccato. Conserva checkpoint e dati.',
    'AIO_IMPORT_REFUSED': 'L’importatore AIO ha rifiutato gli input o la compatibilità. Nessun database esistente viene sovrascritto.',
    'MANUAL_AIO_IMPORT_CONFLICT': 'Sono già presenti database o un’importazione AIO. Il programma li conserva e ferma il cambio di modalità.',
    'AIO_EXPORT_PROFILE_AMBIGUOUS': 'Il profilo dell’export non è identificabile. Seleziona un payload DR esplicito.',
    'APPLICATION_START_REFUSED': 'Avvio o verifica applicativa fallita. Conserva lo stato e controlla la VM.',
    'APPLICATION_IMAGE_DOWNLOAD_FAILED': 'Download di un’immagine Docker fallito. Controlla rete e accesso al registro; il checkpoint resta conservato.',
    'APPLICATION_PINNED_IMAGES_REQUIRED': 'Il piano contiene un’immagine priva del digest del backup. L’avvio è stato fermato.',
    'SERVICE_HEALTHCHECK_REQUIRED': 'Una dipendenza non ha il controllo di salute richiesto, anche dopo il download delle immagini.',
    'APPLICATION_HEALTH_WAIT_FAILED': 'Un gruppo di servizi non è diventato pronto entro il tempo previsto. Salva gli esiti; lo stato sulla VM è conservato.',
    'APPLICATION_IMAGE_PLATFORM_REFUSED': 'Una delle immagini non corrisponde alla piattaforma Linux amd64 richiesta dal backup.',
    'APPLICATION_FINAL_CHECK_FAILED': 'Un servizio è assente, fermo o non sano al controllo finale. Salva gli esiti; il checkpoint resta conservato.',
    'PGBOUNCER_NOT_READY': 'PgBouncer non risponde sulla propria porta. L’avvio dei servizi dipendenti è stato fermato.',
    'RECOVERY_SUPPLEMENT_INVALID': 'Il file integrativo cifrato non rispetta il formato atteso. Seleziona il companion verificato per questo backup.',
    'RECOVERY_SUPPLEMENT_SCOPE_CHANGED': 'Il file integrativo appartiene a una release o a un commit diverso.',
    'OAUTH_ALLOWLIST_INVALID': 'La lista email OAuth non è valida. Nessun valore è stato registrato.',
    'OAUTH_ALLOWLIST_SUPPLEMENT_REQUIRED': 'La copia Infisical non contiene la lista email autorizzate. Completa la voce nell’originale e crea un nuovo backup. Un companion cifrato compatibile può essere selezionato in Opzioni avanzate per i vecchi tentativi.',
    'COMETNET_DATABASE_NOT_PROVISIONED': 'La connessione CometNet richiede un database o un utente non creato dal piano SQL del backup. Correggi il mapping in Infisical prima dell’avvio.',
    'RUNTIME_PROFILE_SCOPE_REFUSED': 'Il profilo del primo avvio non corrisponde a utente, macchina o punto di recupero. Controlla il backup scelto e conserva il checkpoint per verificarlo.',
    'RUNTIME_PROFILE_SQL_CHANGED': 'Il controllo di lettura dell’inizializzazione PostgreSQL è fallito. Nessun permesso viene aperto automaticamente.',
    'RUNTIME_PROFILE_COMMAND_FAILED': 'Un comando di preparazione del primo avvio è fallito. Il checkpoint resta conservato; questo codice generico non distingue download, Compose o letture locali.',
    'RUNTIME_PROFILE_POSTGRES_PULL_FAILED': 'Download dell’immagine PostgreSQL fissata nel backup fallito. Controlla la connessione e scegli Rileva e continua; il checkpoint è conservato.',
    'RUNTIME_PROFILE_DNS_PULL_FAILED': 'Download dell’immagine DNSCrypt fissata nel backup fallito. Controlla la connessione e scegli Rileva e continua; il checkpoint è conservato.',
    'RUNTIME_PROFILE_OAUTH_PULL_FAILED': 'Download dell’immagine OAuth2 Proxy fissata nel backup fallito. Controlla la connessione e scegli Rileva e continua; il checkpoint è conservato.',
    'RUNTIME_PROFILE_PGBOUNCER_PULL_FAILED': 'Download dell’immagine PgBouncer fissata nel backup fallito. Controlla la connessione e scegli Rileva e continua; il checkpoint è conservato.',
    'RUNTIME_PROFILE_IMAGE_CACHE_INSPECT_FAILED': 'Docker non ha potuto controllare le immagini già presenti sulla VM. Il programma non considera questo errore una semplice immagine mancante.',
    'RUNTIME_PROFILE_IMAGE_CACHE_INVALID': 'Le informazioni dell’immagine locale non corrispondono al digest o alla piattaforma Linux amd64 del backup. Nessuna immagine alternativa è stata usata.',
    'RUNTIME_PROFILE_IMAGE_INSPECT_FAILED': 'Il controllo locale dei metadati di un’immagine Docker è fallito. Il checkpoint resta conservato.',
    'RUNTIME_PROFILE_IMAGE_SAVE_FAILED': 'Docker non ha potuto leggere l’archivio locale di un’immagine per verificarne utenti e permessi. Il passo non è un download.',
    'RUNTIME_PROFILE_IMAGE_ARCHIVE_REFUSED': 'L’archivio locale dell’immagine non supera la verifica di digest, piattaforma o contenuti. Il checkpoint resta conservato; nessuna immagine alternativa viene usata.',
    'RUNTIME_PROFILE_COMPOSE_CONFIG_FAILED': 'Docker Compose non ha potuto leggere la configurazione dello stack. Il problema riguarda il Compose o i suoi file di input, non necessariamente la connessione al registro immagini.',
    'RUNTIME_PROFILE_COMPOSE_CONFIG_INVALID': 'Docker Compose ha restituito dati non leggibili come configurazione JSON. Il profilo non viene installato.',
    'RUNTIME_PROFILE_COMPOSE_VERSION_FAILED': 'La lettura della versione del plugin Docker Compose è fallita.',
    'RUNTIME_PROFILE_GIT_READ_FAILED': 'La lettura dello stack come utente della VM è fallita. Conserva il checkpoint e i file per verificare accesso e proprietà.',
    'RUNTIME_PROFILE_DOCKER_RESOURCE_CHECK_FAILED': 'Docker non ha potuto leggere container o volumi durante il controllo del primo avvio. Nessuna risorsa viene cancellata da questo controllo.',
    'RUNTIME_PROFILE_FRESH_HOST_REQUIRED': 'Il controllo Docker ha trovato container o un volume non vuoto. Il profilo del primo avvio non viene applicato a questo stato; i dati sono conservati.',
    'RUNTIME_PROFILE_PRESTART_CHECKPOINT_REQUIRED': 'Il recupero precedente ha già tentato l’avvio senza il profilo di compatibilità. Per la prova .29/.30 seleziona «Ricomincia il test da zero», poi Verifica e Ripristina entrambe le VM. Questa scelta archivia i dati e rimuove i container e i volumi del tentativo precedente.',
    'TEST_RESET_SCOPE_REFUSED': 'La nuova simulazione è limitata a test@192.168.178.29 e test2@192.168.178.30, al backup dr-20261006T210601Z e commit 28f6ca7…. Usa AIO manuale e TLS disattivato.',
    'TEST_RESET_METADATA_REFUSED': 'Il controllo della nuova simulazione ha restituito metadati inattesi. L’operazione è stata fermata.',
    'TEST_RESET_BOTH_VMS_REQUIRED': 'Con «Ricomincia il test da zero» usa Ripristina entrambe le VM. Prepara stack e Avvia servizi servono a riprendere un recupero esistente.',
    'TEST_RESET_SPACE_REQUIRED': 'Lo spazio sulla VM non basta per conservare e verificare tutti i dati dei volumi. Libera spazio prima di riprovare; le copie esistenti restano conservate.',
    'TEST_RESET_FILESYSTEM_REFUSED': 'Le cartelle da archiviare e l’archivio non sono sullo stesso filesystem. La pulizia automatica si ferma per conservare i dati.',
    'TEST_RESET_ALREADY_RUNNING': 'Un altro recupero o una pulizia sono già in corso. Attendi la fine prima di riprovare.',
    'TEST_RESET_CHECKPOINT_REFUSED': 'Il tentativo presente non corrisponde al recupero verificato per questa prova. Nessuna pulizia automatica viene autorizzata da quel checkpoint.',
    'TEST_RESET_FOREIGN_CONTAINER': 'Sono presenti container estranei al recupero di test. La pulizia automatica si ferma.',
    'TEST_RESET_FOREIGN_VOLUME': 'Sono presenti volumi estranei o con proprietà non verificate. La pulizia automatica si ferma.',
    'TEST_RESET_BIND_SCOPE_REFUSED': 'Un collegamento del container non corrisponde al Compose del recupero. Il programma riconosce il dispositivo TUN, il socket Docker e i file temporanei dichiarati; altri percorsi richiedono un controllo prima della pulizia.',
    'TEST_RESET_ARCHIVE_CHANGED': 'Una copia o i dati da archiviare sono cambiati durante la verifica. Conserva lo stato e le copie; il controllo non viene saltato.',
    'TEST_RESET_TICKET_CHANGED': 'Lo stato è cambiato dopo il controllo preliminare. Premi Verifica e riprova mantenendo le stesse destinazioni.',
    'RECOVERY_AIO_MODE_CHANGED': 'La modalità AIO è diversa da quella del checkpoint. Conserva lo stato prima di cambiare modalità.',
    'MANUAL_AIO_INPUT_CONTRACT_INVALID': 'Il piano di input non consente la configurazione AIO manuale richiesta.',
    'REMOTE_OPERATION_FAILED': 'La VM ha fermato il comando. Se presente, il codice del passo è indicato nel registro.',
    'SSH_CHANNEL_CLOSED': 'Il canale SSH si è chiuso senza comunicare l’esito del comando. Conserva il tentativo e verifica connessione e stato della VM prima di ripetere l’avvio.',
    'REMOTE_EXIT_137': 'Il comando remoto è terminato con codice 137. Il solo esito non ne identifica la causa: controlla stato della VM e memoria, conservando i dati.',
    'REMOTE_EXIT_143': 'Il comando remoto è terminato con codice 143. Il checkpoint e i dati restano conservati; verifica il tentativo prima di riprendere.',
    'UBUNTU_LTS_VERSION_REQUIRED': 'Usa Ubuntu Server 26.04 o 24.04 amd64.',
    'UBUNTU_CODENAME_MISMATCH': 'Versione e nome della distribuzione Ubuntu non corrispondono.',
    'SEPARATE_RECOVERY_VMS_REQUIRED': 'Stack e Infisical devono essere due VM nuove distinte.',
    'SSH_API_FORWARDING_REQUIRED': 'Il server SSH deve consentire forwarding sul loopback per la prova Infisical.',
    'INFISICAL_CONFIG_ARCHIVE_LAYOUT_REQUIRES_REVIEW': 'Il backup contiene file diversi dal contratto Infisical. Conserva il materiale per controllarlo.',
    'INFISICAL_DUMP_NOT_COMPATIBLE': 'Il dump PostgreSQL non è leggibile con la versione recuperata.',
    'INFISICAL_RESTORED_API_NOT_READY': 'Il nuovo Infisical non risponde ancora al controllo API locale.',
}


for message, codes in (
    ('La copia AIO non contiene database integri e profili nel formato previsto. Scegli un backup completo verificato; i file presenti restano conservati.',
     ('AIO_SNAPSHOT_DATABASE_CORRUPT','AIO_SNAPSHOT_DATABASE_INVALID','AIO_SNAPSHOT_DATABASE_SIZE_INVALID',
      'AIO_SNAPSHOT_FOREIGN_KEY_INVALID','AIO_SNAPSHOT_CONFIGURATION_MISSING')),
    ('Versione, immagini o percorso dei database AIO non corrispondono al backup. Serve un punto completo compatibile con lo stack recuperato.',
     ('AIO_SNAPSHOT_BIND_LAYOUT_REQUIRED','AIO_SNAPSHOT_COMPOSE_INVALID','AIO_SNAPSHOT_DEPLOYMENT_INVALID',
      'AIO_SNAPSHOT_IMAGE_CHECK_FAILED','AIO_SNAPSHOT_PINNED_IMAGE_REQUIRED','AIO_SNAPSHOT_SQLITE_LAYOUT_REQUIRED')),
    ('Le chiavi applicative AIO richieste sono assenti o non valide. Controlla gli input Infisical del backup; i database non vengono sostituiti.',
     ('AIO_SNAPSHOT_ENVIRONMENT_INVALID','AIO_SNAPSHOT_SECRET_KEY_REQUIRED')),
    ('Un file privato AIO non rispetta percorso, tipo o permessi previsti. Il recupero conserva i dati e ferma l’importazione.',
     ('AIO_SNAPSHOT_FILE_INVALID','AIO_SNAPSHOT_PRIVATE_OUTPUT_REQUIRED','AIO_SNAPSHOT_REQUIRES_MODE_600','AIO_SNAPSHOT_SYMLINK_REFUSED')),
    ('La copia AIO non appartiene al punto di recupero selezionato. Ricarica release e commit associati in Accessi e backup.',
     ('AIO_SNAPSHOT_SCOPE_CHANGED','AIO_SNAPSHOT_SCOPE_INVALID')),
    ('Le applicazioni AIO non erano disponibili o sono cambiate durante il backup. Serve una nuova copia completa prodotta e verificata dall’originale.',
     ('AIO_SNAPSHOT_CAPTURE_TIMEOUT','AIO_SNAPSHOT_CAPTURE_WINDOW_INVALID','AIO_SNAPSHOT_SOURCE_CONTAINER_REQUIRED',
      'AIO_SNAPSHOT_SOURCE_ENV_CHANGED','AIO_SNAPSHOT_SOURCE_IMAGE_CHANGED','AIO_SNAPSHOT_SOURCE_MOUNT_CHANGED',
      'AIO_SNAPSHOT_SOURCE_NOT_RUNNING')),
    ('Docker non ha permesso di verificare quali servizi usano i database AIO. Controlla lo stato della VM e scegli Rileva e continua dopo aver risolto la causa.',
     ('AIO_SNAPSHOT_DOCKER_CHECK_FAILED',)),
):
    for code in codes:
        ERRORS.setdefault(code,message)


def validate_first_boot_choice(data):
    """Reject unsupported scoped compatibility before modifying either host."""
    require(data.get('user') == 'test'
            and data.get('dr_tag') == 'dr-20261006T210601Z'
            and data.get('public_commit') == '28f6ca7cc6f5fd10418fc0af2926815927ef98c8',
            'RUNTIME_PROFILE_SCOPE_REFUSED')


def host_check_message(info, role='stack'):
    label = 'VM stack' if role == 'stack' else 'VM Infisical'
    message = (label + ' verificata: ' + info['os'] + ' amd64; '
               + str(info['containers']) + ' container, ' + str(info['volumes']) + ' volumi Docker.')
    if info.get('existing_recovery'):
        phases = info.get('recovery') or {}
        if role == 'infisical':
            return message + (' Recupero Infisical completato nel checkpoint.'
                              if phases.get('infisical_completed') is True else ' Recupero Infisical parziale presente.')
        attempted = phases.get('application_start_attempted')
        startup = ('avvio già tentato' if attempted is True else
                   'avvio non ancora tentato' if attempted is False else 'fase di avvio da verificare')
        message += (' Recupero precedente presente: '
                    + ('preparazione completata' if phases.get('prepared') is True else 'preparazione parziale')
                    + ', ' + startup + '. Profilo di compatibilità '
                    + ('presente' if phases.get('runtime_profile_recorded') is True else 'assente')
                    + ' nel checkpoint.')
    return message


from .ui_dashboard import App


def main():
    App().mainloop()


if __name__ == '__main__':
    main()
