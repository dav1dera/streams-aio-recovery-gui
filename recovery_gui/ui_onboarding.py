"""Guided service addition, with local analysis and explicit remote execution.

This module creates no connection on import or when a panel is opened. The
controller owns SSH/API operations; workers only send fixed presentation events
to the Tk thread. Drafts, private values, tokens and receipts stay in memory.
"""
from dataclasses import dataclass, field
import importlib
import json
from pathlib import Path
import queue
import re
import threading
import tkinter as tk
from tkinter import filedialog, ttk
from urllib.parse import urlsplit


CODE = re.compile(r'[A-Z][A-Z0-9_]{0,100}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
TAG = re.compile(r'dr-[0-9]{8}T[0-9]{6}Z\Z')
STAGES = {
    'HOST': 'VM e stack esistente',
    'INFISICAL': 'Segreti in Infisical',
    'FILES': 'Compose e file pubblici',
    'AGENT': 'Collegamento Agent',
    'SERVICE': 'Avvio e salute del servizio',
    'GITHUB': 'Pubblicazione GitHub',
    'BACKUP': 'Nuovo backup cifrato',
}
STAGE_ALIASES = {
    'INSPECT': 'HOST', 'PREFLIGHT': 'HOST', 'CONFIGURATION': 'FILES',
    'PUBLIC_SYNC': 'GITHUB', 'DR': 'BACKUP', 'HEALTH': 'SERVICE',
    'START': 'SERVICE', 'STARTED': 'SERVICE', 'NATIVE_AGENT': 'AGENT',
    'DEPENDENCIES': 'HOST',
    'INFISICAL_CONFIG': 'INFISICAL', 'INFISICAL_DATABASE': 'INFISICAL',
    'INFISICAL_SERVER': 'INFISICAL', 'INFISICAL_TRANSFER': 'INFISICAL',
    'STACK_TRANSFER': 'FILES', 'CLONES': 'FILES', 'DOWNLOAD': 'FILES',
    'DECRYPT': 'FILES', 'INITIALIZE': 'FILES', 'INPUTS': 'FILES',
    'RENDER': 'FILES', 'EMPTY_STATE': 'FILES', 'RUNTIME_PROFILE': 'FILES',
    'NPM': 'FILES', 'AIO': 'FILES', 'NPM_TOPOLOGY': 'FILES', 'PREPARED': 'FILES',
}
STATUS_LABELS = {
    'RUNNING': 'In corso', 'START': 'In corso', 'PASS': 'Verificato',
    'VERIFIED': 'Verificato', 'REFUSED': 'Da risolvere',
    'FAILED': 'Da risolvere', 'ERROR': 'Da risolvere',
    'PENDING': 'In attesa', 'SKIPPED': 'Non necessario',
}
PROGRESS_TEXT = {
    'SERVICE_LAB_CHECKING_INPUTS': 'Controllo degli accessi, della chiave age e del backup selezionato.',
    'SERVICE_LAB_READING_BACKUP': 'Verifica del backup pubblicato su GitHub in corso.',
    'SERVICE_LAB_CONNECTING_STACK': 'Collegamento SSH alla VM stack di collaudo in corso.',
    'SERVICE_LAB_CONNECTING_INFISICAL': 'Collegamento SSH alla VM Infisical di collaudo in corso.',
    'SERVICE_LAB_CHECKING_STACK': 'Verifica della VM stack: vuota oppure stesso laboratorio riprendibile.',
    'SERVICE_LAB_CHECKING_INFISICAL': 'Verifica della VM Infisical: vuota oppure stesso laboratorio riprendibile.',
}
ERROR_TEXT = {
    'SERVICE_VOLUME_DRIVER_UNSUPPORTED': 'Il volume usa un archivio esterno: dichiara la sua procedura di recupero esterna prima di continuare.',
    'ONBOARDING_CONFIGURATION_DATA_OVERLAP': 'Separa i file pubblici dalle cartelle dati da archiviare.',
    'ONBOARDING_CONFIGURATION_READ_ONLY_REQUIRED': 'Monta i file pubblici in sola lettura e usa una cartella separata per i dati.',
    'SSH_CONNECTION_FAILED': 'La connessione SSH non è stata completata. Conserva gli esiti per identificare il passaggio che si è fermato.',
    'SSH_CONNECT_TIMEOUT': 'Il collegamento SSH ha superato il tempo di attesa. Verifica indirizzo, porta e raggiungibilità della VM.',
    'SSH_CONNECTION_REFUSED': 'La destinazione rifiuta la connessione SSH. Verifica la porta e che il servizio SSH sia avviato.',
    'SSH_NAME_RESOLUTION_FAILED': 'Il nome della VM non si risolve. Controlla il nome oppure usa il suo indirizzo IP.',
    'SSH_NETWORK_UNREACHABLE': 'La rete della VM non è raggiungibile da questo PC. Controlla indirizzo, rete e instradamento.',
    'SSH_LOCAL_NETWORK_DENIED': 'Il PC blocca l’accesso di rete per SSH. Verifica le autorizzazioni del programma e il firewall locale.',
    'SSH_PROTOCOL_FAILED': 'La negoziazione SSH non è stata completata. Verifica il registro SSH della VM; il collegamento può essere stato interrotto prima dell’accesso.',
    'SSH_KEY_PASSPHRASE_REQUIRED': 'La chiave SSH privata richiede una passphrase. Inseriscila nelle opzioni avanzate della VM corrispondente.',
    'SSH_KEY_FILE_UNAVAILABLE': 'Il file della chiave SSH non è leggibile dal programma. Controlla il percorso e i permessi sul PC.',
    'SSH_KEY_FORMAT_INVALID': 'Il file selezionato non è una chiave SSH privata supportata. Se usi una password, svuota il campo della chiave SSH; la chiave age va nel riquadro backup.',
    'SSH_TRANSPORT_CLOSED': 'Il server ha chiuso la sessione SSH prima che il collegamento fosse pronto. Verifica il registro SSH della VM e riprendi.',
    'SSH_HOST_KEY_STORE_FAILED': 'Impossibile leggere o salvare il registro locale delle impronte SSH. Controlla l’accesso alla cartella StreamsAIORecovery e al file known_hosts di questo utente Windows.',
    'RUNTIME_PROFILE_IMAGE_CHANGED': 'Un’immagine non supera i controlli del profilo del backup selezionato. Conserva lo stato delle VM e consulta il codice del passaggio.',
    'RUNTIME_PROFILE_IMAGE_LOCK_INVALID': 'Il catalogo delle immagini nel backup è mancante o non valido. Conserva il checkpoint e verifica il backup selezionato.',
    'RUNTIME_PROFILE_IMAGE_LOCK_MISMATCH': 'Compose e catalogo delle immagini non corrispondono al punto selezionato. Nessuna immagine viene sostituita automaticamente.',
    'RUNTIME_PROFILE_IMAGE_REPOSITORY_REFUSED': 'Un servizio di base usa un repository diverso da quello supportato dal profilo. Il recupero conserva lo stato per verificarne la compatibilità.',
    'RUNTIME_PROFILE_IMAGE_PLATFORM_REFUSED': 'Un’immagine del backup non è compatibile con Linux amd64. Il recupero è fermo e lo stato resta conservato.',
    'RUNTIME_PROFILE_IMAGE_METADATA_INVALID': 'Docker non ha restituito metadati validi per un’immagine del backup. Conserva lo stato e riprova dopo aver verificato Docker.',
    'SERVICE_CONTROLLER_REQUIRED': 'Il collegamento di installazione non è disponibile in questa versione.',
    'SERVICE_ANALYSIS_REQUIRED': 'Analizza le variabili e prepara il piano prima di collegarti alla VM.',
    'SERVICE_REVIEW_REQUIRED': 'Verifica le variabili e come conservare i dati prima di preparare il piano.',
    'SERVICE_INSPECTION_REQUIRED': 'Premi Verifica VM prima di aggiungere il servizio.',
    'SERVICE_INPUTS_CHANGED': 'I dati sono cambiati: prepara e verifica di nuovo il piano.',
    'SERVICE_OPERATION_INCOMPLETE': 'Il servizio non ha ancora superato tutti i controlli. Consulta il passaggio indicato.',
    'SERVICE_OPERATION_STOPPED': 'Operazione fermata. Verifica lo stato registrato prima di riprendere.',
    'SERVICE_OPERATION_BUSY': 'È già in corso un’operazione. Attendi il suo esito oppure interrompila prima di preparare le VM.',
    'SERVICE_LAB_PREPARATION_INCOMPLETE': 'La preparazione delle VM di collaudo non è stata verificata. Controlla l’esito prima di aggiungere un servizio.',
    'LAB_INPUTS_REQUIRED': 'Apri Accessi e backup e configura entrambe le VM di collaudo, il token GitHub, la chiave age e il backup da usare.',
    'LAB_EMPTY_VMS_REQUIRED': 'Una delle VM contiene dati che non risultano un tentativo di laboratorio riprendibile. Usa VM vuote o verifica il punto originale del tentativo. I dati presenti vengono conservati.',
    'LAB_RUNTIME_SCOPE_REFUSED': 'Il checkpoint del laboratorio non corrisponde a macchina, utente o backup selezionato, oppure contiene un avvio dello stack. Seleziona il backup originale del tentativo. I dati restano conservati.',
    'LAB_APPLICATION_START_REFUSED': 'Questa VM è un laboratorio per aggiungere singoli servizi. Prosegui da Aggiungi servizio in Collaudo locale; il recupero completo dello stack richiede altre VM vuote.',
    'LAB_HOST_IDENTITY_INVALID': 'Utente, cartella home o identità della VM non corrispondono al collaudo. Verifica gli accessi delle VM di prova in Accessi e backup.',
    'LAB_MARKER_REFUSED': 'La registrazione del laboratorio non è stata verificata. Conserva lo stato delle VM e controlla gli esiti prima di riprendere.',
    'LAB_PREPARATION_FAILED': 'La preparazione del laboratorio si è fermata. Controlla il passaggio indicato e conserva lo stato delle VM prima di riprovare.',
    'SEPARATE_RECOVERY_VMS_REQUIRED': 'Stack e Infisical devono usare due VM diverse. Correggi gli indirizzi in Accessi e backup.',
    'INFISICAL_API_PORT_REQUIRES_REVIEW': 'La porta API Infisical del backup richiede una verifica. Usa un backup completo compatibile prima di riprovare.',
    'GITHUB_TOKEN_REQUIRED': 'Apri Accessi e backup e inserisci il token GitHub con permesso Contents: Read sui due repository del recupero.',
    'SELECT_GITHUB_RECOVERY_POINT': 'Apri Accessi e backup, carica i backup e seleziona il punto da usare per il collaudo.',
    'AGE_IDENTITY_FILE_REQUIRED': 'Apri Accessi e backup e scegli il file della chiave privata age PRIMARY o RECOVERY con Sfoglia.',
    'SERVICE_INFISICAL_ADDRESS_REQUIRED': 'Per l’accesso alternativo inserisci un indirizzo HTTPS diretto di Infisical, senza credenziali nel collegamento. Il tunnel Agent viene preferito quando disponibile.',
    'SERVICE_INFISICAL_ACCESS_REQUIRED': 'Per creare i segreti servono progetto, ambiente e un token Infisical con permessi di scrittura.',
    'SERVICE_STACK_ROOT_REQUIRED': 'Questa anteprima richiede lo stack in /home/utente-SSH/streams-aio, per esempio /home/pi/streams-aio.',
    'SERVICE_STACK_OWNER_MISMATCH': 'La cartella dello stack deve appartenere allo stesso utente usato per il collegamento SSH.',
    'SERVICE_PERSISTENT_DATA_COVERAGE_REQUIRED': 'I dati del servizio richiedono una scelta di conservazione verificata. Analizza di nuovo il Compose e controlla i dati previsti nel piano.',
    'SERVICE_PRIVATE_VALUES_INVALID': 'Un valore privato manca o non è valido. Inseriscilo nel campo mascherato e prepara di nuovo il piano.',
    'SERVICE_PRIVATE_VALUE_QUOTING_UNSUPPORTED': 'Questa versione non supporta valori privati con apostrofi, righe multiple, caratteri di controllo o una barra inversa finale. Non applica modifiche a quel valore.',
    'INFISICAL_AUTH_FAILED': 'Il token Infisical non è valido o è scaduto. Inserisci un nuovo token e verifica di nuovo la VM.',
    'INFISICAL_PERMISSION_DENIED': 'Il token Infisical deve poter leggere e creare cartelle e segreti nel progetto e ambiente scelti.',
    'INFISICAL_SECRET_CONFLICT': 'In Infisical esiste già un segreto con lo stesso nome e un valore diverso. Il valore esistente viene conservato: verifica il piano prima di continuare.',
    'INFISICAL_FOLDER_CONFLICT': 'Infisical restituisce più cartelle con lo stesso nome. Risolvi il duplicato prima di continuare.',
    'INFISICAL_REDIRECT_REFUSED': 'Inserisci l’indirizzo HTTPS diretto di Infisical: i reindirizzamenti vengono rifiutati.',
    'INFISICAL_CONNECTION_FAILED': 'Infisical non risponde correttamente via HTTPS. Verifica indirizzo, raggiungibilità e certificato.',
    'INFISICAL_API_VERSION_UNSUPPORTED': 'Le API richieste non sono disponibili a questo indirizzo Infisical. Verifica indirizzo e versione del server.',
    'INFISICAL_RATE_LIMITED': 'Infisical ha temporaneamente limitato le richieste. Attendi e verifica di nuovo la VM.',
    'INFISICAL_READBACK_FAILED': 'Non è stato possibile rileggere tutti i segreti creati. Lo stato resta conservato: verifica di nuovo prima di riprovare.',
    'INFISICAL_SSH_TARGET_INVALID': 'Il tunnel Agent non espone una destinazione locale valida. Controlla il collegamento di Infisical sulla VM stack.',
    'INFISICAL_SSH_REQUEST_REFUSED': 'Il controllo ha rifiutato una richiesta fuori dal percorso previsto per Infisical. Nessuna destinazione alternativa viene usata.',
    'SERVICE_PROBE_URL_INVALID': 'Il controllo HTTP deve usare http://127.0.0.1:porta/percorso, senza credenziali o parametri.',
    'SSH_ADDRESS_REQUIRED': 'Completa l’accesso della VM stack in Accessi e backup.',
    'SERVICE_TOOL_FAILED': 'Il controllo non è stato completato. Nessuna credenziale viene inserita negli esiti.',
    # Fixed messages for public files, linked services, data and recovery policies.
    'SERVICE_CONFIGURATION_INVALID': 'Controlla l’elenco dei file pubblici: ogni file richiede percorso, contenuto e permessi.',
    'SERVICE_CONFIGURATION_DATA_OVERLAP': 'Un file pubblico si trova anche nei dati da archiviare. Collega separatamente la sottocartella public in sola lettura e la cartella dei dati del servizio.',
    'SERVICE_CONFIGURATION_CONTENT_INVALID': 'Un file pubblico supera i limiti di dimensione o contiene caratteri non supportati. Controlla i file e riprova.',
    'SERVICE_CONFIGURATION_FILE_REQUIRED': 'Aggiungi il contenuto del file pubblico collegato dal Compose prima di preparare il piano.',
    'SERVICE_CONFIGURATION_MISSING': 'Manca un file pubblico richiesto dal Compose. Aggiungilo nella sezione File pubblici.',
    'SERVICE_CONFIGURATION_MODE_INVALID': 'I permessi del file non sono validi. Usa per esempio 420 per 0644, 416 per 0640 o 384 per 0600.',
    'SERVICE_CONFIGURATION_PATH_INVALID': 'Salva i file pubblici sotto data/nome-servizio/public/, senza usare percorsi esterni o la cartella dei segreti.',
    'SERVICE_CONFIGURATION_NOT_MOUNTED': 'Un file pubblico non è collegato ad alcun servizio nel Compose. Correggi il collegamento oppure rimuovi il file.',
    'SERVICE_CONFIGURATION_SOURCE_INVALID': 'Il collegamento al file pubblico non corrisponde a un percorso gestito. Usa data/nome-servizio/public/.',
    'SERVICE_DATA_RECOVERY_REQUIRED': 'I dati del servizio devono essere archiviati a servizio fermo. Verifica la scelta stopped_archive per questi dati.',
    'SERVICE_DATA_RESOURCE_OUTSIDE_STACK': 'I nuovi dati devono restare nella cartella dello stack oppure in volumi gestiti da Docker.',
    'SERVICE_EXTERNAL_CONFIGURATION_UNSUPPORTED': 'Questa configurazione dipende da un file esterno non gestito. Aggiungi il file pubblico nella cartella prevista.',
    'SERVICE_STORAGE_POLICY_INVALID': 'Controlla le scelte di conservazione dei dati. Ogni scelta deve indicare servizio, destinazione e metodo supportato.',
    'SERVICE_STORAGE_POLICY_TARGET_MISSING': 'Una scelta di conservazione riguarda dati non presenti nel Compose. Analizza di nuovo il servizio.',
    'SERVICE_RUNTIME_ARCHIVE_REFUSED': 'I collegamenti al sistema vengono ricreati durante il recupero. Non possono essere archiviati come dati del servizio.',
    'SERVICE_RUNTIME_SOURCE_INVALID': 'Un collegamento al sistema usa un percorso non supportato. Verifica il Compose prima di continuare.',
    'SERVICE_BUNDLE_INVALID': 'Il Compose con più servizi non è valido. Controlla nomi, immagini e collegamenti tra i servizi.',
    'SERVICE_COMPOSE_RESOURCE_CONFLICT': 'Una rete o un volume esiste già con una definizione diversa. Conserva la definizione attuale oppure scegli un altro nome.',
    'SERVICE_COMPOSE_RESOURCE_INVALID': 'Una rete o un volume nel Compose non è valido. Controlla la relativa definizione.',
    'SERVICE_COMPOSE_TOP_LEVEL_UNSUPPORTED': 'Il Compose contiene una sezione non ancora gestita. Controlla servizi, reti, volumi e file di configurazione.',
    'SERVICE_VARIABLE_CONFLICT': 'Due variabili hanno definizioni incompatibili. Controlla le variabili dei servizi indicati nel Compose.',
    'SERVICE_VOLUME_INVALID': 'Controlla il collegamento ai dati nel Compose: origine e destinazione devono essere valide.',
    'SERVICE_VOLUME_NAME_INVALID': 'Il nome del volume non è valido. Usa lettere, numeri, punti, trattini o trattini bassi.',
    'SERVICE_MOUNT_INVALID': 'Un collegamento a file o dati non è valido. Controlla origine e destinazione nel Compose.',
    'SERVICE_MOUNT_OPTIONS_INVALID': 'Il collegamento usa opzioni non supportate. Controlla le opzioni di accesso ai file nel Compose.',
    'SERVICE_MOUNT_TARGET_DUPLICATE': 'Lo stesso servizio collega più risorse alla stessa destinazione. Mantieni un solo collegamento per percorso.',
    'SERVICE_MOUNT_TYPE_INVALID': 'Il tipo di collegamento a file o dati non è supportato. Usa i tipi gestiti dal Compose.',
    'SERVICE_RESOURCE_PATH_INVALID': 'Un percorso di file o dati non è valido. Evita risalite di cartella e riferimenti a variabili nel percorso.',
    'SERVICE_RESOURCES_INVALID': 'L’elenco di file, dati o collegamenti non è valido. Analizza di nuovo il Compose.',
    'SERVICE_TMPFS_INVALID': 'La memoria temporanea del servizio non è configurata correttamente. Controlla il Compose.',
    'ONBOARDING_RESOURCE_BACKUP_CAPABILITY_REQUIRED': 'Il sistema di backup della VM deve supportare i nuovi dati prima dell’installazione. Aggiorna il sistema di backup e verifica di nuovo.',
    'ONBOARDING_BACKUP_RESOURCE_COVERAGE_MISMATCH': 'Il nuovo backup non contiene tutti i dati previsti. Conserva lo stato e verifica la copertura prima di riprovare.',
    'ONBOARDING_ANONYMOUS_VOLUME_MAPPING_REQUIRED': 'Un volume senza nome non ha una destinazione verificabile nel recupero. Assegna un nome al volume e prepara di nuovo il piano.',
    'ONBOARDING_RUNTIME_RESOURCE_MISSING': 'Sulla VM manca un collegamento al sistema richiesto dal servizio. Verifica che la destinazione possa fornirlo.',
    'ONBOARDING_EXTERNAL_RESOURCE_MISSING': 'Sulla VM manca una rete o un volume esterno richiesto dal Compose. Preparalo prima di continuare.',
    'ONBOARDING_DATA_RESOURCE_OUTSIDE_STACK': 'Un percorso dei nuovi dati esce dalla cartella dello stack. Correggi il Compose e prepara un nuovo piano.',
    'ONBOARDING_CONFIGURATION_FILES_INVALID': 'L’elenco dei file pubblici non supera i controlli. Prepara di nuovo il piano con file e permessi validi.',
    'ONBOARDING_CONFIGURATION_HASH_INVALID': 'Il contenuto di un file pubblico non corrisponde al piano verificato. Prepara e verifica di nuovo il piano.',
    'ONBOARDING_CONFIGURATION_FILE_NOT_MOUNTED': 'Un file pubblico non è collegato ai servizi del piano. Controlla il Compose e prepara di nuovo il piano.',
    'ONBOARDING_CONFIGURATION_RESOURCE_MISSING': 'Manca un file pubblico richiesto dai servizi del piano. Aggiungilo e prepara di nuovo il piano.',
    'ONBOARDING_PUBLIC_CONFIGURATION_READBACK_FAILED': 'Non è stato possibile verificare tutti i file pubblici scritti sulla VM. Conserva lo stato e verifica di nuovo.',
    'ONBOARDING_PUBLIC_RESOURCE_READBACK_FAILED': 'Reti, volumi o collegamenti scritti sulla VM non corrispondono al piano. Conserva lo stato e verifica di nuovo.',
    'ONBOARDING_RESOURCE_INVENTORY_CONFLICT': 'Lo stack registra già dati o collegamenti con una definizione diversa. Conserva la registrazione attuale e controlla il piano.',
    'ONBOARDING_RESOURCE_INVENTORY_INVALID': 'La registrazione dei dati dello stack non è valida. Conserva lo stato e verifica il piano prima di riprovare.',
    'ONBOARDING_MOUNT_INVENTORY_MISMATCH': 'I collegamenti ai dati non corrispondono a quelli del piano verificato. Prepara e verifica un nuovo piano.',
    'ONBOARDING_RECOVERY_POLICY_INVALID': 'La scelta di conservazione dei dati non è valida. Analizza il servizio e verifica le scelte nel riepilogo.',
    'ONBOARDING_RUNTIME_POLICY_INVALID': 'I collegamenti al sistema devono essere ricreati durante il recupero. Correggi la scelta di conservazione.',
    'ONBOARDING_COMPOSE_RESOURCE_CONFLICT': 'Una rete o un volume della VM ha una definizione diversa dal piano. Conserva lo stato e controlla i nomi e i collegamenti.',
    'ONBOARDING_COMPOSE_RESOURCES_INVALID': 'Le reti o i volumi del piano non superano i controlli. Prepara un nuovo piano dal Compose corretto.',
    'ONBOARDING_RESOURCES_INVALID': 'L’elenco dei dati e dei collegamenti del piano non è valido. Prepara e verifica un nuovo piano.',
    'ONBOARDING_RESOURCE_PATH_INVALID': 'Un percorso di dati del piano non è valido. Correggi il Compose e prepara di nuovo il piano.',
    'ONBOARDING_COMPONENTS_INVALID': 'L’elenco dei servizi collegati non è valido. Prepara e verifica un nuovo piano.',
    'ONBOARDING_EXTERNAL_CONFIGURATION_UNSUPPORTED': 'Il servizio richiede una configurazione esterna non gestita. Aggiungi un file pubblico nella cartella prevista.',
}


class InputFailure(ValueError):
    """A fixed presentation code, never a copy of an input or response."""


def safe_code(error):
    if not isinstance(error, InputFailure) and not type(error).__module__.startswith('recovery_gui.'):
        return 'SERVICE_TOOL_FAILED'
    text = str(error)
    return text if CODE.fullmatch(text) else 'SERVICE_TOOL_FAILED'


def safe_stage_event(value):
    """Keep only the stage protocol; backend text can contain private data."""
    if not isinstance(value, dict):
        return None
    stage = value.get('stage')
    stage = STAGE_ALIASES.get(stage, stage)
    status = value.get('status')
    if stage not in STAGES or status not in STATUS_LABELS:
        return None
    result = {'stage': stage, 'status': status}
    code = value.get('code')
    if (isinstance(code, str) and CODE.fullmatch(code)
            and code.startswith(('SERVICE_', 'ONBOARD_', 'ONBOARDING_', 'SSH_', 'INFISICAL_',
                                 'COMPOSE_', 'AGENT_', 'PUBLIC_', 'DR_', 'OPERATION_'))):
        result['code'] = code
    return result


def verified_completion(result):
    """A green container or a generic PASS is insufficient for completion."""
    if not isinstance(result, dict) or result.get('status') != 'PASS':
        return False
    checks = result.get('checks')
    return (isinstance(checks, dict)
            and all(checks.get(key) is True for key in ('service', 'agent', 'github', 'backup'))
            and isinstance(result.get('public_commit'), str)
            and COMMIT.fullmatch(result['public_commit']) is not None
            and isinstance(result.get('backup_tag'), str)
            and TAG.fullmatch(result['backup_tag']) is not None)


def verified_local_completion(result):
    """A local trial proves service/Agent only, never publication or backup."""
    if not isinstance(result, dict) or result.get('status') != 'PASS_LOCAL':
        return False
    checks = result.get('checks')
    return (isinstance(checks, dict) and checks.get('service') is True and checks.get('agent') is True
            and checks.get('github') is False and checks.get('backup') is False
            and result.get('public_commit') in (None, '') and result.get('backup_tag') in (None, ''))


def connection_from_snapshot(snapshot, stack_root, *, probe_url='', verification_scope='full'):
    """No backup, recovery identity or unrelated VM credentials enter this job."""
    if not isinstance(snapshot, dict):
        raise InputFailure('SSH_ADDRESS_REQUIRED')
    names = ('host', 'user', 'port', 'password', 'ssh_key', 'key_password', 'sudo_password')
    result = {key: snapshot.get(key, '') for key in names}
    for key in ('host', 'user', 'port', 'ssh_key'):
        if not isinstance(result[key], str):
            raise InputFailure('SSH_ADDRESS_REQUIRED')
        result[key] = result[key].strip()
    for key in ('password', 'key_password', 'sudo_password'):
        if not isinstance(result[key], str):
            raise InputFailure('SSH_ADDRESS_REQUIRED')
    if not result['host'] or not result['user'] or not (result['password'] or result['ssh_key']):
        raise InputFailure('SSH_ADDRESS_REQUIRED')
    try:
        result['port'] = int(result['port'] or '22')
        if not 1 <= result['port'] <= 65535:
            raise ValueError()
    except (TypeError, ValueError):
        raise InputFailure('SSH_ADDRESS_REQUIRED') from None
    root = stack_root.strip().rstrip('/')
    if not re.fullmatch(r'/home/[A-Za-z_][A-Za-z0-9_-]*/streams-aio', root):
        raise InputFailure('SERVICE_STACK_ROOT_REQUIRED')
    if root.split('/')[2] != result['user']:
        raise InputFailure('SERVICE_STACK_OWNER_MISMATCH')
    result['stack_root'] = root
    probe_url = probe_url.strip()
    if probe_url:
        try:
            probe = urlsplit(probe_url)
            valid = (probe.scheme == 'http' and probe.hostname == '127.0.0.1'
                     and probe.port is not None and 1 <= probe.port <= 65535
                     and probe.username is None and probe.password is None
                     and not probe.query and not probe.fragment)
        except ValueError:
            valid = False
        if not valid:
            raise InputFailure('SERVICE_PROBE_URL_INVALID')
    result['probe_url'] = probe_url
    if verification_scope not in ('full', 'local_lab'):
        raise InputFailure('SERVICE_INPUTS_CHANGED')
    result['verification_scope'] = verification_scope
    return result


def infisical_from_fields(endpoint, project_id, environment, access_token, *, private_required):
    """Fields are captured on the UI thread; the token is never in a report."""
    endpoint, project_id, environment = endpoint.strip(), project_id.strip(), environment.strip()
    if endpoint:
        try:
            parts = urlsplit(endpoint)
            valid = (parts.scheme == 'https' and bool(parts.hostname) and parts.username is None
                     and parts.password is None and not parts.query and not parts.fragment
                     and parts.path in ('', '/') and (parts.port is None or 1 <= parts.port <= 65535))
        except ValueError:
            valid = False
        if not valid:
            raise InputFailure('SERVICE_INFISICAL_ADDRESS_REQUIRED')
    if private_required and (not project_id or not environment or not access_token.strip()):
        raise InputFailure('SERVICE_INFISICAL_ACCESS_REQUIRED')
    return {'endpoint': endpoint.rstrip('/'), 'project_id': project_id,
            'environment': environment, 'access_token': access_token}


def resource_editor_inputs(configuration_text='', policy_text=''):
    """Parse optional editor lists without returning excerpts of invalid input."""
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError()
            result[key] = value
        return result
    result = {}
    for key, source, code, limit in (
            ('configuration_files', configuration_text, 'SERVICE_CONFIGURATION_INVALID', 5 * 1024 * 1024),
            ('storage_policies', policy_text, 'SERVICE_STORAGE_POLICY_INVALID', 256 * 1024)):
        if not isinstance(source, str) or len(source) > limit:
            raise InputFailure(code)
        if not source.strip():
            continue
        try:
            rows = json.loads(source, object_pairs_hook=unique_object)
        except (ValueError, RecursionError):
            raise InputFailure(code) from None
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise InputFailure(code)
        if rows:
            result[key] = rows
    return result


def plan_public_metadata(public):
    """A second presentation boundary keeps config and variable bytes out."""
    def fields(row, names):
        return {key: row[key] for key in names if key in row and isinstance(row[key], (str, int, bool))}
    result = fields(public, ('schema', 'service_name', 'image', 'public_env_path', 'private_env_path', 'fingerprint'))
    result['private_names'] = list(public['private_bindings']) if isinstance(public.get('private_bindings'), dict) else []
    names = public.get('service_names')
    if isinstance(names, (list, tuple)):
        result['service_names'] = [name for name in names if isinstance(name, str)]
    if isinstance(public.get('images'), dict):
        result['images'] = {name: image for name, image in public['images'].items() if isinstance(name, str) and isinstance(image, str)}
    for key, allowed in (
            ('components', ('service_name', 'service', 'name', 'image', 'public_env_path', 'private_env_path')),
            ('configuration_files', ('path', 'mode', 'sha256', 'hash')),
            ('resources', ('service', 'type', 'source', 'target', 'read_only', 'role', 'id'))):
        if not isinstance(public.get(key), (list, tuple)):
            continue
        result[key] = []
        for row in public[key]:
            if not isinstance(row, dict):
                continue
            item = fields(row, allowed)
            if key == 'components':
                item['private_names'] = list(row['private_bindings']) if isinstance(row.get('private_bindings'), dict) else []
            if key == 'resources' and isinstance(row.get('recovery'), dict) and row['recovery'].get('method') in ('recreate', 'stopped_archive', 'external'):
                item['recovery'] = {'method': row['recovery']['method']}
            result[key].append(item)
    return result


def plan_summary(public, *, local_lab=False):
    """Readable, value-free recap, including linked services and data choices."""
    plan = plan_public_metadata(public)
    names = plan.get('service_names') or [plan.get('service_name', 'Servizio')]
    lines = ['Servizi: ' + ', '.join(names)]
    images = plan.get('images', {})
    for name in names:
        image = images.get(name, plan.get('image', ''))
        if image:
            lines.append('  ' + name + ': ' + image)
    for file in plan.get('configuration_files', []):
        mode = file.get('mode')
        permission = (' · permessi ' + format(mode, '04o')) if type(mode) is int else ''
        lines.append('File pubblico: ' + file.get('path', '') + permission)
    for resource in plan.get('resources', []):
        prefix = resource.get('service', '') + ': ' + resource.get('source', 'Gestito da Docker') + ' → ' + resource.get('target', '')
        method = resource.get('recovery', {}).get('method')
        if method == 'external':
            label = 'Risorsa esterna: da predisporre sulla destinazione'
        elif resource.get('role') == 'data' and not resource.get('read_only'):
            label = 'Archivia con container fermi'
        else:
            label = 'Ricreato durante il recupero'
        lines.append(prefix + '\n  ' + label)
    lines.append('Variabili private: ' + (', '.join(plan['private_names']) or 'nessuna'))
    lines.append('Collaudo locale: GitHub e backup esclusi.' if local_lab else 'Percorso completo: GitHub e nuovo backup cifrato verificati.')
    return '\n'.join(lines)


@dataclass
class OnboardingState:
    """Memory-only workflow state, also usable in headless tests."""
    revision: int = 0
    analysis: object = field(default=None, repr=False)
    inspection: object = field(default=None, repr=False)
    private_values: dict = field(default_factory=dict, repr=False)

    def invalidate(self, *, analysis=True):
        self.revision += 1
        self.inspection = None
        if analysis:
            self.analysis = None

    def record_inspection(self, receipt, revision):
        if self.analysis is None or revision != self.revision:
            raise InputFailure('SERVICE_INPUTS_CHANGED')
        if receipt is None:
            raise InputFailure('SERVICE_INSPECTION_REQUIRED')
        self.inspection = receipt

    def clear(self):
        self.invalidate()
        self.private_values.clear()


class ServiceOnboardingPanel(ttk.Frame):
    """Controller: inspect(analysis, connection, infisical, progress_callback)
    and apply(analysis, connection, infisical, receipt, progress_callback).
    Results must be safe dictionaries; only the explicit proof protocol above
    can mark the whole operation complete. Controller credentials stay in RAM.
    """
    def __init__(self, parent, app, controller=None):
        super().__init__(parent, style='Page.TFrame')
        self.app, self.controller = app, controller
        self.state = OnboardingState()
        self.inventory, self.private_names = (), set()
        self.resource_inventory = ()
        self.events, self._busy, self._alive = queue.Queue(), False, True
        self._active_action = ''
        self._controls, self._restore_states, self._traces = [], [], []
        self._scan_sources = None
        self.safe_events = []
        self.service_name = tk.StringVar(self)
        self.stack_root = tk.StringVar(self)
        self.probe_url = tk.StringVar(self)
        self.local_lab = tk.BooleanVar(self, False)
        self.lab_hint = tk.StringVar(self, 'Usa solo due VM vuote dedicate al collaudo; configura i loro accessi e il backup in Accessi e backup.')
        self.endpoint = tk.StringVar(self, self._app_value('infisical_address'))
        self.project_id = tk.StringVar(self, self._app_value('project_id'))
        self.environment = tk.StringVar(self, self._app_value('environment') or 'prod')
        self.access_token = tk.StringVar(self)
        self.reviewed = tk.BooleanVar(self, False)
        self.secret_name = tk.StringVar(self, 'Seleziona una variabile privata')
        self.secret_value = tk.StringVar(self)
        self.status = tk.StringVar(self, 'Incolla il nuovo servizio: l’analisi funziona anche senza collegarti.')
        self.connection_hint = tk.StringVar(self)
        self.stage_labels = {}
        self._build()
        for variable in (self.service_name,):
            self._trace(variable, lambda *_: self._input_changed())
        for variable in (self.stack_root, self.probe_url, self.endpoint, self.project_id, self.environment, self.access_token):
            self._trace(variable, lambda *_: self._connection_changed())
        for key in ('host', 'user', 'port', 'password', 'ssh_key', 'key_password', 'sudo_password'):
            variable = getattr(app, 'vars', {}).get(key)
            if variable is not None:
                self._trace(variable, lambda *_: self._connection_changed())
        self._trace(self.reviewed, lambda *_: self._refresh_buttons())
        self._trace(self.local_lab, lambda *_: self._connection_changed())
        self.bind('<Destroy>', self._destroyed, add='+')
        self._refresh_connection_hint()
        self._refresh_buttons()
        self._poll_id = self.after(100, self.poll)

    def _app_value(self, key):
        variable = getattr(self.app, 'vars', {}).get(key)
        return variable.get() if variable is not None else ''

    def _trace(self, variable, callback):
        self._traces.append((variable, variable.trace_add('write', callback)))

    def _control(self, widget):
        self._controls.append(widget)
        if hasattr(self.app, 'controls'):
            self.app.controls.append(widget)
        return widget

    def _card(self, title, hint=''):
        outer = ttk.Frame(self, style='Card.TFrame', padding=18)
        outer.pack(fill='x', pady=(0, 14))
        ttk.Label(outer, text=title, style='CardTitle.TLabel').pack(anchor='w')
        if hint:
            ttk.Label(outer, text=hint, style='CardHint.TLabel', wraplength=820).pack(anchor='w', pady=(5, 0))
        body = ttk.Frame(outer)
        body.pack(fill='x', pady=(12, 0))
        return body

    def _entry(self, parent, label, variable, *, secret=False, row=0, column=0):
        frame = ttk.Frame(parent)
        frame.grid(row=row, column=column, sticky='ew', padx=(0, 12), pady=(0, 10))
        ttk.Label(frame, text=label, style='Field.TLabel').pack(anchor='w', pady=(0, 4))
        entry = ttk.Entry(frame, textvariable=variable, show='●' if secret else '')
        entry.pack(fill='x')
        self._control(entry)
        parent.columnconfigure(column, weight=1)
        return entry

    def _editor(self, parent, title, height):
        ttk.Label(parent, text=title, style='Field.TLabel').pack(anchor='w', pady=(8, 4))
        frame = ttk.Frame(parent)
        frame.pack(fill='x')
        text = tk.Text(frame, height=height, wrap='none', font=('Consolas', 10),
                       bg='#f8fafd', fg='#17263c', insertbackground='#17263c',
                       relief='solid', borderwidth=1, undo=True)
        scrollbar = ttk.Scrollbar(frame, orient='vertical', command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        text.pack(side='left', fill='x', expand=True)
        scrollbar.pack(side='right', fill='y')
        text.bind('<<Modified>>', self._text_changed, add='+')
        self._control(text)
        return text

    def _build(self):
        lab = self._card('Collaudo su due VM vuote', 'Solo VM di prova: non usare le VM operative. La preparazione recupera file e Agent senza avviare lo stack completo.')
        self.lab_feedback = ttk.Label(lab, textvariable=self.lab_hint, style='CardHint.TLabel', wraplength=820)
        self.lab_feedback.pack(anchor='w', pady=(0, 9))
        self.lab_button = self._control(ttk.Button(lab, text='Prepara le VM di collaudo', command=self.prepare_lab))
        self.lab_button.pack(anchor='w', pady=(0, 9))
        self.lab_check = self._control(ttk.Checkbutton(lab,
            text='Solo collaudo locale: non pubblicare su GitHub né creare backup', variable=self.local_lab))
        self.lab_check.pack(anchor='w')
        connection = self._card('1. Destinazione', 'Si usa l’accesso SSH della sola VM stack configurato in Accessi e backup.')
        ttk.Label(connection, textvariable=self.connection_hint, style='CardHint.TLabel').pack(anchor='w', pady=(0, 8))
        grid = ttk.Frame(connection)
        grid.pack(fill='x')
        self._entry(grid, 'Cartella dello stack sulla VM', self.stack_root)
        self._entry(grid, 'Controllo HTTP locale (facoltativo)', self.probe_url, row=1)
        ttk.Label(connection, text='Lascia il controllo HTTP vuoto se l’immagine ha già un HEALTHCHECK. Esempio: http://127.0.0.1:8080/health',
                  style='CardHint.TLabel', wraplength=820).pack(anchor='w', pady=(0, 8))
        ttk.Button(connection, text='Apri Accessi e backup', command=lambda: self.app.book.select(1)).pack(anchor='w')

        inputs = self._card('2. Nuovo servizio', 'Incolla il Compose, anche con più servizi collegati. Nel prossimo passo verifica variabili, file pubblici e conservazione dei dati.')
        grid = ttk.Frame(inputs)
        grid.pack(fill='x')
        self._entry(grid, 'Nome del servizio principale (facoltativo)', self.service_name)
        self.compose = self._editor(inputs, 'Compose da aggiungere', 11)
        self.public_env = self._editor(inputs, 'Variabili .env del servizio (facoltative)', 6)
        self.configuration_files = self._editor(inputs, 'File pubblici · elenco JSON facoltativo: path, content, mode', 5)
        ttk.Label(inputs, text='Solo configurazioni pubbliche, senza password o token. Usa data/nome-servizio/public/nome-file. Il campo mode usa 420 per 0644, 416 per 0640 o 384 per 0600. Lascia vuoto se non servono file.', style='CardHint.TLabel', wraplength=820).pack(anchor='w', pady=(5, 8))
        self.storage_policies = self._editor(inputs, 'Conservazione dati · elenco JSON facoltativo: service, target, method', 3)
        ttk.Label(inputs, text='Lascia vuoto per archiviare i dati con i servizi fermi (stopped_archive). recreate è riservato ai collegamenti al sistema e ai file pubblici; external indica risorse esterne da predisporre sulla destinazione.', style='CardHint.TLabel', wraplength=820).pack(anchor='w', pady=(5, 8))
        self.analyse_button = self._control(ttk.Button(inputs, text='Analizza servizio', command=self.analyse_variables))
        self.analyse_button.pack(anchor='w', pady=(10, 0))

        classification = self._card('3. Dati e segreti', 'Verifica i dati da conservare e quali variabili devono restare private.')
        self.resources = ttk.Treeview(classification, columns=('service', 'path', 'recovery'), show='headings', height=4)
        for name, label, width in (('service', 'Servizio', 160), ('path', 'Dati e collegamenti', 330), ('recovery', 'Conservazione', 260)):
            self.resources.heading(name, text=label)
            self.resources.column(name, width=width, minwidth=80, stretch=True)
        self.resources.pack(fill='x', pady=(0, 14))
        self.variables = ttk.Treeview(classification, columns=('name', 'source', 'scope', 'value'), show='headings', height=7, selectmode='browse')
        for name, label, width in (('name', 'Variabile', 250), ('source', 'Origine', 110), ('scope', 'Destinazione', 130), ('value', 'Valore', 150)):
            self.variables.heading(name, text=label)
            self.variables.column(name, width=width, minwidth=80, stretch=name == 'name')
        self.variables.pack(fill='x')
        self.variables.bind('<<TreeviewSelect>>', self._selected_variable, add='+')
        choices = ttk.Frame(classification)
        choices.pack(fill='x', pady=(9, 9))
        self.public_button = self._control(ttk.Button(choices, text='Rendi pubblica', command=lambda: self.set_private(False)))
        self.public_button.pack(side='left', padx=(0, 8))
        self.private_button = self._control(ttk.Button(choices, text='Rendi privata', command=lambda: self.set_private(True)))
        self.private_button.pack(side='left')
        ttk.Label(classification, textvariable=self.secret_name, style='Field.TLabel').pack(anchor='w', pady=(5, 4))
        private_row = ttk.Frame(classification)
        private_row.pack(fill='x')
        self.secret_entry = self._control(ttk.Entry(private_row, textvariable=self.secret_value, show='●'))
        self.secret_entry.pack(side='left', fill='x', expand=True, padx=(0, 8))
        self.secret_button = self._control(ttk.Button(private_row, text='Imposta valore privato', command=self.store_secret))
        self.secret_button.pack(side='left')
        ttk.Label(classification, text='I valori già presenti nel testo vengono usati senza mostrarli nella tabella. I valori privati non vengono esportati.',
                  style='CardHint.TLabel', wraplength=820).pack(anchor='w', pady=(7, 8))
        self.review_check = self._control(ttk.Checkbutton(classification, text='Ho verificato le variabili e come conservare i dati', variable=self.reviewed))
        self.review_check.pack(anchor='w')
        self.plan_button = self._control(ttk.Button(classification, text='Prepara piano', command=self.prepare_plan))
        self.plan_button.pack(anchor='w', pady=(10, 0))

        infisical = self._card('4. Infisical', 'Si preferisce il tunnel Agent rilevato sulla VM: non serve raggiungere il dominio di produzione. Lascia vuoto l’indirizzo HTTPS se usi il tunnel. Progetto, ambiente e token con permessi di scrittura servono per creare i segreti; restano in memoria.')
        grid = ttk.Frame(infisical)
        grid.pack(fill='x')
        self._entry(grid, 'HTTPS alternativo (facoltativo)', self.endpoint, column=0)
        self._entry(grid, 'ID del progetto', self.project_id, column=1)
        self._entry(grid, 'Ambiente', self.environment, row=1, column=0)
        self._entry(grid, 'Token di accesso Infisical', self.access_token, secret=True, row=1, column=1)

        review = self._card('5. Verifica e aggiungi', 'Prima si controlla la VM. Il percorso completo verifica servizio, Agent, GitHub e backup. Il collaudo locale verifica solo servizio e Agent e lascia esclusi GitHub e backup.')
        self.preview = tk.Text(review, height=9, wrap='word', font=('Consolas', 9),
                               bg='#f8fafd', fg='#52647d', relief='flat', state='disabled')
        self.preview.pack(fill='x')
        buttons = ttk.Frame(review)
        buttons.pack(fill='x', pady=(12, 12))
        self.inspect_button = self._control(ttk.Button(buttons, text='Verifica VM', command=self.inspect))
        self.inspect_button.pack(side='left', padx=(0, 8))
        self.apply_button = self._control(ttk.Button(buttons, text='Aggiungi e verifica', style='Accent.TButton', command=self.apply))
        self.apply_button.pack(side='left', padx=(0, 8))
        self.export_button = self._control(ttk.Button(buttons, text='Salva piano senza valori', command=self.export_plan))
        self.export_button.pack(side='left')
        self.cancel_button = ttk.Button(review, text='Interrompi', command=self.cancel, state='disabled')
        self.cancel_button.pack(anchor='w', pady=(0, 10))
        for stage, title in STAGES.items():
            row = ttk.Frame(review)
            row.pack(fill='x', pady=3)
            ttk.Label(row, text=title).pack(side='left')
            label = ttk.Label(row, text='In attesa', style='CardHint.TLabel')
            label.pack(side='right')
            self.stage_labels[stage] = label
        ttk.Label(review, textvariable=self.status, wraplength=820, style='CardHint.TLabel').pack(anchor='w', pady=(12, 0))

    def set_controller(self, controller):
        self.controller = controller
        self._refresh_buttons()

    def _planner(self):
        return importlib.import_module('.service_plan', __package__)

    def _sources(self):
        return (self.compose.get('1.0', 'end-1c'), self.public_env.get('1.0', 'end-1c'), self.service_name.get().strip(),
                self.configuration_files.get('1.0', 'end-1c'), self.storage_policies.get('1.0', 'end-1c'))

    def _text_changed(self, event):
        if event.widget.edit_modified():
            event.widget.edit_modified(False)
            self._input_changed()

    def _input_changed(self):
        self.state.invalidate()
        self.reviewed.set(False)
        self._refresh_buttons()

    def _connection_changed(self):
        self.state.invalidate(analysis=False)
        self._refresh_connection_hint()
        self._refresh_buttons()

    def _refresh_connection_hint(self):
        address, user = self._app_value('host').strip(), self._app_value('user').strip()
        self.connection_hint.set(f'VM stack: {user}@{address}' if address and user else 'VM stack: completa l’accesso SSH in Accessi e backup.')
        if not self.stack_root.get() and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', user or ''):
            self.stack_root.set('/home/' + user + '/streams-aio')

    def _show_error(self, error):
        code = safe_code(error)
        self.safe_events.append({'stage': 'REFUSED', 'status': 'REFUSED', 'code': code})
        description = ERROR_TEXT.get(code)
        app_errors = getattr(self.app, 'errors', None)
        if description is None and isinstance(app_errors, dict):
            description = app_errors.get(code)
        if not isinstance(description, str):
            description = 'Controlla il piano e il passaggio indicato; le credenziali non vengono registrate.'
        message = code + ' · ' + description
        self.status.set(message)
        if getattr(self, '_active_action', '') == 'prepare_lab':
            # The action starts in the first card; its failure must remain
            # visible there, even when the final status card is off screen.
            self.lab_hint.set(message)
            try:
                self.lab_feedback.configure(foreground='#a6413c')
            except tk.TclError:
                pass

    def _fill_inventory(self):
        self.variables.delete(*self.variables.get_children())
        for item in self.inventory:
            value = 'Inserito in memoria' if item.name in self.state.private_values else ('Presente nel testo' if item.has_value else 'Da inserire')
            self.variables.insert('', 'end', iid=item.name, values=(item.name, {'env': '.env', 'compose': 'Compose', 'interpolation': 'Riferimento'}.get(item.source, item.source),
                                  'Infisical' if item.name in self.private_names else 'File pubblico', value))
        self.secret_value.set('')
        self._selected_variable()

    def analyse_variables(self):
        if self._operation_running():
            return
        try:
            sources = self._sources()
            options = resource_editor_inputs(*sources[3:])
            inventory = self._planner().inspect_inputs(*sources[:3], **options)
            resources = self._planner().inspect_resources(*sources[:3], **options)
            self.resource_inventory = tuple(resources) if isinstance(resources, (tuple, list)) else ()
            self.resources.delete(*self.resources.get_children())
            for resource in self.resource_inventory:
                method = resource.get('recovery', {}).get('method')
                if method == 'external':
                    label = 'Risorsa esterna: da predisporre sulla destinazione'
                elif resource.get('role') == 'data' and not resource.get('read_only'):
                    label = 'Archivia con container fermi'
                else:
                    label = 'Ricreato durante il recupero'
                self.resources.insert('', 'end', values=(resource.get('service', ''), resource.get('source', '') + ' → ' + resource.get('target', ''), label))
            self.inventory = tuple(inventory)
            self.private_names = {item.name for item in self.inventory if item.suggested_private}
            self.state.private_values = {key: value for key, value in self.state.private_values.items()
                                         if key in self.private_names}
            self._scan_sources = sources
            self.state.invalidate()
            self.reviewed.set(False)
            self._fill_inventory()
            self.status.set('Servizio analizzato. Verifica dati e variabili, poi prepara il piano.')
        except Exception as error:
            self.inventory, self._scan_sources = (), None
            self.state.invalidate()
            self._show_error(error)
        self._refresh_buttons()

    def _selected_name(self):
        selected = self.variables.selection()
        return selected[0] if selected else None

    def _selected_variable(self, event=None):
        name = self._selected_name()
        self.secret_name.set('Valore privato di ' + name if name in self.private_names else 'Seleziona una variabile privata')
        self.secret_value.set('')
        self._refresh_buttons()

    def set_private(self, private):
        if self._operation_running():
            return
        name = self._selected_name()
        if name is None:
            return
        if private:
            self.private_names.add(name)
        else:
            self.private_names.discard(name)
            self.state.private_values.pop(name, None)
        self.state.invalidate()
        self.reviewed.set(False)
        self._fill_inventory()
        self.variables.selection_set(name)
        self._selected_variable()

    def store_secret(self):
        if self._operation_running():
            return
        name = self._selected_name()
        if name not in self.private_names:
            return
        self.state.private_values[name] = self.secret_value.get()
        self.secret_value.set('')
        self.state.invalidate()
        self.reviewed.set(False)
        self._fill_inventory()
        self.variables.selection_set(name)
        self.status.set('Valore privato conservato in memoria. Verifica le scelte e prepara il piano.')

    def prepare_plan(self):
        if self._operation_running():
            return
        try:
            if self._scan_sources != self._sources():
                raise InputFailure('SERVICE_INPUTS_CHANGED')
            if not self.reviewed.get():
                raise InputFailure('SERVICE_REVIEW_REQUIRED')
            self.state.invalidate()
            sources = self._sources()
            self.state.analysis = self._planner().analyze_inputs(*sources[:3],
                private_names=tuple(sorted(self.private_names)), private_values=dict(self.state.private_values),
                **resource_editor_inputs(*sources[3:]))
            public = self.state.analysis.plan.to_public_dict()
            self.preview.configure(state='normal')
            self.preview.delete('1.0', 'end')
            self.preview.insert('1.0', plan_summary(public, local_lab=self.local_lab.get()))
            self.preview.configure(state='disabled')
            self.status.set('Piano pronto. Verifica la VM prima di aggiungere il servizio.')
        except Exception as error:
            self.state.analysis = None
            self._show_error(error)
        self._refresh_buttons()

    def _operation_running(self):
        return self._busy or bool(getattr(self.app, 'busy', False))

    def _capture(self):
        if self.state.analysis is None:
            raise InputFailure('SERVICE_ANALYSIS_REQUIRED')
        if self._scan_sources != self._sources():
            raise InputFailure('SERVICE_INPUTS_CHANGED')
        connection = connection_from_snapshot(self.app.snapshot(), self.stack_root.get(), probe_url=self.probe_url.get(),
            verification_scope='local_lab' if self.local_lab.get() else 'full')
        infisical = infisical_from_fields(self.endpoint.get(), self.project_id.get(), self.environment.get(),
                                        self.access_token.get(), private_required=bool(self.private_names))
        return self.state.analysis, connection, infisical

    def _freeze(self):
        self._restore_states = []
        widgets = list(getattr(self.app, 'buttons', ())) + list(getattr(self.app, 'controls', ())) + self._controls
        seen = set()
        for widget in widgets:
            if id(widget) in seen:
                continue
            seen.add(id(widget))
            try:
                previous = widget.cget('state')
                widget.configure(state='disabled')
                self._restore_states.append((widget, previous))
            except (tk.TclError, TypeError):
                continue
        self.cancel_button.configure(state='normal')

    def _unfreeze(self):
        for widget, previous in self._restore_states:
            try:
                widget.configure(state=previous)
            except (tk.TclError, TypeError):
                pass
        self._restore_states.clear()
        self.cancel_button.configure(state='disabled')
        self._refresh_buttons()

    def inspect(self):
        self._start_job('inspect')

    def apply(self):
        self._start_job('apply')

    def prepare_lab(self):
        self._start_job('prepare_lab')

    def _start_job(self, action):
        if self._operation_running():
            if action == 'prepare_lab':
                message = 'SERVICE_OPERATION_BUSY · ' + ERROR_TEXT['SERVICE_OPERATION_BUSY']
                self.lab_hint.set(message)
                self.status.set(message)
            return
        # Set before snapshot/freeze: synchronous startup failures need the
        # same first-card feedback as failures returned by the worker.
        self._active_action = action
        try:
            if self.controller is None:
                raise InputFailure('SERVICE_CONTROLLER_REQUIRED')
            if action not in ('inspect', 'apply', 'prepare_lab'):
                raise InputFailure('SERVICE_TOOL_FAILED')
            if action == 'prepare_lab':
                lab_snapshot = self.app.snapshot()
                if not isinstance(lab_snapshot, dict) or not callable(getattr(self.controller, 'prepare_lab', None)):
                    raise InputFailure('SERVICE_CONTROLLER_REQUIRED')
                analysis = connection = infisical = None
            else:
                analysis, connection, infisical = self._capture()
            if action == 'apply' and self.state.inspection is None:
                raise InputFailure('SERVICE_INSPECTION_REQUIRED')
            receipt, revision = self.state.inspection, self.state.revision
            self._busy = self.app.busy = True
            self.app.cancelled.clear()
            self._freeze()
            if action == 'prepare_lab':
                self.status.set('Preparazione delle sole VM di collaudo in corso. Lo stack completo non viene avviato.')
                self.lab_hint.set('Preparazione delle sole VM di collaudo in corso. Attendi l’esito verificato.')
                self.lab_feedback.configure(foreground='#5563df')
            elif action == 'inspect':
                self.status.set('Controllo della VM in corso.')
            else:
                self.status.set('Aggiunta del servizio e collaudo locale in corso.' if self.local_lab.get()
                                else 'Aggiunta del servizio e verifica completa in corso.')
            for stage, label in self.stage_labels.items():
                skipped = stage in ('GITHUB', 'BACKUP') and (action == 'prepare_lab' or self.local_lab.get())
                label.configure(text='Escluso dal collaudo' if skipped else 'In attesa', foreground='#64748b')
            controller = self.controller
            def progress(value):
                event = safe_stage_event(value)
                if event is not None:
                    self.events.put(('stage', event))
            def worker():
                try:
                    if action == 'prepare_lab':
                        result = controller.prepare_lab(lab_snapshot, progress)
                    elif action == 'inspect':
                        result = controller.inspect(analysis, connection, infisical, progress)
                    else:
                        result = controller.apply(analysis, connection, infisical, receipt, progress)
                    self.events.put((action, (revision, result)))
                except Exception as error:
                    self.events.put(('error', safe_code(error)))
                finally:
                    self.events.put(('done', None))
            threading.Thread(target=worker, daemon=True).start()
        except Exception as error:
            if self._busy:
                self._busy = self.app.busy = False
                try:
                    self._unfreeze()
                except (tk.TclError, TypeError):
                    pass
            self._show_error(error)
            self._active_action = ''

    def _refresh_buttons(self):
        if not hasattr(self, 'inspect_button'):
            return
        running = self._operation_running()
        ready = self.state.analysis is not None
        self.lab_button.configure(state='normal' if not running and self.controller is not None else 'disabled')
        self.analyse_button.configure(state='disabled' if running else 'normal')
        self.plan_button.configure(state='normal' if not running and self._scan_sources is not None and self.reviewed.get() else 'disabled')
        self.inspect_button.configure(state='normal' if not running and ready and self.controller is not None else 'disabled')
        self.apply_button.configure(state='normal' if not running and ready and self.state.inspection is not None and self.controller is not None else 'disabled')
        self.export_button.configure(state='normal' if not running and ready else 'disabled')
        selected = self._selected_name()
        for button in (self.public_button, self.private_button):
            button.configure(state='normal' if not running and selected is not None else 'disabled')
        private = selected is not None and selected in self.private_names
        for widget in (self.secret_entry, self.secret_button):
            widget.configure(state='normal' if not running and private else 'disabled')

    def cancel(self):
        if self._busy:
            self.app.cancelled.set()
            self.status.set('Interruzione richiesta. Attendi l’esito del passaggio in corso.')
            if getattr(self, '_active_action', '') == 'prepare_lab':
                self.lab_hint.set('Interruzione richiesta: attendo la chiusura del passaggio sulle VM di collaudo.')
            self.cancel_button.configure(state='disabled')

    def poll(self):
        if not self._alive:
            return
        while True:
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == 'stage':
                stage, status = value['stage'], value['status']
                if stage in ('GITHUB', 'BACKUP') and (self.local_lab.get() or getattr(self, '_active_action', '') == 'prepare_lab'):
                    value = dict(stage=stage, status='SKIPPED')
                    status = 'SKIPPED'
                self.safe_events.append(value)
                tone = '#1e8069' if status in ('PASS', 'VERIFIED') else '#a6413c' if status in ('REFUSED', 'FAILED', 'ERROR') else '#5563df'
                self.stage_labels[stage].configure(text=STATUS_LABELS[status], foreground=tone)
                description = PROGRESS_TEXT.get(value.get('code'))
                message = (description or STAGES[stage] + ' · ' + STATUS_LABELS[status]) + (' · ' + value['code'] if value.get('code') else '')
                self.status.set(message)
                if getattr(self, '_active_action', '') == 'prepare_lab':
                    self.lab_hint.set(message if description else 'Preparazione VM di collaudo · ' + message)
            elif kind == 'prepare_lab':
                revision, result = value
                try:
                    if revision != self.state.revision:
                        raise InputFailure('SERVICE_INPUTS_CHANGED')
                    if not isinstance(result, dict) or result.get('status') != 'PREPARED_LAB':
                        raise InputFailure('SERVICE_LAB_PREPARATION_INCOMPLETE')
                    user = self._app_value('user').strip()
                    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', user):
                        raise InputFailure('SSH_ADDRESS_REQUIRED')
                    self.state.invalidate()
                    self.local_lab.set(True)
                    self.stack_root.set('/home/' + user + '/streams-aio')
                    self.lab_hint.set('File e Agent preparati. Stack completo non avviato; puoi aggiungere un servizio di prova.')
                    self.lab_feedback.configure(foreground='#1e8069')
                    self.status.set('VM di collaudo preparate. Aggiungi un servizio di prova: GitHub e backup restano esclusi.')
                except InputFailure as error:
                    self._show_error(error)
            elif kind == 'inspect':
                revision, receipt = value
                try:
                    self.state.record_inspection(receipt, revision)
                    self.status.set('VM verificata. Puoi premere Aggiungi e verifica per applicare questo piano.')
                except InputFailure as error:
                    self._show_error(error)
            elif kind == 'apply':
                revision, result = value
                self.state.inspection = None
                if revision != self.state.revision:
                    self._show_error(InputFailure('SERVICE_INPUTS_CHANGED'))
                elif not self.local_lab.get() and verified_completion(result):
                    self.status.set('Servizio aggiunto e verificato. GitHub aggiornato · backup ' + result['backup_tag'] + '.')
                    for label in self.stage_labels.values():
                        label.configure(text='Verificato', foreground='#1e8069')
                    self.access_token.set('')
                    self.state.private_values.clear()
                    self.secret_value.set('')
                    self.state.analysis = None
                elif self.local_lab.get() and verified_local_completion(result):
                    self.status.set('Collaudo locale completato: servizio e Agent verificati. GitHub e backup non eseguiti.')
                    for stage, label in self.stage_labels.items():
                        skipped = stage in ('GITHUB', 'BACKUP')
                        label.configure(text='Escluso dal collaudo' if skipped else 'Verificato',
                                        foreground='#64748b' if skipped else '#1e8069')
                    self.access_token.set('')
                    self.state.private_values.clear()
                    self.secret_value.set('')
                    self.state.analysis = None
                else:
                    self._show_error(InputFailure('SERVICE_OPERATION_INCOMPLETE'))
            elif kind == 'error':
                self.state.inspection = None
                self._show_error(InputFailure(value))
            elif kind == 'done':
                self._busy = self.app.busy = False
                self._active_action = ''
                self._unfreeze()
        self._refresh_buttons()
        self._poll_id = self.after(100, self.poll)

    def export_plan(self):
        if self._operation_running() or self.state.analysis is None:
            return
        path = filedialog.asksaveasfilename(parent=self, title='Salva piano senza valori', defaultextension='.json',
                                          filetypes=[('Piano senza valori', '*.json')])
        if path:
            try:
                Path(path).write_text(json.dumps(plan_public_metadata(self.state.analysis.plan.to_public_dict()), indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
                self.status.set('Piano senza valori salvato. Credenziali e valori privati non sono inclusi.')
            except Exception:
                self._show_error(InputFailure('SERVICE_TOOL_FAILED'))

    def clear_sensitive(self):
        self.state.clear()
        for variable in (self.access_token, self.secret_value):
            try:
                variable.set('')
            except tk.TclError:
                pass
        self._scan_sources = None

    def _destroyed(self, event):
        if event.widget is not self:
            return
        self._alive = False
        if self._busy:
            self.app.cancelled.set()
        for variable, callback in self._traces:
            try:
                variable.trace_remove('write', callback)
            except tk.TclError:
                pass
        self._traces.clear()
        self.clear_sensitive()
        try:
            self.after_cancel(self._poll_id)
        except tk.TclError:
            pass
