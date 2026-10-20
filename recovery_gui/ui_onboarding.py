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
ERROR_TEXT = {
    'SERVICE_CONTROLLER_REQUIRED': 'Il collegamento di installazione non è disponibile in questa versione.',
    'SERVICE_ANALYSIS_REQUIRED': 'Analizza le variabili e prepara il piano prima di collegarti alla VM.',
    'SERVICE_REVIEW_REQUIRED': 'Verifica la scelta pubblico/privato delle variabili prima di preparare il piano.',
    'SERVICE_INSPECTION_REQUIRED': 'Premi Verifica VM prima di aggiungere il servizio.',
    'SERVICE_INPUTS_CHANGED': 'I dati sono cambiati: prepara e verifica di nuovo il piano.',
    'SERVICE_OPERATION_INCOMPLETE': 'Il servizio non ha ancora superato tutti i controlli. Consulta il passaggio indicato.',
    'SERVICE_OPERATION_STOPPED': 'Operazione fermata. Verifica lo stato registrato prima di riprendere.',
    'SERVICE_LAB_PREPARATION_INCOMPLETE': 'La preparazione delle VM di collaudo non è stata verificata. Controlla l’esito prima di aggiungere un servizio.',
    'SERVICE_INFISICAL_ADDRESS_REQUIRED': 'Per l’accesso alternativo inserisci un indirizzo HTTPS diretto di Infisical, senza credenziali nel collegamento. Il tunnel Agent viene preferito quando disponibile.',
    'SERVICE_INFISICAL_ACCESS_REQUIRED': 'Per creare i segreti servono progetto, ambiente e un token Infisical con permessi di scrittura.',
    'SERVICE_STACK_ROOT_REQUIRED': 'Questa anteprima richiede lo stack in /home/utente-SSH/streams-aio, per esempio /home/pi/streams-aio.',
    'SERVICE_STACK_OWNER_MISMATCH': 'La cartella dello stack deve appartenere allo stesso utente usato per il collegamento SSH.',
    'SERVICE_PERSISTENT_DATA_COVERAGE_REQUIRED': 'Questa anteprima aggiunge servizi senza nuovi volumi dati o database. Per aggiungere dati persistenti serve prima includerli nel backup e nel recupero.',
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
        self.events, self._busy, self._alive = queue.Queue(), False, True
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
        ttk.Label(lab, textvariable=self.lab_hint, style='CardHint.TLabel', wraplength=820).pack(anchor='w', pady=(0, 9))
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

        inputs = self._card('2. Nuovo servizio', 'Anteprima: un solo servizio, senza nuovi volumi dati o database. I file esistenti dello stack vengono conservati; i dati persistenti richiedono prima una copertura nel backup e nel recupero.')
        grid = ttk.Frame(inputs)
        grid.pack(fill='x')
        self._entry(grid, 'Nome del servizio (facoltativo se già nel Compose)', self.service_name)
        self.compose = self._editor(inputs, 'Compose da aggiungere', 11)
        self.public_env = self._editor(inputs, 'Variabili .env del servizio (facoltative)', 6)
        self.analyse_button = self._control(ttk.Button(inputs, text='Analizza variabili', command=self.analyse_variables))
        self.analyse_button.pack(anchor='w', pady=(10, 0))

        classification = self._card('3. Pubblico o privato', 'Verifica le proposte: il nome della variabile, da solo, non identifica sempre un segreto.')
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
        self.review_check = self._control(ttk.Checkbutton(classification, text='Ho verificato la scelta pubblico/privato delle variabili', variable=self.reviewed))
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
        return (self.compose.get('1.0', 'end-1c'), self.public_env.get('1.0', 'end-1c'), self.service_name.get().strip())

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
        self.status.set(code + ' · ' + ERROR_TEXT.get(code, 'Controlla il piano e il passaggio indicato; le credenziali non vengono registrate.'))

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
            inventory = self._planner().inspect_inputs(*sources)
            self.inventory = tuple(inventory)
            self.private_names = {item.name for item in self.inventory if item.suggested_private}
            self.state.private_values = {key: value for key, value in self.state.private_values.items()
                                         if key in self.private_names}
            self._scan_sources = sources
            self.state.invalidate()
            self.reviewed.set(False)
            self._fill_inventory()
            self.status.set('Variabili rilevate. Verifica pubblico/privato, poi prepara il piano.')
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
            self.state.analysis = self._planner().analyze_inputs(*self._sources(),
                private_names=tuple(sorted(self.private_names)), private_values=dict(self.state.private_values))
            public = self.state.analysis.plan.to_public_dict()
            self.preview.configure(state='normal')
            self.preview.delete('1.0', 'end')
            self.preview.insert('1.0', json.dumps(public, indent=2, ensure_ascii=False))
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
                self._restore_states.append((widget, widget.cget('state')))
                widget.configure(state='disabled')
            except (tk.TclError, TypeError):
                continue
        self.cancel_button.configure(state='normal')

    def _unfreeze(self):
        for widget, previous in self._restore_states:
            try:
                widget.configure(state=previous)
            except tk.TclError:
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
            return
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
            self._active_action = action
            if action == 'prepare_lab':
                self.status.set('Preparazione delle sole VM di collaudo in corso. Lo stack completo non viene avviato.')
                self.lab_hint.set('Preparazione delle sole VM di collaudo in corso. Attendi l’esito verificato.')
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
                self._unfreeze()
            self._show_error(error)

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
                self.status.set(STAGES[stage] + ' · ' + STATUS_LABELS[status] + (' · ' + value['code'] if value.get('code') else ''))
                if getattr(self, '_active_action', '') == 'prepare_lab':
                    self.lab_hint.set('Preparazione VM di collaudo · ' + STAGES[stage] + ' · ' + STATUS_LABELS[status])
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
                Path(path).write_text(json.dumps(self.state.analysis.plan.to_public_dict(), indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
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
