"""Tk desktop wizard. Worker threads never call Tk; all dialogs use a UI queue."""
import json
from pathlib import Path
import queue
import re
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import webbrowser

from .backend import Failure, GitHub, Host, SSH, SHA, TAG, require, restore_all
from .codes import ERROR_CODES
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
}
ERRORS = {
    'SSH_AUTH_FAILED': 'Accesso SSH rifiutato. Controlla utente, password o chiave.',
    'SSH_CONNECTION_FAILED': 'La VM non risponde via SSH.',
    'SSH_HOST_KEY_CHANGED': 'La chiave SSH è cambiata: verifica la VM dalla console prima di aggiornare known_hosts.',
    'FRESH_DOCKER_HOST_REQUIRED': 'Sono presenti container o volumi. Usa una VM nuova.',
    'EXISTING_STACK_REFUSED': 'È già presente uno stack. La destinazione non viene sovrascritta.',
    'INCOMPLETE_STEP_REQUIRES_REVIEW': 'Un passo è rimasto incompleto. Conserva i dati e controlla il checkpoint prima di riprendere.',
    'AGENT_BOOTSTRAP_CONFIG_NOT_UNIQUE': 'Bootstrap Agent non riconosciuto. Usa i campi avanzati per i file Universal Auth.',
    'AGENT_CREDENTIAL_PATH_UNSUPPORTED': 'Il backup Agent usa percorsi non supportati. Fornisci i due file Universal Auth.',
    'PRIVATE_INPUT_FILE_REQUIRED': 'Un file privato richiesto manca nel materiale recuperato.',
    'HTTPS_INFISICAL_ORIGIN_REQUIRED': 'Serve l’endpoint HTTPS Infisical raggiungibile dalla VM.',
    'INFISICAL_SNAPSHOT_FAILED': 'Autenticazione o lettura Infisical fallita. Nessun valore è stato registrato.',
    'AIO_IMPORT_REFUSED': 'L’importatore AIO ha rifiutato gli input o la compatibilità. Nessun database esistente viene sovrascritto.',
    'AIO_EXPORT_PROFILE_AMBIGUOUS': 'Il profilo dell’export non è identificabile. Seleziona un payload DR esplicito.',
    'APPLICATION_START_REFUSED': 'Avvio o verifica applicativa fallita. Conserva lo stato e controlla la VM.',
    'REMOTE_OPERATION_FAILED': 'La VM ha fermato il comando. Se presente, il codice del passo è indicato nel registro.',
    'UBUNTU_LTS_VERSION_REQUIRED': 'Usa Ubuntu Server 26.04 o 24.04 amd64.',
    'UBUNTU_CODENAME_MISMATCH': 'Versione e nome della distribuzione Ubuntu non corrispondono.',
    'SEPARATE_RECOVERY_VMS_REQUIRED': 'Stack e Infisical devono essere due VM nuove distinte.',
    'SSH_API_FORWARDING_REQUIRED': 'Il server SSH deve consentire forwarding sul loopback per la prova Infisical.',
    'INFISICAL_CONFIG_ARCHIVE_LAYOUT_REQUIRES_REVIEW': 'Il backup contiene file diversi dal contratto Infisical. Conserva il materiale per controllarlo.',
    'INFISICAL_DUMP_NOT_COMPATIBLE': 'Il dump PostgreSQL non è leggibile con la versione recuperata.',
    'INFISICAL_RESTORED_API_NOT_READY': 'Il nuovo Infisical non risponde ancora al controllo API locale.',
}


class ScrollPage(ttk.Frame):
    """Keep every input reachable at small window sizes and higher DPI."""
    def __init__(self, parent):
        super().__init__(parent, style='Page.TFrame')
        self.canvas = tk.Canvas(self, bg='#f5f7fb', highlightthickness=0)
        scrollbar = ttk.Scrollbar(self, orient='vertical', command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        self.canvas.pack(side='left', fill='both', expand=True)
        self.content = ttk.Frame(self.canvas, style='Page.TFrame', padding=(0, 0, 16, 8))
        item = self.canvas.create_window(0, 0, anchor='nw', window=self.content)
        self.content.bind('<Configure>', lambda e:self.canvas.configure(scrollregion=self.canvas.bbox('all')))
        self.canvas.bind('<Configure>', lambda e:self.canvas.itemconfigure(item, width=e.width))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Streams AIO · Recovery')
        self.geometry('1180x800')
        self.minsize(980, 700)
        self.configure(bg='#f5f7fb')
        self.events = queue.Queue()
        self.cancelled = threading.Event()
        self.busy = False
        self.prepared = False
        self.vars = {}
        self.files = {'aiostreams_exports': [], 'aiometadata_exports': []}
        self.safe_report = []
        self.return_page = None
        self.active_phase = None
        self.protocol('WM_DELETE_WINDOW', self.close_app)
        self._theme()
        sidebar = tk.Frame(self, bg='#101b30', width=222)
        sidebar.pack(side='left', fill='y')
        sidebar.pack_propagate(False)
        brand = tk.Canvas(sidebar, width=42, height=42, bg='#101b30', highlightthickness=0)
        brand.pack(anchor='w', padx=24, pady=(30, 15))
        brand.create_rectangle(2, 2, 40, 40, fill='#4b63f0', outline='')
        brand.create_line(12, 25, 21, 15, 30, 25, fill='white', width=3)
        brand.create_line(21, 16, 21, 31, fill='white', width=3)
        tk.Label(sidebar, text='STREAMS AIO', bg='#101b30', fg='#f8fafc',
                 font=('Segoe UI', 12, 'bold')).pack(anchor='w', padx=24)
        tk.Label(sidebar, text='Recovery workspace', bg='#101b30', fg='#8e9bb2',
                 font=('Segoe UI', 10)).pack(anchor='w', padx=24, pady=(4, 26))
        tk.Label(sidebar, text='IL TUO PERCORSO', bg='#101b30', fg='#718198',
                 font=('Segoe UI', 8, 'bold')).pack(anchor='w', padx=24, pady=(0, 10))
        self.nav = []
        self.titles = ['VM e GitHub', 'Backup', 'Nuova VM Infisical', 'Opzioni', 'Ripristino']
        self.descriptions = ['Collega la VM stack e scegli il punto di recupero.',
                             'Scegli dal PC la chiave age e le configurazioni AIO.',
                             'Collega la seconda VM: recupereremo prima i segreti.',
                             'Completa solo le opzioni che ti servono.',
                             'Controlla le destinazioni, poi avvia il recupero.']
        for index, label in enumerate(self.titles):
            button = tk.Button(sidebar, text=f'  {index+1:02d}    {label}', anchor='w',
                               font=('Segoe UI', 10), bg='#101b30', fg='#a4b0c4',
                               activebackground='#243454', activeforeground='white',
                               relief='flat', bd=0, padx=12, pady=13, cursor='hand2',
                               command=lambda i=index:self.book.select(i))
            button.pack(fill='x', padx=12, pady=3)
            self.nav.append(button)
        tk.Label(sidebar, text=f'v{__version__}  /  WINDOWS', bg='#101b30', fg='#718198',
                 font=('Segoe UI', 8)).pack(side='bottom', anchor='w', padx=24, pady=22)
        note = tk.Frame(sidebar, bg='#192842', padx=13, pady=13)
        note.pack(side='bottom', fill='x', padx=18, pady=6)
        tk.Label(note, text='Una prova, due VM nuove', bg='#192842', fg='#dbe5f7',
                 font=('Segoe UI', 9, 'bold'), anchor='w').pack(fill='x')
        tk.Label(note, text='Le VM operative possono\nrestare disponibili.', bg='#192842', fg='#91a1ba',
                 font=('Segoe UI', 9), justify='left').pack(anchor='w', pady=(6, 0))
        workspace = ttk.Frame(self, style='Page.TFrame', padding=(28, 22, 20, 16))
        workspace.pack(side='left', fill='both', expand=True)
        top = ttk.Frame(workspace, style='Page.TFrame')
        top.pack(fill='x')
        self.step_text = tk.StringVar()
        ttk.Label(top, textvariable=self.step_text, style='Eyebrow.TLabel').pack(side='left')
        ttk.Button(top, text='Apri la guida ↗', style='Link.TButton', command=lambda:webbrowser.open(
            'https://github.com/dav1dera/streams-aio-recovery-gui/blob/main/README.md')).pack(side='right')
        self.page_title = tk.StringVar()
        self.page_description = tk.StringVar()
        ttk.Label(workspace, textvariable=self.page_title, style='Title.TLabel').pack(anchor='w', pady=(12, 4))
        ttk.Label(workspace, textvariable=self.page_description, style='Muted.TLabel').pack(anchor='w', pady=(0, 18))
        self.book = ttk.Notebook(workspace, style='Wizard.TNotebook')
        self.book.pack(fill='both', expand=True)
        self.pages = [ScrollPage(self.book) for _ in range(5)]
        for page, title in zip(self.pages, self.titles):
            self.book.add(page, text=title)
        self._connections(self.pages[0].content)
        self._backups(self.pages[1].content)
        self._infisical(self.pages[2].content)
        self._advanced(self.pages[3].content)
        self._run(self.pages[4].content)
        footer = ttk.Frame(workspace, style='Page.TFrame', padding=(0, 14, 0, 0))
        footer.pack(fill='x')
        self.status = tk.StringVar(value='Pronto. Nessuna operazione avviata.')
        ttk.Label(footer, textvariable=self.status, style='Status.TLabel', wraplength=490).pack(side='left')
        self.next_button = ttk.Button(footer, text='Continua →', style='Accent.TButton', command=lambda:self._move(1))
        self.next_button.pack(side='right')
        self.previous_button = ttk.Button(footer, text='← Indietro', command=lambda:self._move(-1))
        self.previous_button.pack(side='right', padx=(8, 10))
        self.book.bind('<<NotebookTabChanged>>', self._page_changed)
        self.bind_all('<MouseWheel>', self._wheel, add='+')
        self._page_changed()
        self.after(100, self.poll)

    def _theme(self):
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('.', font=('Segoe UI', 10), background='#ffffff', foreground='#18243b')
        style.configure('Page.TFrame', background='#f5f7fb')
        style.configure('Card.TFrame', background='#ffffff', relief='solid', borderwidth=1,
                        bordercolor='#e2e8f2')
        style.configure('Wizard.TNotebook', background='#f5f7fb', borderwidth=0, padding=0,
                        bordercolor='#f5f7fb', lightcolor='#f5f7fb', darkcolor='#f5f7fb')
        style.layout('Wizard.TNotebook.Tab', [])
        style.configure('TLabel', background='#ffffff')
        style.configure('Title.TLabel', font=('Segoe UI', 24, 'bold'), background='#f5f7fb', foreground='#15223b')
        style.configure('Eyebrow.TLabel', font=('Segoe UI', 9, 'bold'), background='#f5f7fb', foreground='#4963db')
        style.configure('Muted.TLabel', background='#f5f7fb', foreground='#6c7a90')
        style.configure('Status.TLabel', font=('Segoe UI', 9), background='#f5f7fb', foreground='#6c7a90')
        style.configure('CardTitle.TLabel', font=('Segoe UI', 12, 'bold'))
        style.configure('CardHint.TLabel', font=('Segoe UI', 9), foreground='#6c7a90')
        style.configure('Field.TLabel', font=('Segoe UI', 9), foreground='#526178')
        style.configure('TEntry', padding=(10, 8), fieldbackground='#f8faff', bordercolor='#dce3ef',
                        lightcolor='#dce3ef', darkcolor='#dce3ef', insertcolor='#18243b')
        style.map('TEntry', bordercolor=[('focus', '#6b80f5')], lightcolor=[('focus', '#6b80f5')],
                  darkcolor=[('focus', '#6b80f5')])
        style.configure('TCombobox', padding=(8, 8), fieldbackground='#f8faff', background='#edf1f9',
                        bordercolor='#dce3ef', arrowcolor='#596880')
        style.map('TCombobox', fieldbackground=[('readonly', '#f8faff')], foreground=[('readonly', '#18243b')])
        style.configure('TButton', padding=(14, 9), background='#ffffff', foreground='#36445d',
                        borderwidth=1, bordercolor='#dce3ef', relief='flat')
        style.map('TButton', background=[('active', '#edf1fb'), ('disabled', '#eef1f6')],
                  foreground=[('disabled', '#9da7b8')])
        style.configure('Accent.TButton', background='#4963e9', foreground='white', borderwidth=0)
        style.map('Accent.TButton', background=[('active', '#3a50c8'), ('disabled', '#c1caec')],
                  foreground=[('disabled', '#ffffff')])
        style.configure('Link.TButton', padding=(8, 4), background='#f5f7fb', foreground='#4963db', borderwidth=0)
        style.configure('TCheckbutton', background='#ffffff', font=('Segoe UI', 9))
        style.map('TCheckbutton', background=[('active', '#ffffff')])
        style.configure('Horizontal.TProgressbar', background='#4963e9', troughcolor='#e9edf5',
                        borderwidth=0, thickness=4)

    def _page_changed(self, event=None):
        index = self.book.index(self.book.select())
        self.after_idle(lambda:self.pages[index].canvas.yview_moveto(0))
        self.step_text.set(f'PASSO {index+1:02d} DI 05  /  RECUPERO DELLO STACK')
        self.page_title.set(self.titles[index])
        self.page_description.set(self.descriptions[index])
        for i, button in enumerate(self.nav):
            button.configure(bg='#283b63' if i==index else '#101b30',
                             fg='#ffffff' if i==index else '#a4b0c4',
                             font=('Segoe UI', 10, 'bold') if i==index else ('Segoe UI', 10))
        if hasattr(self, 'next_button'):
            self.previous_button.configure(state='disabled' if index==0 else 'normal')
            self.next_button.configure(state='disabled' if index==4 else 'normal')
        if hasattr(self, 'summary'):
            self.summary.set('Stack: '+(self.var('host').get() or 'da configurare')+'    ·    Infisical: '+
                             (self.var('infisical_host').get() or 'da configurare')+'\nBackup: '+
                             (self.var('dr_tag').get() or 'da selezionare'))

    def _move(self, direction):
        self.book.select(max(0, min(4, self.book.index(self.book.select())+direction)))

    def _wheel(self, event):
        if isinstance(event.widget, (ttk.Entry, ttk.Combobox, tk.Text)):
            return
        page = self.pages[self.book.index(self.book.select())]
        if page.content.winfo_reqheight() > page.canvas.winfo_height():
            page.canvas.yview_scroll(-int(event.delta/120), 'units')

    def card(self, parent, title, hint=''):
        outer = ttk.Frame(parent, style='Card.TFrame', padding=16)
        outer.pack(fill='x', pady=(0, 12))
        ttk.Label(outer, text=title, style='CardTitle.TLabel').pack(anchor='w')
        if hint:
            ttk.Label(outer, text=hint, style='CardHint.TLabel', wraplength=760).pack(anchor='w', pady=(5, 0))
        body = ttk.Frame(outer)
        body.pack(fill='x', pady=(10, 0))
        return body

    def var(self, key, default=''):
        if key not in self.vars:
            self.vars[key] = tk.StringVar(value=default)
        return self.vars[key]

    def entry(self, parent, label, key, row, default='', secret=False, browse=False, column=0, span=1):
        block = ttk.Frame(parent)
        block.grid(row=row, column=column, columnspan=span, sticky='ew', padx=(0, 12), pady=(0, 10))
        ttk.Label(block, text=label, style='Field.TLabel').pack(anchor='w', pady=(0, 5))
        field = ttk.Frame(block)
        field.pack(fill='x')
        entry = ttk.Entry(field, textvariable=self.var(key, default), show='•' if secret else '', width=20)
        entry.pack(side='left', fill='x', expand=True)
        if browse:
            ttk.Button(field, text='Sfoglia…', command=lambda:self.select_file(key)).pack(side='right', padx=(8, 0))
        parent.columnconfigure(column, weight=1)
        return entry

    def _connections(self, tab):
        vm = self.card(tab, 'La nuova VM stack', 'Ubuntu 26.04 o 24.04 amd64 · utente UID/GID 1000 · SSH e sudo')
        self.entry(vm, 'Host / IP SSH', 'host', 0)
        self.entry(vm, 'Utente', 'user', 0, default='pi', column=1)
        self.entry(vm, 'Porta', 'port', 0, default='22', column=2)
        self.entry(vm, 'Password SSH', 'password', 1, secret=True)
        self.entry(vm, 'Chiave SSH (in alternativa)', 'ssh_key', 1, browse=True, column=1, span=2)
        git = self.card(tab, 'GitHub e punto di recupero', 'Token fine-grained · Contents: Read per streams-aio-dr e streams-aio-sanitized')
        self.entry(git, 'Token GitHub', 'github_token', 0, secret=True, span=2)
        ttk.Button(git, text='Carica release da GitHub', command=self.load_choices).grid(row=0, column=2, sticky='es', pady=(0, 12))
        release = ttk.Frame(git)
        release.grid(row=1, column=0, sticky='ew', padx=(0, 12), pady=(0, 12))
        ttk.Label(release, text='Release DR pubblicata', style='Field.TLabel').pack(anchor='w', pady=(0, 5))
        self.tags = ttk.Combobox(release, textvariable=self.var('dr_tag'), state='readonly', width=23)
        self.tags.pack(fill='x')
        self.entry(git, 'Commit dello stack', 'public_commit', 1, column=1, span=2)
        ttk.Label(tab, text='Scegli release e commit coerenti: i due repository vengono aggiornati separatamente.',
                  style='Muted.TLabel', wraplength=790).pack(anchor='w', pady=2)

    def _backups(self, tab):
        age = self.card(tab, 'La chiave del tuo backup', 'Usa la identity privata PRIMARY o RECOVERY custodita fuori da Git.')
        self.entry(age, 'Chiave age PRIMARY o RECOVERY', 'age_identity', 0, browse=True)
        aio = self.card(tab, 'Le configurazioni AIO', 'Gli export JSON non sono inclusi nelle release DR automatiche.')
        for index, (key, title) in enumerate((('aiostreams_exports', 'AIOStreams · 2.35.3'),
                                             ('aiometadata_exports', 'AIOMetadata · 3.3.0'))):
            box = ttk.Frame(aio, style='Card.TFrame', padding=14)
            box.grid(row=0, column=index, sticky='nsew', padx=(0, 12))
            aio.columnconfigure(index, weight=1)
            ttk.Label(box, text=title, font=('Segoe UI', 11, 'bold')).pack(anchor='w')
            ttk.Label(box, textvariable=self.var(key, 'Nessun file selezionato'), style='CardHint.TLabel').pack(anchor='w', pady=10)
            ttk.Button(box, text='Scegli JSON…', command=lambda k=key:self.select_many(k)).pack(anchor='w')
        payload = self.card(tab, 'Hai già un payload completo?', 'In alternativa ai due gruppi di export, seleziona il PRIVATE_DR_PAYLOAD.')
        self.entry(payload, 'PRIVATE_DR_PAYLOAD (alternativa)', 'aio_payload', 0, browse=True)
        ttk.Label(tab, text='Per più profili, gli export devono corrispondere ai binding presenti in Infisical.',
                  style='Muted.TLabel', wraplength=790).pack(anchor='w')

    def _infisical(self, tab):
        vm = self.card(tab, 'La nuova VM Infisical', 'Una seconda VM Ubuntu 26.04 o 24.04 amd64. Le chiavi applicative arrivano dal backup.')
        self.entry(vm, 'Host / IP SSH', 'infisical_host', 0)
        self.entry(vm, 'Utente', 'infisical_user', 0, default='infiscal', column=1)
        self.entry(vm, 'Porta SSH', 'infisical_port', 0, default='22', column=2)
        self.entry(vm, 'Password SSH', 'infisical_password', 1, secret=True)
        self.entry(vm, 'Chiave SSH (in alternativa)', 'infisical_key', 1, browse=True, column=1, span=2)
        self.entry(vm, 'Passphrase chiave SSH', 'infisical_key_password', 2, secret=True)
        self.entry(vm, 'Password sudo (se diversa)', 'infisical_sudo_password', 2, secret=True, column=1, span=2)
        info = self.card(tab, 'I tuoi segreti, sul server recuperato')
        ttk.Label(info, text='Infisical v0.165.16  ·  PostgreSQL 14.24  ·  Redis', font=('Segoe UI', 11, 'bold')).pack(anchor='w')
        ttk.Label(info, text='Database, chiavi e Universal Auth vengono recuperati dalla release cifrata.\n'
                  'Il collegamento tra le VM passa da SSH e prosegue anche senza Windows.',
                  style='CardHint.TLabel', wraplength=760, justify='left').pack(anchor='w', pady=(10, 4))

    def _advanced(self, tab):
        access = self.card(tab, 'Accesso alla VM stack', 'Compila soltanto se sudo usa una password diversa o la chiave SSH ha una passphrase.')
        self.entry(access, 'Password sudo (se diversa)', 'sudo_password', 0, secret=True)
        self.entry(access, 'Passphrase chiave SSH', 'key_password', 0, secret=True, column=1)
        advanced = self.card(tab, 'Infisical già disponibile? Opzioni avanzate',
                             'Per il recupero delle due VM lascia questi campi vuoti: useremo il backup Agent.')
        self.entry(advanced, 'Endpoint HTTPS Infisical', 'infisical_address', 0, span=2)
        self.entry(advanced, 'Project ID (opzionale)', 'project_id', 1)
        self.entry(advanced, 'Ambiente (opzionale)', 'environment', 1, column=1)
        self.entry(advanced, 'File Universal Auth client-id', 'client_id_file', 2, browse=True)
        self.entry(advanced, 'File Universal Auth client-secret', 'client_secret_file', 2, browse=True, column=1)

    def _run(self, tab):
        self.lab = tk.BooleanVar(value=False)
        self.tls = tk.BooleanVar(value=False)
        self.native_agent = tk.BooleanVar(value=True)
        self.summary = tk.StringVar()
        action = self.card(tab, 'Rivedi e avvia')
        ttk.Label(action, textvariable=self.summary, style='CardHint.TLabel', wraplength=760).pack(anchor='w', pady=(0, 10))
        ttk.Checkbutton(action, text='Confermo che le VM selezionate sono nuove e destinate a questa prova.',
                        variable=self.lab).pack(anchor='w', pady=(0, 6))
        ttk.Checkbutton(action, text='Installa l’Agent continuo e il tunnel SSH permanente tra le VM.',
                        variable=self.native_agent).pack(anchor='w', pady=(0, 6))
        ttk.Checkbutton(action, text='Riemetti TLS e verifica HTTPS NPM (Cloudflare/ACME reali).',
                        variable=self.tls).pack(anchor='w', pady=(0, 8))
        actions = ttk.Frame(action)
        actions.pack(fill='x')
        self.buttons = []
        for text, fn, style in [('Verifica', self.verify, 'TButton'),
                                ('Ripristina entrambe le VM', self.one_click, 'Accent.TButton')]:
            button = ttk.Button(actions, text=text, command=fn, style=style)
            button.pack(side='left', padx=(0, 10))
            self.buttons.append(button)
        self.phase_labels = {}
        phases = ttk.Frame(tab, style='Page.TFrame')
        phases.pack(fill='x', pady=(0, 8))
        for index, name in enumerate(('Infisical', 'Stack', 'Agent', 'Servizi')):
            phases.columnconfigure(index, weight=1)
            box = ttk.Frame(phases, style='Card.TFrame', padding=(12, 10))
            box.grid(row=0, column=index, sticky='nsew', padx=(0, 8))
            ttk.Label(box, text=name, font=('Segoe UI', 9, 'bold')).pack(anchor='w')
            label = ttk.Label(box, text='Da avviare', style='CardHint.TLabel')
            label.pack(anchor='w', pady=(3, 0))
            self.phase_labels[name] = label
        self.progress = ttk.Progressbar(tab, mode='indeterminate')
        self.progress.pack(fill='x', pady=(0, 8))
        log_card = ttk.Frame(tab, style='Card.TFrame', padding=12)
        log_card.pack(fill='x')
        toolbar = ttk.Frame(log_card)
        toolbar.pack(fill='x')
        ttk.Label(toolbar, text='Attività del ripristino', style='CardTitle.TLabel').pack(side='left')
        save = ttk.Button(toolbar, text='Salva esiti', command=self.save_report)
        save.pack(side='right')
        self.buttons.append(save)
        self.log = tk.Text(log_card, height=4, bg='#f8faff', fg='#526178', relief='flat',
                           font=('Consolas', 9), padx=12, pady=8, wrap='word', state='disabled')
        self.log.pack(fill='x', pady=(10, 0))
        self.log.tag_configure('ok', foreground='#148569')
        self.log.tag_configure('error', foreground='#bf4250')
        self.write_log('Nessuna operazione avviata. Gli esiti compariranno qui.')
        separate = ttk.Frame(tab, style='Page.TFrame')
        separate.pack(fill='x', pady=(8, 4))
        for text, fn in [('Prepara stack', self.prepare), ('Avvia servizi', self.start_services)]:
            button = ttk.Button(separate, text=text, command=fn)
            button.pack(side='left', padx=(0, 8))
            self.buttons.append(button)
        self.cancel_button = ttk.Button(separate, text='Interrompi', command=lambda:self.cancelled.set(), state='disabled')
        self.cancel_button.pack(side='right')
        ttk.Label(tab, text='Dopo l’avvio verifica login, enrollment e HTTPS. I timer di pubblicazione restano disattivati.',
                  style='Muted.TLabel', wraplength=790).pack(anchor='w', pady=(4, 0))

    def phase_event(self, stage, status):
        name = ('Infisical' if stage.startswith('INFISICAL_') else 'Agent' if stage=='NATIVE_AGENT'
                else 'Servizi' if stage in ('STARTED', 'TLS') else 'Stack' if stage in
                ('INITIALIZE', 'INPUTS', 'RENDER', 'EMPTY_STATE', 'NPM', 'AIO', 'PREFLIGHT', 'PREPARED') else None)
        if stage == 'REFUSED':
            name = self.active_phase
        if name:
            self.active_phase = name
            done = stage in ('INFISICAL_SERVER', 'PREPARED', 'NATIVE_AGENT', 'STARTED', 'TLS') and status=='PASS'
            label = 'Fermato' if status=='REFUSED' else 'Completato' if done else 'In corso'
            color = '#bf4250' if status=='REFUSED' else '#148569' if done else '#4963db'
            self.phase_labels[name].configure(text=label, foreground=color)


    def select_file(self, key):
        path = filedialog.askopenfilename(title='Seleziona il file privato', parent=self)
        if path:
            self.var(key).set(path)

    def select_many(self, key):
        paths = filedialog.askopenfilenames(title='Seleziona gli export logici JSON', parent=self,
                                           filetypes=[('JSON', '*.json'), ('Tutti i file', '*')])
        if paths:
            self.files[key] = list(paths)
            self.var(key).set(f'{len(paths)} file selezionati')

    def snapshot(self):
        return {key: variable.get().strip() if key not in ('password', 'sudo_password', 'key_password', 'infisical_password',
                                                         'infisical_key_password', 'infisical_sudo_password')
                else variable.get() for key, variable in self.vars.items()}

    @staticmethod
    def host(data):
        try:
            return Host(data['host'], data['user'], int(data['port']), data['password'],
                        data['ssh_key'], data['key_password'], data['sudo_password'])
        except ValueError:
            raise Failure('SSH_ADDRESS_REQUIRED') from None

    @staticmethod
    def infisical_host(data):
        try:
            return Host(data['infisical_host'], data['infisical_user'], int(data['infisical_port']),
                        data['infisical_password'], data['infisical_key'], data['infisical_key_password'],
                        data['infisical_sudo_password'])
        except ValueError:
            raise Failure('SSH_ADDRESS_REQUIRED') from None

    def key_dialog(self, host, fingerprint):
        done = threading.Event()
        answer = []
        self.events.put(('key', (host, fingerprint, done, answer)))
        while not done.wait(0.1):
            if self.cancelled.is_set():
                return False
        return bool(answer and answer[0])

    def job(self, action, return_page=None):
        if self.busy:
            return
        self.busy = True
        self.return_page = return_page
        self.cancelled.clear()
        self.book.select(4)
        self.progress.start(15)
        self.cancel_button.configure(state='normal')
        for button in self.buttons:
            button.configure(state='disabled')
        self.status.set('Operazione in corso. Le credenziali non vengono registrate.')
        def worker():
            try:
                action()
            except Failure as error:
                code = str(error)
                self.events.put(('error', code if code in ERROR_CODES else 'OPERATION_STOPPED'))
            except Exception:
                self.events.put(('error', 'OPERATION_STOPPED'))
            finally:
                self.events.put(('done', None))
        threading.Thread(target=worker, daemon=True).start()

    def load_choices(self):
        token = self.var('github_token').get()
        def action():
            self.events.put(('choices', GitHub(token).choices()))
        self.job(action, return_page=0)

    def verify(self):
        data = self.snapshot()
        def action():
            tags, commit = GitHub(data['github_token']).choices()
            ssh = SSH(self.host(data), self.key_dialog, self.cancelled)
            try:
                info = ssh.check()
                self.events.put(('message', 'VM stack verificata: ' + info['os'] + ' amd64; nessun container o volume esistente.'))
                self.events.put(('choices', (tags, data.get('public_commit') or commit)))
            finally:
                ssh.close()
            if data.get('infisical_host'):
                host = self.infisical_host(data)
                other = SSH(host, self.key_dialog, self.cancelled)
                try:
                    other.check(role='infisical')
                    self.events.put(('message', 'Nuova destinazione Infisical verificata. Nessun servizio modificato.'))
                finally:
                    other.close()
        self.job(action)

    def one_click(self):
        data = self.snapshot()
        try:
            self.host(data).validate()
            self.infisical_host(data).validate()
            require(self.lab.get(), 'FRESH_VM_CONFIRMATION_REQUIRED')
            require(bool(SHA.fullmatch(data['public_commit'])) and bool(TAG.fullmatch(data['dr_tag'])), 'SELECT_GITHUB_RECOVERY_POINT')
            require(Path(data['age_identity']).is_file(), 'AGE_IDENTITY_FILE_REQUIRED')
            require(bool(data.get('aio_payload') or (self.files['aiostreams_exports'] and self.files['aiometadata_exports'])),
                    'AIO_EXPORTS_OR_PAYLOAD_REQUIRED')
            require(bool(data['client_id_file']) == bool(data['client_secret_file']), 'BOTH_UNIVERSAL_AUTH_FILES_REQUIRED')
        except Failure as error:
            messagebox.showinfo('Completa gli input', str(error), parent=self)
            return
        summary = ('Nuovo stack: ' + data['host'] + '\nNuovo Infisical: ' + data['infisical_host']
                   + '\nRelease: ' + data['dr_tag'] + '\nCommit: ' + data['public_commit'][:12]
                   + '\n\nInstallerà Docker su entrambe le VM e ripristinerà Infisical in /opt/infisical.\n'
                   'Poi leggerà i segreti recuperati, preparerà lo stack e avvierà i servizi.\n'
                   'Chiave age ed export resteranno in storage privato sulle nuove VM.\n'
                   'DNS, timer, DDNS, Watchtower ed enrollment richiedono il collaudo successivo.\n'
                   + ('Installerà anche l’Agent e una chiave SSH dedicata, limitata all’API Infisical.'
                      if self.native_agent.get() else 'Agent continuo escluso da questa prova.'))
        if not messagebox.askokcancel('Ripristina le due VM nuove', summary, parent=self):
            return
        data.update({k:list(v) for k,v in self.files.items()})
        data['native_agent']=self.native_agent.get()
        tls = self.tls.get()
        def action():
            stack = SSH(self.host(data), self.key_dialog, self.cancelled)
            server = None
            try:
                server = SSH(self.infisical_host(data), self.key_dialog, self.cancelled)
                restore_all(stack, server, data, lambda item:self.events.put(('stage',item)), tls)
                self.events.put(('message','Infisical recuperato, segreti letti dalla nuova VM e stack avviato. Ora verifica gli accessi applicativi.'))
            finally:
                stack.close()
                if server is not None:
                    server.close()
        self.job(action)

    def prepare(self):
        data = self.snapshot()
        try:
            self.host(data).validate()
            require(self.lab.get(), 'FRESH_VM_CONFIRMATION_REQUIRED')
            require(bool(SHA.fullmatch(data['public_commit'])) and bool(TAG.fullmatch(data['dr_tag'])), 'SELECT_GITHUB_RECOVERY_POINT')
            require(Path(data['age_identity']).is_file(), 'AGE_IDENTITY_FILE_REQUIRED')
            require(bool(data.get('aio_payload') or (self.files['aiostreams_exports'] and self.files['aiometadata_exports'])),
                    'AIO_EXPORTS_OR_PAYLOAD_REQUIRED')
            require(bool(data['client_id_file']) == bool(data['client_secret_file']), 'BOTH_UNIVERSAL_AUTH_FILES_REQUIRED')
        except Failure as error:
            messagebox.showinfo('Completa gli input', str(error), parent=self)
            return
        summary = ('VM: ' + data['user'] + '@' + data['host'] + '\n'
                   'Release: ' + data['dr_tag'] + '\nCommit: ' + data['public_commit'][:12] + '\n\n'
                   'Installerà Docker e dipendenze e preparerà ~/streams-aio.\n'
                   'Trasferirà la chiave age e gli export via SSH in una cartella privata.\n'
                   'Non avvierà container né installerà timer. Infisical deve già essere raggiungibile.')
        if not messagebox.askokcancel('Prepara questa VM', summary, parent=self):
            return
        data.update({k: list(v) for k, v in self.files.items()})
        def action():
            ssh = SSH(self.host(data), self.key_dialog, self.cancelled)
            try:
                ssh.prepare(data, lambda item: self.events.put(('stage', item)))
            finally:
                ssh.close()
        self.job(action)

    def start_services(self):
        data, tls = self.snapshot(), self.tls.get()
        if not self.lab.get():
            messagebox.showinfo('Seleziona la VM di prova', 'Conferma la destinazione nella scheda Ripristino.', parent=self)
            return
        if not messagebox.askokcancel('Avvia sulla VM nuova',
                'Avvio per dipendenze su ' + data['host'] + '.\nWatchtower, DDNS e deunhealth restano esclusi.\n'
                + ('Richiederà certificati reali Cloudflare/ACME.\n' if tls else '')
                + 'La verifica backend richiede un ripristino preparato su questa stessa VM.', parent=self):
            return
        def action():
            ssh = SSH(self.host(data), self.key_dialog, self.cancelled)
            try:
                ssh.start(tls, lambda item: self.events.put(('stage', item)))
            finally:
                ssh.close()
        self.job(action)

    def write_log(self, text, tag=None):
        self.log.configure(state='normal')
        self.log.insert('end', text + '\n', tag)
        self.log.see('end')
        self.log.configure(state='disabled')

    def poll(self):
        while True:
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == 'key':
                host, fingerprint, done, answer = value
                answer.append(messagebox.askyesno('Verifica la VM SSH', 'Host: ' + host + '\n' + fingerprint
                    + '\n\nConfronta l’impronta con la console della VM. Riconosci questa chiave?', parent=self))
                done.set()
            elif kind == 'choices':
                tags, commit = value
                old = self.var('dr_tag').get()
                self.tags['values'] = tags
                if old not in tags:
                    self.var('dr_tag').set(tags[0])
                self.var('public_commit').set(commit)
                self.write_log('GitHub verificato. Release pubblicate caricate; controlla il punto scelto.', 'ok')
                self.status.set('GitHub pronto. Configura la VM e seleziona i backup.')
            elif kind == 'stage':
                self.safe_report.append(value)
                stage, status = value['stage'], value['status']
                self.phase_event(stage, status)
                self.write_log(TEXT[stage] + ' · ' + status + ((' · ' + value['code']) if value.get('code') else ''),
                               'error' if status == 'REFUSED' else ('ok' if status == 'PASS' else None))
                self.status.set(TEXT[stage] + ': ' + status)
                if stage == 'PREPARED' and status == 'PASS':
                    self.prepared = True
                    self.write_log('Ora puoi avviare i servizi. Il ripristino funzionale e l’Agent continuo sono ancora da verificare.')
                if stage == 'STARTED' and status == 'PASS':
                    self.write_log('Servizi avviati. Verifica login, enrollment e HTTPS; i timer restano disattivati.')
            elif kind == 'message':
                self.write_log(value, 'ok')
            elif kind == 'error':
                self.safe_report.append(dict(stage='REFUSED', status='REFUSED', code=value))
                self.phase_event('REFUSED', 'REFUSED')
                self.write_log(value + ' · ' + ERRORS.get(value, 'Procedura fermata; dati di recupero conservati.'), 'error')
                self.status.set('Procedura fermata: ' + value)
            elif kind == 'done':
                self.busy = False
                self.progress.stop()
                self.cancel_button.configure(state='disabled')
                for button in self.buttons:
                    button.configure(state='normal')
                if self.return_page is not None:
                    self.book.select(self.return_page)
                    self.return_page = None
        self.after(100, self.poll)

    def save_report(self):
        path = filedialog.asksaveasfilename(title='Salva gli esiti senza credenziali', defaultextension='.json', parent=self)
        if path:
            Path(path).write_text(json.dumps(dict(schema=1, events=self.safe_report,
                scope='SERVER_RESTORE_AND_STACK_START; FUNCTIONAL_DR_NOT_VERIFIED'), indent=2) + '\n', encoding='utf-8')

    def close_app(self):
        if self.busy and not messagebox.askokcancel('Operazione in corso',
                'Chiudere interrompe la connessione; non annulla quanto già fatto sulla VM. I dati vengono conservati.', parent=self):
            return
        self.cancelled.set()
        for key in ('password', 'github_token', 'sudo_password', 'key_password', 'infisical_password',
                    'infisical_key_password','infisical_sudo_password'):
            self.var(key).set('')
        self.destroy()


def main():
    App().mainloop()


if __name__ == '__main__':
    main()
