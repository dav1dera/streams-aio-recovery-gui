"""Compact Windows recovery dashboard with two guarded backend actions."""
import json
import ipaddress
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import webbrowser

from . import __version__, backend
from .backend import Failure, GitHub, Host, SHA, TAG, require
from .codes import ERROR_CODES
from .startup_diagnostic import lines as startup_diagnostic_lines
from .external_dependencies import lines as external_dependency_lines
from .ui_state import PHASES, phase_for, phase_status, machine_status, error_destination, operational_request
from .onboarding import ServiceController
from .ui_onboarding import ServiceOnboardingPanel


class ScrollPage(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style='Page.TFrame')
        self.canvas = tk.Canvas(self, bg='#f4f6fa', highlightthickness=0)
        scrollbar = ttk.Scrollbar(self, orient='vertical', command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        self.canvas.pack(side='left', fill='both', expand=True)
        self.content = ttk.Frame(self.canvas, style='Page.TFrame', padding=(0, 0, 14, 12))
        item = self.canvas.create_window(0, 0, anchor='nw', window=self.content)
        self.content.bind('<Configure>', lambda e: self.canvas.configure(scrollregion=self.canvas.bbox('all')))
        self.canvas.bind('<Configure>', lambda e: self.canvas.itemconfigure(item, width=e.width))


class App(tk.Tk):
    def __init__(self):
        # Import presentation text here to keep app.py's public helpers usable
        # without creating a module-import cycle.
        from .app import TEXT, ERRORS
        super().__init__()
        self.stage_text, self.errors = TEXT, ERRORS
        self.title('Streams AIO Recovery')
        self.geometry('1220x860')
        self.minsize(960, 720)
        self.configure(bg='#f4f6fa')
        self.events, self.cancelled = queue.Queue(), threading.Event()
        self.busy = False
        self.vars, self.files = {}, {}
        self.safe_report, self.buttons, self.controls = [], [], []
        self.return_page, self.active_phase, self.last_error = None, None, None
        self.backup_has_aio = None
        self.supplement_scope = None
        self.protocol('WM_DELETE_WINDOW', self.close_app)
        self._theme()
        self._variables()
        self._shell()
        self._dashboard(self.pages[0].content)
        self._setup(self.pages[1].content)
        self._advanced(self.pages[2].content)
        self.onboarding = ServiceOnboardingPanel(self.pages[3].content, self,
            ServiceController(self.key_dialog, confirm_changed_key=self.changed_key_dialog,
                              cancelled=self.cancelled))
        self.onboarding.pack(fill='both', expand=True)
        self.book.bind('<<NotebookTabChanged>>', self._page_changed)
        self.bind_all('<MouseWheel>', self._wheel, add='+')
        self._page_changed()
        self.after(100, self.poll)

    def _variables(self):
        defaults = {'user': 'test', 'port': '22', 'infisical_user': 'test2',
                    'infisical_port': '22', 'routing_mode': 'parallel_test'}
        keys = ('host', 'user', 'port', 'password', 'ssh_key', 'key_password', 'sudo_password',
                'infisical_host', 'infisical_user', 'infisical_port', 'infisical_password',
                'infisical_key', 'infisical_key_password', 'infisical_sudo_password',
                'github_token', 'dr_tag', 'public_commit', 'age_identity', 'supplemental_inputs',
                'infisical_address', 'project_id', 'environment', 'client_id_file',
                'client_secret_file', 'domain_target_address', 'routing_mode')
        for key in keys:
            self.var(key, defaults.get(key, ''))
        self.routing_label = tk.StringVar(value='Prova affiancata alle VM operative')
        self.status = tk.StringVar(value='Configura gli accessi, poi scegli come iniziare.')
        self.hero_status = tk.StringVar(value='Il tuo stack, pronto a ripartire.')
        self.hero_detail = tk.StringVar(value='Infisical, configurazioni AIO, NPM, domini e servizi in un unico percorso.')
        self.infrastructure_verified = False
        self.external_unavailable = 0
        self.summary = tk.StringVar(value='Nessun punto di recupero selezionato')
        self.phase_detail = tk.StringVar(value='I controlli iniziano quando scegli un’azione.')
        self.failure_title, self.failure_detail = tk.StringVar(), tk.StringVar()
        self.connection_labels, self.phase_labels = {}, {}

    def _theme(self):
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('.', font=('Segoe UI', 10), background='#ffffff', foreground='#17263c')
        style.configure('Page.TFrame', background='#f4f6fa')
        style.configure('Card.TFrame', background='#ffffff', borderwidth=1, relief='solid', bordercolor='#e3e9f2')
        style.configure('Hero.TFrame', background='#172845')
        style.configure('HeroTitle.TLabel', background='#172845', foreground='#ffffff', font=('Segoe UI', 24, 'bold'))
        style.configure('HeroBody.TLabel', background='#172845', foreground='#b9c9df')
        style.configure('Title.TLabel', background='#f4f6fa', font=('Segoe UI', 23, 'bold'))
        style.configure('Muted.TLabel', background='#f4f6fa', foreground='#64748b')
        style.configure('Eyebrow.TLabel', background='#f4f6fa', foreground='#5563df', font=('Segoe UI', 9, 'bold'))
        style.configure('CardTitle.TLabel', font=('Segoe UI', 12, 'bold'))
        style.configure('CardHint.TLabel', foreground='#64748b', font=('Segoe UI', 9))
        style.configure('Field.TLabel', foreground='#52647d', font=('Segoe UI', 9))
        style.configure('TEntry', padding=(10, 9), fieldbackground='#f8fafd', bordercolor='#dce4ee',
                        lightcolor='#dce4ee', darkcolor='#dce4ee', insertcolor='#17263c')
        style.map('TEntry', bordercolor=[('focus', '#626ee9')])
        style.configure('TCombobox', padding=(8, 9), fieldbackground='#f8fafd', bordercolor='#dce4ee', arrowcolor='#52647d')
        style.map('TCombobox', fieldbackground=[('readonly', '#f8fafd')], foreground=[('readonly', '#17263c')])
        style.configure('TButton', padding=(15, 10), relief='flat', background='#ffffff', foreground='#34465e', borderwidth=1, bordercolor='#dce4ee')
        style.map('TButton', background=[('active', '#edf1f8'), ('disabled', '#f1f4f8')], foreground=[('disabled', '#97a5b8')])
        style.configure('Accent.TButton', background='#5563df', foreground='#ffffff', borderwidth=0,
                        font=('Segoe UI', 11, 'bold'), padding=(22, 14))
        style.map('Accent.TButton', background=[('active', '#4553c8'), ('disabled', '#bbc3ed')], foreground=[('disabled', '#ffffff')])
        style.configure('Secondary.TButton', font=('Segoe UI', 11, 'bold'), padding=(22, 14), foreground='#4553c8')
        style.configure('Link.TButton', padding=(6, 4), background='#f4f6fa', foreground='#5563df', borderwidth=0)
        style.configure('Error.TFrame', background='#fff4f2', bordercolor='#f0cbc6', relief='solid', borderwidth=1)
        style.configure('ErrorTitle.TLabel', background='#fff4f2', foreground='#9d3d39', font=('Segoe UI', 11, 'bold'))
        style.configure('ErrorBody.TLabel', background='#fff4f2', foreground='#815550', font=('Segoe UI', 9))
        style.configure('Horizontal.TProgressbar', background='#5563df', troughcolor='#e5eaf3', thickness=5, borderwidth=0)
        style.configure('Dashboard.TNotebook', background='#f4f6fa', borderwidth=0, padding=0)
        style.layout('Dashboard.TNotebook.Tab', [])

    def _shell(self):
        side = tk.Frame(self, bg='#111f35', width=190)
        side.pack(side='left', fill='y')
        side.pack_propagate(False)
        mark = tk.Canvas(side, width=44, height=44, bg='#111f35', highlightthickness=0)
        mark.pack(anchor='w', padx=23, pady=(29, 14))
        mark.create_oval(2, 2, 42, 42, fill='#6977f4', outline='')
        mark.create_line(14, 25, 22, 17, 30, 25, fill='white', width=3)
        mark.create_line(22, 18, 22, 32, fill='white', width=3)
        tk.Label(side, text='STREAMS AIO', bg='#111f35', fg='#ffffff', font=('Segoe UI', 11, 'bold')).pack(anchor='w', padx=23)
        tk.Label(side, text='Recovery', bg='#111f35', fg='#879bb8', font=('Segoe UI', 10)).pack(anchor='w', padx=23, pady=(4, 32))
        self.titles = ['Panoramica', 'Accessi e backup', 'Opzioni avanzate', 'Aggiungi servizio']
        self.descriptions = ['Scegli il percorso. Ogni passaggio viene verificato e conservato.',
                             'Inserisci le destinazioni e scegli un backup. Password e token restano in memoria.',
                             'Porte SSH e password sudo, soltanto se diverse dagli accessi principali.',
                             'Prepara un servizio, collega i segreti e verifica avvio, GitHub e backup. Anteprima 0.5.']
        self.nav = []
        for index, text in enumerate(self.titles):
            button = tk.Button(side, text=text, anchor='w', padx=16, pady=12, relief='flat', bd=0,
                               bg='#111f35', fg='#a2b1c7', activebackground='#243755', activeforeground='#ffffff',
                               font=('Segoe UI', 10), cursor='hand2', command=lambda i=index: self.book.select(i))
            button.pack(fill='x', padx=10, pady=3)
            self.nav.append(button)
            self.controls.append(button)
        tk.Label(side, text=f'v{__version__} · Windows', bg='#111f35', fg='#879bb8', font=('Segoe UI', 8)).pack(side='bottom', anchor='w', padx=23, pady=22)
        tk.Label(side, text='Dati privati cifrati.\nRipresa dal punto verificato.', bg='#111f35', fg='#879bb8', justify='left', font=('Segoe UI', 9)).pack(side='bottom', anchor='w', padx=23, pady=12)
        workspace = ttk.Frame(self, style='Page.TFrame', padding=(28, 23, 18, 14))
        workspace.pack(side='left', fill='both', expand=True)
        top = ttk.Frame(workspace, style='Page.TFrame')
        top.pack(fill='x')
        ttk.Label(top, text='DISASTER RECOVERY', style='Eyebrow.TLabel').pack(side='left')
        ttk.Button(top, text='Guida ↗', style='Link.TButton', command=lambda: webbrowser.open('https://github.com/dav1dera/streams-aio-recovery-gui/blob/main/README.md')).pack(side='right')
        self.page_title, self.page_description = tk.StringVar(), tk.StringVar()
        ttk.Label(workspace, textvariable=self.page_title, style='Title.TLabel').pack(anchor='w', pady=(13, 4))
        ttk.Label(workspace, textvariable=self.page_description, style='Muted.TLabel', wraplength=900).pack(anchor='w', pady=(0, 18))
        self.book = ttk.Notebook(workspace, style='Dashboard.TNotebook')
        self.book.pack(fill='both', expand=True)
        self.pages = [ScrollPage(self.book) for _ in self.titles]
        for page, title in zip(self.pages, self.titles):
            self.book.add(page, text=title)
        footer = ttk.Frame(workspace, style='Page.TFrame', padding=(0, 9, 0, 0))
        footer.pack(fill='x')
        ttk.Label(footer, textvariable=self.status, style='Muted.TLabel', wraplength=830, font=('Segoe UI', 9)).pack(side='left')

    def card(self, parent, title, hint=''):
        outer = ttk.Frame(parent, style='Card.TFrame', padding=18)
        outer.pack(fill='x', pady=(0, 14))
        ttk.Label(outer, text=title, style='CardTitle.TLabel').pack(anchor='w')
        if hint:
            ttk.Label(outer, text=hint, style='CardHint.TLabel', wraplength=820).pack(anchor='w', pady=(5, 0))
        body = ttk.Frame(outer)
        body.pack(fill='x', pady=(12, 0))
        return body

    def _dashboard(self, tab):
        hero = ttk.Frame(tab, style='Hero.TFrame', padding=24)
        hero.pack(fill='x', pady=(0, 16))
        ttk.Label(hero, textvariable=self.hero_status, style='HeroTitle.TLabel', wraplength=850).pack(anchor='w')
        ttk.Label(hero, textvariable=self.hero_detail, style='HeroBody.TLabel', wraplength=850).pack(anchor='w', pady=(8, 0))
        row = ttk.Frame(tab, style='Page.TFrame')
        row.pack(fill='x', pady=(0, 14))
        for index, (role, label) in enumerate((('stack', 'VM STACK'), ('infisical', 'VM INFISICAL'))):
            row.columnconfigure(index, weight=1, uniform='machines')
            box = ttk.Frame(row, style='Card.TFrame', padding=17)
            box.grid(row=0, column=index, sticky='nsew', padx=(0, 10 if index == 0 else 0))
            ttk.Label(box, text=label, style='Field.TLabel').pack(anchor='w')
            title = ttk.Label(box, text='Da configurare', font=('Segoe UI', 13, 'bold'))
            title.pack(anchor='w', pady=(7, 4))
            subtitle = ttk.Label(box, text='Accesso SSH necessario', style='CardHint.TLabel')
            subtitle.pack(anchor='w')
            self.connection_labels[role] = (title, subtitle)
        self.domain_card = self._domain_settings(tab)
        actions = self.card(tab, 'Un’azione per iniziare, una per riprendere')
        ttk.Label(actions, textvariable=self.summary, style='CardHint.TLabel', wraplength=820).pack(anchor='w', pady=(0, 12))
        row = ttk.Frame(actions)
        row.pack(fill='x')
        for label, command, style in [('Crea da zero', lambda: self.recover('fresh'), 'Accent.TButton'),
                                      ('Rileva e continua', lambda: self.recover('resume'), 'Secondary.TButton')]:
            button = ttk.Button(row, text=label, command=command, style=style)
            button.pack(side='left', padx=(0, 12))
            self.buttons.append(button)
        button = ttk.Button(row, text='Configura accessi', command=lambda: self.book.select(1))
        button.pack(side='right')
        self.buttons.append(button)
        ttk.Label(actions, text='Crea: usa VM vuote. Continua: riconosce il recupero e completa i passaggi mancanti.',
                  style='CardHint.TLabel', wraplength=820).pack(anchor='w', pady=(12, 0))
        self.failure_box = ttk.Frame(tab, style='Error.TFrame', padding=16)
        ttk.Label(self.failure_box, textvariable=self.failure_title, style='ErrorTitle.TLabel').pack(anchor='w')
        ttk.Label(self.failure_box, textvariable=self.failure_detail, style='ErrorBody.TLabel', wraplength=820).pack(anchor='w', pady=(6, 10))
        self.error_action = ttk.Button(self.failure_box, text='Controlla la configurazione', command=self.open_error_destination)
        self.error_action.pack(anchor='w')
        self.buttons.append(self.error_action)
        progress = self.card(tab, 'Avanzamento', 'Una fase è verificata soltanto dopo il relativo controllo.')
        self.progress_card = progress.master
        phases = ttk.Frame(progress)
        phases.pack(fill='x')
        for index, name in enumerate(PHASES):
            phases.columnconfigure(index, weight=1, uniform='phases')
            box = ttk.Frame(phases)
            box.grid(row=0, column=index, sticky='ew', padx=(0, 8))
            ttk.Label(box, text=name, font=('Segoe UI', 9, 'bold')).pack(anchor='w')
            state = ttk.Label(box, text='In attesa', style='CardHint.TLabel')
            state.pack(anchor='w', pady=(5, 0))
            self.phase_labels[name] = state
        self.progress = ttk.Progressbar(progress, mode='indeterminate')
        self.progress.pack(fill='x', pady=(16, 9))
        ttk.Label(progress, textvariable=self.phase_detail, style='CardHint.TLabel', wraplength=820).pack(anchor='w')
        activity = self.card(tab, 'Attività recente')
        toolbar = ttk.Frame(activity)
        toolbar.pack(fill='x')
        save = ttk.Button(toolbar, text='Salva esiti', command=self.save_report)
        save.pack(side='left')
        self.buttons.append(save)
        self.cancel_button = ttk.Button(toolbar, text='Interrompi', command=self.cancelled.set, state='disabled')
        self.cancel_button.pack(side='right')
        self.log = tk.Text(activity, height=7, bg='#f8fafd', fg='#52647d', relief='flat',
                           font=('Segoe UI', 9), padx=12, pady=10, wrap='word', state='disabled')
        self.log.pack(fill='x', pady=(10, 0))
        self.log.tag_configure('ok', foreground='#1e8069')
        self.log.tag_configure('error', foreground='#a6413c')
        self.write_log('Pronto. Nessuna operazione avviata.')

    def _setup(self, tab):
        for prefix, title in (('', 'VM dello stack'), ('infisical_', 'VM Infisical')):
            card = self.card(tab, title, 'Ubuntu Server 26.04 o 24.04 amd64 · SSH e sudo · utente UID/GID 1000')
            self.entry(card, 'Indirizzo IP o nome host', prefix + 'host', 0)
            self.entry(card, 'Utente SSH', prefix + 'user', 0, column=1)
            self.entry(card, 'Password dell’utente SSH', prefix + 'password', 1, secret=True)
            self.entry(card, 'Chiave SSH (alternativa alla password)', 'infisical_key' if prefix else 'ssh_key', 1, browse=True, column=1)
        git = self.card(tab, 'Punto di recupero', 'Token GitHub con Contents: Read per streams-aio-dr e streams-aio-sanitized.')
        self.entry(git, 'Token GitHub', 'github_token', 0, secret=True, span=2)
        button = ttk.Button(git, text='Carica backup', command=self.load_choices)
        button.grid(row=0, column=2, sticky='es', pady=(0, 12))
        self.buttons.append(button)
        release = ttk.Frame(git)
        release.grid(row=1, column=0, sticky='ew', padx=(0, 12), pady=(0, 12))
        ttk.Label(release, text='Backup pubblicato', style='Field.TLabel').pack(anchor='w', pady=(0, 5))
        self.tags = ttk.Combobox(release, textvariable=self.var('dr_tag'), state='readonly', width=23)
        self.tags.pack(fill='x')
        self.tags.bind('<<ComboboxSelected>>', self.load_point)
        self.controls.append(self.tags)
        self.entry(git, 'Commit associato al backup', 'public_commit', 1, column=1, span=2)
        self.entry(git, 'File della chiave privata age PRIMARY o RECOVERY', 'age_identity', 2, browse=True, span=3)
        ttk.Label(git, text='La chiave privata inizia con AGE-SECRET-KEY-1. I codici age1… sono chiavi pubbliche.',
                  style='CardHint.TLabel', wraplength=820).grid(row=3, column=0, columnspan=3, sticky='w')
        self._domain_settings(tab)
        button = ttk.Button(tab, text='Torna alla panoramica', style='Accent.TButton', command=lambda: self.book.select(0))
        button.pack(anchor='e', pady=(3, 0))
        self.buttons.append(button)

    def _domain_settings(self, tab):
        mode = self.card(tab, 'Domini e controller prima dell’avvio',
                         'Scegli la destinazione prima di creare o riprendere lo stack.')
        ttk.Label(mode, text='Destinazione del recupero', style='Field.TLabel').pack(anchor='w', pady=(0, 5))
        routing = ttk.Combobox(mode, state='readonly', textvariable=self.routing_label, values=(
            'Prova affiancata alle VM operative', 'Recupero della produzione'))
        routing.pack(fill='x')
        routing.bind('<<ComboboxSelected>>', self._routing_changed)
        self.controls.append(routing)
        domain_fields = ttk.Frame(mode)
        domain_fields.pack(fill='x', pady=(12, 0))
        self.entry(domain_fields, 'Indirizzo IP previsto per i domini', 'domain_target_address', 0)
        use_stack = ttk.Button(domain_fields, text='Usa IP della VM stack (LAN)', command=self._use_stack_domain_address)
        use_stack.grid(row=0, column=1, sticky='es', padx=(12, 0), pady=(0, 12))
        self.buttons.append(use_stack)
        ttk.Label(mode, text='NPM, HTTPS, Headscale/Tailscale e CometNet usano i domini del backup. Il programma controlla la destinazione prima della registrazione del nodo.',
                  style='CardHint.TLabel', wraplength=820).pack(anchor='w', pady=(10, 0))
        ttk.Label(mode, text='Indica l’IP LAN se i domini sono risolti nella rete locale, oppure l’IP pubblico previsto per l’instradamento esterno. Il DNS e le porte del router devono già raggiungere questa destinazione.',
                  style='CardHint.TLabel', wraplength=820).pack(anchor='w', pady=(7, 0))
        ttk.Label(mode, text='Questo campo non modifica il DNS. AIOStreams e AIOMetadata vengono recuperati automaticamente dal backup completo.',
                  style='CardHint.TLabel', wraplength=820).pack(anchor='w', pady=(7, 0))
        return mode

    def _use_stack_domain_address(self):
        value = self.var('host').get().strip()
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            self.show_error('PUBLIC_DOMAIN_CONFIGURATION_REQUIRED')
            return
        if address.is_unspecified or address.is_multicast:
            self.show_error('PUBLIC_DOMAIN_CONFIGURATION_REQUIRED')
            return
        self.var('domain_target_address').set(str(address))

    def _advanced(self, tab):
        access = self.card(tab, 'Opzioni SSH', 'Se le password SSH e sudo sono uguali puoi lasciare vuoti i campi sudo.')
        self.entry(access, 'Porta SSH stack', 'port', 0)
        self.entry(access, 'Porta SSH Infisical', 'infisical_port', 0, column=1)
        self.entry(access, 'Password sudo stack (se diversa)', 'sudo_password', 1, secret=True)
        self.entry(access, 'Password sudo Infisical (se diversa)', 'infisical_sudo_password', 1, secret=True, column=1)
        self.entry(access, 'Passphrase chiave SSH stack', 'key_password', 2, secret=True)
        self.entry(access, 'Passphrase chiave SSH Infisical', 'infisical_key_password', 2, secret=True, column=1)
        compatibility = self.card(tab, 'Input mancante nel backup', 'Il recupero ha richiesto un file integrativo cifrato compatibile con questo backup. Le configurazioni AIO vengono recuperate automaticamente.')
        self.supplement_card = compatibility.master
        self.entry(compatibility, 'File integrativo cifrato .age', 'supplemental_inputs', 0, browse=True, span=2)
        self.supplement_card.pack_forget()

    def _supplement_needed(self):
        return self.supplement_scope == (self.var('dr_tag').get(), self.var('public_commit').get())

    def _refresh_supplement(self):
        if self._supplement_needed():
            self.supplement_card.pack(fill='x', pady=(0, 14))
        else:
            self.supplement_scope = None
            self.var('supplemental_inputs').set('')
            self.supplement_card.pack_forget()

    def var(self, key, default=''):
        if key not in self.vars:
            self.vars[key] = tk.StringVar(value=default)
        return self.vars[key]

    def entry(self, parent, label, key, row, secret=False, browse=False, column=0, span=1):
        block = ttk.Frame(parent)
        block.grid(row=row, column=column, columnspan=span, sticky='ew', padx=(0, 12), pady=(0, 12))
        ttk.Label(block, text=label, style='Field.TLabel').pack(anchor='w', pady=(0, 5))
        field = ttk.Frame(block)
        field.pack(fill='x')
        entry = ttk.Entry(field, textvariable=self.var(key), show='•' if secret else '', width=22)
        entry.pack(side='left', fill='x', expand=True)
        self.controls.append(entry)
        if browse:
            button = ttk.Button(field, text='Sfoglia…', command=lambda: self.select_file(key))
            button.pack(side='right', padx=(7, 0))
            self.buttons.append(button)
        parent.columnconfigure(column, weight=1)
        return entry

    def _page_changed(self, event=None):
        self._refresh_supplement()
        index = self.book.index(self.book.select())
        self.page_title.set(self.titles[index])
        self.page_description.set(self.descriptions[index])
        for i, button in enumerate(self.nav):
            button.configure(bg='#243755' if i == index else '#111f35', fg='#ffffff' if i == index else '#a2b1c7')
        aio = ('AIO dal backup' if self.backup_has_aio is True else
               'Backup AIO assente' if self.backup_has_aio is False else 'Compatibilità AIO da verificare')
        self.summary.set('Backup: ' + (self.var('dr_tag').get() or 'da selezionare') + '   ·   ' + aio + '   ·   NPM e HTTPS')
        for role, key in (('stack', 'host'), ('infisical', 'infisical_host')):
            title, subtitle = self.connection_labels[role]
            if title.cget('text') == 'Da configurare':
                subtitle.configure(text=self.var(key).get() or 'Accesso SSH necessario')

    def _routing_changed(self, event=None):
        self.var('routing_mode').set('production_recovery' if self.routing_label.get() == 'Recupero della produzione' else 'parallel_test')

    def _wheel(self, event):
        if isinstance(event.widget, (ttk.Entry, ttk.Combobox, tk.Text)):
            return
        page = self.pages[self.book.index(self.book.select())]
        if page.content.winfo_reqheight() > page.canvas.winfo_height():
            page.canvas.yview_scroll(-int(event.delta / 120), 'units')

    def select_file(self, key):
        options = {'filetypes': [('Backup cifrato age', '*.age'), ('Tutti i file', '*')]} if key == 'supplemental_inputs' else {}
        path = filedialog.askopenfilename(title='Seleziona il file privato', parent=self, **options)
        if path:
            self.var(key).set(path)

    def snapshot(self):
        secrets = {'password', 'sudo_password', 'key_password', 'infisical_password', 'infisical_key_password', 'infisical_sudo_password'}
        return {key: variable.get() if key in secrets else variable.get().strip() for key, variable in self.vars.items()}

    @staticmethod
    def host(data):
        try:
            return Host(data['host'], data['user'], int(data['port']), data['password'], data['ssh_key'], data['key_password'], data['sudo_password'])
        except (ValueError, KeyError):
            raise Failure('SSH_ADDRESS_REQUIRED') from None

    @staticmethod
    def infisical_host(data):
        try:
            return Host(data['infisical_host'], data['infisical_user'], int(data['infisical_port']), data['infisical_password'], data['infisical_key'], data['infisical_key_password'], data['infisical_sudo_password'])
        except (ValueError, KeyError):
            raise Failure('SSH_ADDRESS_REQUIRED') from None

    def key_dialog(self, host, fingerprint):
        done, answer = threading.Event(), []
        self.events.put(('key', (host, fingerprint, done, answer)))
        while not done.wait(0.1):
            if self.cancelled.is_set():
                return False
        return bool(answer and answer[0])

    def changed_key_dialog(self, host, previous, current):
        done, answer = threading.Event(), []
        self.events.put(('key_changed', (host, previous, current, done, answer)))
        while not done.wait(0.1):
            if self.cancelled.is_set():
                return False
        return bool(answer and answer[0])

    def job(self, action, return_page=None):
        if self.busy:
            return
        self.busy, self.return_page, self.last_error = True, return_page, None
        self.infrastructure_verified = False
        self.external_unavailable = 0
        self.failure_box.pack_forget()
        self.cancelled.clear()
        self.book.select(0)
        self.progress.start(15)
        self.cancel_button.configure(state='normal')
        self.hero_status.set('Recupero in corso')
        self.hero_detail.set('Puoi seguire i passaggi qui. Le credenziali non vengono registrate.')
        for button in self.buttons:
            button.configure(state='disabled')
        for widget in self.controls:
            widget.configure(state='disabled')
        self.status.set('Operazione in corso. Attendi l’esito prima di avviarne un’altra.')
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
        old = self.var('dr_tag').get()
        def worker():
            github = GitHub(token)
            tags, commit = github.choices()
            chosen = old if old in tags else tags[0] if tags else ''
            require(bool(chosen), 'PUBLISHED_RELEASE_REQUIRED')
            point = github.point(chosen)
            self.events.put(('choices', (tags, point['public_commit'])))
            self.events.put(('point', point))
        self.job(worker, return_page=1)

    def load_point(self, event=None):
        token, tag = self.var('github_token').get(), self.var('dr_tag').get()
        self.backup_has_aio = None
        self.job(lambda: self.events.put(('point', GitHub(token).point(tag))), return_page=1)

    def recover(self, action):
        data = operational_request(self.snapshot(), action, self.files)
        if self._supplement_needed() is not True:
            data['supplemental_inputs'] = ''
        try:
            if action == 'fresh':
                try:
                    address = ipaddress.ip_address(data.get('domain_target_address', ''))
                except ValueError:
                    raise Failure('PUBLIC_DOMAIN_CONFIGURATION_REQUIRED') from None
                require(str(address) == data['domain_target_address'] and not address.is_unspecified
                        and not address.is_multicast, 'PUBLIC_DOMAIN_CONFIGURATION_REQUIRED')
                require(data['routing_mode'] in ('parallel_test', 'production_recovery'), 'OPERATIONAL_DEPLOYMENT_REFUSED')
            self.host(data).validate()
            self.infisical_host(data).validate()
            require(data['host'] != data['infisical_host'], 'SEPARATE_RECOVERY_VMS_REQUIRED')
            if action == 'fresh':
                require(bool(SHA.fullmatch(data['public_commit'])) and bool(TAG.fullmatch(data['dr_tag'])), 'SELECT_GITHUB_RECOVERY_POINT')
                require(self.backup_has_aio is not False, 'AIO_SNAPSHOT_REQUIRED')
            require(Path(data['age_identity']).is_file(), 'AGE_IDENTITY_FILE_REQUIRED')
            require(not Path(data['age_identity']).is_symlink() and Path(data['age_identity']).stat().st_size <= 65536, 'AGE_IDENTITY_FILE_INVALID')
            if action == 'fresh':
                require(not data.get('supplemental_inputs') or Path(data['supplemental_inputs']).is_file(), 'RECOVERY_SUPPLEMENT_INVALID')
        except Failure as error:
            self.show_error(str(error))
            self.book.select(0)
            return
        def worker():
            stack, server = None, None
            try:
                stack = backend.SSH(self.host(data), self.key_dialog, self.cancelled,
                                    confirm_changed_key=self.changed_key_dialog)
                server = backend.SSH(self.infisical_host(data), self.key_dialog, self.cancelled,
                                     confirm_changed_key=self.changed_key_dialog)
                job_request = data
                if action == 'resume':
                    job_request = backend.resolve_resume_request(stack, server, data)
                    if (job_request['dr_tag'], job_request['public_commit']) != (data['dr_tag'], data['public_commit']):
                        job_request = dict(job_request, supplemental_inputs='')
                    point = GitHub(data['github_token']).point(job_request['dr_tag'])
                    require(point['public_commit'] == job_request['public_commit'], 'DR_STACK_COMMIT_MISMATCH')
                    require(point['aio_snapshot'] is True, 'AIO_SNAPSHOT_BACKUP_REQUIRED')
                    self.events.put(('resumed_selection', dict(point=point,
                        routing_mode=job_request['routing_mode'], domain_target_address=job_request['domain_target_address'])))
                require(not job_request.get('supplemental_inputs') or Path(job_request['supplemental_inputs']).is_file(), 'RECOVERY_SUPPLEMENT_INVALID')
                detected = backend.inspect_recovery(stack, server, job_request)
                self.events.put(('detected', detected))
                backend.restore_all(stack, server, job_request, lambda item: self.events.put(('stage', item)), tls=True)
                self.events.put(('finished', None))
            finally:
                if stack is not None:
                    stack.close()
                if server is not None:
                    server.close()
        self.job(worker)

    def one_click(self):
        self.recover('fresh')

    def verify(self):
        self.recover('resume')

    def phase_event(self, stage, status):
        name = phase_for(stage, self.active_phase)
        if name:
            self.active_phase = name
            label, tone = phase_status(stage, status)
            colors = {'error': '#a6413c', 'ok': '#1e8069', 'active': '#5563df', 'pending': '#64748b'}
            self.phase_labels[name].configure(text=label, foreground=colors[tone])

    def show_error(self, code):
        if code == 'OAUTH_ALLOWLIST_SUPPLEMENT_REQUIRED' or code.startswith('RECOVERY_SUPPLEMENT_'):
            self.supplement_scope = (self.var('dr_tag').get(), self.var('public_commit').get())
            self._refresh_supplement()
        self.last_error = code
        self.hero_status.set('Un passaggio richiede attenzione')
        self.hero_detail.set('L’avanzamento resta sulla VM. Risolvi la causa e scegli Rileva e continua.')
        self.failure_title.set('Operazione fermata · ' + code)
        self.failure_detail.set(self.errors.get(code, 'Il controllo ha fermato il recupero. Gli esiti conservano il codice del passaggio; i dati presenti non vengono cancellati.'))
        _, label = error_destination(code)
        self.error_action.configure(text=label)
        self.failure_box.pack(fill='x', pady=(0, 14), before=self.progress_card)
        self.status.set('Da risolvere: ' + code)

    def open_error_destination(self):
        index, _ = error_destination(self.last_error or '')
        self.book.select(index)

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
                answer.append(messagebox.askyesno('Verifica l’identità della VM', 'Host: ' + host + '\n' + fingerprint + '\n\nConfronta questa impronta con la console della VM. Riconosci la chiave?', parent=self))
                done.set()
            elif kind == 'key_changed':
                host, previous, current, done, answer = value
                answer.append(not self.cancelled.is_set() and messagebox.askyesno('VM ricreata: verifica la nuova identità SSH',
                    'Destinazione: ' + host + '\n\nImpronta precedente:\n' + previous
                    + '\n\nNuova impronta:\n' + current
                    + '\n\nUna VM ricreata genera una nuova chiave SSH. Confronta la nuova impronta con la console della VM.'
                    + '\n\nAggiornare l’identità di questa destinazione e continuare?', parent=self, default='no'))
                done.set()
            elif kind == 'choices':
                tags, commit = value
                old = self.var('dr_tag').get()
                self.tags['values'] = tags
                if tags and old not in tags:
                    self.var('dr_tag').set(tags[0])
                if not self.var('public_commit').get():
                    self.var('public_commit').set(commit)
                self._page_changed()
                self.write_log('Backup pubblicati caricati. Verifica release e commit associati.', 'ok')
                self.hero_status.set('Scegli come ripartire')
                self.hero_detail.set('Accessi e punto di recupero sono nella configurazione.')
            elif kind == 'resumed_selection':
                point = value['point']
                self.var('dr_tag').set(point['tag'])
                self.var('public_commit').set(point['public_commit'])
                self.var('routing_mode').set(value['routing_mode'])
                self.var('domain_target_address').set(value['domain_target_address'])
                self.routing_label.set('Prova affiancata alle VM operative' if value['routing_mode'] == 'parallel_test'
                                       else 'Recupero della produzione')
                self.backup_has_aio = True
                self._page_changed()
                self.write_log('Riprendo il backup '+point['tag']+' e l’instradamento già verificati sulle VM.', 'ok')
            elif kind == 'point':
                self.var('dr_tag').set(value['tag'])
                self.var('public_commit').set(value['public_commit'])
                self.backup_has_aio = value.get('aio_snapshot') is True
                self._page_changed()
                if self.backup_has_aio:
                    self.write_log('Backup completo selezionato: configurazioni AIO incluse e commit associato verificato.', 'ok')
                else:
                    self.hero_status.set('Questo backup richiede un aggiornamento')
                    self.hero_detail.set('Le configurazioni AIO automatiche non sono incluse. Scegli un backup completo prima del recupero operativo.')
                    self.write_log('Il backup selezionato non contiene la copia AIO richiesta dal recupero completo.', 'error')
            elif kind == 'detected':
                for role in ('stack', 'infisical'):
                    title, subtitle = machine_status(value.get(role), role)
                    self.connection_labels[role][0].configure(text=title)
                    self.connection_labels[role][1].configure(text=subtitle)
                self.write_log('Destinazioni rilevate. Proprietà e punto di recupero vengono verificati prima di continuare.', 'ok')
            elif kind == 'stage':
                self.safe_report.append(value)
                stage, status = value['stage'], value['status']
                self.phase_event(stage, status)
                extra = {'DOMAINS': 'Domini dello stack', 'PUBLIC_COMETNET': 'CometNet sul dominio',
                         'NPM_TOPOLOGY': 'Collegamenti NPM alle nuove VM',
                         'OPERATIONAL_PROFILE': 'Configurazione per i domini del recupero',
                         'PUBLIC_DOMAINS': 'NPM, HTTPS e dominio CometNet',
                         'TAILSCALE': 'Controller Headscale e registrazione Tailscale',
                         'EXTERNAL_UPSTREAMS': 'Collegamenti a dispositivi esterni',
                         'PUBLIC_CONTROLLERS': 'Servizi automatici della produzione',
                         'OPERATIONAL_READY': 'Controlli dell’infrastruttura', 'AIO_BACKUP': 'Configurazioni AIO dal backup',
                         'AIO_DATABASES': 'Dati AIO dal backup'}
                label = self.stage_text.get(stage, extra.get(stage, 'Passaggio del recupero'))
                display = {'RUNNING': 'in corso', 'PASS': 'verificato', 'SKIPPED': 'non completato', 'REFUSED': 'fermato', 'WARNING': 'da controllare'}.get(status, status)
                self.write_log(label + ' · ' + display + ((' · ' + value['code']) if value.get('code') else ''),
                               'error' if status == 'REFUSED' else 'ok' if status == 'PASS' else None)
                self.phase_detail.set(label + ' · ' + display)
                self.status.set(label + ' · ' + display)
                if status == 'REFUSED' and value.get('code'):
                    self.show_error(value['code'])
                if stage == 'REFUSED' and value.get('code') == 'APPLICATION_HEALTH_WAIT_FAILED' and 'diagnostic' in value:
                    for line in startup_diagnostic_lines(value['diagnostic']):
                        self.write_log(line, 'error')
                if stage == 'EXTERNAL_UPSTREAMS':
                    self.external_unavailable = len(value['diagnostic']['unavailable'])
                    for line in external_dependency_lines(value['diagnostic']):
                        self.write_log(line)
                if stage == 'OPERATIONAL_READY' and status == 'PASS':
                    self.infrastructure_verified = True
                    self.hero_status.set('Infrastruttura ripristinata')
                    self.hero_detail.set('Servizi e domini hanno superato i controlli. Restano da verificare login, profili AIO e collegamenti alle applicazioni.')
                    if self.external_unavailable:
                        self.hero_status.set('Stack ripristinato · collegamenti esterni da controllare')
                        self.hero_detail.set(str(self.external_unavailable)+' dispositivi esterni non rispondono. I collegamenti NPM sono conservati. Restano da verificare login e profili applicativi.')
            elif kind == 'error':
                self.safe_report.append(dict(stage='REFUSED', status='REFUSED', code=value))
                self.phase_event('REFUSED', 'REFUSED')
                self.write_log(value + ' · ' + self.errors.get(value, 'Il recupero è fermo; lo stato resta conservato.'), 'error')
                self.show_error(value)
            elif kind == 'finished':
                self.write_log('Percorso di recupero completato. Gli esiti indicano i controlli verificati.', 'ok')
                if not self.infrastructure_verified:
                    self.hero_status.set('Percorso completato')
                    self.hero_detail.set('Consulta gli esiti per i controlli effettuati. Login, profili e collegamenti applicativi richiedono il collaudo finale.')
            elif kind == 'done':
                self.busy = False
                self.progress.stop()
                self.cancel_button.configure(state='disabled')
                for button in self.buttons:
                    button.configure(state='normal')
                for widget in self.controls:
                    widget.configure(state='readonly' if isinstance(widget, ttk.Combobox) else 'normal')
                if self.return_page == 1 and self.last_error is None:
                    if self.backup_has_aio is True:
                        self.status.set('Backup selezionato. Puoi avviare o riprendere il recupero.')
                    else:
                        self.status.set('Seleziona un backup completo con le configurazioni AIO.')
                if self.return_page is not None:
                    self.book.select(self.return_page)
                    self.return_page = None
        self.after(100, self.poll)

    def save_report(self):
        path = filedialog.asksaveasfilename(title='Salva esiti senza credenziali', defaultextension='.json', parent=self)
        if path:
            report = dict(schema=2, events=self.safe_report, scope='RECOVERY_CHECKS_RECORDED; SEE_VERIFIED_STAGES')
            Path(path).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')

    def close_app(self):
        if self.busy and not messagebox.askokcancel('Recupero in corso', 'Chiudere interrompe la connessione. Lo stato resta sulla VM per la ripresa successiva. Chiudere ora?', parent=self):
            return
        self.cancelled.set()
        self.onboarding.clear_sensitive()
        for key in ('password', 'github_token', 'sudo_password', 'key_password', 'infisical_password', 'infisical_key_password', 'infisical_sudo_password'):
            self.var(key).set('')
        self.destroy()
