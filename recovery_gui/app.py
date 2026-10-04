"""Tk desktop wizard. Worker threads never call Tk; all dialogs use a UI queue."""
import json
from pathlib import Path
import queue
import re
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import webbrowser

from .backend import Failure, GitHub, Host, SSH, SHA, TAG, require
from .codes import ERROR_CODES

TEXT = {
    'DEPENDENCIES': 'Docker e dipendenze', 'CLONES': 'Repository e commit scelto',
    'DOWNLOAD': 'Release e verifica SHA256', 'DECRYPT': 'Decifratura privata age',
    'INITIALIZE': 'Destinazione vuota', 'INPUTS': 'Secret da Infisical',
    'RENDER': 'Configurazioni dello stack', 'EMPTY_STATE': 'Directory e permessi',
    'NPM': 'Database NPM', 'AIO': 'Configurazioni AIO', 'PREFLIGHT': 'Controlli finali',
    'PREPARED': 'Preparazione completata', 'STARTED': 'Avvio dei servizi', 'TLS': 'Certificati e HTTPS',
    'REFUSED': 'Procedura fermata',
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
    'UBUNTU_2404_REQUIRED': 'Questa versione richiede Ubuntu Server 24.04 amd64.',
}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Streams AIO · Recovery')
        self.geometry('1040x800')
        self.minsize(940, 720)
        self.configure(bg='#f3f5f8')
        self.events = queue.Queue()
        self.cancelled = threading.Event()
        self.busy = False
        self.prepared = False
        self.vars = {}
        self.files = {'aiostreams_exports': [], 'aiometadata_exports': []}
        self.safe_report = []
        self.protocol('WM_DELETE_WINDOW', self.close_app)
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('.', font=('Segoe UI', 10), background='#f3f5f8', foreground='#192a42')
        style.configure('TNotebook', background='#f3f5f8', borderwidth=0)
        style.configure('TNotebook.Tab', padding=(18, 10), background='#e6ecf3')
        style.map('TNotebook.Tab', background=[('selected', '#ffffff')])
        style.configure('TEntry', padding=6)
        style.configure('TButton', padding=(12, 8))
        style.configure('Accent.TButton', background='#245fc5', foreground='white', borderwidth=0)
        style.map('Accent.TButton', background=[('active', '#194ea9'), ('disabled', '#d0d9e8')])
        header = tk.Frame(self, bg='#152940', height=100)
        header.pack(fill='x')
        tk.Label(header, text='STREAMS AIO  /  RECOVERY', bg='#152940', fg='#8dbcfb',
                 font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=28, pady=(18, 0))
        tk.Label(header, text='Ricostruisci il tuo stack, da Windows.', bg='#152940', fg='white',
                 font=('Segoe UI', 23, 'bold')).pack(anchor='w', padx=28, pady=(2, 12))
        ttk.Label(self, text='1  Collega la VM     →     2  Scegli il recupero     →     3  Verifica e prepara     →     4  Avvia',
                  font=('Segoe UI', 11)).pack(anchor='w', padx=28, pady=(18, 10))
        self.book = ttk.Notebook(self)
        self.book.pack(fill='both', expand=True, padx=24)
        connections, backups, advanced, run = [ttk.Frame(self.book, padding=20) for _ in range(4)]
        for tab, title in zip((connections, backups, advanced, run), ('VM e GitHub', 'Backup', 'Infisical e opzioni', 'Ripristino')):
            self.book.add(tab, text=title)
        self._connections(connections)
        self._backups(backups)
        self._advanced(advanced)
        self._run(run)
        self.status = tk.StringVar(value='Pronto. Inizia con una VM vuota; la produzione può restare accesa.')
        ttk.Label(self, textvariable=self.status, wraplength=970).pack(fill='x', padx=28, pady=14)
        self.after(100, self.poll)

    def var(self, key, default=''):
        if key not in self.vars:
            self.vars[key] = tk.StringVar(value=default)
        return self.vars[key]

    def entry(self, parent, label, key, row, default='', secret=False, browse=False, width=42):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky='w', padx=(0, 18), pady=5)
        entry = ttk.Entry(parent, textvariable=self.var(key, default), width=width, show='•' if secret else '')
        entry.grid(row=row, column=1, sticky='ew', pady=5)
        if browse:
            ttk.Button(parent, text='Sfoglia…', command=lambda: self.select_file(key)).grid(row=row, column=2, padx=8)
        parent.columnconfigure(1, weight=1)
        return entry

    def _connections(self, tab):
        left = ttk.LabelFrame(tab, text=' Nuova VM docker-stack ', padding=14)
        left.pack(fill='x')
        self.entry(left, 'Host / IP SSH', 'host', 0)
        self.entry(left, 'Utente', 'user', 1, default='pi')
        self.entry(left, 'Porta', 'port', 2, default='22')
        self.entry(left, 'Password SSH', 'password', 3, secret=True)
        self.entry(left, 'Chiave SSH (in alternativa)', 'ssh_key', 4, browse=True)
        git = ttk.LabelFrame(tab, text=' GitHub · accesso in sola lettura ', padding=14)
        git.pack(fill='x', pady=(14, 0))
        self.entry(git, 'Token GitHub', 'github_token', 0, secret=True)
        ttk.Label(git, text='Fine-grained token: Contents / Read per streams-aio-dr e streams-aio-sanitized.\n'
                  'Il programma non crea token e non richiede permessi di push.', wraplength=730).grid(row=1, column=1, sticky='w', pady=6)
        ttk.Button(git, text='Carica release da GitHub', command=self.load_choices).grid(row=2, column=1, sticky='w')
        self.entry(git, 'Commit dello stack', 'public_commit', 3)
        ttk.Label(git, text='Release DR pubblicata').grid(row=4, column=0, sticky='w')
        self.tags = ttk.Combobox(git, textvariable=self.var('dr_tag'), state='readonly', width=44)
        self.tags.grid(row=4, column=1, sticky='ew', pady=5)

    def _backups(self, tab):
        ttk.Label(tab, text='I backup privati restano fuori dai repository.', font=('Segoe UI', 15, 'bold')).pack(anchor='w')
        ttk.Label(tab, text='La release selezionata contiene NPM, Agent e Infisical. Gli export AIO vengono scelti dal PC.',
                  wraplength=880).pack(anchor='w', pady=(6, 16))
        frame = ttk.Frame(tab)
        frame.pack(fill='x')
        self.entry(frame, 'Chiave age PRIMARY o RECOVERY', 'age_identity', 0, browse=True)
        for index, (key, title) in enumerate((('aiostreams_exports', 'Export AIOStreams · 2.35.3'),
                                               ('aiometadata_exports', 'Export AIOMetadata · 3.3.0')), 1):
            ttk.Label(frame, text=title).grid(row=index, column=0, sticky='w', pady=12)
            ttk.Label(frame, textvariable=self.var(key, 'Nessun file selezionato')).grid(row=index, column=1, sticky='w')
            ttk.Button(frame, text='Scegli JSON…', command=lambda k=key: self.select_many(k)).grid(row=index, column=2, padx=8)
        ttk.Separator(tab).pack(fill='x', pady=22)
        ttk.Label(tab, text='Hai già un payload DR completo?', font=('Segoe UI', 12, 'bold')).pack(anchor='w')
        payload = ttk.Frame(tab)
        payload.pack(fill='x', pady=10)
        self.entry(payload, 'PRIVATE_DR_PAYLOAD (alternativa)', 'aio_payload', 0, browse=True)
        ttk.Label(tab, text='Per più profili, il programma associa gli UUID ai binding in Infisical. Se l’associazione è ambigua,\n'
                  'si ferma e chiede un payload esplicito. Non inventa password o profili.', wraplength=850).pack(anchor='w', pady=10)

    def _advanced(self, tab):
        ttk.Label(tab, text='Il minimo, quando il backup Agent è riconosciuto.', font=('Segoe UI', 15, 'bold')).pack(anchor='w')
        ttk.Label(tab, text='Progetto, ambiente e Universal Auth vengono letti dal backup Agent. Usa questi campi solo per\n'
                  'cambiare l’endpoint o se la struttura dell’archivio non è riconosciuta.', wraplength=880).pack(anchor='w', pady=(6, 12))
        frame = ttk.Frame(tab)
        frame.pack(fill='x')
        self.entry(frame, 'Endpoint HTTPS Infisical', 'infisical_address', 0)
        self.entry(frame, 'Project ID (opzionale)', 'project_id', 1)
        self.entry(frame, 'Ambiente (opzionale)', 'environment', 2)
        self.entry(frame, 'File Universal Auth client-id', 'client_id_file', 3, browse=True)
        self.entry(frame, 'File Universal Auth client-secret', 'client_secret_file', 4, browse=True)
        self.entry(frame, 'Password sudo (se diversa)', 'sudo_password', 5, secret=True)
        self.entry(frame, 'Passphrase chiave SSH', 'key_password', 6, secret=True)
        ttk.Separator(tab).pack(fill='x', pady=16)
        vm = ttk.Frame(tab)
        vm.pack(fill='x')
        self.entry(vm, 'VM Infisical · host SSH opzionale', 'infisical_host', 0)
        self.entry(vm, 'Utente VM Infisical', 'infisical_user', 1, default='infiscal')
        self.entry(vm, 'Password SSH / sudo Infisical', 'infisical_password', 2, secret=True)
        ttk.Label(tab, text='La connessione Infisical è per il controllo host. Il restore del server PostgreSQL/config non\n'
                  'è ancora automatizzato: richiede il contratto del deployment privato. Infisical deve già rispondere.',
                  wraplength=890).pack(anchor='w', pady=(8, 0))

    def _run(self, tab):
        ttk.Label(tab, text='Un passo alla volta, con esiti verificabili.', font=('Segoe UI', 15, 'bold')).pack(anchor='w')
        ttk.Label(tab, text='Ubuntu 24.04 amd64 · utente UID/GID 1000 · sudo · SSH attivo', wraplength=850).pack(anchor='w', pady=8)
        self.lab = tk.BooleanVar(value=False)
        ttk.Checkbutton(tab, text='Confermo che la VM docker-stack è nuova e destinata a questa prova.', variable=self.lab).pack(anchor='w', pady=8)
        actions = ttk.Frame(tab)
        actions.pack(fill='x', pady=8)
        self.buttons = []
        for text, fn, style in [('Verifica', self.verify, 'TButton'), ('Prepara ripristino', self.prepare, 'Accent.TButton'),
                                ('Avvia servizi', self.start_services, 'TButton'), ('Salva esiti', self.save_report, 'TButton')]:
            button = ttk.Button(actions, text=text, command=fn, style=style)
            button.pack(side='left', padx=(0, 10))
            self.buttons.append(button)
        self.cancel_button = ttk.Button(actions, text='Interrompi', command=lambda: self.cancelled.set(), state='disabled')
        self.cancel_button.pack(side='right')
        self.tls = tk.BooleanVar(value=False)
        ttk.Checkbutton(tab, text='All’avvio richiedi anche riemissione TLS e verifica HTTPS NPM (Cloudflare/ACME reali).',
                        variable=self.tls).pack(anchor='w', pady=8)
        self.progress = ttk.Progressbar(tab, mode='indeterminate')
        self.progress.pack(fill='x', pady=(10, 12))
        self.log = tk.Text(tab, height=13, bg='#152940', fg='#e2ebf9', relief='flat',
                           font=('Consolas', 10), padx=14, pady=12, wrap='word', state='disabled')
        self.log.pack(fill='both', expand=True)
        self.log.tag_configure('ok', foreground='#8fe0b7')
        self.log.tag_configure('error', foreground='#ffb0a5')
        ttk.Label(tab, text='Preparato ≠ ripristino verificato: restano login, enrollment, Agent continuo e test applicativi.\n'
                  'Watchtower, DDNS, deunhealth e timer di pubblicazione/backup restano disattivati.',
                  wraplength=890).pack(anchor='w', pady=(12, 0))

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
        return {key: variable.get().strip() if key not in ('password', 'sudo_password', 'key_password', 'infisical_password')
                else variable.get() for key, variable in self.vars.items()}

    @staticmethod
    def host(data):
        try:
            return Host(data['host'], data['user'], int(data['port']), data['password'],
                        data['ssh_key'], data['key_password'], data['sudo_password'])
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

    def job(self, action):
        if self.busy:
            return
        self.busy = True
        self.cancelled.clear()
        self.book.select(3)
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
        self.job(action)

    def verify(self):
        data = self.snapshot()
        def action():
            tags, commit = GitHub(data['github_token']).choices()
            ssh = SSH(self.host(data), self.key_dialog, self.cancelled)
            try:
                info = ssh.check()
                self.events.put(('message', 'VM stack verificata: Ubuntu 24.04 amd64; nessun container o volume esistente.'))
                self.events.put(('choices', (tags, data.get('public_commit') or commit)))
            finally:
                ssh.close()
            if data.get('infisical_host'):
                host = Host(data['infisical_host'], data['infisical_user'], password=data['infisical_password'])
                other = SSH(host, self.key_dialog, self.cancelled)
                try:
                    other.check(fresh=False)
                    self.events.put(('message', 'Accesso SSH alla VM Infisical verificato. Il servizio secret non è stato modificato.'))
                finally:
                    other.close()
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
                self.write_log(value + ' · ' + ERRORS.get(value, 'Procedura fermata; dati di recupero conservati.'), 'error')
                self.status.set('Procedura fermata: ' + value)
            elif kind == 'done':
                self.busy = False
                self.progress.stop()
                self.cancel_button.configure(state='disabled')
                for button in self.buttons:
                    button.configure(state='normal')
        self.after(100, self.poll)

    def save_report(self):
        path = filedialog.asksaveasfilename(title='Salva gli esiti senza credenziali', defaultextension='.json', parent=self)
        if path:
            Path(path).write_text(json.dumps(dict(schema=1, events=self.safe_report,
                scope='PREPARATION_AND_OPTIONAL_START; FULL_DR_NOT_VERIFIED'), indent=2) + '\n', encoding='utf-8')

    def close_app(self):
        if self.busy and not messagebox.askokcancel('Operazione in corso',
                'Chiudere interrompe la connessione; non annulla quanto già fatto sulla VM. I dati vengono conservati.', parent=self):
            return
        self.cancelled.set()
        for key in ('password', 'github_token', 'sudo_password', 'key_password', 'infisical_password'):
            self.var(key).set('')
        self.destroy()


def main():
    App().mainloop()


if __name__ == '__main__':
    main()
