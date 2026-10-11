"""Presentation rules shared by the dashboard and headless UI tests.

The dashboard describes backend decisions. It never authorizes existing Docker
resources, edits checkpoints, or treats a successful preparation as a restore.
"""

PHASES = ('Infisical', 'Stack', 'AIO', 'Agent', 'Domini', 'Servizi')
PHASE_STAGES = {
    'Infisical': {'INFISICAL_TRANSFER', 'INFISICAL_CONFIG', 'INFISICAL_DATABASE', 'INFISICAL_SERVER'},
    'Stack': {'INITIALIZE', 'INPUTS', 'RENDER', 'EMPTY_STATE', 'PREFLIGHT',
              'PREPARED', 'RUNTIME_PROFILE', 'OPERATIONAL_PROFILE', 'STACK_TRANSFER'},
    'AIO': {'AIO', 'AIO_BACKUP', 'AIO_IMPORT', 'AIO_DATABASES'},
    'Agent': {'NATIVE_AGENT'},
    'Domini': {'NPM', 'NPM_TOPOLOGY', 'TLS', 'DOMAINS', 'PUBLIC_DOMAINS', 'PUBLIC_ROUTING', 'PUBLIC_COMETNET', 'EXTERNAL_UPSTREAMS'},
    'Servizi': {'IMAGES', 'STARTED', 'APPLICATION_CHECKS', 'OPERATIONAL_READY', 'PUBLIC_CONTROLLERS'},
}
FINISHED_STAGES = {
    'INFISICAL_SERVER', 'PREPARED', 'AIO', 'AIO_IMPORT', 'AIO_DATABASES',
    'NATIVE_AGENT', 'DOMAINS', 'PUBLIC_DOMAINS', 'PUBLIC_COMETNET', 'OPERATIONAL_READY',
}


def phase_for(stage, active=None):
    if stage == 'REFUSED':
        return active
    return next((name for name, stages in PHASE_STAGES.items() if stage in stages), None)


def phase_status(stage, status):
    if stage == 'EXTERNAL_UPSTREAMS' and status == 'WARNING':
        return 'Collegamenti esterni da verificare', 'pending'
    if status == 'REFUSED':
        return 'Da risolvere', 'error'
    if status == 'SKIPPED':
        return 'Non completato', 'pending'
    if status == 'PASS' and stage in FINISHED_STAGES:
        return 'Verificato', 'ok'
    if status == 'PASS':
        return 'Controllo superato', 'active'
    return 'In corso', 'active'


def machine_status(info, role='stack'):
    """Use only approved probe metadata, never paths or exception strings."""
    if not isinstance(info, dict):
        return 'Da verificare', 'Collega la VM per rilevarne lo stato.'
    containers, volumes = info.get('containers', 0), info.get('volumes', 0)
    if type(containers) is not int or type(volumes) is not int:
        return 'Da verificare', 'Metadati della destinazione non disponibili.'
    phases = info.get('recovery') or {}
    if info.get('existing_recovery'):
        if role == 'stack' and phases.get('infrastructure_verified') is True:
            title = 'Infrastruttura ripristinata'
        elif role == 'infisical' and phases.get('infisical_completed') is True:
            title = 'Infisical recuperato'
        elif phases.get('application_completed') is True:
            title = 'Avvio registrato'
        elif phases.get('prepared') is True:
            title = 'Pronta per continuare'
        else:
            title = 'Recupero presente'
    else:
        title = 'VM vuota' if not containers and not volumes else 'Risorse da verificare'
    return title, f'{containers} container · {volumes} volumi'


def error_destination(code):
    if code in ('INCOMPLETE_STEP_REQUIRES_REVIEW','RECOVERY_OPERATION_INCOMPLETE',
                'AIO_SNAPSHOT_JOURNAL_INVALID','AIO_SNAPSHOT_RESTORED_DATABASE_CHANGED',
                'AIO_SNAPSHOT_TARGET_MOUNTED','NPM_TOPOLOGY_ALREADY_MOUNTED',
                'NPM_TOPOLOGY_DATABASE_IDENTITY_REQUIRED',
                'NPM_TOPOLOGY_JOURNAL_INVALID','NPM_TOPOLOGY_EVIDENCE_REQUIRED',
                'NPM_TOPOLOGY_SOURCE_DRIFT','NPM_TOPOLOGY_APPLY_FAILED'):
        return 0, 'Consulta il passaggio interrotto'
    if code.startswith('NPM_TOPOLOGY_'):
        return 1, 'Controlla il backup e le destinazioni NPM'
    if code.startswith('AIO_SNAPSHOT_') or code in ('DR_STACK_COMMIT_MISMATCH', 'UNEXPECTED_RELEASE_ASSETS', 'DR_BUNDLE_VERIFICATION_FAILED'):
        return 1, 'Controlla il backup selezionato'
    if code.startswith(('OPERATIONAL_', 'PUBLIC_DOMAIN_', 'PUBLIC_CONTROLLER_')):
        return 1, 'Controlla l’instradamento dei domini'
    if code.startswith(('SSH_', 'GITHUB_', 'AGE_')) or code in {
        'SELECT_GITHUB_RECOVERY_POINT', 'SSH_ADDRESS_REQUIRED',
        'AGE_IDENTITY_FILE_REQUIRED', 'SEPARATE_RECOVERY_VMS_REQUIRED',
    }:
        return 1, 'Controlla accessi e backup'
    if code == 'OAUTH_ALLOWLIST_SUPPLEMENT_REQUIRED':
        return 2, 'Controlla gli input del backup OAuth'
    if code.startswith(('AIO_', 'OAUTH_', 'RECOVERY_SUPPLEMENT_', 'INFISICAL_')):
        return 2, 'Controlla le opzioni del recupero'
    return 0, 'Rileva di nuovo e continua'


def operational_request(data, action, files=None):
    if action not in ('fresh', 'resume'):
        raise ValueError('Unsupported recovery action')
    request = dict(data)
    request.update(recovery_action=action, operational_profile=True,
                   aio_mode='snapshot', native_agent=True, restart_test=False)
    request.update({key: list(paths) for key, paths in (files or {}).items()})
    # An SSH LAN address is not evidence of the public DNS destination.
    request['domain_target_address'] = request.get('domain_target_address', '')
    request.setdefault('routing_mode', 'parallel_test')
    return request
