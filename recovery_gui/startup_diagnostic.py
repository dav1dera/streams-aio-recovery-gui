"""Closed public metadata for a failed startup wave; no arbitrary log text."""

SERVICES = frozenset('aiomanager aiometadata aiostreams cloudflare-ddns comet cometnet '
    'deunhealth dnscrypt-proxy easyproxy gluetun gost headplane headscale honey jackett '
    'mediaflow-proxy-light microwarp npm oauth2-proxy pgbouncer portainer postgres redis '
    'seanime seanime-shared streamvix stremthru tailscale teamspeak tvvoo watchtower'.split())
STATUSES = frozenset({'NOT_STARTED', 'RUNNING', 'HEALTHY', 'UNHEALTHY', 'STARTING',
    'RESTARTING', 'PAUSED', 'EXITED', 'CREATED', 'DEAD', 'UNKNOWN', 'DEFERRED'})
RESULTS = frozenset({'COMPLETE', 'UNAVAILABLE', 'OWNERSHIP_REFUSED'})
FIELDS = frozenset({'status', 'exit_code', 'health_exit_code', 'restarts', 'oom_killed'})


def unavailable():
    return dict(schema=1, status='UNAVAILABLE', wave=[], services={})


def validate(value):
    def require(ok):
        if not ok:
            raise ValueError('INVALID_STARTUP_DIAGNOSTIC')
    require(isinstance(value, dict) and set(value) == {'schema', 'status', 'wave', 'services'}
            and type(value['schema']) is int and value['schema'] == 1
            and isinstance(value['status'], str) and value['status'] in RESULTS)
    wave = value['wave']
    require(isinstance(wave, list) and len(wave) <= len(SERVICES)
            and all(isinstance(name, str) and name in SERVICES for name in wave)
            and len(wave) == len(set(wave)))
    rows = value['services']
    require(isinstance(rows, dict) and set(rows) <= SERVICES)
    if value['status'] != 'COMPLETE':
        require(not rows)
    else:
        require(bool(rows) and set(wave) <= set(rows))
    for row in rows.values():
        require(isinstance(row, dict) and set(row) == FIELDS
                and isinstance(row['status'], str) and row['status'] in STATUSES)
        for key in ('exit_code', 'health_exit_code', 'restarts'):
            maximum = 10000 if key == 'restarts' else 255
            require(row[key] is None or type(row[key]) is int and 0 <= row[key] <= maximum)
        require(row['oom_killed'] is None or type(row['oom_killed']) is bool)
    return value


def safe(value):
    """Invalid diagnostic details never obscure the original fixed refusal."""
    try:
        return validate(value)
    except (ValueError, TypeError, KeyError):
        return unavailable()


def lines(value):
    value = safe(value)
    if value['status'] != 'COMPLETE':
        return ['Controllo automatico dopo l’errore: ' + value['status'] + '.']
    rows = value['services']
    result = ['Gruppo fermato: ' + ', '.join(value['wave']) + '.',
              'Controllo automatico: ' + str(sum(row['status'] == 'HEALTHY' for row in rows.values()))
              + ' sani; ' + str(sum(row['status'] == 'RUNNING' for row in rows.values()))
              + ' in esecuzione; ' + str(sum(row['status'] == 'DEFERRED' for row in rows.values()))
              + ' esclusi dalla prova. Il report salvato contiene tutti i servizi.']
    relevant = set(value['wave']) | {name for name, row in rows.items()
        if row['status'] not in {'RUNNING', 'HEALTHY', 'DEFERRED', 'NOT_STARTED'}}
    for name in sorted(relevant):
        row = value['services'][name]
        result.append('SERVIZIO=' + name + ' STATO=' + row['status']
            + ' EXIT=' + str(row['exit_code']) + ' HEALTH_EXIT=' + str(row['health_exit_code'])
            + ' RIAVVII=' + str(row['restarts']) + ' OOM=' + str(row['oom_killed']))
    return result
