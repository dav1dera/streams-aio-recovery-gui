"""Closed, nonfatal status for backup routes outside the recovered VM scope."""


def validate(value):
    def require(ok):
        if not ok:
            raise ValueError('INVALID_EXTERNAL_DEPENDENCIES')
    require(isinstance(value,dict) and set(value)=={'schema','total','unavailable'}
            and type(value['schema'])is int and value['schema']==1
            and type(value['total'])is int and 0<=value['total']<=4096
            and isinstance(value['unavailable'],list)
            and all(type(v)is int and 1<=v<=2**31-1 for v in value['unavailable'])
            and value['unavailable']==sorted(set(value['unavailable']))
            and len(value['unavailable'])<=value['total'])
    return value


def lines(value):
    value=validate(value)
    if not value['unavailable']:
        return ['Collegamenti esterni verificati: '+str(value['total'])+'.']
    return ['Collegamenti esterni non raggiungibili: '+str(len(value['unavailable']))
            +'. Destinazioni e configurazioni NPM conservate.',
            'Voci NPM da controllare sui dispositivi esterni: '+', '.join(map(str,value['unavailable']))+'.',
            'Questi dispositivi non vengono creati dal recupero delle due VM.']
