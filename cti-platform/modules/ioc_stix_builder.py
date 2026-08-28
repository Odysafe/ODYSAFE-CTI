"""Normalize ODYSAFE IOCs and build clean STIX 2.1 bundles."""
from __future__ import annotations

import ipaddress, json, re, uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urlsplit, unquote

TLP_IDS = {
    'RED': 'marking-definition--5e57c739-391a-4eb3-b6c8-b55b8d663e2e',
    'AMBER': 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
    'GREEN': 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
    'WHITE': 'marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487',
    'CLEAR': 'marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487',
}
TLP_RANK = {'WHITE': 0, 'CLEAR': 0, 'GREEN': 1, 'AMBER': 2, 'RED': 3}
NAMESPACE = uuid.UUID('c7b4d196-d8aa-4f13-a4cf-5c6571431a87')
BLOCKCHAINS = {'bitcoin','bitcoincash','cardano','dashcoin','dogecoin','ethereum','litecoin','monero','ripple','solana','stellar','tezos','tron','zcash'}
SOCIAL = {'facebook','github','instagram','linkedin','pinterest','telegram','twitter','x','whatsapp','youtube','youtubechannel'}
IOC_CLASSIFICATION = {
    'ipv4':('native','ipv4-addr'),'ipv6':('native','ipv6-addr'),'domain':('native','domain-name'),
    'url':('native','url'),'email':('native','email-addr'),'md5':('native','file'),'sha1':('native','file'),
    'sha256':('native','file'),'sha512':('native','file'),'cve':('native','vulnerability'),'ttp':('native','attack-pattern'),
    'phone':('extension','x-odysafe-phone-number'),'uuid':('extension','x-odysafe-identifier'),
    'arn':('extension','x-odysafe-cloud-resource'),'iban':('extension','x-odysafe-financial-account'),
    'webmoney':('extension','x-odysafe-financial-account'),'chineseicp':('extension','x-odysafe-registration-identifier'),
    'spanishnif':('extension','x-odysafe-registration-identifier'),'tox':('contextual',None),
    'packagename':('contextual',None),'copyright':('unsupported',None),'trademark':('unsupported',None),
}
for _kind in BLOCKCHAINS: IOC_CLASSIFICATION[_kind]=('extension','x-odysafe-cryptocurrency-address')
for _kind in SOCIAL: IOC_CLASSIFICATION[_kind]=('native','user-account')
TYPE_ALIASES = {
    'ip':'ipv4','ip4':'ipv4','ip4net':'ipv4','ipv4subnet':'ipv4','ip6':'ipv6','ip6net':'ipv6',
    'fqdn':'domain','onionaddress':'domain','emailaddr':'email','md5hash':'md5','sha1hash':'sha1',
    'sha256hash':'sha256','sha512hash':'sha512','mitreattack':'ttp','attack':'ttp','phonenumber':'phone',
    'amazonarn':'arn','androidpackagename':'packagename','icp':'chineseicp','nif':'spanishnif','toxidentifier':'tox',
}
HASH_NAMES={'md5':('MD5',32),'sha1':('SHA-1',40),'sha256':('SHA-256',64),'sha512':('SHA-512',128)}
CONFIDENCE_VALUES={'confirmed':100,'highly likely':90,'likely':70,'possible':50,'unlikely':20}

def utc_now(): return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')
def stix_id(kind,value,deterministic=True):
    token=uuid.uuid5(NAMESPACE,f'{kind}:{value}') if deterministic else uuid.uuid4()
    return f'{kind}--{token}'
def canonical_type(value):
    raw=re.sub(r'[-_\s/]+','',str(value or '').strip().lower()); return TYPE_ALIASES.get(raw,raw)
def classify_ioc_type(value):
    kind=canonical_type(value); support,stix_type=IOC_CLASSIFICATION.get(kind,('unsupported',None))
    return {'odysafe_type':kind,'support':support,'stix_type':stix_type}
def normalize_tlp(value):
    color=str(value or 'WHITE').upper().replace('TLP:',''); return color if color in TLP_IDS else 'WHITE'

def normalize_value(kind,value):
    text=str(value or '').strip()
    if not text:return None
    if kind in {'ipv4','ipv6'}:
        try: parsed=ipaddress.ip_network(text,strict=False) if '/' in text else ipaddress.ip_address(text)
        except ValueError:return None
        if parsed.version != (4 if kind=='ipv4' else 6):return None
        return str(parsed)
    if kind=='domain':
        result=text.rstrip('.').lower(); return result if result and ' ' not in result and '.' in result else None
    if kind in HASH_NAMES:
        result=text.lower(); return result if len(result)==HASH_NAMES[kind][1] and re.fullmatch(r'[0-9a-f]+',result) else None
    if kind=='email':return text.lower() if re.fullmatch(r'[^@\s]+@[^@\s]+',text) else None
    if kind=='url':
        try: parsed=urlsplit(text); return text if parsed.scheme and parsed.netloc else None
        except ValueError:return None
    if kind in SOCIAL:
        result=text
        if '://' in result:result=unquote(urlsplit(result).path.strip('/').split('/')[-1])
        return result.lstrip('@').strip() or None
    if kind=='cve':
        result=text.upper(); return result if re.fullmatch(r'CVE-\d{4}-\d{4,}',result) else None
    if kind=='ttp':
        result=text.upper(); return result if re.fullmatch(r'T\d{4}(?:\.\d{3})?',result) else None
    return text

def _local(ioc,kind,original):
    tags=[x.get('name') for x in (ioc.get('tags') or []) if isinstance(x,dict) and x.get('name')]
    return {'odysafeIocIds':[ioc['id']] if ioc.get('id') is not None else [],'sourceIds':[ioc['source_id']] if ioc.get('source_id') is not None else [],
            'sourceNames':[ioc['source_name']] if ioc.get('source_name') else [],'originalType':str(ioc.get('ioc_type') or kind),
            'originalValues':[original],'validation':str(ioc.get('validation_status') or 'Unverified'),'confidence':ioc.get('confidence'),
            'groups':list(ioc.get('groups') or []),'tags':tags,'firstSeen':ioc.get('first_seen'),'lastSeen':ioc.get('last_seen')}
def _producer(name):
    now=utc_now();return {'type':'identity','spec_version':'2.1','id':stix_id('identity',name),'created':now,'modified':now,'name':name,'identity_class':'organization'}

def _object(kind,value,marking,producer_id,extensions):
    info=classify_ioc_type(kind); stix_type=info['stix_type']; common={'spec_version':'2.1','object_marking_refs':[marking]}
    if info['support'] in {'unsupported','contextual'}:return None
    if info['support']=='extension':
        if not extensions:return None
        obj={'type':stix_type,'id':stix_id(stix_type,f'{kind}:{value}'),**common}
        if kind in BLOCKCHAINS:obj.update(currency=kind,address=value)
        elif kind=='arn':obj.update(provider='aws',identifier_type='arn',value=value)
        elif kind in {'iban','webmoney'}:obj.update(account_type=kind,value=value)
        elif kind in {'chineseicp','spanishnif'}:obj.update(scheme=kind,value=value)
        else:obj['value']=value
        return obj
    if stix_type in {'ipv4-addr','ipv6-addr','domain-name','url','email-addr'}:return {'type':stix_type,'id':stix_id(stix_type,value),'value':value,**common}
    if stix_type=='file':
        algorithm=HASH_NAMES[kind][0];return {'type':'file','id':stix_id('file',f'{algorithm}:{value}'),'hashes':{algorithm:value},**common}
    if stix_type=='user-account':return {'type':'user-account','id':stix_id('user-account',f'{kind}:{value}'),'account_type':kind,'account_login':value,**common}
    now=utc_now();obj={'type':stix_type,'id':stix_id(stix_type,value),'created':now,'modified':now,'created_by_ref':producer_id,'name':value,**common}
    if stix_type=='vulnerability':obj['external_references']=[{'source_name':'cve','external_id':value}]
    if stix_type=='attack-pattern':obj['external_references']=[{'source_name':'mitre-attack','external_id':value}]
    return obj
def _merge_local(old,new):
    for key in ('odysafeIocIds','sourceIds','sourceNames','originalValues','groups','tags'):old[key]=list(dict.fromkeys([*old.get(key,[]),*new.get(key,[])]))

def build_bundle(iocs:Iterable[Dict[str,Any]],include_extensions=False,producer_name='ODYSAFE CTI'):
    objects=[];skipped=[];metadata={'objects':{},'omitted':[]};producer=_producer(producer_name);seen={};has_sdo=False
    for ioc in iocs:
        info=classify_ioc_type(ioc.get('ioc_type'));kind=info['odysafe_type'];original=str(ioc.get('ioc_value') or '');value=normalize_value(kind,original)
        if value is None:
            item={'id':str(ioc.get('id') or ''),'type':str(ioc.get('ioc_type') or ''),'reason':'invalid'};skipped.append(item);metadata['omitted'].append(item);continue
        obj=_object(kind,value,TLP_IDS[normalize_tlp(ioc.get('tlp'))],producer['id'],include_extensions)
        if obj is None:
            item={'id':str(ioc.get('id') or ''),'type':str(ioc.get('ioc_type') or ''),'reason':info['support']};skipped.append(item);metadata['omitted'].append({**item,'value':original});continue
        local=_local(ioc,kind,original)
        confidence=CONFIDENCE_VALUES.get(str(ioc.get('confidence') or '').strip().lower())
        if confidence is not None and obj['type'] in {'vulnerability','attack-pattern'}:obj['confidence']=confidence
        if obj['id'] in seen:_merge_local(metadata['objects'][obj['id']],local);continue
        seen[obj['id']]=obj;metadata['objects'][obj['id']]=local;objects.append(obj);has_sdo|=obj['type'] in {'vulnerability','attack-pattern'}
    if has_sdo:objects.insert(0,producer)
    return {'type':'bundle','id':f'bundle--{uuid.uuid4()}','objects':objects},skipped,metadata
def bundle_json(iocs,include_extensions=False,producer_name='ODYSAFE CTI'):
    bundle,skipped,metadata=build_bundle(iocs,include_extensions,producer_name);return json.dumps(bundle,indent=2),skipped,metadata
