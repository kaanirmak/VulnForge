"""Read-time evidence expiry. Freshness is about a snapshot, never a safety claim."""
import copy
import json
import math
import re
import time

INVENTORY_MAX_AGE=86400
INTELLIGENCE_MAX_AGE=3600


def age_state(value,now,limit):
    if type(value) not in (int,float) or not math.isfinite(value) or value<=0 or value>now:
        return 'unknown'
    return 'fresh' if now-value<limit else 'stale'


def assess_scan(scan,now=None,default_branch=None):
    now=time.time() if now is None else now
    coverage=scan.get('coverage') or {}
    if isinstance(coverage,str): coverage=json.loads(coverage)
    reasons=[]
    kind=scan.get('kind')
    if kind!='dependencies': reasons.append('not_default_branch_inventory')
    if scan.get('state')!='complete': reasons.append('scan_'+str(scan.get('state','unknown')))
    if coverage.get('scope')!='dependency_manifests': reasons.append('snapshot_scope_unverified')
    if coverage.get('issues') or coverage.get('files_skipped',0): reasons.append('incomplete_coverage')
    counts=[coverage.get(key) for key in ('files_total','files_scanned','files_skipped')]
    if (any(type(n) is not int or n<0 for n in counts) or not counts[0] or
        counts[1]+counts[2]!=counts[0] or not coverage.get('manifests')):
        reasons.append('manifest_coverage_unverified')
    if not re.fullmatch(r'[0-9a-f]{40}',scan.get('commit_sha') or ''):
        reasons.append('snapshot_sha_unverified')
    if not coverage.get('default_branch') or (default_branch is not None and coverage['default_branch']!=default_branch):
        reasons.append('default_branch_unverified')
    inventory_age=age_state(scan.get('finished_at'),now,INVENTORY_MAX_AGE)
    intelligence_age=age_state(coverage.get('intelligence_checked_at'),now,INTELLIGENCE_MAX_AGE)
    if inventory_age!='fresh': reasons.append('inventory_'+inventory_age)
    if intelligence_age!='fresh': reasons.append('intelligence_'+intelligence_age)
    if coverage.get('intelligence_source') not in ('public_osv','private_osv'):
        reasons.append('intelligence_source_unverified')
    times=[scan.get('started_at'),coverage.get('intelligence_checked_at'),scan.get('finished_at')]
    if (any(type(t) not in (int,float) or not math.isfinite(t) for t in times) or
        not 0<times[0]<=times[1]<=times[2]<=now):
        reasons.append('evidence_timeline_unverified')
    return {'status':'fresh_snapshot' if not reasons else 'needs_review','reasons':reasons,
            'inventory_age':inventory_age,'intelligence_age':intelligence_age,
            'inventory_max_age_seconds':INVENTORY_MAX_AGE,'intelligence_max_age_seconds':INTELLIGENCE_MAX_AGE,
            'scan_id':scan.get('id'),'commit_sha':scan.get('commit_sha'),'scan_state':scan.get('state'),
            'snapshot_started_at':scan.get('started_at'),
            'inventory_observed_at':scan.get('finished_at'),
            'intelligence_checked_at':coverage.get('intelligence_checked_at'),
            'scope':coverage.get('scope','unknown'),'history':'not_verified',
            'snapshot_only':True,'current_head_verified':False,'safe':False}


def repository_evidence(c,repo,now=None):
    row=c.execute('SELECT default_branch,evidence_invalidated_at FROM repositories WHERE full_name=?',(repo,)).fetchone()
    scans=c.execute("SELECT * FROM scans WHERE repo=? AND kind='dependencies' ORDER BY started_at DESC,id DESC LIMIT 2",(repo,)).fetchall()
    if not scans:
        return {'status':'missing','reasons':['no_default_branch_inventory'],'scan_id':None,
                'inventory_age':'unknown','intelligence_age':'unknown','history':'not_verified',
                'snapshot_only':True,'current_head_verified':False,'safe':False}
    latest=dict(scans[0]);result=assess_scan(latest,now,row['default_branch'] if row else '')
    # Timestamp ties have no trustworthy ordering; UUID order is not recency.
    if len(scans)>1 and scans[0]['started_at']==scans[1]['started_at']:
        result['status']='needs_review';result['reasons'].append('scan_order_ambiguous')
    pushed=row['evidence_invalidated_at'] if row else None
    if pushed is not None and pushed>=latest['started_at']:
        result['status']='needs_review';result['reasons'].append('default_branch_push_since_snapshot')
    return result


def recommendation_view(recommendation,freshness,now=None):
    result=copy.deepcopy(recommendation)
    now=time.time() if now is None else now
    current=(freshness['status']=='fresh_snapshot' and
             age_state(result.get('verified_at'),now,INTELLIGENCE_MAX_AGE)=='fresh')
    result['freshness']='fresh_snapshot' if current else 'needs_reverification'
    if not current:
        result['previous_recommended_version']=result.get('recommended_version')
        result['recommended_version']=None
        result['previous_status']=result.get('status')
        result['status']='needs_reverification'
        result['note']='Snapshot or intelligence evidence is missing, incomplete or expired; recheck before considering an upgrade.'
    result['requires_review']=True
    return result


def scan_evidence(c,scan,cache=None,now=None):
    result=assess_scan(scan,now)
    if scan.get('kind')=='dependencies':
        cache={} if cache is None else cache
        if scan['repo'] not in cache: cache[scan['repo']]=repository_evidence(c,scan['repo'],now)
        current=cache[scan['repo']]
        result['reasons']=list(dict.fromkeys(result['reasons']+current['reasons']))
        if scan.get('id')!=current.get('scan_id'): result['reasons'].append('scan_superseded')
        if result['reasons']: result['status']='needs_review'
    return result


def impact_view(c,item,cache=None,now=None):
    result=copy.deepcopy(item)
    cache={} if cache is None else cache
    if item['repo'] not in cache: cache[item['repo']]=repository_evidence(c,item['repo'],now)
    freshness=copy.deepcopy(cache[item['repo']])
    if item.get('scan_id')!=freshness.get('scan_id'):
        freshness['reasons'].append('impact_snapshot_superseded');freshness['status']='needs_review'
    advisory=c.execute('SELECT source_sha256,withdrawn FROM advisories WHERE id=?',(item['advisory_id'],)).fetchone()
    if advisory is None or item.get('evidence',{}).get('advisory_sha256')!=advisory['source_sha256']:
        freshness['reasons'].append('advisory_revision_unverified');freshness['status']='needs_review'
    if item.get('evidence',{}).get('stale') or not item.get('evidence',{}).get('coverage_complete'):
        freshness['reasons'].append('impact_coverage_incomplete');freshness['status']='needs_review'
    result['freshness']=freshness
    # Preserve history separately. Existing consumers of `state` must also fail
    # closed rather than present an expired negative as current confirmation.
    result['observed_state']=item['state']
    result['assessment_state']=('withdrawn' if advisory and advisory['withdrawn'] else
        'under_investigation' if item['state']=='not_affected' and freshness['status']!='fresh_snapshot' else item['state'])
    result['state']=result['assessment_state']
    result['recommendations']=[recommendation_view(rec,freshness,now) for rec in item['recommendations']]
    if result['assessment_state']=='withdrawn': result['recommendations']=[]
    return result


def finding_view(c,item,cache=None,now=None):
    result=copy.deepcopy(item)
    details=result.get('details',{})
    if isinstance(details,str): details=json.loads(details)
    result['details']=details
    rec=details.get('update_recommendation')
    if not rec: return result
    view=impact_view(c,{'repo':item['repo'],'advisory_id':details.get('advisory_id',details.get('osv_id')),
        'scan_id':details.get('scan_id'),'state':'affected','recommendations':[rec],
        'evidence':{'advisory_sha256':details.get('advisory_sha256'),'coverage_complete':True}},cache,now)
    details['update_recommendation']=view['recommendations'][0] if view['recommendations'] else None
    details['evidence_status']=view['freshness']
    return result
