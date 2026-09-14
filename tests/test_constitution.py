"""Confirmed security principles require class, method and unique service binding."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from websec_validator import constitution, findings


def endpoint(service='a', method='POST'):
    return {'method':method,'path':'/orders','code_path':service+'/app.js','service_id':service,
            'analyzed':True,'guarded':False,'public_hint':False}


def confirmed(**changes):
    return {'category':'access-control','attack_class':'missing-auth','method':'POST','location':'/orders',
            'file':'a/app.js','service_id':'a','evidence_verified':True,'verification_state':'confirmed-vulnerable',
            'evidence':[{'layer':'dynamic','confirmed':True}],**changes}


class ConstitutionEvidenceTests(unittest.TestCase):
    def test_blocked_or_unconfirmed_observation_never_violates_principle(self):
        facts={'authz':{'endpoint_guards':[endpoint()]}}
        dynamic={'write_auth_enforcement':{'results':[{'method':'POST','path':'/orders','status':403,'state':'blocked','verdict':'blocked'}]}}
        ledger=findings.build_ledger(facts,None,dynamic)
        self.assertTrue(ledger['findings'][0]['dynamic_observation'])
        self.assertEqual(constitution.build(facts,ledger)[0]['status'],'VERIFY')

    def test_positive_missing_auth_evidence_has_exact_class_method_service(self):
        facts={'authz':{'endpoint_guards':[endpoint(),endpoint('b'),endpoint('a','GET')]}}
        invariants=constitution.build(facts,{'findings':[confirmed()]})[:3]
        self.assertEqual([row['status'] for row in invariants],['VIOLATED','VERIFY','VERIFY'])
        for update in ({'attack_class':'bola'},{'evidence_verified':False},{'verification_state':'unconfirmed'},
                       {'method':'DELETE'},{'service_id':'b','file':'a/app.js'}):
            self.assertTrue(all(row['status']=='VERIFY' for row in constitution.build(facts,{'findings':[confirmed(**update)]})[:3]))

    def test_unscoped_same_path_evidence_remains_unverified(self):
        facts={'authz':{'endpoint_guards':[endpoint(),endpoint('b')]}}
        evidence=confirmed();evidence.pop('service_id');evidence.pop('file')
        self.assertEqual([row['status'] for row in constitution.build(facts,{'findings':[evidence]})[:2]],['VERIFY','VERIFY'])

    def test_runtime_observation_does_not_fan_out_across_services(self):
        facts={'authz':{'endpoint_guards':[endpoint(),endpoint('b')]}}
        observation={'method':'POST','path':'/orders','status':200,'state':'candidate','verdict':'reachable'}
        ledger=findings.build_ledger(facts,None,{'write_auth_enforcement':{'results':[observation]}})
        self.assertEqual(len(ledger['findings']),2)
        self.assertTrue(all(row.get('dynamic_association')=='unknown' for row in ledger['findings']))
        observation['service_id']='a'
        ledger=findings.build_ledger(facts,None,{'write_auth_enforcement':{'results':[observation]}})
        rows={row['service_id']:row for row in ledger['findings']}
        self.assertIn('dynamic_observation',rows['a']);self.assertNotIn('dynamic_observation',rows['b'])
        self.assertNotEqual(rows['a']['fingerprint'],rows['b']['fingerprint'])

    def test_two_scoped_observations_are_order_independent_and_conflicts_unknown(self):
        facts={'authz':{'endpoint_guards':[endpoint(),endpoint('b')]}}
        rows=[{'method':'POST','path':'/orders','service_id':'a','status':200},
              {'method':'POST','path':'/orders','service_id':'b','status':403}]
        for observations in (rows,list(reversed(rows))):
            ledger=findings.build_ledger(facts,None,{'write_auth_enforcement':{'results':observations}})
            self.assertEqual({row['service_id']:row.get('dynamic_observation',{}).get('status') for row in ledger['findings']},
                             {'a':200,'b':403})
        conflict=rows+[dict(rows[0],status=403)]
        ledger=findings.build_ledger(facts,None,{'write_auth_enforcement':{'results':conflict}})
        current={row['service_id']:row for row in ledger['findings']}
        self.assertNotIn('dynamic_observation',current['a'])
        self.assertEqual(current['a']['dynamic_association'],'unknown')
        self.assertEqual(current['b']['dynamic_observation']['status'],403)

if __name__=='__main__':unittest.main()
