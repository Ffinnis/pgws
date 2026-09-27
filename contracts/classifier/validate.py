#!/usr/bin/env python3
"""Validate proposed contracts only. Requires jsonschema; trains no model."""
from pathlib import Path
import copy,json,math
from jsonschema import Draft202012Validator
ROOT=Path(__file__).resolve().parent
checks=[]
def check(condition, name):
 if not condition: raise ValueError(name)
 checks.append(name)
spec=json.loads((ROOT/'spec.json').read_text());a=spec['architecture'];labels=spec['labels']
check(len(labels)==len(set(labels))==a['class_count']==24,'24 distinct ordered semantic labels')
check(a['input_dimension']==a['hashed_feature_count']+a['numeric_feature_count']==16416,'Feature dimensions agree')
f=spec['feature_contract']['numeric_features']
check(len(f)==32 and [x['index'] for x in f]==list(range(16384,16416)),'32 contiguous numeric features')
check(a['weight_matrix_bytes']==a['class_count']*a['input_dimension']*4==1575936,'FP32 matrix size is 1,575,936 bytes')
check(a['bias_bytes']==96,'FP32 bias size is 96 bytes')
check(math.isclose(sum(spec['training']['split_fractions'].values()),1),'Split fractions sum to one')
check(spec['safety']['auto_accept_default'] is False and spec['safety']['model_may_authorize_raw_copy'] is False,'Automatic acceptance off; model cannot authorize raw copying')
check(not spec['safety']['classifiers_in_cdc_path'] and not spec['safety']['classifiers_in_workspace_creation_path'],'No classifier in CDC or workspace creation')
check(not spec['trained_artifacts_included'] and not spec['training']['corpus_exists'],'No trained-model or existing-corpus claim')
plan=spec['training']['auto_accept_family_plan']
required_families=spec['unmeasured_acceptance_targets']['minimum_test_application_families_per_auto_class']
check(plan['minimum_held_out_families_per_enabled_class']==required_families,'Acquisition and release gates agree on held-out families per class')
check(math.floor(plan['nominal_total_family_lower_bound']*spec['training']['split_fractions']['test'])>=required_families,'Nominal auto-accept corpus can hold the minimum test families')
check(plan['actual_per_class_split_manifest_required'] and plan['sufficient_accepted_cases_required'] and plan['independent_calibration_groups_required'],'Nominal total cannot replace per-class evidence and independent calibration')
check(plan['insufficient_evidence_action']=='disable_auto_accept_for_class','Insufficient acquisition evidence disables automatic acceptance')
schema=json.loads((ROOT/'training-record.schema.json').read_text());Draft202012Validator.check_schema(schema)
Draft202012Validator.check_schema(json.loads((ROOT/'column-profile.schema.json').read_text()))
v=Draft202012Validator(schema);base=json.loads((ROOT/'training-record.example.json').read_text())
cases=[('synthetic example',base,True)]
def mutated(name,fn):
 x=copy.deepcopy(base);fn(x);cases.append((name,x,False))
mutated('raw sample payload forbidden',lambda x:x['profile'].update({'raw_values':['Alice']}))
mutated('unknown label forbidden',lambda x:x.update({'label':'safe_to_copy'}))
mutated('numeric values bounded',lambda x:x['profile']['numeric_features'].update({'null_fraction':2}))
mutated('missing provenance forbidden',lambda x:x.pop('provenance'))
mutated('arbitrary executable field forbidden',lambda x:x.update({'transform_sql':'SELECT 1'}))
mutated('unreviewed example forbidden',lambda x:x['review'].update({'status':'unreviewed'}))
mutated('missing feature forbidden',lambda x:x['profile']['numeric_features'].pop('text_like'))
mutated('unknown feature contract forbidden',lambda x:x['profile'].update({'feature_contract_id':'unknown'}))
for name,x,expected in cases:
 check((not list(v.iter_errors(x)))==expected,f'Example: {name}')
print(json.dumps({'status':'classifier_contract_checks_passed','check_count':len(checks),'checks':checks,'not_validated':['No model training or evaluation','No Python/Go inference parity','No empirical latency/RSS benchmark','No live database sampling or CDC','No privacy guarantee or complete feature/parser implementation']},indent=2))
