"""Contract v2 regression: scheduling semantics and rejection of retired request shapes."""
import copy
import json
import runpy
from pathlib import Path
import unittest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
ROOT=Path(__file__).resolve().parents[1]
DOCS=[json.loads(p.read_text()) for p in ROOT.rglob('*.schema.json')]
REGISTRY=Registry().with_resources((d['$id'],Resource.from_contents(d)) for d in DOCS)
ID='01934f6a-0000-7000-8000-000000000001'
OTHER='01934f6a-0000-7000-8000-000000000002'
check_manifest_binding=runpy.run_path(str(ROOT/'tests/manifest_binding.py'))['check_manifest_binding']
FORMAT_CHECKER=runpy.run_path(str(ROOT/'validation.py'))['format_checker']()
def validator(name):
 return Draft202012Validator(json.loads((ROOT/name).read_text()),registry=REGISTRY,format_checker=FORMAT_CHECKER)
class ToolContracts(unittest.TestCase):
 def test_campaign_explicit_limits_and_retired_fields(self):
  v=validator('campaign/roe-policy.v2.schema.json'); base={'network_profile':'lab','max_parallel_jobs':10,'max_duration_hours':168}
  self.assertTrue(v.is_valid(base))
  # internet (the default) needs the structured authorization; lab does not.
  self.assertFalse(v.is_valid({'max_parallel_jobs':10,'max_duration_hours':168}))
  self.assertTrue(v.is_valid({'network_profile':'lab','max_parallel_jobs':10,'max_duration_hours':168}))
  for key,value in [('scan_profile','passive'),('max_impact_tier','T3'),('t3_approval_mode','auto'),('approval_required_tiers',['T3'])]:
   self.assertFalse(v.is_valid(dict(base,**{key:value})),key)
 def test_mcp_priority_and_dependency_bounds(self):
  v=validator('mcp/capability-request.v2.schema.json'); base={'input':{'targets':['example.test']},'rationale':'Discover declared domain','objective_id':ID}
  self.assertTrue(v.is_valid(base))
  self.assertTrue(v.is_valid(dict(base,priority=100,depends_on=[OTHER])))
  for changes in [{'priority':101},{'priority':-1},{'priority':1.2},{'depends_on':[OTHER,OTHER]},{'depends_on':['not-a-uuid']},{'profile':'standard'},{'impact_tier':'T0'}]:
   self.assertFalse(v.is_valid(dict(base,**changes)),changes)
 def test_approved_task_requires_resolved_scheduling(self):
  v=validator('capability/approved-task.v2.schema.json')
  d=json.loads((ROOT/'fixtures/valid/approved-task.subfinder.json').read_text())
  self.assertEqual(list(v.iter_errors(d)),[])
  for field in ['priority','depends_on']:
   bad=copy.deepcopy(d);bad.pop(field);self.assertFalse(v.is_valid(bad))
  self.assertFalse(v.is_valid(dict(d,profile='standard')))
 def test_receipt_is_shared_and_quarantine_is_structured(self):
  import yaml
  v=validator('ingestion/ingest-receipt.v2.schema.json')
  d=json.loads((ROOT/'fixtures/valid/ingest-receipt.json').read_text())
  self.assertTrue(v.is_valid(d))
  self.assertTrue(v.is_valid(dict(d,quarantined=[])))
  self.assertFalse(v.is_valid(dict(d,quarantined=['/results/assets/0'])))
  self.assertFalse(v.is_valid(dict(d,quarantined=[{'pointer':'/x','gate':'G1'}])))
  api=yaml.safe_load((ROOT/'api/openapi.v2.yaml').read_text())
  self.assertEqual(api['paths']['/ingestion/results']['post']['responses']['202']['content']['application/json']['schema'],{'$ref':'../ingestion/ingest-receipt.v2.schema.json'})
 def test_agent_session_has_only_dispatched_job_ids(self):
  v=validator('agent/session-result.v2.schema.json')
  d={'session_id':ID,'decision':'wait','steps_used':1,'requested_jobs':[OTHER],'denied':[],'hypothesis_updates':[],'usage':{'input_tokens':1,'output_tokens':1,'cost_usd':0}}
  self.assertTrue(v.is_valid(d))
  proposal={'input':{},'rationale':'Review known asset','objective_id':ID}
  self.assertFalse(v.is_valid(dict(d,proposals=[proposal])))
  bad=copy.deepcopy(d);bad.pop('requested_jobs');bad['proposals']=[proposal]
  self.assertFalse(v.is_valid(bad))
  self.assertFalse(validator('mcp/capability-request.v2.schema.json').is_valid(dict(proposal,capability='dns.resolve')))
 def test_task_pins_exact_manifest_and_adapter(self):
  import yaml
  v=validator('capability/approved-task.v2.schema.json')
  d=json.loads((ROOT/'fixtures/valid/approved-task.subfinder.json').read_text())
  raw=(ROOT/'fixtures/valid/manifest.subfinder.yaml').read_bytes()
  self.assertEqual(check_manifest_binding(d,raw),[])
  for field in ['adapter_version','manifest_sha256']:
   bad=copy.deepcopy(d);bad.pop(field);self.assertFalse(v.is_valid(bad),field)
  variant=yaml.safe_load(raw);variant['metadata']['version']='1.1.0';variant['spec']['budget']['cpu']=2
  altered=yaml.safe_dump(variant,sort_keys=False).encode()
  self.assertTrue(validator('capability/provider-manifest.v2.schema.json').is_valid(variant))
  self.assertTrue(check_manifest_binding(d,altered))
  self.assertTrue(check_manifest_binding(dict(d,provider_version='wrong'),raw))
  self.assertTrue(check_manifest_binding(dict(d,image_digest='sha256:'+'0'*64),raw))
  self.assertTrue(check_manifest_binding(d,raw+b'\n'))
  self.assertFalse(v.is_valid(dict(d,manifest_sha256='not-a-sha256')))
 def test_manifest_has_concrete_input_and_runtime(self):
  import yaml
  v=validator('capability/provider-manifest.v2.schema.json'); d=yaml.safe_load((ROOT/'fixtures/valid/manifest.subfinder.yaml').read_text())
  self.assertTrue(v.is_valid(d))
  for field,value in [('impactTier','T0'),('safety',{'defaultProfile':'passive'})]:
   bad=copy.deepcopy(d);bad['spec'][field]=value;self.assertFalse(v.is_valid(bad))
  bad=copy.deepcopy(d);bad['spec']['runtime']['type']='rest';self.assertFalse(v.is_valid(bad))
 def test_model_direct_config_and_finding_severity_preserved(self):
  v=validator('finding/severity-assessment.v2.schema.json'); d=json.loads((ROOT/'fixtures/valid/severity-assessment.json').read_text())
  self.assertTrue(v.is_valid(d)); self.assertEqual(d['severity'],'HIGH')
  bad=copy.deepcopy(d);bad['assessed_by']['profile']='MID';self.assertFalse(v.is_valid(bad))
 def test_error_does_not_request_retired_approval_workflow(self):
  v=validator('common/error.v2.schema.json')
  self.assertTrue(v.is_valid({'code':'INPUT_INVALID','message':'Missing target','next_action':'FIX_INPUT'}))
  self.assertFalse(v.is_valid({'code':'APPROVAL_REQUIRED','message':'Legacy approval','next_action':'FIX_INPUT'}))
  self.assertFalse(v.is_valid({'code':'POLICY_DENIED','message':'Legacy wait','next_action':'WAIT_APPROVAL'}))
 def test_current_schema_has_no_retired_properties(self):
  banned={'impact_tier','impactTier','profile','profiles','scan_profile','max_impact_tier','t3_approval_mode','approval_required_tiers','defaultProfile'}
  def walk(x):
   if isinstance(x,dict):
    self.assertFalse(set(x.get('properties',{})) & banned)
    for value in x.values():walk(value)
   elif isinstance(x,list):
    for value in x:walk(value)
  for doc in DOCS:walk(doc)
if __name__=='__main__':unittest.main()
