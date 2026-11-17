-- Run after0004; transaction rollback leaves the test database unchanged.
SET search_path=aegis,public;
BEGIN;
DO $$
DECLARE blocked int := 0; k text; sample jsonb;
BEGIN
 sample := jsonb_build_object('usage_id','01900000-0000-7000-8000-000000009906',
   'provider','openai','model','fixture','input_tokens',0,'output_tokens',0,
   'cost_usd',0,'latency_ms',0,'status','ok','trace_id',repeat('9',32));
 FOREACH k IN ARRAY ARRAY['input_tokens','output_tokens','cost_usd','latency_ms'] LOOP
  BEGIN
   INSERT INTO model_usage SELECT (jsonb_populate_record(NULL::model_usage,
     sample || jsonb_build_object(k,-1,'created_at',now()))).*;
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;
 END LOOP;
 IF blocked <> 4 THEN RAISE EXCEPTION 'only % / 4 negative usage values rejected',blocked; END IF;
 INSERT INTO model_usage SELECT (jsonb_populate_record(NULL::model_usage,
   sample || jsonb_build_object('created_at',now()))).*;
 IF EXISTS(SELECT 1 FROM model_usage WHERE model='historical-invalid') AND
    NOT EXISTS(SELECT 1 FROM model_usage WHERE model='historical-invalid'
       AND input_tokens=-1 AND output_tokens=-2 AND cost_usd=-1 AND latency_ms=-1) THEN
   RAISE EXCEPTION 'invalid append-only history was rewritten';
 END IF;
 RAISE NOTICE 'usage: 4/4 negative inputs rejected; zero usage accepted; historical rows preserved';
END $$;
ROLLBACK;
