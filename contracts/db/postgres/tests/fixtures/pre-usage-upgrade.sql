-- Only for an isolated upgrade test after0003 and before0004.
-- Prove invalid append-only history is preserved without granting new credits.
INSERT INTO aegis.model_usage
  (usage_id,provider,model,input_tokens,output_tokens,cost_usd,latency_ms,status,trace_id)
VALUES ('01900000-0000-7000-8000-000000009905','openai','historical-invalid',-1,-2,-1,-1,'ok',repeat('9',32));
