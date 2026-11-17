-- Usage is consumed work, never a credit against a campaign budget.
-- Preserve prior append-only rows, including invalid historical measurements.
BEGIN;
SET LOCAL search_path = aegis, public;
ALTER TABLE model_usage
  ADD CONSTRAINT model_usage_input_nonnegative CHECK (input_tokens >= 0) NOT VALID,
  ADD CONSTRAINT model_usage_output_nonnegative CHECK (output_tokens >= 0) NOT VALID,
  ADD CONSTRAINT model_usage_cost_nonnegative CHECK (cost_usd >= 0) NOT VALID,
  ADD CONSTRAINT model_usage_latency_nonnegative CHECK (latency_ms >= 0) NOT VALID;
COMMENT ON TABLE model_usage IS
  'M04 append-only usage. New rows require nonnegative tokens/cost/latency. NOT VALID preserves earlier measurements; readers must surface invalid historical rows as an integrity error, never use them to reduce consumed budget or report an exact total.';
COMMIT;
