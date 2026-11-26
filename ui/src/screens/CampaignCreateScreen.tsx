import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ChevronLeft, Plus, Shield, Target, Info } from 'lucide-react';
import { ApiError, apiClient, generateIdempotencyKey, toUiError } from '../api/client';
import type { AppError, CapabilityItem, CreateCampaignRequest, UiError } from '../api/types';
import { ErrorDisplay, InlineFieldError } from '../components/ErrorDisplay';
import { RoEPolicyFields } from '../components/RoEPolicyFields';
import { InternetConfirmModal } from '../components/InternetConfirmModal';
import {
  SAFE_LAB_POLICY_DEFAULTS,
  mapServerFieldToKey,
  validateCampaignForm,
  type CampaignFormValues,
} from '../utils/campaignValidation';

const INITIAL_VALUES: CampaignFormValues = {
  ...SAFE_LAB_POLICY_DEFAULTS,
  name: '',
  objective: '',
  authorizationLabel: '',
  domainsText: '',
  ipsText: '',
  keywordsText: '',
};

export const CampaignCreateScreen: React.FC = () => {
  const navigate = useNavigate();
  const [values, setValues] = useState<CampaignFormValues>(INITIAL_VALUES);
  const [capabilities, setCapabilities] = useState<CapabilityItem[]>([]);
  const [clientErrors, setClientErrors] = useState<Record<string, string>>({});
  const [serverErrors, setServerErrors] = useState<Record<string, AppError | undefined>>({});
  const [topError, setTopError] = useState<UiError | null>(null);
  const [idempotencyKey, setIdempotencyKey] = useState<string>(() => generateIdempotencyKey());
  const [submitting, setSubmitting] = useState(false);
  const [pendingInternetPayload, setPendingInternetPayload] = useState<CreateCampaignRequest | null>(
    null
  );

  useEffect(() => {
    let mounted = true;
    apiClient
      .listCapabilities()
      .then((res) => {
        if (mounted) setCapabilities(res.items);
      })
      .catch(() => {
        // Capability quick-select chips are optional helper metadata
      });
    return () => {
      mounted = false;
    };
  }, []);

  const updateValues = (patch: Partial<CampaignFormValues>) => {
    setValues((prev) => ({ ...prev, ...patch }));
    // Rotate Idempotency-Key whenever the user edits the payload; retries on identical input keep the same key.
    setIdempotencyKey(generateIdempotencyKey());
    setTopError(null);

    const changedKeys = Object.keys(patch);
    setClientErrors((prev) => {
      const next = { ...prev };
      for (const k of changedKeys) {
        delete next[k];
      }
      if (
        changedKeys.includes('domainsText') ||
        changedKeys.includes('ipsText') ||
        changedKeys.includes('keywordsText')
      ) {
        delete next.targets;
      }
      return next;
    });
    setServerErrors((prev) => {
      const next = { ...prev };
      for (const k of changedKeys) {
        delete next[k];
      }
      if (
        changedKeys.includes('domainsText') ||
        changedKeys.includes('ipsText') ||
        changedKeys.includes('keywordsText')
      ) {
        delete next.targets;
      }
      return next;
    });
  };

  const executeSubmit = async (payload: CreateCampaignRequest) => {
    try {
      setSubmitting(true);
      setTopError(null);
      setServerErrors({});
      const created = await apiClient.createCampaign(payload, { idempotencyKey });
      setPendingInternetPayload(null);
      navigate(`/campaigns/${created.campaign_id}`);
    } catch (err: unknown) {
      setPendingInternetPayload(null);
      setTopError(toUiError(err, '/campaigns'));
      if (err instanceof ApiError && err.appError) {
        const mappedKey = mapServerFieldToKey(err.appError.field);
        if (mappedKey) {
          setServerErrors({ [mappedKey]: err.appError });
        }
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const { errors, payload } = validateCampaignForm(values);
    setClientErrors(errors);
    setServerErrors({});
    setTopError(null);

    if (Object.keys(errors).length > 0 || !payload) {
      return;
    }

    if (payload.policy.network_profile === 'internet') {
      setPendingInternetPayload(payload);
      return;
    }

    await executeSubmit(payload);
  };

  return (
    <div>
      <div className="filter-bar">
        <div>
          <div style={{ marginBottom: 8 }}>
            <Link
              to="/campaigns"
              className="btn btn-sm"
              style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}
            >
              <ChevronLeft size={14} /> Quay lại danh sách chiến dịch
            </Link>
          </div>
          <h1 style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--ink)' }}>
            Tạo chiến dịch mới (Create Campaign)
          </h1>
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--muted)', marginTop: 2 }}>
            Gửi yêu cầu <code className="mono">POST /api/v2/campaigns</code> kèm{' '}
            <code className="mono">Idempotency-Key</code> và bản chụp RoE theo hợp đồng{' '}
            <code className="mono">campaign-create.v2</code>.
          </p>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
          <span className="brand-badge">Idempotency-Key: {idempotencyKey}</span>
          <span style={{ fontSize: '11px', color: 'var(--muted)' }}>
            Tự động giữ nguyên khi thử lại cùng nội dung; tự cấp mới khi chỉnh sửa.
          </span>
        </div>
      </div>

      {topError && (
        <div style={{ marginBottom: 16 }}>
          <ErrorDisplay error={topError} />
        </div>
      )}

      <form onSubmit={handleSubmit} noValidate>
        <div className="form-layout-2col">
          {/* Left column: Metadata + Targets */}
          <div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                <Info size={18} style={{ color: 'var(--accent)' }} />
                <span>Thông tin chiến dịch</span>
              </div>

              <div className="form-field">
                <label className="form-label" htmlFor="campaign-name">
                  Tên chiến dịch (name) *
                </label>
                <input
                  id="campaign-name"
                  type="text"
                  className="form-input"
                  maxLength={200}
                  placeholder="Ví dụ: Khảo sát vùng lab nội bộ"
                  value={values.name}
                  disabled={submitting}
                  aria-invalid={Boolean(clientErrors.name || serverErrors.name)}
                  onChange={(e) => updateValues({ name: e.target.value })}
                />
                <InlineFieldError clientError={clientErrors.name} serverError={serverErrors.name} />
              </div>

              <div className="form-field">
                <label className="form-label" htmlFor="campaign-objective">
                  Mục tiêu tác chiến (objective) *
                </label>
                <textarea
                  id="campaign-objective"
                  className="form-textarea"
                  style={{ fontFamily: 'inherit', minHeight: 84 }}
                  maxLength={4000}
                  placeholder="Mô tả mục tiêu khảo sát bề mặt tấn công trong phạm vi được phép..."
                  value={values.objective}
                  disabled={submitting}
                  aria-invalid={Boolean(clientErrors.objective || serverErrors.objective)}
                  onChange={(e) => updateValues({ objective: e.target.value })}
                />
                <InlineFieldError
                  clientError={clientErrors.objective}
                  serverError={serverErrors.objective}
                />
              </div>

              <div className="form-field" style={{ marginBottom: 0 }}>
                <label className="form-label" htmlFor="campaign-authorization-label">
                  Tham chiếu ủy quyền (labels.authorization — tùy chọn)
                </label>
                <input
                  id="campaign-authorization-label"
                  type="text"
                  className="form-input"
                  maxLength={200}
                  placeholder="Ví dụ: owner, item 63, 2026-11-25"
                  value={values.authorizationLabel}
                  disabled={submitting}
                  aria-invalid={Boolean(
                    clientErrors.authorizationLabel || serverErrors.authorizationLabel
                  )}
                  onChange={(e) => updateValues({ authorizationLabel: e.target.value })}
                />
                <span className="form-help">
                  Hợp đồng <code className="mono">campaign-create.v2</code> chưa có trường{' '}
                  <code className="mono">authorization_reference</code> riêng; giá trị được ghi vào{' '}
                  <code className="mono">labels.authorization</code> để M01/M06 lưu nhật ký kiểm toán
                  (không hiển thị lại trên <code className="mono">GET /campaigns/&#123;id&#125;</code>).
                </span>
                <InlineFieldError
                  clientError={clientErrors.authorizationLabel}
                  serverError={serverErrors.authorizationLabel}
                />
              </div>
            </div>

            <div className="card">
              <div className="card-title" style={{ marginBottom: 8 }}>
                <Target size={18} style={{ color: 'var(--accent)' }} />
                <span>Mục tiêu đầu vào (Target Seeds) *</span>
              </div>
              <p className="form-help" style={{ marginBottom: 12 }}>
                Nhập mỗi mục tiêu trên một dòng. Cần ít nhất một mục tiêu thuộc Domain, IP/CIDR hoặc Từ khóa.
              </p>

              <InlineFieldError clientError={clientErrors.targets} serverError={serverErrors.targets} />

              <div className="form-field" style={{ marginTop: clientErrors.targets || serverErrors.targets ? 10 : 0 }}>
                <label className="form-label" htmlFor="campaign-targets-domains">
                  Tên miền (targets.domains — mỗi dòng một tên miền)
                </label>
                <textarea
                  id="campaign-targets-domains"
                  className="form-textarea"
                  placeholder="lab.aegis.test"
                  value={values.domainsText}
                  disabled={submitting}
                  aria-invalid={Boolean(clientErrors.domainsText || serverErrors.domainsText)}
                  onChange={(e) => updateValues({ domainsText: e.target.value })}
                />
                <InlineFieldError
                  clientError={clientErrors.domainsText}
                  serverError={serverErrors.domainsText}
                />
              </div>

              <div className="form-field">
                <label className="form-label" htmlFor="campaign-targets-ips">
                  Địa chỉ IP / CIDR (targets.ips — mỗi dòng một IP hoặc CIDR)
                </label>
                <textarea
                  id="campaign-targets-ips"
                  className="form-textarea"
                  placeholder="10.20.0.0/24&#10;203.0.113.10"
                  value={values.ipsText}
                  disabled={submitting}
                  aria-invalid={Boolean(clientErrors.ipsText || serverErrors.ipsText)}
                  onChange={(e) => updateValues({ ipsText: e.target.value })}
                />
                <InlineFieldError clientError={clientErrors.ipsText} serverError={serverErrors.ipsText} />
              </div>

              <div className="form-field" style={{ marginBottom: 0 }}>
                <label className="form-label" htmlFor="campaign-targets-keywords">
                  Từ khóa (targets.keywords — mỗi dòng một từ khóa, 2–200 ký tự)
                </label>
                <textarea
                  id="campaign-targets-keywords"
                  className="form-textarea"
                  placeholder="acme corp"
                  value={values.keywordsText}
                  disabled={submitting}
                  aria-invalid={Boolean(clientErrors.keywordsText || serverErrors.keywordsText)}
                  onChange={(e) => updateValues({ keywordsText: e.target.value })}
                />
                <InlineFieldError
                  clientError={clientErrors.keywordsText}
                  serverError={serverErrors.keywordsText}
                />
              </div>
            </div>
          </div>

          {/* Right column: RoE Policy */}
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              <Shield size={18} style={{ color: 'var(--accent)' }} />
              <span>Chính sách Thực thi RoE (roe-policy.v2)</span>
            </div>

            <RoEPolicyFields
              idPrefix="create-policy"
              values={values}
              onChange={(patch) => updateValues(patch)}
              clientErrors={clientErrors}
              serverErrors={serverErrors}
              capabilities={capabilities}
              disabled={submitting}
            />
          </div>
        </div>

        <div
          className="card"
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 12,
          }}
        >
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--muted)' }}>
            Mặc định an toàn: <code className="mono">network_profile=lab</code>, giới hạn tốc độ &amp; ngân sách thấp.
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            <Link to="/campaigns" className="btn">
              Hủy
            </Link>
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              <Plus size={15} />
              {submitting
                ? 'Đang tạo chiến dịch...'
                : values.networkProfile === 'internet'
                ? 'Kiểm tra & Xác nhận Internet'
                : 'Tạo chiến dịch'}
            </button>
          </div>
        </div>
      </form>

      <InternetConfirmModal
        isOpen={pendingInternetPayload !== null}
        policy={pendingInternetPayload?.policy ?? null}
        targets={pendingInternetPayload?.targets}
        authorizationLabel={values.authorizationLabel}
        submitting={submitting}
        onCancel={() => setPendingInternetPayload(null)}
        onConfirm={() => pendingInternetPayload && executeSubmit(pendingInternetPayload)}
      />
    </div>
  );
};
