import React, { useEffect } from 'react';
import { Play, Shield, Sparkles, X } from 'lucide-react';

export interface NewEngagementModalProps {
  open: boolean;
  brief: string;
  useCloudSandbox: boolean;
  isStreaming: boolean;
  onClose: () => void;
  onBriefChange: (brief: string) => void;
  onApplyPreset: (preset: 'firecrawl' | 'candid') => void;
  onToggleSandbox: (enabled: boolean) => void;
  onLaunch: () => void;
}

export const NewEngagementModal: React.FC<NewEngagementModalProps> = ({
  open,
  brief,
  useCloudSandbox,
  isStreaming,
  onClose,
  onBriefChange,
  onApplyPreset,
  onToggleSandbox,
  onLaunch,
}) => {
  useEffect(() => {
    if (!open || typeof document === 'undefined') return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  const canLaunch = brief.trim().length > 0 && !isStreaming;

  return (
    <div
      className="oc-modal-overlay"
      role="dialog"
      aria-modal="true"
      aria-label="Launch New Bugcrowd Engagement"
      onClick={onClose}
    >
      <div
        className="oc-modal-panel is-launchpad"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="oc-modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
            <span className="oc-brand-mark" aria-hidden="true">
              <Shield size={14} />
            </span>
            <div>
              <h2 style={{ margin: 0, fontSize: '15px', fontWeight: 600 }}>
                Launch New Cyber Squad Engagement
              </h2>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                Paste a Bugcrowd brief to lock scope.yaml and stream multi-agent
                recon &amp; hypothesis testing live.
              </div>
            </div>
          </div>

          <button
            type="button"
            id="btn-close-new-engagement"
            className="oc-icon-btn"
            onClick={onClose}
            aria-label="Close new engagement modal"
          >
            <X size={16} />
          </button>
        </div>

        <div
          className="oc-modal-body"
          style={{ display: 'flex', flexDirection: 'column', gap: 12 }}
        >
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 8,
            }}
          >
            <span style={{ fontSize: '12px', fontWeight: 600 }}>
              Real Bugcrowd Safe-Harbor VDP Briefs
            </span>

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              <button
                type="button"
                id="btn-preset-firecrawl"
                className="oc-btn"
                onClick={() => onApplyPreset('firecrawl')}
              >
                <Sparkles size={12} style={{ color: 'var(--cyan-fg)' }} />
                <span>Firecrawl VDP Brief</span>
              </button>

              <button
                type="button"
                id="btn-preset-candid"
                className="oc-btn"
                onClick={() => onApplyPreset('candid')}
              >
                <Sparkles size={12} style={{ color: 'var(--amber-fg)' }} />
                <span>Candid VDP Pro Brief</span>
              </button>
            </div>
          </div>

          <textarea
            id="input-engagement-brief"
            rows={12}
            className="oc-textarea-card mono"
            placeholder="Paste Bugcrowd program scope, out-of-scope exclusions, rate limits, and researcher header rules…"
            value={brief}
            onChange={(e) => onBriefChange(e.target.value)}
          />
        </div>

        <div
          className="oc-modal-footer"
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 10,
          }}
        >
          <label
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 8,
              fontSize: '12px',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
            }}
          >
            <input
              type="checkbox"
              id="toggle-e2b-sandbox"
              checked={useCloudSandbox}
              onChange={(e) => onToggleSandbox(e.target.checked)}
            />
            <span>
              Execute inside isolated <strong>E2B Cloud Sandbox</strong> + HTTP
              451 Mandatory Egress Gateway
            </span>
          </label>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <button type="button" className="oc-btn" onClick={onClose}>
              Cancel
            </button>
            <button
              type="button"
              id="btn-launch-engagement"
              className="oc-btn oc-btn-primary"
              disabled={!canLaunch}
              onClick={onLaunch}
            >
              <Play size={13} />
              <span>Launch Cyber Squad</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
