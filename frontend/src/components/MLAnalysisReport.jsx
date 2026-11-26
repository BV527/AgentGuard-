import { Shield, AlertTriangle, CheckCircle, Activity, Brain, Lock, TrendingUp, FileSearch, X } from 'lucide-react';

function RiskBar({ label, value, color }) {
  const pct = Math.max(0, Math.min(100, Number(value) || 0));
  const barColor = color || (pct > 75 ? '#dc2626' : pct > 45 ? '#d97706' : '#16a34a');
  return (
    <div className="ml-risk-bar">
      <div className="ml-risk-bar-header">
        <span>{label}</span>
        <b style={{ color: barColor }}>{pct.toFixed(1)} / 100</b>
      </div>
      <div className="ml-risk-bar-track">
        <div className="ml-risk-bar-fill" style={{ width: `${pct}%`, background: barColor }} />
      </div>
    </div>
  );
}

function ProbabilityGauge({ label, value, color }) {
  const pct = Math.round((Number(value) || 0) * 100);
  return (
    <div className="ml-prob-gauge">
      <div className="ml-prob-ring" style={{ '--pct': pct, '--color': color }}>
        <span>{pct}%</span>
      </div>
      <div className="ml-prob-label">{label}</div>
    </div>
  );
}

const RISK_STYLE = {
  CRITICAL: { bg: '#fff1f2', border: '#fca5a5', color: '#b91c1c', icon: AlertTriangle },
  HIGH:     { bg: '#fff7ed', border: '#fdba74', color: '#c2410c', icon: AlertTriangle },
  MEDIUM:   { bg: '#fefce8', border: '#fde047', color: '#a16207', icon: Activity },
  LOW:      { bg: '#f0fdf4', border: '#86efac', color: '#15803d', icon: CheckCircle },
};

export default function MLAnalysisReport({ event, onClose }) {
  if (!event) return null;

  const trace = event.trace || {};
  const classProbs = trace.classifier_class_probabilities || trace.classifier_prediction?.class_probabilities || {};
  const mlLabel = event.classifier_label || trace.classifier_prediction?.class || 'NOT_EVALUATED';
  const mlRisk = Number(event.probability_risk_score) || 0;
  const taskRelevance = Number(event.task_relevance_score) || 0;
  const dataSensitivity = Number(event.data_sensitivity_score) || 0;
  const combinedRisk = Number(trace.risk_score) || mlRisk;
  const riskLevel = combinedRisk > 80 ? 'CRITICAL' : combinedRisk > 60 ? 'HIGH' : combinedRisk > 40 ? 'MEDIUM' : 'LOW';
  const style = RISK_STYLE[riskLevel];
  const RiskIcon = style.icon;

  const reasons = trace.reasons || trace.policy_violations || [];
  const isBlocked = event.decision === 'BLOCK';
  const isAnomalous = mlLabel === 'MALICIOUS' || mlLabel === 'SUSPICIOUS';

  // Build risk factors from available data
  const riskFactors = [];
  if (trace.policy_violations?.length) {
    trace.policy_violations.forEach(v => riskFactors.push({ factor: 'Policy violation', contribution: 'High', detail: v }));
  }
  if (mlLabel === 'MALICIOUS') riskFactors.push({ factor: 'Classifier: MALICIOUS', contribution: 'Critical', detail: `P(MALICIOUS) = ${Math.round((classProbs.MALICIOUS || 0) * 100)}%` });
  else if (mlLabel === 'SUSPICIOUS') riskFactors.push({ factor: 'Classifier: SUSPICIOUS', contribution: 'Medium', detail: `P(SUSPICIOUS) = ${Math.round((classProbs.SUSPICIOUS || 0) * 100)}%` });
  if (taskRelevance < 40 && taskRelevance > 0) riskFactors.push({ factor: 'Low task relevance', contribution: 'Medium', detail: `Action relevance to task: ${taskRelevance.toFixed(1)}%` });
  if (dataSensitivity > 70) riskFactors.push({ factor: 'High data sensitivity', contribution: 'High', detail: `Sensitivity score: ${dataSensitivity.toFixed(1)} / 100` });
  if (!riskFactors.length) riskFactors.push({ factor: 'No significant risk factors', contribution: 'Low', detail: 'Action passed all checks' });

  const CONTRIB_COLOR = { Critical: '#b91c1c', High: '#c2410c', Medium: '#a16207', Low: '#15803d' };

  const recommendation = isBlocked
    ? 'Investigate immediately — action was blocked due to policy or permission violation.'
    : event.decision === 'ASK'
    ? 'Review pending — action requires human approval before execution.'
    : 'Action was allowed. No immediate action required.';

  return (
    <div className="ml-report-overlay" onClick={onClose}>
      <div className="ml-report-panel" onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div className="ml-report-header">
          <div className="ml-report-title">
            <Brain size={18} />
            <div>
              <div className="section-kicker">ML-BASED ANALYSIS REPORT</div>
              <h2>Action Risk Breakdown</h2>
            </div>
          </div>
          <button className="ml-report-close" onClick={onClose}><X size={15} /></button>
        </div>

        <div className="ml-report-body">

          {/* Action summary banner */}
          <div className="ml-action-summary" style={{ background: style.bg, borderColor: style.border }}>
            <div className="ml-action-summary-left">
              <RiskIcon size={20} color={style.color} />
              <div>
                <b style={{ color: style.color }}>{riskLevel} RISK</b>
                <span>{event.agent} · <code>{event.action || event.tool}</code> → <code>{event.resource}</code></span>
              </div>
            </div>
            <div className="ml-action-decision" style={{ color: style.color }}>{event.decision}</div>
          </div>

          <div className="ml-report-grid">

            {/* Left column */}
            <div className="ml-report-col">

              {/* Combined risk score */}
              <div className="ml-card">
                <div className="ml-card-title"><TrendingUp size={14} /> Overall Risk Score</div>
                <RiskBar label="Combined risk" value={combinedRisk} />
                <p className="ml-card-note">
                  Weighted combination of ML classifier, anomaly signals, permission check, task relevance, data sensitivity, and policy violations.
                </p>
              </div>

              {/* Classifier */}
              <div className="ml-card">
                <div className="ml-card-title"><Brain size={14} /> Random Forest Classifier</div>
                {mlLabel === 'NOT_EVALUATED' ? (
                  <p className="ml-card-note">This action was not evaluated by the classifier (passthrough or input-only event).</p>
                ) : (
                  <>
                    <div className="ml-classifier-label" style={{ color: mlLabel === 'MALICIOUS' ? '#b91c1c' : mlLabel === 'SUSPICIOUS' ? '#c2410c' : '#15803d' }}>
                      Predicted: <b>{mlLabel}</b>
                      <span>· ML risk: {mlRisk.toFixed(1)}%</span>
                    </div>
                    <div className="ml-prob-gauges">
                      <ProbabilityGauge label="SAFE"       value={classProbs.SAFE       || 0} color="#16a34a" />
                      <ProbabilityGauge label="SUSPICIOUS" value={classProbs.SUSPICIOUS || 0} color="#d97706" />
                      <ProbabilityGauge label="MALICIOUS"  value={classProbs.MALICIOUS  || 0} color="#dc2626" />
                    </div>
                    <p className="ml-card-note">
                      18 input features: agent role, tool, operation, resource type, permission level, task relevance, data sensitivity, destination trust, action frequency, previous risk, sequence length, privilege level, time of day, suspicious content score, authorization, historical anomaly, and agent age.
                    </p>
                  </>
                )}
              </div>

            </div>

            {/* Right column */}
            <div className="ml-report-col">

              {/* Scores */}
              <div className="ml-card">
                <div className="ml-card-title"><Activity size={14} /> Signal Scores</div>
                <RiskBar label="Task relevance" value={taskRelevance} color={taskRelevance > 60 ? '#16a34a' : '#d97706'} />
                <p className="ml-card-note">TF-IDF similarity between the task description and this action.</p>
                <RiskBar label="Data sensitivity" value={dataSensitivity} color={dataSensitivity > 70 ? '#dc2626' : dataSensitivity > 40 ? '#d97706' : '#16a34a'} />
                <p className="ml-card-note">Sensitivity of the resource being accessed (credentials = 99, public doc = low).</p>
              </div>

              {/* Permission */}
              <div className="ml-card">
                <div className="ml-card-title"><Lock size={14} /> Permission & Decision</div>
                <div className={`ml-permission-row ${isBlocked ? 'perm-fail' : 'perm-ok'}`}>
                  {isBlocked ? <AlertTriangle size={13} /> : <CheckCircle size={13} />}
                  <span>Decision: <b>{event.decision}</b> · Threshold used: <b>{event.threshold_used ?? '—'}</b></span>
                </div>
                <p className="ml-card-note">{trace.explanation || event.rule || 'No explanation recorded.'}</p>
              </div>

              {/* Risk factors */}
              <div className="ml-card">
                <div className="ml-card-title"><FileSearch size={14} /> Risk Factor Breakdown</div>
                <div className="ml-risk-factors">
                  {riskFactors.map((f, i) => (
                    <div key={i} className="ml-risk-factor-row">
                      <span className="ml-factor-contribution" style={{ color: CONTRIB_COLOR[f.contribution] || '#64748b' }}>{f.contribution}</span>
                      <div>
                        <b>{f.factor}</b>
                        <span>{f.detail}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

            </div>
          </div>

          {/* Policy reasons */}
          {reasons.length > 0 && (
            <div className="ml-card ml-policy-reasons">
              <div className="ml-card-title"><Shield size={14} /> Policy Decision Reasons</div>
              <ul>{reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>
            </div>
          )}

          {/* Recommendation */}
          <div className="ml-recommendation" style={{ borderColor: style.border, background: style.bg }}>
            <b style={{ color: style.color }}>Recommendation</b>
            <p>{recommendation}</p>
          </div>

        </div>
      </div>
    </div>
  );
}
