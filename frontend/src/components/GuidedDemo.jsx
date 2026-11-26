import { Play, RefreshCw, ShieldAlert, XCircle, AlertTriangle, FileText } from 'lucide-react';

const STEPS = [
  {
    number: 1,
    title: 'Run the supervised task',
    caption: 'Starts the 3-agent pipeline. Watch each agent move through the gateway.',
    action: 'run_task',
    buttonLabel: 'Run supervised task',
    icon: Play,
    color: '#3b82f6',
  },
  {
    number: 2,
    title: 'Attempt a restricted read',
    caption: 'The agent tries to read credentials.txt — the gateway blocks it before the callback runs.',
    action: 'restricted_read',
    buttonLabel: 'Try restricted read',
    icon: ShieldAlert,
    color: '#dc2626',
  },
  {
    number: 3,
    title: 'Inspect the incident evidence',
    caption: 'Open the incident panel. See the violated rule, ML risk score, and cause hypothesis.',
    action: 'inspect',
    buttonLabel: 'Show incident evidence',
    icon: AlertTriangle,
    color: '#d97706',
  },
  {
    number: 4,
    title: 'Narrow permissions & rerun',
    caption: 'Remove research_findings.txt from the approved list. The next run stops when AnalysisAgent hits that boundary.',
    action: 'narrow_rerun',
    buttonLabel: 'Narrow scope & rerun',
    icon: XCircle,
    color: '#8b5cf6',
  },
];

const EXTRA_SCENARIOS = [
  { key: 'unauthorized_tool', label: 'Unauthorized tool', desc: 'ResearchAgent attempts an ungranted tool call', icon: XCircle },
  { key: 'poisoned_document', label: 'Poisoned document', desc: 'Retrieved text asks the agent to ignore its rules', icon: AlertTriangle },
  { key: 'dataset_gap', label: 'Unsupported answer', desc: 'Agent tries to fill a dataset gap from memory', icon: FileText },
];

export default function GuidedDemo({ step, onStep, onRun, onScenario, onReset, busy }) {
  return (
    <div className="guide-wrap">
      <div className="guide-header">
        <div>
          <div className="section-kicker">GUIDED DEMO · {step + 1} OF {STEPS.length}</div>
          <h2>{STEPS[step].title}</h2>
          <p>{STEPS[step].caption}</p>
        </div>
        <div className="guide-stepper">
          {STEPS.map((s, i) => (
            <button
              key={s.number}
              className={`guide-step-dot ${i === step ? 'dot-active' : i < step ? 'dot-done' : ''}`}
              onClick={() => onStep(i)}
              title={s.title}
            >
              {i < step ? '✓' : i + 1}
            </button>
          ))}
        </div>
      </div>

      <div className="guide-body">
        <div className="guide-steps-list">
          {STEPS.map((s, i) => {
            const Icon = s.icon;
            const isActive = i === step;
            const isDone = i < step;
            return (
              <div
                key={s.number}
                className={`guide-step-row ${isActive ? 'step-row-active' : ''} ${isDone ? 'step-row-done' : ''}`}
                onClick={() => onStep(i)}
              >
                <div className="guide-step-num" style={isActive ? { background: s.color, color: '#fff', borderColor: s.color } : {}}>
                  {isDone ? '✓' : s.number}
                </div>
                <div className="guide-step-text">
                  <b>{s.title}</b>
                  <span>{s.caption}</span>
                </div>
                {isActive && (
                  <button
                    className="guide-run-btn"
                    style={{ background: s.color }}
                    disabled={busy}
                    onClick={(e) => { e.stopPropagation(); onRun(i); }}
                  >
                    <Icon size={13} />
                    {busy ? 'Running…' : s.buttonLabel}
                  </button>
                )}
              </div>
            );
          })}
        </div>

        <div className="guide-extras">
          <div className="section-kicker" style={{ marginBottom: 10 }}>EXTRA SCENARIOS</div>
          {EXTRA_SCENARIOS.map(s => {
            const Icon = s.icon;
            return (
              <button key={s.key} className="extra-scenario-btn" disabled={busy} onClick={() => onScenario(s.key)}>
                <Icon size={14} />
                <div>
                  <b>{s.label}</b>
                  <span>{s.desc}</span>
                </div>
              </button>
            );
          })}
          <button className="reset-btn" disabled={busy} onClick={onReset}>
            <RefreshCw size={13} /> Reset demo
          </button>
        </div>
      </div>

      <div className="guide-nav">
        <button className="nav-btn" disabled={step === 0 || busy} onClick={() => onStep(Math.max(0, step - 1))}>← Back</button>
        <button className="nav-btn nav-btn-primary" disabled={busy} onClick={() => onRun(step)}>
          <Play size={13} /> Run this step
        </button>
        <button className="nav-btn" disabled={step === STEPS.length - 1 || busy} onClick={() => onStep(Math.min(STEPS.length - 1, step + 1))}>Next →</button>
      </div>
    </div>
  );
}
