import { Shield, Search, BarChart2, FileText, Lock, CheckCircle, XCircle, AlertTriangle } from 'lucide-react';

const AGENTS = [
  { icon: Search,   color: '#3b82f6', bg: '#eff6ff', label: 'Research Agent',  desc: 'Reads approved EV battery data files.',          tools: ['read_file','search_data','extract_information'] },
  { icon: BarChart2,color: '#8b5cf6', bg: '#f5f3ff', label: 'Analysis Agent',  desc: 'Processes findings into structured analysis.',    tools: ['analyze_data','process_findings','write_file'] },
  { icon: FileText, color: '#10b981', bg: '#ecfdf5', label: 'Report Agent',    desc: 'Compiles report with provenance citations.',      tools: ['compile_report','validate_provenance','export_report'] },
];

const DECISIONS = [
  { icon: CheckCircle,  color: '#16a34a', bg: '#dcfce7', label: 'ALLOW',  desc: 'Action is within policy — runs normally.' },
  { icon: AlertTriangle,color: '#d97706', bg: '#fef9c3', label: 'ASK',    desc: 'Borderline risk — paused for human review.' },
  { icon: XCircle,      color: '#dc2626', bg: '#fee2e2', label: 'BLOCK',  desc: 'Policy violation — action never executes.' },
];

export default function WorkflowExplainer() {
  return (
    <div className="explainer-wrap">
      <div className="explainer-header">
        <div className="section-kicker" style={{ justifyContent: 'center', display: 'flex' }}>HOW AGENTGUARD WORKS</div>
        <h2>Three agents. One security gateway. Every action checked.</h2>
        <p>Each agent can only use the tools and files it was granted. Before any tool call runs, AgentGuard checks it against the policy, runs an ML risk score, and decides: Allow, Ask, or Block.</p>
      </div>

      {/* Pipeline bar */}
      <div className="explainer-pipeline">
        {/* Task node */}
        <div className="explainer-node" style={{ minWidth: 110 }}>
          <span className="explainer-node-icon">📋</span>
          <b>User Task</b>
          <small>"Research EV battery technology"</small>
        </div>

        {/* Agents */}
        {AGENTS.map((agent) => {
          const Icon = agent.icon;
          return (
            <div key={agent.label} className="explainer-agent-wrap">
              <div className="explainer-arrow-col">→</div>
              <div className="explainer-agent">
                <div className="explainer-agent-top">
                  <div className="explainer-agent-icon" style={{ background: agent.bg, color: agent.color }}>
                    <Icon size={16} />
                  </div>
                  <b>{agent.label}</b>
                </div>
                <p>{agent.desc}</p>
                <div className="explainer-tools">
                  {agent.tools.map(t => <code key={t}>{t}</code>)}
                </div>
                <div className="explainer-gateway-badge">
                  <Shield size={9} /> Gateway check
                </div>
              </div>
            </div>
          );
        })}

        {/* Report node */}
        <div className="explainer-arrow-col" style={{ borderRight: 'none' }}>→</div>
        <div className="explainer-node explainer-report-node" style={{ minWidth: 110 }}>
          <span className="explainer-node-icon">📄</span>
          <b>Final Report</b>
          <small>With provenance citations</small>
        </div>
      </div>

      {/* Gateway decisions */}
      <div className="explainer-decisions">
        <div className="explainer-decisions-label">Gateway can decide:</div>
        <div className="explainer-decisions-grid">
          {DECISIONS.map(d => {
            const Icon = d.icon;
            return (
              <div key={d.label} className="explainer-decision-item" style={{ borderColor: d.color + '55', background: d.bg }}>
                <Icon size={16} color={d.color} />
                <b style={{ color: d.color }}>{d.label}</b>
                <span>{d.desc}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Key concept */}
      <div className="explainer-key-concept">
        <Lock size={14} style={{ flexShrink: 0, marginTop: 2 }} />
        <span><b>Key concept:</b> The gateway sits between every agent and every tool call. Agents cannot bypass it — even if an attacker injects instructions into retrieved text.</span>
      </div>

      {/* CTA */}
      <div className="explainer-cta">
        <p>Ready to see it in action?</p>
      </div>
    </div>
  );
}
