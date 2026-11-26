import { useState } from 'react';
import { Shield, Activity, RefreshCw, CheckCircle, Download, Brain } from 'lucide-react';
import MarkdownView from './MarkdownView.jsx';
import MLAnalysisReport from './MLAnalysisReport.jsx';

function DecisionBadge({ value }) {
  const map = {
    ALLOW: 'badge-allow', ALLOWED: 'badge-allow',
    BLOCK: 'badge-block', BLOCKED: 'badge-block',
    ASK: 'badge-ask',
  };
  return <span className={`decision-badge ${map[value] || 'badge-default'}`}>{value}</span>;
}

function AgentNode({ name, status, lastAction }) {
  const stateClass = {
    COMPLETED: 'agent-node-done',
    BLOCKED: 'agent-node-blocked',
    RUNNING: 'agent-node-running',
  }[status] || '';
  const icons = { ResearchAgent: '🔍', AnalysisAgent: '📊', ReportAgent: '📝' };
  return (
    <div className={`agent-node ${stateClass}`}>
      <div className="agent-node-icon">{icons[name] || '🤖'}</div>
      <div className="agent-node-body">
        <b>{name.replace('Agent', ' Agent')}</b>
        <span className="agent-node-status">{status || 'IDLE'}</span>
        {lastAction && <small>{lastAction}</small>}
      </div>
    </div>
  );
}

function EventRow({ event, selected, onClick }) {
  const decision = event.decision === 'BLOCK' ? 'BLOCKED' : event.decision === 'ALLOW' ? 'ALLOWED' : event.decision || 'PENDING';
  const time = (() => {
    const d = new Date(Number(event.timestamp) * 1000);
    return isNaN(d) ? '—' : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  })();
  return (
    <button className={`event-row ${decision === 'BLOCKED' ? 'event-row-blocked' : ''} ${selected ? 'event-row-selected' : ''}`} onClick={onClick}>
      <span className="event-row-time">{time}</span>
      <span className="event-row-main">
        <b>{event.agent}</b>
        <span><code>{event.action || event.tool}</code> → <code>{event.resource}</code></span>
        <small>{event.rule || event.explanation || 'Gateway decision recorded'}</small>
      </span>
      <DecisionBadge value={decision} />
    </button>
  );
}

export default function LiveDashboard({ current, events, incidents, approvals, selectedEvent, onSelectEvent, onApprove, onRefresh, filter, onFilter }) {
  const [mlReportEvent, setMlReportEvent] = useState(null);
  const mergedEvents = events.slice().sort((a, b) => Number(a.timestamp || 0) - Number(b.timestamp || 0));
  const visible = mergedEvents.filter(e => filter === 'All' || (e.decision || '').toUpperCase().startsWith(filter.toUpperCase().slice(0, 4)));
  const activeEvent = mergedEvents.find(e => (e.id || e.event_id) === selectedEvent);
  const activeIncident = incidents.find(i => i.task_id === activeEvent?.task_id) || incidents.find(i => i.status === 'OPEN');

  const agentLastAction = (agent) => {
    const ev = mergedEvents.slice().reverse().find(e => e.agent === agent);
    return ev ? `${ev.action || ev.tool} · ${ev.decision}` : null;
  };

  return (
    <div className="dashboard-wrap">
      {/* Pipeline status */}
      <div className="dash-section pipeline-section">
        <div className="dash-section-header">
          <div>
            <div className="section-kicker">LIVE PIPELINE</div>
            <h3>Agent status</h3>
          </div>
          <div className="pipeline-status-row">
            <span className={`pipeline-status-badge status-${(current.status || 'idle').toLowerCase()}`}>
              {current.status || 'IDLE'}
            </span>
            <button className="icon-btn" onClick={onRefresh} title="Refresh"><RefreshCw size={14} /></button>
          </div>
        </div>
        <div className="pipeline-nodes">
          <div className="pipeline-task-chip">
            <span>📋</span>
            <span>{current.task || 'No task running'}</span>
          </div>
          <div className="pipeline-arrow">→</div>
          {['ResearchAgent', 'AnalysisAgent', 'ReportAgent'].map((agent, i) => (
            <div key={agent} className="pipeline-agent-wrap">
              <AgentNode name={agent} status={current.agent_statuses?.[agent]} lastAction={agentLastAction(agent)} />
              {i < 2 && <div className="pipeline-arrow">→</div>}
            </div>
          ))}
          <div className="pipeline-arrow">→</div>
          <div className="pipeline-gateway-chip">
            <Shield size={13} />
            <span>Gateway</span>
          </div>
        </div>
      </div>

      <div className="dash-two-col">
        {/* Event timeline */}
        <div className="dash-section timeline-section">
          <div className="dash-section-header">
            <div>
              <div className="section-kicker">02 · GATEWAY EVIDENCE</div>
              <h3>Event timeline</h3>
            </div>
          </div>
          <div className="filter-chips">
            {['All', 'Allowed', 'Blocked'].map(f => (
              <button key={f} className={filter === f ? 'chip-active' : ''} onClick={() => onFilter(f)}>{f}</button>
            ))}
          </div>
          <div className="event-list">
            {visible.length ? visible.slice().reverse().map((ev, i) => (
              <div key={ev.id || ev.event_id || i} className="event-row-wrap">
                <EventRow
                  event={ev}
                  selected={selectedEvent === (ev.id || ev.event_id)}
                  onClick={() => onSelectEvent(ev.id || ev.event_id)}
                />
                <button className="ml-report-trigger" onClick={() => setMlReportEvent(ev)}>
                  <Brain size={11} /> ML Report
                </button>
              </div>
            )) : (
              <div className="empty-state">
                <Activity size={20} />
                <b>No events yet</b>
                <span>Run a task or scenario to see gateway decisions here.</span>
              </div>
            )}
          </div>
          {activeEvent && (
            <div className="event-detail-box">
              <div className="section-kicker">SELECTED EVENT</div>
              <b>{activeEvent.agent} · {activeEvent.action || activeEvent.tool} · {activeEvent.resource}</b>
              <p>{activeEvent.rule || activeEvent.explanation}</p>
              <div className="event-detail-meta">
                <span>ML risk: <b>{activeEvent.probability_risk_score != null ? `${Number(activeEvent.probability_risk_score).toFixed(1)} / 100` : '—'}</b></span>
                <span>Threshold: <b>{activeEvent.threshold_used ?? '—'}</b></span>
                <span>Label: <b>{activeEvent.classifier_label || '—'}</b></span>
              </div>
            </div>
          )}
        </div>

        {/* Incident panel */}
        <div className={`dash-section incident-section ${activeIncident ? 'incident-section-open' : ''}`}>
          <div className="dash-section-header">
            <div>
              <div className="section-kicker">03 · INCIDENT REPORT</div>
              <h3>Why was it blocked?</h3>
            </div>
            {activeIncident && <DecisionBadge value="BLOCKED" />}
          </div>
          {activeIncident ? (
            <div className="incident-body">
              <div className="incident-title-row">
                <b>{activeIncident.title}</b>
                <span className="incident-status-chip">{activeIncident.status || 'OPEN'}</span>
              </div>
              <div className="incident-facts">
                <div className="incident-fact">
                  <small>What happened</small>
                  <p>{activeEvent?.agent || 'Agent'} attempted <code>{activeEvent?.action || activeEvent?.tool || 'action'}</code> on <code>{activeEvent?.resource || 'resource'}</code>.</p>
                </div>
                <div className="incident-fact">
                  <small>Rule violated</small>
                  <p>{activeEvent?.rule || activeIncident.explanation}</p>
                </div>
                <div className="incident-fact">
                  <small>Action taken</small>
                  <p>Blocked before execution. The protected callback was not run.</p>
                </div>
                <div className="incident-fact">
                  <small>Recommended fix</small>
                  <p>Review the task's approved resource list. Narrow or expand it deliberately, then rerun.</p>
                </div>
              </div>
              <details className="incident-evidence-details">
                <summary>Evidence trace</summary>
                {(activeIncident.evidence || []).map((item, i) => (
                  <div key={i} className="evidence-item">
                    <b>{item.agent} · {item.tool || item.action} · {item.decision}</b>
                    <p>{item.explanation || item.rule}</p>
                  </div>
                ))}
              </details>
              <button
                className="download-btn"
                onClick={() => {
                  const blob = new Blob([JSON.stringify(activeIncident, null, 2)], { type: 'application/json' });
                  const a = document.createElement('a');
                  a.href = URL.createObjectURL(blob);
                  a.download = `incident-${activeIncident.incident_id}.json`;
                  a.click();
                }}
              >
                <Download size={13} /> Download incident JSON
              </button>
            </div>
          ) : (
            <div className="empty-state">
              <CheckCircle size={20} className="text-green-500" />
              <b>No incident selected</b>
              <span>When the gateway blocks an action, its evidence appears here. Click a BLOCKED event in the timeline.</span>
            </div>
          )}
        </div>
      </div>

      {/* Approvals */}
      {approvals.length > 0 && (
        <div className="dash-section approval-section">
          <div className="section-kicker">REVIEW REQUIRED</div>
          <h3>Pending approvals</h3>
          {approvals.map(item => (
            <div key={item.approval_id} className="approval-row">
              <span><b>{item.agent}</b> requests <code>{item.tool}</code> on <code>{item.resource}</code></span>
              <div>
                <button className="approve-btn" onClick={() => onApprove(item.approval_id, true)}>Approve</button>
                <button className="reject-btn" onClick={() => onApprove(item.approval_id, false)}>Reject</button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Report */}
      {current.report?.content && (
        <div className="dash-section report-section">
          <div className="dash-section-header">
            <div>
              <div className="section-kicker">04 · RESULT</div>
              <h3>Generated report</h3>
            </div>
            <a
              className="download-btn"
              download="agentguard-report.md"
              href={`data:text/markdown;charset=utf-8,${encodeURIComponent(current.report.content)}`}
            >
              <Download size={13} /> Download
            </a>
          </div>
          <MarkdownView content={current.report.content} />
        </div>
      )}
      {mlReportEvent && <MLAnalysisReport event={mlReportEvent} onClose={() => setMlReportEvent(null)} />}
    </div>
  );
}
