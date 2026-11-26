const API_BASE = '/api';

async function runtimeRequest(path, options = {}) {
  const response = await fetch(`${API_BASE}/runtime${path}`, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || `Runtime request failed (${response.status})`);
  return body;
}

export const fetchRuntimeStatus = () => runtimeRequest('/task/status');
export const fetchRuntimeEvents = () => runtimeRequest('/events?limit=100');
export const fetchRuntimeIncidents = () => runtimeRequest('/incidents');
export const fetchRuntimeApprovals = () => runtimeRequest('/approvals');
export const fetchRuntimeScoreboard = () => runtimeRequest('/scoreboard');
export const fetchRuntimeEvaluation = () => runtimeRequest('/evaluation');
export const startRuntimeTask = (payload) => runtimeRequest('/task/start', {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
});
export const approveRuntimeAction = (approvalId, approved) => runtimeRequest(`/approval/${approvalId}`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ approved }),
});
export const triggerRuntimeUnauthorizedDemo = () => runtimeRequest('/demo/unauthorized', { method: 'POST' });
export const runRuntimeScenario = (scenario) => runtimeRequest(`/demo/scenario/${scenario}`, { method: 'POST' });
export const resetRuntimeDemo = () => runtimeRequest('/demo/reset', { method: 'POST' });
export const runProtectionComparison = (payload) => runtimeRequest('/compare', {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
});
export const resumeComparisonWithoutAction = (comparisonId) => runtimeRequest(`/compare/${comparisonId}/resume-without-action`, { method: 'POST' });
export const fetchActionMLReport = (actionId) => fetch(`/api/actions/${actionId}/ml-report`).then(r => r.json());
