import React, { useState, useEffect, useRef, useCallback } from 'react';

const ACTION_ICONS = {
  initialize: '🚀',
  scan: '🔍',
  analyze: '🔬',
  explain: '🧠',
  investigate: '🔬',
  remediate: '🛡️',
  execute: '⚡',
  summary: '✅',
  error: '❌',
};

const STATUS_STYLES = {
  running: {
    card: 'bg-blue-50 border-l-4 border-blue-500',
    badge: 'bg-blue-100 text-blue-800',
    dot: 'bg-blue-500 animate-pulse',
  },
  completed: {
    card: 'bg-emerald-50 border-l-4 border-emerald-500',
    badge: 'bg-emerald-100 text-emerald-800',
    dot: 'bg-emerald-500',
  },
  pending_approval: {
    card: 'bg-amber-50 border-l-4 border-amber-500 ring-2 ring-amber-300 ring-opacity-50',
    badge: 'bg-amber-100 text-amber-800 animate-pulse',
    dot: 'bg-amber-500 animate-pulse',
  },
  approved: {
    card: 'bg-emerald-50 border-l-4 border-emerald-500',
    badge: 'bg-emerald-100 text-emerald-800',
    dot: 'bg-emerald-500',
  },
  failed: {
    card: 'bg-red-50 border-l-4 border-red-500',
    badge: 'bg-red-100 text-red-800',
    dot: 'bg-red-500',
  },
  rejected: {
    card: 'bg-gray-50 border-l-4 border-gray-400',
    badge: 'bg-gray-100 text-gray-600',
    dot: 'bg-gray-400',
  },
};

const SESSION_STATUS_CONFIG = {
  running: {
    label: 'RUNNING',
    className: 'text-blue-700 bg-blue-50 border-blue-200',
    icon: '⏳',
    showSpinner: true,
  },
  awaiting_approval: {
    label: 'AWAITING APPROVAL',
    className: 'text-amber-700 bg-amber-50 border-amber-200 animate-pulse',
    icon: '⚠️',
    showSpinner: false,
  },
  completed: {
    label: 'COMPLETED',
    className: 'text-emerald-700 bg-emerald-50 border-emerald-200',
    icon: '✅',
    showSpinner: false,
  },
  failed: {
    label: 'FAILED',
    className: 'text-red-700 bg-red-50 border-red-200',
    icon: '❌',
    showSpinner: false,
  },
};

function getStepStyle(status) {
  return STATUS_STYLES[status] || STATUS_STYLES.running;
}

function parseResultData(resultData) {
  if (!resultData) return null;
  try {
    return typeof resultData === 'string' ? JSON.parse(resultData) : resultData;
  } catch {
    return null;
  }
}

function getRiskBadgeClass(risk) {
  switch (risk?.toLowerCase()) {
    case 'critical': return 'bg-red-200 text-red-900 border border-red-300';
    case 'high': return 'bg-orange-200 text-orange-900 border border-orange-300';
    case 'medium': return 'bg-amber-200 text-amber-900 border border-amber-300';
    case 'low': return 'bg-blue-100 text-blue-800 border border-blue-200';
    default: return 'bg-gray-100 text-gray-800 border border-gray-200';
  }
}

// ─── Sub-components ──────────────────────────────────────────────────

function StatusHeader({ session }) {
  if (!session) return null;
  const config = SESSION_STATUS_CONFIG[session.status] || SESSION_STATUS_CONFIG.running;

  return (
    <div className={`flex items-center justify-between rounded-lg border px-5 py-3 ${config.className}`}>
      <div className="flex items-center gap-3">
        <span className="text-xl">{config.icon}</span>
        <div>
          <span className="text-sm font-bold uppercase tracking-wider">{config.label}</span>
          <p className="text-xs opacity-75 mt-0.5">
            Target: <span className="font-mono font-semibold">{session.target}</span> · Profile: <span className="capitalize font-semibold">{session.profile}</span>
          </p>
        </div>
      </div>
      <div className="flex items-center gap-2">
        {config.showSpinner && (
          <svg className="animate-spin h-5 w-5 text-blue-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
        )}
        <span className="text-xs font-mono opacity-60">Session #{session.id}</span>
      </div>
    </div>
  );
}

function ApprovalActions({ step, sessionId, onApprove, onReject, isSubmitting }) {
  const parsed = parseResultData(step.result_data);
  const actions = parsed?.actions || parsed?.proposed_actions || [];

  return (
    <div className="mt-4 space-y-3">
      {actions.length > 0 && (
        <div className="space-y-2">
          <p className="text-sm font-semibold text-amber-800">Proposed Remediation Actions:</p>
          {actions.map((action, idx) => (
            <div key={idx} className="bg-white rounded-md border border-amber-200 p-3 shadow-sm">
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm font-bold text-gray-900">{action.title || `Action ${idx + 1}`}</span>
                {action.risk && (
                  <span className={`px-2 py-0.5 text-xs font-bold rounded-full uppercase ${getRiskBadgeClass(action.risk)}`}>
                    {action.risk} risk
                  </span>
                )}
              </div>
              {action.description && (
                <p className="text-xs text-gray-600 mb-2">{action.description}</p>
              )}
              {action.command && (
                <pre className="text-xs font-mono bg-slate-900 text-emerald-400 rounded p-2 overflow-x-auto">
                  {action.command}
                </pre>
              )}
            </div>
          ))}
        </div>
      )}
      <div className="flex gap-3 pt-2">
        <button
          onClick={() => onApprove(sessionId, step.id)}
          disabled={isSubmitting}
          className="flex-1 bg-emerald-600 hover:bg-emerald-700 disabled:bg-emerald-400 text-white font-bold py-3 px-6 rounded-lg shadow-lg transition duration-150 ease-in-out text-sm"
        >
          {isSubmitting ? 'Processing...' : '✅ Approve & Execute'}
        </button>
        <button
          onClick={() => onReject(sessionId, step.id)}
          disabled={isSubmitting}
          className="flex-1 bg-red-600 hover:bg-red-700 disabled:bg-red-400 text-white font-bold py-3 px-6 rounded-lg shadow-lg transition duration-150 ease-in-out text-sm"
        >
          {isSubmitting ? 'Processing...' : '❌ Reject Actions'}
        </button>
      </div>
    </div>
  );
}

function TimelineStep({ step, sessionId, onApprove, onReject, isSubmitting }) {
  const [expanded, setExpanded] = useState(false);
  const style = getStepStyle(step.status);
  const icon = ACTION_ICONS[step.action_type] || '📋';
  const parsed = parseResultData(step.result_data);
  const isPendingRemediation = step.status === 'pending_approval' && step.action_type === 'remediate';

  return (
    <div className="relative pl-8 pb-6 last:pb-0">
      {/* Timeline vertical line */}
      <div className="absolute left-3 top-0 bottom-0 w-0.5 bg-gray-200" />
      {/* Timeline dot */}
      <div className={`absolute left-1.5 top-1 w-3 h-3 rounded-full ring-2 ring-white ${style.dot}`} />

      <div className={`rounded-lg shadow-sm p-4 ${style.card}`}>
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-start gap-2 min-w-0">
            <span className="text-lg flex-shrink-0 mt-0.5">{icon}</span>
            <div className="min-w-0">
              <h4 className="text-sm font-bold text-gray-900 leading-tight">{step.title}</h4>
              <p className="text-xs text-gray-600 mt-1">{step.description}</p>
            </div>
          </div>
          <span className={`flex-shrink-0 px-2.5 py-0.5 text-xs font-bold rounded-full uppercase whitespace-nowrap ${style.badge}`}>
            {step.status?.replace('_', ' ')}
          </span>
        </div>

        {/* Expandable result details */}
        {parsed && !isPendingRemediation && (
          <div className="mt-3">
            <button
              onClick={() => setExpanded(!expanded)}
              className="text-xs font-medium text-blue-600 hover:text-blue-800 transition"
            >
              {expanded ? '▼ Hide Details' : '▶ Show Details'}
            </button>
            {expanded && (
              <pre className="mt-2 text-xs font-mono bg-slate-900 text-slate-200 rounded p-3 overflow-auto max-h-64">
                {JSON.stringify(parsed, null, 2)}
              </pre>
            )}
          </div>
        )}

        {/* Approval section for remediation steps */}
        {isPendingRemediation && (
          <ApprovalActions
            step={step}
            sessionId={sessionId}
            onApprove={onApprove}
            onReject={onReject}
            isSubmitting={isSubmitting}
          />
        )}
      </div>
    </div>
  );
}

function SessionCard({ session, isSelected, onClick }) {
  const statusConfig = SESSION_STATUS_CONFIG[session.status] || SESSION_STATUS_CONFIG.running;

  return (
    <button
      onClick={onClick}
      className={`w-full text-left bg-white rounded-lg shadow-sm border p-4 transition hover:shadow-md ${
        isSelected ? 'ring-2 ring-blue-500 border-blue-300' : 'border-gray-200 hover:border-gray-300'
      }`}
    >
      <div className="flex items-center justify-between mb-1">
        <span className="text-sm font-bold text-gray-900 font-mono">{session.target}</span>
        <span className={`px-2 py-0.5 text-xs font-bold rounded-full uppercase ${statusConfig.className}`}>
          {session.status?.replace('_', ' ')}
        </span>
      </div>
      <div className="flex items-center gap-3 text-xs text-gray-500">
        <span className="capitalize">{session.profile}</span>
        <span>·</span>
        <span>{session.steps?.length || 0} steps</span>
        <span>·</span>
        <span className="font-mono">{session.created_at ? new Date(session.created_at).toLocaleString() : '—'}</span>
      </div>
    </button>
  );
}

// ─── Main Component ──────────────────────────────────────────────────

export default function AutonomousAgent() {
  const [target, setTarget] = useState('');
  const [profile, setProfile] = useState('quick');
  const [sessions, setSessions] = useState([]);
  const [selectedSessionId, setSelectedSessionId] = useState(null);
  const [selectedSession, setSelectedSession] = useState(null);
  const [isStarting, setIsStarting] = useState(false);
  const [isApproving, setIsApproving] = useState(false);
  const [error, setError] = useState('');
  const [loadingSession, setLoadingSession] = useState(false);
  const pollRef = useRef(null);

  // ── Fetch all sessions ──
  const fetchSessions = useCallback(async () => {
    try {
      const res = await fetch('/api/agent/sessions');
      if (res.ok) {
        const data = await res.json();
        setSessions(data);
      }
    } catch (err) {
      console.error('Failed to fetch sessions:', err);
    }
  }, []);

  // ── Fetch single session detail ──
  const fetchSessionDetail = useCallback(async (id) => {
    try {
      const res = await fetch(`/api/agent/sessions/${id}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedSession(data);
        return data;
      }
    } catch (err) {
      console.error('Failed to fetch session detail:', err);
    }
    return null;
  }, []);

  // ── Polling logic ──
  const startPolling = useCallback((sessionId) => {
    // Clear any existing poll
    if (pollRef.current) clearInterval(pollRef.current);

    pollRef.current = setInterval(async () => {
      const data = await fetchSessionDetail(sessionId);
      if (data && (data.status === 'completed' || data.status === 'failed')) {
        clearInterval(pollRef.current);
        pollRef.current = null;
        fetchSessions(); // refresh the session list too
      }
    }, 2000);
  }, [fetchSessionDetail, fetchSessions]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  // Initial load
  useEffect(() => {
    fetchSessions();
  }, [fetchSessions]);

  // ── Select a session ──
  const handleSelectSession = async (session) => {
    setSelectedSessionId(session.id);
    setLoadingSession(true);
    const data = await fetchSessionDetail(session.id);
    setLoadingSession(false);

    if (data && (data.status === 'running' || data.status === 'awaiting_approval')) {
      startPolling(session.id);
    }
  };

  // ── Start investigation ──
  const handleStartInvestigation = async () => {
    const trimmedTarget = target.trim();
    if (!trimmedTarget) {
      setError('Please enter a target IP or hostname.');
      return;
    }

    setError('');
    setIsStarting(true);

    try {
      const res = await fetch('/api/agent/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: trimmedTarget, profile }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || 'Failed to start investigation.');
      }

      const session = await res.json();
      setSelectedSessionId(session.id);
      setSelectedSession(session);
      setTarget('');
      await fetchSessions();
      startPolling(session.id);
    } catch (err) {
      setError(err.message || 'Error starting investigation.');
    } finally {
      setIsStarting(false);
    }
  };

  // ── Approve actions ──
  const handleApprove = async (sessionId, stepId) => {
    setIsApproving(true);
    try {
      const res = await fetch(`/api/agent/sessions/${sessionId}/approve/${stepId}`, {
        method: 'POST',
      });
      if (res.ok) {
        await fetchSessionDetail(sessionId);
        startPolling(sessionId);
      }
    } catch (err) {
      console.error('Approval failed:', err);
    } finally {
      setIsApproving(false);
    }
  };

  // ── Reject actions ──
  const handleReject = async (sessionId, stepId) => {
    setIsApproving(true);
    try {
      const res = await fetch(`/api/agent/sessions/${sessionId}/reject/${stepId}`, {
        method: 'POST',
      });
      if (res.ok) {
        await fetchSessionDetail(sessionId);
        fetchSessions();
        if (pollRef.current) {
          clearInterval(pollRef.current);
          pollRef.current = null;
        }
      }
    } catch (err) {
      console.error('Rejection failed:', err);
    } finally {
      setIsApproving(false);
    }
  };

  const sortedSteps = selectedSession?.steps
    ? [...selectedSession.steps].sort((a, b) => a.step_number - b.step_number)
    : [];

  return (
    <div className="space-y-6">
      {/* ── Investigation Launcher ── */}
      <div className="bg-white shadow rounded-lg overflow-hidden">
        <div className="bg-gradient-to-r from-indigo-600 to-blue-600 px-6 py-4">
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            🤖 Autonomous Investigation Agent
          </h2>
          <p className="text-sm text-indigo-100 mt-1">
            Launch an AI-driven investigation that scans, analyzes, and proposes remediations.
          </p>
        </div>
        <div className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-end">
            <div>
              <label htmlFor="agent-target" className="block text-sm font-medium text-gray-700">
                Target IP / Hostname
              </label>
              <input
                type="text"
                id="agent-target"
                placeholder="192.168.1.10"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleStartInvestigation()}
                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 p-2 border font-mono"
              />
            </div>
            <div>
              <label htmlFor="agent-profile" className="block text-sm font-medium text-gray-700">
                Investigation Profile
              </label>
              <select
                id="agent-profile"
                value={profile}
                onChange={(e) => setProfile(e.target.value)}
                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 p-2 border"
              >
                <option value="quick">Quick (Common Ports)</option>
                <option value="full">Full (Comprehensive)</option>
                <option value="targeted">Targeted (Custom)</option>
              </select>
            </div>
            <div>
              <button
                id="btn-start-investigation"
                onClick={handleStartInvestigation}
                disabled={isStarting}
                className="w-full bg-indigo-600 hover:bg-indigo-700 disabled:bg-indigo-400 text-white font-semibold py-2 px-4 rounded-md shadow-sm transition duration-150 ease-in-out flex items-center justify-center gap-2"
              >
                {isStarting ? (
                  <>
                    <svg className="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                    Starting...
                  </>
                ) : (
                  <>🧠 Start Investigation</>
                )}
              </button>
            </div>
          </div>
          {error && (
            <div className="mt-3 text-sm text-red-600 bg-red-50 border border-red-200 rounded-md px-3 py-2">
              {error}
            </div>
          )}
        </div>
      </div>

      {/* ── Two-column layout: Session History + Investigation Timeline ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Session History (left sidebar) */}
        <div className="lg:col-span-1">
          <div className="bg-white shadow rounded-lg p-6">
            <h2 className="text-lg font-bold text-gray-900 mb-4">Session History</h2>
            {sessions.length === 0 ? (
              <p className="text-sm text-gray-500 text-center py-6">
                No investigation sessions yet. Start one above.
              </p>
            ) : (
              <div className="space-y-2 max-h-[600px] overflow-y-auto">
                {[...sessions].sort((a, b) => b.id - a.id).map((session) => (
                  <SessionCard
                    key={session.id}
                    session={session}
                    isSelected={selectedSessionId === session.id}
                    onClick={() => handleSelectSession(session)}
                  />
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Investigation Timeline (main panel) */}
        <div className="lg:col-span-2">
          <div className="bg-white shadow rounded-lg p-6">
            {!selectedSessionId ? (
              <div className="text-center py-12">
                <span className="text-4xl mb-3 block">🤖</span>
                <h3 className="text-lg font-semibold text-gray-700">No Session Selected</h3>
                <p className="text-sm text-gray-500 mt-1">
                  Start a new investigation or select an existing session to view its timeline.
                </p>
              </div>
            ) : loadingSession ? (
              <div className="text-center py-12">
                <svg className="animate-spin h-8 w-8 text-blue-600 mx-auto mb-3" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                <p className="text-sm text-gray-500">Loading session...</p>
              </div>
            ) : selectedSession ? (
              <div className="space-y-4">
                {/* Status Header */}
                <StatusHeader session={selectedSession} />

                {/* Timeline */}
                <div className="pt-2">
                  <h3 className="text-sm font-bold text-gray-700 uppercase tracking-wider mb-4">
                    Investigation Timeline
                  </h3>
                  {sortedSteps.length === 0 ? (
                    <div className="text-center py-8">
                      <svg className="animate-spin h-6 w-6 text-blue-500 mx-auto mb-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                      </svg>
                      <p className="text-sm text-gray-500">Waiting for the agent to begin...</p>
                    </div>
                  ) : (
                    <div className="relative">
                      {sortedSteps.map((step) => (
                        <TimelineStep
                          key={step.id}
                          step={step}
                          sessionId={selectedSession.id}
                          onApprove={handleApprove}
                          onReject={handleReject}
                          isSubmitting={isApproving}
                        />
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="text-center py-12">
                <span className="text-4xl mb-3 block">⚠️</span>
                <p className="text-sm text-gray-500">Failed to load session details.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
