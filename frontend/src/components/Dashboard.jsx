import React from 'react';

export default function Dashboard({ scans, alerts, switchTab }) {
  // System health logic matching mock_frontend.html
  const hasCritical = alerts.some(a => a.severity?.toLowerCase() === 'critical');
  const hasHigh = alerts.some(a => a.severity?.toLowerCase() === 'high');
  const hasMedium = alerts.some(a => a.severity?.toLowerCase() === 'medium');

  let healthStatus = 'Healthy';
  let healthCardClass = 'bg-white rounded-lg shadow p-6 border-l-4 border-emerald-500';
  let healthTextClass = 'mt-2 text-3xl font-semibold text-emerald-600';

  if (hasCritical) {
    healthStatus = 'Critical';
    healthCardClass = 'bg-white rounded-lg shadow p-6 border-l-4 border-red-500';
    healthTextClass = 'mt-2 text-3xl font-semibold text-red-600';
  } else if (hasHigh) {
    healthStatus = 'Warning';
    healthCardClass = 'bg-white rounded-lg shadow p-6 border-l-4 border-orange-500';
    healthTextClass = 'mt-2 text-3xl font-semibold text-orange-600';
  } else if (hasMedium) {
    healthStatus = 'Elevated Risk';
    healthCardClass = 'bg-white rounded-lg shadow p-6 border-l-4 border-amber-500';
    healthTextClass = 'mt-2 text-3xl font-semibold text-amber-600';
  }

  // Sort and display top 5 recent alerts
  const recentAlerts = [...alerts].sort((a, b) => b.id - a.id).slice(0, 5);

  const getSeverityBadgeClass = (severity) => {
    switch(severity?.toLowerCase()) {
      case 'critical': return 'bg-red-200 text-red-900 border border-red-300';
      case 'high': return 'bg-orange-200 text-orange-900 border border-orange-300';
      case 'medium': return 'bg-amber-200 text-amber-900 border border-amber-300';
      case 'low': return 'bg-blue-100 text-blue-800 border border-blue-200';
      default: return 'bg-gray-100 text-gray-800 border border-gray-200';
    }
  };

  return (
    <div className="space-y-6">
      {/* Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className={healthCardClass} id="card-health">
          <h2 className="text-sm font-medium text-gray-500 uppercase tracking-wider">System Health</h2>
          <p className={healthTextClass} id="metric-health">{healthStatus}</p>
          <p className="mt-1 text-xs text-gray-400">Calculated from active alerts</p>
        </div>

        <div className="bg-white rounded-lg shadow p-6 border-l-4 border-blue-500">
          <h2 className="text-sm font-medium text-gray-500 uppercase tracking-wider">Scans Conducted</h2>
          <p className="mt-2 text-3xl font-semibold text-blue-600" id="metric-scans">{scans.length}</p>
          <p className="mt-1 text-xs text-gray-400">Active scanner history count</p>
        </div>

        <div className="bg-white rounded-lg shadow p-6 border-l-4 border-amber-500" id="card-alerts">
          <h2 className="text-sm font-medium text-gray-500 uppercase tracking-wider">Total Security Alerts</h2>
          <p className="mt-2 text-3xl font-semibold text-amber-600" id="metric-alerts">{alerts.length}</p>
          <p className="mt-1 text-xs text-gray-400">Captured and ingested threats</p>
        </div>
      </div>

      {/* Recent Alerts List */}
      <div className="bg-white shadow rounded-lg p-6">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-lg font-bold text-gray-900">Recent Security Alerts</h2>
          <button 
            className="text-sm text-blue-600 hover:text-blue-800 font-medium" 
            onClick={() => switchTab('traffic')}
          >
            View All Alerts &rarr;
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Alert Type</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source IP</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200" id="dashboard-recent-alerts">
              {recentAlerts.length === 0 ? (
                <tr>
                  <td colSpan="4" className="px-6 py-4 text-center text-sm text-gray-500">No security alerts logged yet.</td>
                </tr>
              ) : (
                recentAlerts.map(alert => (
                  <tr key={alert.id}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      <span className={`px-2.5 py-0.5 text-xs font-bold rounded-full uppercase ${getSeverityBadgeClass(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 font-bold">{alert.alert_type}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono">{alert.source_ip}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono text-xs">{alert.timestamp}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
