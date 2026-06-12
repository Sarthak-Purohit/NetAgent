import React, { useState } from 'react';

export default function Scanner({ scans, refreshScans, triggerExplain }) {
  const [target, setTarget] = useState('');
  const [profile, setProfile] = useState('quick');
  const [statusMsg, setStatusMsg] = useState('');
  const [statusClass, setStatusClass] = useState('hidden');
  const [selectedScanDetails, setSelectedScanDetails] = useState(null);

  const validateIP = (ip) => {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    for (let part of parts) {
      if (!/^\d+$/.test(part)) return false;
      const num = parseInt(part, 10);
      if (num < 0 || num > 255) return false;
    }
    return true;
  };

  const handleStartScan = async () => {
    setStatusClass('mt-2 text-sm text-gray-500');
    setStatusMsg('Triggering scan...');

    const trimmedTarget = target.trim();

    // Custom Client-Side IP validation required by E2E test assertions
    if (!trimmedTarget || !validateIP(trimmedTarget)) {
      setStatusClass('mt-2 text-sm text-red-500');
      setStatusMsg('Invalid IP address format');
      return;
    }

    try {
      const response = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: trimmedTarget, profile })
      });

      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.detail || 'Error triggering scan.');
      }

      const scan = await response.json();
      setStatusClass('mt-2 text-sm text-green-600');
      setStatusMsg(`Scan #${scan.id} triggered successfully against ${scan.target}!`);
      refreshScans();
      
      // Auto-hide status banner after a few seconds
      setTimeout(() => setStatusClass('hidden'), 5000);
    } catch (err) {
      setStatusClass('mt-2 text-sm text-red-500');
      setStatusMsg(err.message || 'Error triggering scan.');
    }
  };

  const fetchDetails = async (scanId) => {
    try {
      const res = await fetch(`/api/scans/${scanId}`);
      const data = await res.json();
      setSelectedScanDetails(data);
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6">
      {/* Scan Config */}
      <div className="bg-white shadow rounded-lg p-6">
        <h2 className="text-lg font-bold text-gray-900 mb-4">Configure & Start Active Scan</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-end">
          <div>
            <label htmlFor="scan-target" className="block text-sm font-medium text-gray-700">Target IP Address / Range</label>
            <input 
              type="text" 
              id="scan-target" 
              placeholder="127.0.0.1" 
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 p-2 border"
            />
          </div>
          <div>
            <label htmlFor="scan-profile" className="block text-sm font-medium text-gray-700">Scan Profile</label>
            <select 
              id="scan-profile"
              value={profile}
              onChange={(e) => setProfile(e.target.value)}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 p-2 border"
            >
              <option value="quick">Quick Scan (Common Ports)</option>
              <option value="full">Full Scan (Comprehensive)</option>
              <option value="targeted">Targeted Scan (Custom)</option>
            </select>
          </div>
          <div>
            <button 
              id="btn-trigger-scan" 
              onClick={handleStartScan}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded-md shadow-sm transition duration-150 ease-in-out"
            >
              Start Scan
            </button>
          </div>
        </div>
        <div id="scan-trigger-status" className={statusClass}>{statusMsg}</div>
      </div>

      {/* History */}
      <div className="bg-white shadow rounded-lg p-6">
        <h2 className="text-lg font-bold text-gray-900 mb-4">Scan History</h2>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">ID</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Target</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Profile</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created At</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200" id="scan-list">
              {scans.length === 0 ? (
                <tr>
                  <td colSpan="6" className="px-6 py-4 text-center text-sm text-gray-500">No scans recorded yet.</td>
                </tr>
              ) : (
                scans.map(scan => {
                  const isRunning = scan.status === 'running';
                  return (
                    <tr key={scan.id}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 font-mono">{scan.id}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-semibold">{scan.target}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 capitalize">{scan.profile}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm">
                        <span className={`px-2.5 py-0.5 text-xs font-bold rounded-full uppercase ${isRunning ? 'bg-blue-100 text-blue-800 scan-status-running' : 'bg-emerald-100 text-emerald-800'}`}>
                          {scan.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono">{scan.created_at}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-medium">
                        {!isRunning ? (
                          <>
                            <button 
                              className="btn-view-scan text-blue-600 hover:text-blue-900 mr-4 font-semibold"
                              onClick={() => fetchDetails(scan.id)}
                            >
                              Details
                            </button>
                            <button 
                              className="btn-explain-scan text-violet-600 hover:text-violet-900 font-semibold"
                              data-id={scan.id}
                              onClick={() => triggerExplain('scan', scan.id)}
                            >
                              Explain with AI
                            </button>
                          </>
                        ) : (
                          <span className="text-xs text-gray-400">Scanning in progress...</span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Details panel */}
      {selectedScanDetails && (
        <div id="scan-details-panel" className="bg-slate-900 text-slate-100 shadow rounded-lg p-6">
          <div className="flex justify-between items-center mb-4 border-b border-slate-700 pb-2">
            <h3 className="text-md font-bold text-white" id="scan-details-title">
              Detailed Scan Report: Scan #{selectedScanDetails.id} ({selectedScanDetails.target})
            </h3>
            <button className="text-slate-400 hover:text-white" onClick={() => setSelectedScanDetails(null)}>Close Details</button>
          </div>
          <pre className="text-xs font-mono overflow-auto p-4 bg-slate-950 rounded max-h-96" id="scan-details-raw">
            {JSON.stringify(selectedScanDetails, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
