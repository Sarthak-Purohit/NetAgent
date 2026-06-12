import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import Dashboard from './components/Dashboard';
import Scanner from './components/Scanner';
import Traffic from './components/Traffic';
import AutonomousAgent from './components/AutonomousAgent';
import AiExplainerModal from './components/AiExplainerModal';
import ErrorBoundaryBanner from './components/ErrorBoundaryBanner';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [hasError500, setHasError500] = useState(false);
  const [scans, setScans] = useState([]);
  const [alerts, setAlerts] = useState([]);
  
  // Explainer Modal states
  const [explainerOpen, setExplainerOpen] = useState(false);
  const [explainerSourceType, setExplainerSourceType] = useState('scan');
  const [explainerSourceId, setExplainerSourceId] = useState(null);

  // Fetch scans and alerts helper
  const fetchData = async () => {
    let errorOccurred = false;
    try {
      const scansRes = await fetch('/api/scans');
      if (scansRes.status === 500) {
        setHasError500(true);
        errorOccurred = true;
      } else {
        const scansData = await scansRes.json();
        setScans(scansData);
      }
    } catch (err) {
      setHasError500(true);
      errorOccurred = true;
    }

    try {
      const alertsRes = await fetch('/api/alerts');
      if (alertsRes.status === 500) {
        setHasError500(true);
        errorOccurred = true;
      } else {
        const alertsData = await alertsRes.json();
        setAlerts(alertsData);
      }
    } catch (err) {
      setHasError500(true);
      errorOccurred = true;
    }

    if (!errorOccurred) {
      setHasError500(false);
    }
  };

  useEffect(() => {
    fetchData();
    // Poll every 5 seconds for status updates
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const triggerExplainModal = (type, id) => {
    setExplainerSourceType(type);
    setExplainerSourceId(id);
    setExplainerOpen(true);
  };

  return (
    <div className="bg-gray-100 text-gray-800 min-h-screen flex flex-col">
      <Header />
      <ErrorBoundaryBanner visible={hasError500} />
      
      {/* Navigation Tabs */}
      <nav className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 flex space-x-8">
          <button
            id="tab-dashboard-btn"
            className={`py-4 px-1 text-sm font-medium border-b-2 border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 ${activeTab === 'dashboard' ? 'active-tab' : ''}`}
            onClick={() => setActiveTab('dashboard')}
          >
            Dashboard Overview
          </button>
          <button
            id="tab-scanner-btn"
            className={`py-4 px-1 text-sm font-medium border-b-2 border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 ${activeTab === 'scanner' ? 'active-tab' : ''}`}
            onClick={() => setActiveTab('scanner')}
          >
            Active Scanner
          </button>
          <button
            id="tab-traffic-btn"
            className={`py-4 px-1 text-sm font-medium border-b-2 border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 ${activeTab === 'traffic' ? 'active-tab' : ''}`}
            onClick={() => setActiveTab('traffic')}
          >
            Traffic Analyzer & Alerts
          </button>
          <button
            id="tab-agent-btn"
            className={`py-4 px-1 text-sm font-medium border-b-2 border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 ${activeTab === 'agent' ? 'active-tab' : ''}`}
            onClick={() => setActiveTab('agent')}
          >
            🤖 Autonomous Agent
          </button>
        </div>
      </nav>

      {/* Sections Wrapper */}
      <main className="flex-grow max-w-7xl w-full mx-auto px-4 py-6">
        <div id="section-dashboard" className={activeTab === 'dashboard' ? 'space-y-6' : 'hidden'}>
          <Dashboard scans={scans} alerts={alerts} switchTab={setActiveTab} />
        </div>
        
        <div id="section-scanner" className={activeTab === 'scanner' ? 'space-y-6' : 'hidden'}>
          <Scanner 
            scans={scans} 
            refreshScans={fetchData} 
            triggerExplain={triggerExplainModal}
          />
        </div>

        <div id="section-traffic" className={activeTab === 'traffic' ? 'space-y-6' : 'hidden'}>
          <Traffic 
            alerts={alerts} 
            refreshAlerts={fetchData} 
            triggerExplain={triggerExplainModal}
          />
        </div>

        <div id="section-agent" className={activeTab === 'agent' ? 'space-y-6' : 'hidden'}>
          <AutonomousAgent />
        </div>
      </main>

      <AiExplainerModal 
        visible={explainerOpen} 
        sourceType={explainerSourceType} 
        sourceId={explainerSourceId} 
        onClose={() => setExplainerOpen(false)}
      />

      <footer className="bg-slate-900 text-slate-400 text-xs py-4 text-center mt-6 border-t border-slate-800">
        <div className="max-w-7xl mx-auto px-4">
          &copy; 2026 NetAgent SOC Dashboard.
        </div>
      </footer>
    </div>
  );
}
