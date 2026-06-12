import React, { useState, useRef } from 'react';

export default function Traffic({ alerts, refreshAlerts, triggerExplain }) {
  const [selectedInterface, setSelectedInterface] = useState('eth0');
  const [isCapturing, setIsCapturing] = useState(false);
  const [captureStatusText, setCaptureStatusText] = useState('Stopped');
  const [captureStatusNotification, setCaptureStatusNotification] = useState('');
  
  // Drag and drop / upload state
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadLabel, setUploadLabel] = useState('Click to upload or drag & drop a PCAP file');
  const [uploadStatus, setUploadStatus] = useState('');
  const [uploadStatusClass, setUploadStatusClass] = useState('hidden');
  const [uploadDisabled, setUploadDisabled] = useState(true);
  
  const fileInputRef = useRef(null);

  // Toggle Sniffer
  const handleToggleCapture = async () => {
    setCaptureStatusNotification('');
    const nextAction = isCapturing ? 'stop' : 'start';
    
    try {
      const response = await fetch('/api/alerts/capture', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: nextAction,
          interface: nextAction === 'start' ? selectedInterface : undefined
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to toggle capture');
      }

      const statusObj = await response.json();
      if (nextAction === 'start') {
        setIsCapturing(true);
        setCaptureStatusText(`Capturing (${statusObj.interface || selectedInterface})...`);
      } else {
        setIsCapturing(false);
        setCaptureStatusText('Stopped');
      }
    } catch (err) {
      setCaptureStatusNotification(err.message || 'Failed to toggle capture');
    }
  };

  // Drag & Drop event handlers
  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      processFileSelection(files[0]);
    }
  };

  const handleFileChange = (e) => {
    const files = e.target.files;
    if (files.length > 0) {
      processFileSelection(files[0]);
    }
  };

  const processFileSelection = (file) => {
    const filename = file.name.toLowerCase();
    if (!(filename.endsWith('.pcap') || filename.endsWith('.pcapng'))) {
      setUploadStatus('Only .pcap and .pcapng files are supported');
      setUploadStatusClass('text-sm font-medium text-amber-600 text-center');
      setSelectedFile(null);
      setUploadDisabled(true);
      return;
    }

    setSelectedFile(file);
    setUploadLabel(`Selected File: ${file.name}`);
    setUploadDisabled(false);
    setUploadStatusClass('hidden');
  };

  const handleUpload = async () => {
    if (!selectedFile) return;

    setUploadStatus('Uploading & analyzing PCAP file. Please wait...');
    setUploadStatusClass('text-sm font-medium text-blue-600 text-center');
    setUploadDisabled(true);

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const response = await fetch('/api/alerts/analyze-pcap', {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        throw new Error('Error analyzing PCAP file.');
      }

      const result = await response.json();
      setUploadStatus(`PCAP Ingested! Generated ${result.alerts_generated} alerts.`);
      setUploadStatusClass('text-sm font-medium text-emerald-600 text-center');
      refreshAlerts();
      setSelectedFile(null);
      setUploadLabel('Click to upload or drag & drop a PCAP file');
      if (fileInputRef.current) fileInputRef.current.value = '';
    } catch (err) {
      setUploadStatus(err.message || 'Error analyzing PCAP file.');
      setUploadStatusClass('text-sm font-medium text-red-600 text-center');
      setUploadDisabled(false);
    }
  };

  const getSeverityClass = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'bg-red-200 text-red-900 border border-red-300';
      case 'high': return 'bg-orange-200 text-orange-900 border border-orange-300';
      case 'medium': return 'bg-amber-200 text-amber-900 border border-amber-300';
      case 'low': return 'bg-blue-100 text-blue-800 border border-blue-200';
      default: return 'bg-gray-100 text-gray-800 border border-gray-200';
    }
  };

  const sortedAlerts = [...alerts].sort((a, b) => b.id - a.id);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        
        {/* Live capture settings */}
        <div className="bg-white shadow rounded-lg p-6">
          <h2 className="text-lg font-bold text-gray-900 mb-4">Live Packet Sniffing & Capture</h2>
          <div className="space-y-4">
            <div>
              <label htmlFor="capture-interface" className="block text-sm font-medium text-gray-700">Network Interface</label>
              <select 
                id="capture-interface"
                value={selectedInterface}
                onChange={(e) => setSelectedInterface(e.target.value)}
                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2 border"
              >
                <option value="eth0">eth0 (Standard Interface)</option>
                <option value="wlan0">wlan0 (Wireless Interface)</option>
                <option value="lo">lo (Loopback)</option>
              </select>
            </div>
            <div className="flex items-center justify-between pt-2">
              <div>
                <span className="text-sm font-medium text-gray-500">Capture Status: </span>
                <span id="capture-status" className="text-sm font-bold text-gray-700 uppercase">{captureStatusText}</span>
              </div>
              <button 
                id="btn-capture-toggle"
                onClick={handleToggleCapture}
                className={`font-semibold py-2 px-6 rounded-md shadow-sm transition duration-150 ease-in-out text-white ${isCapturing ? 'bg-red-600 hover:bg-red-700' : 'bg-emerald-600 hover:bg-emerald-700'}`}
              >
                {isCapturing ? 'Stop Capture' : 'Start Capture'}
              </button>
            </div>
            {captureStatusNotification && (
              <div id="capture-status-notification" className="text-xs text-red-500 mt-1">{captureStatusNotification}</div>
            )}
          </div>
        </div>

        {/* Drag and Drop Upload */}
        <div className="bg-white shadow rounded-lg p-6">
          <h2 className="text-lg font-bold text-gray-900 mb-4">Import Offline PCAP File</h2>
          <div className="space-y-4">
            <div 
              id="pcap-drop-area" 
              onDragOver={handleDragOver}
              onDrop={handleDrop}
              className="border-2 border-dashed border-gray-300 rounded-md p-6 text-center hover:border-blue-500 transition duration-150 ease-in-out cursor-pointer"
              onClick={() => fileInputRef.current?.click()}
            >
              <input 
                type="file" 
                id="file-pcap-upload" 
                ref={fileInputRef}
                accept=".pcap,.pcapng" 
                className="hidden" 
                onChange={handleFileChange}
              />
              <svg className="mx-auto h-12 w-12 text-gray-400" stroke="currentColor" fill="none" viewBox="0 0 48 48">
                <path d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-31-31m0 0l-12 12m12-12v12" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              <p className="mt-1 text-sm text-gray-600 font-semibold" id="upload-label-text">{uploadLabel}</p>
              <p className="mt-1 text-xs text-gray-400">Supports .pcap, .pcapng up to 50MB</p>
            </div>
            <div className="flex justify-end">
              <button 
                id="btn-pcap-upload" 
                onClick={handleUpload}
                disabled={uploadDisabled}
                className="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded-md shadow-sm transition duration-150 ease-in-out disabled:opacity-50"
              >
                Upload & Analyze
              </button>
            </div>
            <div id="pcap-upload-status" className={uploadStatusClass}>{uploadStatus}</div>
          </div>
        </div>
      </div>

      {/* Complete Log */}
      <div className="bg-white shadow rounded-lg p-6">
        <h2 className="text-lg font-bold text-gray-900 mb-4">Complete Alert Log</h2>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">ID</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Alert Type</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source IP</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Destination IP</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Description</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200" id="alert-list">
              {sortedAlerts.length === 0 ? (
                <tr>
                  <td colSpan="8" className="px-6 py-4 text-center text-sm text-gray-500">No security alerts logged yet.</td>
                </tr>
              ) : (
                sortedAlerts.map(alert => (
                  <tr key={alert.id}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900">{alert.id}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      <span className={`px-2.5 py-0.5 text-xs font-bold rounded-full uppercase ${getSeverityClass(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 font-bold">{alert.alert_type}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono">{alert.source_ip}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono">{alert.destination_ip}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{alert.protocol}</td>
                    <td className="px-6 py-4 text-sm text-gray-500 truncate max-w-xs">{alert.description}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      <button 
                        className="btn-explain-alert text-violet-600 hover:text-violet-900 font-semibold"
                        data-id={alert.id}
                        onClick={() => triggerExplain('alert', alert.id)}
                      >
                        Explain with AI
                      </button>
                    </td>
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
