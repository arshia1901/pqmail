import React, { useEffect, useState, useCallback } from 'react';
import { AlertCircle, CheckCircle, Clock, Mail, TrendingUp } from 'lucide-react';

interface Email {
  timestamp: string;
  message_id: string;
  from: string;
  to: string[];
  algorithm: string;
  sensitivity: string;
  risk: {
    risk_category: string;
    years_of_safety_remaining: number;
  };
  action: string;
  flag?: string;
}

interface Stats {
  total_emails: number;
  algorithms: Record<string, number>;
  sensitivities: Record<string, number>;
  risk_categories: Record<string, number>;
  avg_years_of_safety: number;
}

const RiskBadge: React.FC<{ risk: string }> = ({ risk }) => {
  const colors: Record<string, string> = {
    CRITICAL: 'bg-red-600 text-white',
    HIGH: 'bg-orange-500 text-white',
    MEDIUM: 'bg-yellow-500 text-white',
    LOW: 'bg-green-500 text-white',
  };

  return (
    <span className={`px-3 py-1 rounded-full text-sm font-semibold ${colors[risk] || 'bg-gray-300'}`}>
      {risk}
    </span>
  );
};

const AlgorithmBadge: React.FC<{ algo: string }> = ({ algo }) => {
  const colors: Record<string, string> = {
    HYBRID: 'bg-purple-200 text-purple-900',
    ECDH: 'bg-blue-200 text-blue-900',
    RSA: 'bg-indigo-200 text-indigo-900',
    UNENCRYPTED: 'bg-red-200 text-red-900',
  };

  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${colors[algo] || 'bg-gray-200 text-gray-900'}`}>
      {algo}
    </span>
  );
};

const LiveEmailFeed: React.FC<{ emails: Email[] }> = ({ emails }) => {
  return (
    <div className="space-y-3 max-h-96 overflow-y-auto">
      {emails.length === 0 ? (
        <p className="text-gray-500 text-center py-8">Waiting for emails...</p>
      ) : (
        emails.slice(0, 20).map((email, idx) => (
          <div key={idx} className="border rounded-lg p-4 bg-white hover:bg-gray-50 transition">
            <div className="flex items-start justify-between mb-2">
              <div className="flex-1">
                <p className="text-sm font-medium text-gray-900 truncate">{email.from}</p>
                <p className="text-xs text-gray-500">{new Date(email.timestamp).toLocaleTimeString()}</p>
              </div>
              <RiskBadge risk={email.risk.risk_category} />
            </div>
            <div className="flex gap-2 mb-2">
              <AlgorithmBadge algo={email.algorithm} />
              <span className={`px-2 py-1 rounded text-xs font-medium ${
                email.sensitivity === 'CRITICAL' ? 'bg-red-100 text-red-900' :
                email.sensitivity === 'HIGH' ? 'bg-orange-100 text-orange-900' :
                'bg-green-100 text-green-900'
              }`}>
                {email.sensitivity}
              </span>
            </div>
            <p className="text-xs text-gray-600">
              ⏱️ {email.risk.years_of_safety_remaining} years of safety
            </p>
          </div>
        ))
      )}
    </div>
  );
};

const StatCard: React.FC<{ title: string; value: string | number; icon: React.ReactNode }> = ({ title, value, icon }) => (
  <div className="bg-white p-4 rounded-lg border shadow-sm">
    <div className="flex items-center justify-between">
      <div>
        <p className="text-gray-600 text-sm">{title}</p>
        <p className="text-2xl font-bold text-gray-900 mt-1">{value}</p>
      </div>
      <div className="text-gray-400">{icon}</div>
    </div>
  </div>
);

const AuditUploader: React.FC<{ onUpload: (file: File) => void }> = ({ onUpload }) => {
  const [uploading, setUploading] = useState(false);

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file && file.name.endsWith('.mbox')) {
      setUploading(true);
      onUpload(file);
      setTimeout(() => setUploading(false), 2000);
    }
  };

  return (
    <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center hover:border-blue-400 transition">
      <input
        type="file"
        accept=".mbox"
        onChange={handleFileChange}
        className="hidden"
        id="mbox-upload"
      />
      <label htmlFor="mbox-upload" className="cursor-pointer">
        <Mail className="mx-auto mb-2 text-gray-400" size={32} />
        <p className="font-medium text-gray-900">Upload .mbox file</p>
        <p className="text-sm text-gray-500 mt-1">Click or drag to audit mailbox</p>
      </label>
      {uploading && <p className="text-blue-600 text-sm mt-2">Uploading...</p>}
    </div>
  );
};

export default function Dashboard() {
  const [emails, setEmails] = useState<Email[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [connected, setConnected] = useState(false);
  const [backendUrl, setBackendUrl] = useState('http://localhost:8000');
  const [auditResult, setAuditResult] = useState<any>(null);

  useEffect(() => {
    let ws: WebSocket;
    const connectWebSocket = () => {
      try {
        ws = new WebSocket('ws://localhost:8000/ws/events');

        ws.onopen = () => {
          console.log('✅ Connected to backend');
          setConnected(true);
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'ping' || data.type === 'pong') {
              // Keep-alive message
              return;
            }
            setEmails((prev) => [data, ...prev.slice(0, 99)]);
          } catch (e) {
            console.error('Failed to parse event:', e);
          }
        };

        ws.onerror = (error) => {
          console.error('WebSocket error:', error);
          setConnected(false);
        };

        ws.onclose = () => {
          console.log('❌ Disconnected from backend');
          setConnected(false);
          setTimeout(connectWebSocket, 3000);
        };
      } catch (error) {
        console.error('Failed to connect:', error);
        setTimeout(connectWebSocket, 3000);
      }
    };

    connectWebSocket();
    return () => ws?.close();
  }, []);

  const handleAuditUpload = useCallback(async (file: File) => {
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch(`${backendUrl}/audit/upload`, {
        method: 'POST',
        body: formData,
      });

      if (response.ok) {
        const result = await response.json();
        setAuditResult(result);
        console.log('Audit result:', result);
      } else {
        console.error('Audit failed:', response.statusText);
      }
    } catch (error) {
      console.error('Upload error:', error);
    }
  }, [backendUrl]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100">
      {/* Header */}
      <div className="bg-white border-b shadow-sm">
        <div className="max-w-7xl mx-auto px-6 py-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900">🔐 PQMail Dashboard</h1>
              <p className="text-gray-600 text-sm mt-1">Post-Quantum Secure Email Gateway</p>
            </div>
            <div className="flex items-center gap-2">
              <div className={`w-3 h-3 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`}></div>
              <span className="text-sm font-medium text-gray-700">
                {connected ? 'Connected' : 'Disconnected'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Stats Row */}
        <div className="grid grid-cols-4 gap-4 mb-8">
          <StatCard
            title="Emails Processed"
            value={emails.length}
            icon={<Mail size={24} />}
          />
          <StatCard
            title="Critical Risk"
            value={emails.filter((e) => e.risk.risk_category === 'CRITICAL').length}
            icon={<AlertCircle size={24} />}
          />
          <StatCard
            title="Hybrid Encrypted"
            value={emails.filter((e) => e.algorithm === 'HYBRID').length}
            icon={<CheckCircle size={24} />}
          />
          <StatCard
            title="Avg Safety"
            value={
              emails.length > 0
                ? (
                    emails.reduce((sum, e) => sum + e.risk.years_of_safety_remaining, 0) /
                    emails.length
                  ).toFixed(1)
                : '—'
            }
            icon={<TrendingUp size={24} />}
          />
        </div>

        {/* Main Grid */}
        <div className="grid grid-cols-3 gap-6">
          {/* Live Feed */}
          <div className="col-span-2">
            <div className="bg-white rounded-lg border shadow-sm p-6">
              <h2 className="text-xl font-bold text-gray-900 mb-4">📨 Live Email Feed</h2>
              <LiveEmailFeed emails={emails} />
            </div>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Audit Upload */}
            <div className="bg-white rounded-lg border shadow-sm p-6">
              <h2 className="text-lg font-bold text-gray-900 mb-4">📤 Audit Mailbox</h2>
              <AuditUploader onUpload={handleAuditUpload} />
            </div>

            {/* Audit Results */}
            {auditResult && (
              <div className="bg-white rounded-lg border shadow-sm p-6">
                <h3 className="font-bold text-gray-900 mb-2">{auditResult.filename}</h3>
                <div className="space-y-2 text-sm">
                  <p>
                    <span className="text-gray-600">Total:</span>{' '}
                    <span className="font-semibold">{auditResult.audit.total_emails}</span>
                  </p>
                  <p>
                    <span className="text-gray-600">Critical:</span>{' '}
                    <span className="font-semibold text-red-600">{auditResult.critical_count}</span>
                  </p>
                  <p>
                    <span className="text-gray-600">Unencrypted:</span>{' '}
                    <span className="font-semibold text-orange-600">{auditResult.unencrypted_count}</span>
                  </p>
                </div>
              </div>
            )}

            {/* Algorithm Distribution */}
            {emails.length > 0 && (
              <div className="bg-white rounded-lg border shadow-sm p-6">
                <h3 className="font-bold text-gray-900 mb-3">🔐 Algorithm Mix</h3>
                <div className="space-y-2 text-sm">
                  {Object.entries(
                    emails.reduce(
                      (acc, e) => {
                        acc[e.algorithm] = (acc[e.algorithm] || 0) + 1;
                        return acc;
                      },
                      {} as Record<string, number>
                    )
                  ).map(([algo, count]) => (
                    <div key={algo} className="flex justify-between">
                      <span className="text-gray-600">{algo}:</span>
                      <span className="font-semibold">
                        {count} ({((count / emails.length) * 100).toFixed(0)}%)
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Risk Distribution */}
            {emails.length > 0 && (
              <div className="bg-white rounded-lg border shadow-sm p-6">
                <h3 className="font-bold text-gray-900 mb-3">⚠️ Risk Distribution</h3>
                <div className="space-y-2 text-sm">
                  {Object.entries(
                    emails.reduce(
                      (acc, e) => {
                        acc[e.risk.risk_category] = (acc[e.risk.risk_category] || 0) + 1;
                        return acc;
                      },
                      {} as Record<string, number>
                    )
                  )
                    .sort(([a], [b]) => {
                      const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
                      return (order[a as keyof typeof order] || 999) - (order[b as keyof typeof order] || 999);
                    })
                    .map(([risk, count]) => (
                      <div key={risk} className="flex justify-between items-center">
                        <span className="text-gray-600">{risk}:</span>
                        <div className="flex items-center gap-2">
                          <div
                            className={`h-2 rounded-full`}
                            style={{ width: `${(count / emails.length) * 100}px` }}
                            className={`h-2 rounded-full ${
                              risk === 'CRITICAL' ? 'bg-red-500' :
                              risk === 'HIGH' ? 'bg-orange-500' :
                              risk === 'MEDIUM' ? 'bg-yellow-500' :
                              'bg-green-500'
                            }`}
                          ></div>
                          <span className="font-semibold w-8 text-right">{count}</span>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
