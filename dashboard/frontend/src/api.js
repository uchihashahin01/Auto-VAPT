/* Auto-VAPT Dashboard — API Service */

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8888';

export async function fetchStats() {
    const res = await fetch(`${API_BASE}/api/stats`);
    if (!res.ok) throw new Error('Failed to fetch stats');
    return res.json();
}

export async function fetchScans(limit = 50) {
    const res = await fetch(`${API_BASE}/api/scans?limit=${limit}`);
    if (!res.ok) throw new Error('Failed to fetch scans');
    return res.json();
}

export async function fetchScanDetail(scanId) {
    const res = await fetch(`${API_BASE}/api/scans/${scanId}`);
    if (!res.ok) throw new Error('Scan not found');
    return res.json();
}

export async function startScan(params) {
    const res = await fetch(`${API_BASE}/api/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
    });
    if (!res.ok) throw new Error('Failed to start scan');
    return res.json();
}

export async function deleteScan(scanId) {
    const res = await fetch(`${API_BASE}/api/scans/${scanId}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete scan');
    return res.json();
}

export async function fetchScanDiff(scanAId, scanBId) {
    const res = await fetch(`${API_BASE}/api/scans/diff/${scanAId}/${scanBId}`);
    if (!res.ok) throw new Error('Failed to fetch scan diff');
    return res.json();
}

export function connectWebSocket(scanId, onMessage) {
    const wsBase = API_BASE.replace('http', 'ws');
    const ws = new WebSocket(`${wsBase}/ws/scans/${scanId}`);

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        onMessage(data);
    };

    ws.onerror = () => { };
    ws.onclose = () => { };

    return ws;
}
