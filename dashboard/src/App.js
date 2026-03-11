import React, { useEffect, useMemo, useState } from "react";
import "./App.css";

const API_URL = "http://127.0.0.1:5000/api/alerts";
const TIME_RANGES = [
  { id: "5m", label: "Last 5m", ms: 5 * 60 * 1000 },
  { id: "1h", label: "Last 1h", ms: 60 * 60 * 1000 },
  { id: "24h", label: "Last 24h", ms: 24 * 60 * 60 * 1000 },
  { id: "all", label: "All", ms: null },
];

function parseTimestamp(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function formatTime(value) {
  const date = parseTimestamp(value);
  return date ? date.toLocaleString() : "Unknown";
}

function toKey(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
}

function pickValue(row, variants) {
  for (const key of variants) {
    if (row[key] !== undefined && row[key] !== null && row[key] !== "") {
      return row[key];
    }
  }

  const normalized = Object.entries(row || {}).reduce((acc, [k, v]) => {
    acc[toKey(k)] = v;
    return acc;
  }, {});

  for (const key of variants) {
    const found = normalized[toKey(key)];
    if (found !== undefined && found !== null && found !== "") {
      return found;
    }
  }

  return null;
}

function normalizePredictionValue(value) {
  if (value === null || value === undefined || value === "") {
    return "UNKNOWN";
  }

  if (typeof value === "number") {
    if (value === 1) {
      return "ATTACK";
    }
    if (value === 0) {
      return "NORMAL";
    }
  }

  const text = String(value).trim().toUpperCase();
  if (text === "1") {
    return "ATTACK";
  }
  if (text === "0") {
    return "NORMAL";
  }
  return text;
}

function normalizeAlert(row) {
  if (Array.isArray(row)) {
    return {
      Timestamp: row[0] ?? null,
      SourceIP: row[1] ?? null,
      DestinationIP: row[2] ?? null,
      SourcePort: row[3] ?? null,
      DestinationPort: row[4] ?? null,
      Protocol: row[5] ?? null,
      Prediction: normalizePredictionValue(row[6]),
    };
  }

  return {
    Timestamp: pickValue(row, ["Timestamp", "Time", "DateTime"]),
    SourceIP: pickValue(row, ["Source IP", "Src IP", "SourceIP", "src_ip"]),
    DestinationIP: pickValue(row, ["Destination IP", "Dst IP", "DestinationIP", "dst_ip"]),
    SourcePort: pickValue(row, ["Source Port", "Src Port", "sport", "src_port"]),
    DestinationPort: pickValue(row, ["Destination Port", "Dst Port", "dport", "dst_port"]),
    Protocol: pickValue(row, ["Protocol", "Proto"]),
    Prediction: normalizePredictionValue(pickValue(row, ["Prediction", "Label", "Class", "pred"])),
  };
}

function toCsv(rows) {
  const headers = ["Timestamp", "Source IP", "Destination IP", "Src Port", "Dst Port", "Protocol", "Prediction"];
  const escapeCell = (value) => {
    const str = value === null || value === undefined ? "" : String(value);
    return /[",\n]/.test(str) ? `"${str.replace(/"/g, '""')}"` : str;
  };

  const lines = rows.map((row) => [
    row.Timestamp,
    row.SourceIP,
    row.DestinationIP,
    row.SourcePort,
    row.DestinationPort,
    row.Protocol,
    row.Prediction,
  ]);

  return [headers, ...lines].map((line) => line.map(escapeCell).join(",")).join("\n");
}

function downloadCsv(filename, content) {
  const blob = new Blob([content], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function TrendChart({ points }) {
  if (!points.length) {
    return <div className="chart-empty">No trend data yet</div>;
  }

  const width = 520;
  const height = 170;
  const padding = 20;
  const max = Math.max(...points, 1);

  const coords = points
    .map((value, index) => {
      const x = padding + (index * (width - padding * 2)) / Math.max(points.length - 1, 1);
      const y = height - padding - (value / max) * (height - padding * 2);
      return `${x},${y}`;
    })
    .join(" ");

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="trend-svg" role="img" aria-label="Alert trend">
      <polyline className="trend-fill" points={`${padding},${height - padding} ${coords} ${width - padding},${height - padding}`} />
      <polyline className="trend-line" points={coords} />
      {points.map((value, index) => {
        const x = padding + (index * (width - padding * 2)) / Math.max(points.length - 1, 1);
        const y = height - padding - (value / max) * (height - padding * 2);
        return <circle key={`dot-${index}`} cx={x} cy={y} r="3" className="trend-dot" />;
      })}
    </svg>
  );
}

function App() {
  const [alerts, setAlerts] = useState([]);
  const [apiState, setApiState] = useState("loading");
  const [timeRange, setTimeRange] = useState("24h");

  const fetchAlerts = async () => {
    try {
      const response = await fetch(API_URL);
      if (!response.ok) {
        throw new Error(`API failed: ${response.status}`);
      }
      const data = await response.json();
      const list = Array.isArray(data) ? data.map(normalizeAlert) : [];
      setAlerts(list.reverse());
      setApiState("online");
    } catch (error) {
      console.error("Error fetching alerts:", error);
      setApiState("offline");
    }
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 3000);
    return () => clearInterval(interval);
  }, []);

  const filteredAlerts = useMemo(() => {
    const selected = TIME_RANGES.find((item) => item.id === timeRange);
    if (!selected || selected.ms === null) {
      return alerts;
    }

    const now = Date.now();
    return alerts.filter((row) => {
      const ts = parseTimestamp(row.Timestamp);
      return ts ? now - ts.getTime() <= selected.ms : false;
    });
  }, [alerts, timeRange]);

  const analytics = useMemo(() => {
    const total = filteredAlerts.length;
    const attacks = filteredAlerts.filter((item) => String(item.Prediction).toUpperCase() === "ATTACK").length;
    const normal = filteredAlerts.filter((item) => String(item.Prediction).toUpperCase() === "NORMAL").length;
    const attackRate = total ? ((attacks / total) * 100).toFixed(1) : "0.0";

    const protocolCounts = filteredAlerts.reduce((acc, row) => {
      const key = row.Protocol || "Unknown";
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {});

    const sourceCounts = filteredAlerts.reduce((acc, row) => {
      const key = row.SourceIP || "Unknown";
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {});

    const topSource = Object.entries(sourceCounts).sort((a, b) => b[1] - a[1])[0] || ["-", 0];

    const latest = filteredAlerts[0] || null;

    const timelineBuckets = 12;
    const sortedByTime = [...filteredAlerts]
      .map((row) => ({ ts: parseTimestamp(row.Timestamp) }))
      .filter((x) => x.ts)
      .sort((a, b) => a.ts - b.ts);

    let trend = [];
    if (sortedByTime.length > 0) {
      const start = sortedByTime[0].ts.getTime();
      const end = sortedByTime[sortedByTime.length - 1].ts.getTime();
      const span = Math.max(end - start, 1);
      const bucketSize = span / timelineBuckets;
      trend = Array.from({ length: timelineBuckets }, () => 0);

      sortedByTime.forEach(({ ts }) => {
        const index = Math.min(
          timelineBuckets - 1,
          Math.floor((ts.getTime() - start) / Math.max(bucketSize, 1))
        );
        trend[index] += 1;
      });
    }

    const protocols = Object.entries(protocolCounts).sort((a, b) => b[1] - a[1]);

    return {
      total,
      attacks,
      normal,
      attackRate,
      protocols,
      topSource,
      latest,
      trend,
    };
  }, [filteredAlerts]);

  const handleExport = () => {
    const csv = toCsv(filteredAlerts);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    downloadCsv(`ids_alerts_${timeRange}_${stamp}.csv`, csv);
  };

  return (
    <div className="dashboard">
      <header className="hero">
        <div>
          <p className="eyebrow">AI-Powered Intrusion Detection</p>
          <h1>Network Threat Operations Console</h1>
          <p className="subtext">Live telemetry, anomaly alerts, and behavior analytics from captured packet flows.</p>
        </div>
        <div className={`api-pill ${apiState}`}>
          <span className="dot" /> API {apiState}
        </div>
      </header>

      <section className="kpi-grid">
        <article className="kpi-card">
          <p>Total Alerts</p>
          <h2>{analytics.total}</h2>
        </article>
        <article className="kpi-card danger">
          <p>Attack Events</p>
          <h2>{analytics.attacks}</h2>
        </article>
        <article className="kpi-card safe">
          <p>Normal Flows</p>
          <h2>{analytics.normal}</h2>
        </article>
        <article className="kpi-card">
          <p>Attack Rate</p>
          <h2>{analytics.attackRate}%</h2>
        </article>
      </section>

      <section className="analysis-grid">
        <article className="panel">
          <div className="panel-head">
            <h3>Alert Trend</h3>
            <span>Distribution across selected time range</span>
          </div>
          <TrendChart points={analytics.trend} />
        </article>

        <article className="panel">
          <div className="panel-head">
            <h3>Protocol Distribution</h3>
            <span>Traffic share by transport protocol</span>
          </div>
          <div className="bars">
            {analytics.protocols.length === 0 ? (
              <div className="chart-empty">No protocol data yet</div>
            ) : (
              analytics.protocols.map(([protocol, count]) => {
                const width = analytics.total ? (count / analytics.total) * 100 : 0;
                return (
                  <div className="bar-row" key={protocol}>
                    <div className="bar-label">{protocol}</div>
                    <div className="bar-track">
                      <div className="bar-fill" style={{ width: `${width}%` }} />
                    </div>
                    <div className="bar-value">{count}</div>
                  </div>
                );
              })
            )}
          </div>
        </article>

        <article className="panel">
          <div className="panel-head">
            <h3>Threat Intelligence</h3>
            <span>Quick analysis from current stream</span>
          </div>
          <div className="intel-list">
            <div>
              <label>Top Source IP</label>
              <strong>{analytics.topSource[0]}</strong>
              <small>{analytics.topSource[1]} events</small>
            </div>
            <div>
              <label>Last Event Time</label>
              <strong>{analytics.latest ? formatTime(analytics.latest.Timestamp) : "No events"}</strong>
              <small>{analytics.latest ? analytics.latest.Prediction || "UNKNOWN" : "-"}</small>
            </div>
            <div>
              <label>Analyst Signal</label>
              <strong>
                {Number(analytics.attackRate) >= 50
                  ? "High Threat Pressure"
                  : Number(analytics.attackRate) >= 20
                  ? "Elevated Monitoring"
                  : "Stable Traffic Profile"}
              </strong>
              <small>Derived from attack ratio</small>
            </div>
          </div>
        </article>
      </section>

      <section className="panel table-wrap">
        <div className="panel-head table-header-row">
          <div>
            <h3>Recent Alert Events</h3>
            <span>Newest records appear first (auto refresh every 3s)</span>
          </div>
          <div className="table-controls">
            <div className="filter-group" role="group" aria-label="Time range filter">
              {TIME_RANGES.map((range) => (
                <button
                  key={range.id}
                  type="button"
                  className={`chip ${timeRange === range.id ? "active" : ""}`}
                  onClick={() => setTimeRange(range.id)}
                >
                  {range.label}
                </button>
              ))}
            </div>
            <button type="button" className="export-btn" onClick={handleExport} disabled={filteredAlerts.length === 0}>
              Export CSV
            </button>
          </div>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Src Port</th>
                <th>Dst Port</th>
                <th>Protocol</th>
                <th>Prediction</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan="7" className="empty-row">
                    No packets/alerts found for selected time range
                  </td>
                </tr>
              ) : (
                filteredAlerts.slice(0, 200).map((alert, index) => (
                  <tr key={`${alert.Timestamp || "unknown"}-${index}`}>
                    <td>{formatTime(alert.Timestamp)}</td>
                    <td>{alert.SourceIP ?? "-"}</td>
                    <td>{alert.DestinationIP ?? "-"}</td>
                    <td>{alert.SourcePort ?? "-"}</td>
                    <td>{alert.DestinationPort ?? "-"}</td>
                    <td>{alert.Protocol ?? "-"}</td>
                    <td>
                      <span className={`status-tag ${String(alert.Prediction).toUpperCase() === "ATTACK" ? "attack" : "normal"}`}>
                        {alert.Prediction ?? "UNKNOWN"}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export default App;
