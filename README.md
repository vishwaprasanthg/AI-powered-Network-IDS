# AI Intrusion Detection System (IDS)

A **Real-Time AI-Powered Network Intrusion Detection System** that monitors network traffic, detects malicious activities, and visualizes alerts through a live dashboard.

This project uses **packet sniffing, machine learning, and a full-stack monitoring dashboard** to identify potential network attacks such as SYN floods.

---

# Project Overview

The system captures live network packets, extracts flow-based features, and uses a **Random Forest machine learning model** to classify traffic as **Normal** or **Attack**.

Detected threats are logged and displayed in a **real-time security dashboard** built using React.

---

# System Architecture

```
Network Traffic
      ↓
Packet Capture (Scapy)
      ↓
Flow Feature Extraction
      ↓
Machine Learning Model (Random Forest)
      ↓
Alert Logging (CSV)
      ↓
Flask REST API
      ↓
React Dashboard
```

---

# Features

* Real-time **network packet capture**
* Flow-based **traffic feature extraction**
* **Machine learning attack detection**
* **SYN flood heuristic detection**
* Real-time **security alert logging**
* REST API for alerts and analytics
* Interactive **React dashboard**
* Configurable IDS runtime parameters
* CSV-based alert storage
* Attack statistics and analytics

---

# Technologies Used

### Backend

* Python
* Flask
* Scapy
* Pandas
* Joblib
* Scikit-learn

### Machine Learning

* Random Forest Classifier
* Feature Scaling
* Flow-based network features

### Frontend

* React.js
* JavaScript
* CSS

### Data Handling

* CSV logging
* REST APIs

---

# Project Structure

```
IDS_project
│
├── models
│   ├── live_random_forest.pkl
│   ├── live_scaler.pkl
│   └── live_feature_names.pkl
│
├── src
│   ├── api
│   │   └── app.py
│   │
│   ├── live_capture
│   │   └── live_flow_ids.py
│   │
│   ├── realtime
│   │   ├── alerts_log.csv
│   │   └── simulated_realtime.py
│   │
│   ├── training
│   │   └── train_rf.py
│   │
│   └── inference
│       └── predict.py
│
├── dashboard
│   └── React frontend
│
└── README.md
```

---

# How It Works

1. **Packet Capture**

   * Scapy captures live TCP packets from the network interface.

2. **Flow Creation**

   * Packets are grouped into flows using:

   ```
   Source IP
   Destination IP
   Source Port
   Destination Port
   Protocol
   ```

3. **Feature Extraction**
   Flow features such as:

   * Duration
   * Packet count
   * Byte count
   * SYN/ACK/RST/FIN counts
   * Packet rate
   * Byte rate

4. **Machine Learning Prediction**

   Extracted features are passed to a trained **Random Forest model** which classifies the traffic.

5. **Alert Logging**

   Alerts are stored in:

   ```
   src/realtime/alerts_log.csv
   ```

6. **Dashboard Visualization**

   The Flask API serves alerts to a React dashboard for real-time monitoring.

---

# API Endpoints

### Get Alerts

```
GET /api/alerts
```

Optional filters:

```
/api/alerts?minutes=60
/api/alerts?prediction=ATTACK
/api/alerts?limit=100
```

---

### Get Statistics

```
GET /api/stats
```

Returns:

```
{
  total_alerts,
  attack_count,
  normal_count
}
```

---

### Analytics Endpoint

```
GET /api/analytics
```

Provides summarized traffic analysis.

---

# Running the Project

## 1. Clone Repository

```
git clone https://github.com/your-username/IDS_project.git
cd IDS_project
```

---

# 2. Install Backend Dependencies

```
pip install -r requirements.txt
```

---

# 3. Train the Model

```
python src/training/train_rf.py
```

---

# 4. Start Live IDS

```
python src/live_capture/live_flow_ids.py
```

---

# 5. Start API Server

```
python src/api/app.py
```

Server runs at:

```
http://127.0.0.1:5000
```

---

# 6. Start Dashboard

```
cd dashboard
npm install
npm start
```

Dashboard runs at:

```
http://localhost:3000
```

---

# Example Alert

```
Timestamp: 2026-03-10 21:45:32
Source IP: 192.168.1.5
Destination IP: 192.168.1.10
Protocol: TCP
Prediction: ATTACK
```

---

# Future Improvements

* Deep learning based anomaly detection
* Database storage (MongoDB/PostgreSQL)
* Real-time visualization charts
* Integration with SIEM systems
* Email/SMS alerting
* Docker deployment

---

# Author

Vishwa Prasanth G and Rakesh R

Information Technology Student
Cybersecurity and Machine Learning Enthusiast

---

# License

This project is intended for **educational and research purposes**.

---
