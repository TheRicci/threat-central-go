# Threat Central

## 🎯 The Problem: Lack of Correlation in Free SIEMs

Modern cybersecurity teams face a critical challenge: **free and open-source SIEM solutions lack sophisticated correlation capabilities**. While tools like Suricata, ModSecurity, and Wazuh excel at generating security alerts, they often produce isolated, disconnected events that make it difficult to:

- **Identify coordinated attacks** across multiple security tools
- **Correlate related threats** from the same source IP
- **Prioritize incidents** based on severity and frequency
- **Reduce alert fatigue** by grouping similar events
- **Gain situational awareness** of ongoing security events

## 🚀 The Solution: Intelligent Threat Correlation

**Threat Central** addresses this gap by providing a lightweight, real-time correlation engine that transforms scattered security alerts into meaningful, actionable intelligence.

### Core Correlation Logic

#### 1. **Threat-Based Correlation**
Groups alerts by **IP + Threat Type + Log Source**:
- **Suricata** alerts: Network intrusion detection events
- **ModSecurity** alerts: Web application firewall events  
- **Wazuh** alerts: Host-based security events

This correlation helps identify when the same threat actor is targeting different parts of your infrastructure.

#### 2. **Event-Based Correlation**
Groups alerts by **IP + Port + Severity Level**:
- Aggregates all security events targeting the same service
- Provides a unified view of attack patterns
- Enables quick identification of high-risk targets

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Suricata      │    │   ModSecurity    │    │     Wazuh       │
│   (Network IDS) │    │   (Web WAF)      │    │   (HIDS/EDR)    │
└─────────┬───────┘    └─────────┬────────┘    └─────────┬───────┘
          │                      │                       │
          └──────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────▼──────────────┐
                    │     Threat Central         │
                    │   Correlation Engine       │
                    │                            │
                    │  • Real-time processing    │
                    │  • Multi-source correlation│
                    │  • Severity normalization  │
                    │  • Event aggregation       │
                    └─────────────┬──────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │     Interactive UI         │
                    │                            │
                    │  • Suricata Tab           │
                    │  • ModSecurity Tab        │
                    │  • Wazuh Tab              │
                    │  • Events Tab             │
                    └────────────────────────────┘
```

## 🎮 Features

### **Real-Time Correlation**
- Processes incoming alerts from multiple security tools
- Groups related events automatically
- Updates correlation counts in real-time

### **Multi-Source Support**
- **Suricata**: Network intrusion detection
- **ModSecurity**: Web application firewall
- **Wazuh**: Host intrusion detection and endpoint security

### **Interactive Dashboard**
- **Tabbed Interface**: Separate views for each security tool
- **Events Tab**: Unified view of all correlated events
- **Detailed Views**: Drill down into specific alerts
- **Real-time Updates**: Live correlation as new alerts arrive

### **Intelligent Grouping**
- **Threat Correlation**: Groups by IP + Threat Type + Source
- **Event Correlation**: Groups by IP + Port + Severity
- **Quantity Tracking**: Shows frequency of similar events
- **Timestamp Management**: Tracks first and last occurrence

## 🔧 Why This Matters

### **For Security Teams**
- **Reduce Alert Fatigue**: Group similar events instead of handling hundreds of individual alerts
- **Improve Response Time**: Quickly identify coordinated attacks
- **Better Prioritization**: Focus on high-frequency, high-severity events
- **Enhanced Visibility**: See the full picture of security events

### **For Organizations**
- **Cost-Effective**: Leverages existing free SIEM tools
- **No Vendor Lock-in**: Works with open-source security stack
- **Easy Integration**: Simple HTTP-based alert ingestion
- **Lightweight**: Minimal resource requirements

## 🎯 Use Cases

### **Incident Response**
- Quickly identify if a single IP is conducting multiple types of attacks
- Correlate web application attacks with network-level threats
- Track attack progression across different security layers

### **Threat Hunting**
- Discover coordinated campaigns by grouping related events
- Identify high-value targets based on event frequency
- Analyze attack patterns across time and services

### **Security Operations**
- Reduce false positives by correlating events
- Improve alert prioritization based on correlation strength
- Gain better situational awareness of security posture

