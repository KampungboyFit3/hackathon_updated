# ShieldAI - Enterprise Phishing Detection Platform

## Presentation Overview

**Product**: ShieldAI  
**Tagline**: Enterprise-Grade Phishing Detection as a Service  
**Target Audience**: CISOs, SOC Teams, IT Security Managers  
**Business Model**: B2B SaaS Subscription

---

## 1. Technical Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      ShieldAI Platform                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │ Web UI   │    │  REST API   │    │  Admin Dashboard │   │
│  └────┬────┘    └──────┬─────┘    └────────┬─────────┘   │
│       │                 │                   │              │
│       └────────────────┼───────────────────┘              │
│                      │                                   │
│              ┌───────▼───────┐                        │
│              │  FastAPI      │                        │
│              │  Backend      │                        │
│              └───────┬───────┘                        │
│                      │                                   │
│    ┌─────────────────┼─────────────────┐               │
│    │                 │                 │               │
│    ▼                 ▼                 ▼               │
│ ┌────────┐    ┌────────┐    ┌────────┐              │
│ │ ML     │    │ Rule   │    │ Virus  │              │
│ │ Model  │    │ Engine │    │Total  │              │
│ └────────┘    └────────┘    └────────┘              │
│    │                 │                 │               │
│    └─────────────────┼─────────────────┘               │
│                      │                                   │
│              ┌───────▼───────┐                        │
│              │  Log Storage │                        │
│              │  (CSV/DB)   │                        │
│              └─────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

### Detection Pipeline

#### Step 1: Input Classification
- URL → ML Model + Rule Engine
- SMS → SMS Detector + Keyword Rules
- Email → Email Parser + Content Analysis
- Command → Command Analyzer + Payload Detection

#### Step 2: Multi-Layer Analysis

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **ML Model** | Random Forest Classifier (54 features) | Statistical pattern detection |
| **Rule Engine** | Pattern matching + heuristics | Known attack signatures |
| **VirusTotal** | 70+ AV engines | External threat intelligence |

#### Step 3: Result Generation
```json
{
  "prediction": "phishing",
  "confidence": 0.92,
  "source": "ml_model",
  "threat_level": "high",
  "flags": ["suspicious_tld", "url_shortener", "fake_brand"]
}
```

### Supported Input Types

#### URL Scanning
- Full URLs with query parameters
- URL-shortened links (bit.ly, tinyurl, etc.)
- Internationalized domain names (IDN)
- Deep link analysis

#### SMS Analysis
- Text message content
- URL/phone number extraction
- Keyword-based detection (urgent, prize, bank, etc.)

#### Email Analysis
- Subject line analysis
- Sender address validation
- Body content scanning
- Attachment detection

#### Command Analysis
- PowerShell scripts
- Bash commands
- CMD commands
- Base64 encoded payloads

---

## 2. Pricing Model

### Subscription Tiers

| Feature | Starter | Professional | Enterprise |
|--------|--------|-------------|-----------|
| **Monthly Price** | $299/mo | $799/mo | Custom |
| **API Calls** | 1,000/mo | 10,000/mo | Unlimited |
| **Users** | 3 | 10 | Unlimited |
| **Scans/Day** | 100 | 1,000 | Unlimited |
| **History Retention** | 30 days | 1 year | Unlimited |
| **VirusTotal** | 100 checks | 1,000 checks | Unlimited |
| **Email Support** | ✓ | ✓ | ✓ |
| **Priority Support** | - | ✓ | ✓ |
| **Dedicated Support** | - | - | ✓ |
| **Custom Integrations** | - | - | ✓ |

### Value Calculator

| Cost Center | Average Cost | ShieldAI Savings |
|------------|--------------|-----------------|
| Manual analysis (1hr/day) | $150/day | 100% automated |
| Incident response | $5,000/incident | Early detection reduces incidents by 80% |
| Employee training | $50/user/year | Reduces click-throughs |
| External tools | $200+/mo each | All-in-one platform |

**ROI Example** (100-employee company):
- Before: $50,000/year in security incidents
- After ShieldAI: $9,600/year (80% reduction)
- **Annual Savings**: $40,400+

---

## 3. Competitive Advantages

### Why ShieldAI?

| Advantage | Description |
|-----------|-------------|
| **Multi-Channel** | One tool covers URL, SMS, Email, Commands |
| **Real-Time** | Instant detection (< 1 second) |
| **Privacy-First** | Data stays with your organization |
| **No Per-Scan Costs** | Unlimited scanning in subscription |
| **Audit Trail** | Full compliance logging |
| **Easy Integration** | REST API for SOC/SiEM |

### Comparison Matrix

| Feature | ShieldAI | PhishTank | VirusTotal | Google Safe Browsing |
|---------|----------|-----------|-----------|-------------------|
| URL Scanning | ✓ | ✓ | ✓ | ✓ |
| SMS Scanning | ✓ | - | - | - |
| Email Scanning | ✓ | - | - | - |
| Command Scanning | ✓ | - | - | - |
| Dashboard | ✓ | - | Limited | - |
| API Access | ✓ | ✓ | ✓ | ✓ |
| Self-Hosted Option | ✓ | - | - | - |
| Subscription Model | ✓ | Free | Paid | Free |

### Unique Selling Points

1. **First-to-Market**: Only solution covering all 4 channels
2. **Hybrid Detection**: ML + Rules + External Intelligence
3. **Pay-Per-Use Ready**: API-first architecture
4. **Deploy Anywhere**: Cloud or on-premise

---

## 4. Demo Scenarios

### Scenario 1: URL Detection

**Input**: `http://paypal-secure-login.xyz/verify`

**Flow**:
1. Admin pastes URL in Analyzer
2. System extracts features (length, TLD, entropy, etc.)
3. ML model evaluates → 84% phishing probability
4. Rule engine checks → matches "fake_login" pattern
5. VirusTotal confirms → 3/70 engines flag as malicious
6. **Result**: PHISHING (92% confidence)

**UI Display**:
```
┌────────────────────────────────────────┐
│ ⚠ PHISHING                          │
│ Confidence: 92%  ·  Source: Consensus │
├────────────────────────────────────────┤
│ ████████████░░░░░░░░░░░░░░░░░░░░░░ │
├────────────────────────────────────────┤
│ Why Flagged:                         │
│ • Suspicious domain (.xyz)          │
│ • URL shortener detected             │
│ • Brand impersonation (PayPal)       │
│ • Known malicious pattern          │
└────────────────────────────────────────┘
```

### Scenario 2: SMS Smishing Detection

**Input**: `URGENT! Your bank account has been suspended. Verify now: http://bnk-verify.xyz/login`

**Detection Rules**:
- "URGENT!" keyword → urgency flag
- "bank account suspended" → financial threat
- Shortened URL → hidden destination
- ".xyz" TLD → high-risk registry

**Result**: PHISHING (85% confidence)

### Scenario 3: Dashboard Analytics

**Metrics Displayed**:
- Total scans (today/week/month)
- Phishing vs Legitimate ratio
- Detection by type (URL/SMS/Email/Command)
- Trend over time
- Recent scan history

**Insights for Security Team**:
- Peak attack times
- Most targeted brands
- Attack type distribution

---

## 5. Security & Compliance

### Audit & Logging

| Data Stored | Retention | Access |
|-----------|----------|-------|
| Scan input | 1 year | Admin only |
| Scan result | 1 year | Admin only |
| User actions | 2 years | Admin only |
| API calls | 6 months | Admin only |
| System logs | 90 days | Support team |

### Data Privacy

- **In-Transit**: TLS 1.3 encryption
- **At-Rest**: AES-256 encryption
- **Isolation**: Per-tenant database
- **Deletion**: GDPR-compliant purge

### Access Control

```
Role Hierarchy:
├── Super Admin (full access)
│   ├── Admin (company management)
│   │   ├── Analyst (scan only)
│   │   │   └── Viewer (read-only)
```

### Compliance Readiness

| Standard | Status |
|----------|--------|
| SOC 2 Type II | In progress |
| ISO 27001 | Ready for audit |
| GDPR | Compliant |
| CCPA | Compliant |
| PCI DSS | Ready for audit |

---

## 6. Implementation Options

### Cloud Deployment (SaaS)
- Quickest setup
- Managed by ShieldAI
- Automatic updates

### Self-Hosted (On-Premise)
- Full data control
- Custom integrations
- Annual license + support

### Hybrid
- Cloud API + on-premise data
- Custom deployments

---

## 7. Call to Action

### Next Steps for Sales

1. **Demo** - Schedule live platform demonstration
2. **Trial** - 14-day free trial (Professional tier)
3. **Pilot** - 3-month pilot program
4. **Contract** - Annual subscription

### Contact Information

- **Email**: sales@shieldai.io
- **Phone**: +1-800-SHIELD-AI
- **Website**: shieldai.io

---

## 8. FAQ - Objection Handling

### "We already haveVirusTotal"
VirusTotal is great for URL lookup but doesn't provide:
- Real-time API for automation
- SMS/Email/Command analysis
- Custom rule engine
- Dashboard analytics

### "We have email security software"
Email security tools scan incoming email but don't:
- Let employees check links before clicking
- Scan outbound suspicious links
- Analyze SMS threats
- Provide audit trail

### "It's too expensive"
Compare to cost of a single data breach:
- Average breach: $4.45M (IBM 2023)
- ShieldAI: $9,600/year
- ROI: 460x return on investment

---

## Appendix: Technical Specifications

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|------------|
| `/predict` | POST | Submit scan request |
| `/logs/data` | GET | Retrieve scan history |
| `/retrain` | POST | Trigger model retrain |
| `/virustotal/check` | POST | Manual VT lookup |

### Performance Metrics

| Metric | Value |
|--------|-------|
| Avg Response Time | < 500ms |
| Uptime | 99.9% |
| Max Concurrent | 100 scans/sec |
| Model Update | Weekly |

### Supported Integrations

- REST API (JSON)
- Webhooks
- SIEM connectors
- SAML SSO