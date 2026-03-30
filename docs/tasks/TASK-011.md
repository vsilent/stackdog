# Task Specification: TASK-011

## Implement Backend API Endpoints

**Phase:** 2 - Detection & Response  
**Priority:** High  
**Estimated Effort:** 2-3 days  
**Status:** 🟢 In Progress  

---

## Objective

Implement REST API endpoints and WebSocket handler in Rust to support the web dashboard. This will enable real-time security monitoring, alert management, and container control from the frontend.

---

## Requirements

### 1. Security Status Endpoint

**Endpoint:** `GET /api/security/status`

**Response:**
```json
{
  "overallScore": 85,
  "activeThreats": 3,
  "quarantinedContainers": 1,
  "alertsNew": 5,
  "alertsAcknowledged": 2,
  "lastUpdated": "2026-03-14T10:00:00Z"
}
```

### 2. Alerts API

**Endpoints:**
- `GET /api/alerts?severity=&status=` - List alerts with filtering
- `GET /api/alerts/stats` - Alert statistics
- `POST /api/alerts/:id/acknowledge` - Acknowledge alert
- `POST /api/alerts/:id/resolve` - Resolve alert

**Query Parameters:**
- `severity` - Filter by severity (multiple)
- `status` - Filter by status (multiple)
- `dateFrom` - Start date
- `dateTo` - End date

### 3. Containers API

**Endpoints:**
- `GET /api/containers` - List containers
- `POST /api/containers/:id/quarantine` - Quarantine container
- `POST /api/containers/:id/release` - Release container

### 4. Threats API

**Endpoints:**
- `GET /api/threats` - List threats
- `GET /api/threats/statistics` - Threat statistics

**Response (statistics):**
```json
{
  "totalThreats": 10,
  "bySeverity": {
    "Info": 1,
    "Low": 2,
    "Medium": 3,
    "High": 3,
    "Critical": 1
  },
  "byType": {
    "CryptoMiner": 3,
    "ContainerEscape": 2,
    "NetworkScanner": 5
  },
  "trend": "increasing"
}
```

### 5. WebSocket Handler

**Endpoint:** `WS /ws`

**Events (Server → Client):**
- `threat:detected` - New threat detected
- `alert:created` - New alert created
- `alert:updated` - Alert status changed
- `container:quarantined` - Container quarantined
- `stats:updated` - Statistics updated

**Events (Client → Server):**
- `subscribe` - Subscribe to event types
- `unsubscribe` - Unsubscribe from event types

---

## TDD Tests to Create

### Test File: `tests/api/security_api_test.rs`

```rust
#[actix_rt::test]
async fn test_get_security_status()
#[actix_rt::test]
async fn test_security_status_format()
```

### Test File: `tests/api/alerts_api_test.rs`

```rust
#[actix_rt::test]
async fn test_list_alerts()
#[actix_rt::test]
async fn test_list_alerts_filter_by_severity()
#[actix_rt::test]
async fn test_list_alerts_filter_by_status()
#[actix_rt::test]
async fn test_get_alert_stats()
#[actix_rt::test]
async fn test_acknowledge_alert()
#[actix_rt::test]
async fn test_resolve_alert()
```

### Test File: `tests/api/containers_api_test.rs`

```rust
#[actix_rt::test]
async fn test_list_containers()
#[actix_rt::test]
async fn test_quarantine_container()
#[actix_rt::test]
async fn test_release_container()
```

### Test File: `tests/api/threats_api_test.rs`

```rust
#[actix_rt::test]
async fn test_list_threats()
#[actix_rt::test]
async fn test_get_threat_statistics()
#[actix_rt::test]
async fn test_statistics_format()
```

### Test File: `tests/api/websocket_test.rs`

```rust
#[actix_rt::test]
async fn test_websocket_connection()
#[actix_rt::test]
async fn test_websocket_subscribe()
#[actix_rt::test]
async fn test_websocket_receive_events()
```

---

## Implementation Files

### API Modules (`src/api/`)

```
src/api/
├── mod.rs                   (update exports)
├── security.rs              (NEW - security endpoints)
├── alerts.rs                (NEW - alert endpoints)
├── containers.rs            (NEW - container endpoints)
├── threats.rs               (NEW - threat endpoints)
└── websocket.rs             (NEW - WebSocket handler)
```

### Response Types (`src/models/api/`)

```
src/models/api/
├── mod.rs
├── security.rs              (NEW - API response types)
├── alerts.rs                (NEW)
├── containers.rs            (NEW)
└── threats.rs               (NEW)
```

---

## Acceptance Criteria

- [ ] All REST endpoints implemented
- [ ] WebSocket handler working
- [ ] Request/response validation
- [ ] Error handling
- [ ] CORS configured
- [ ] All tests passing (target: 20+ tests)
- [ ] Documentation complete
- [ ] Dashboard connects successfully

---

*Created: 2026-03-14*
