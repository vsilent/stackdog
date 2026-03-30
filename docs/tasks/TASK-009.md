# Task Specification: TASK-009

## Implement Web Dashboard

**Phase:** 2 - Detection & Response  
**Priority:** High  
**Estimated Effort:** 4-5 days  
**Status:** 🟢 In Progress  

---

## Objective

Implement a web-based security dashboard using React and TypeScript. The dashboard will provide real-time threat visualization, alert management, container security status, and policy configuration.

---

## Requirements

### 1. Dashboard Architecture

**Frontend Stack:**
- React 18+
- TypeScript
- Bootstrap 5 + Material Design
- WebSocket for real-time updates
- Recharts for data visualization

### 2. Core Components

#### Security Dashboard
- Overall security score
- Active threats count
- Recent alerts feed
- System status indicators
- Quick action buttons

#### Threat Map
- Real-time threat visualization
- Geographic distribution (optional)
- Threat type breakdown
- Severity heat map

#### Container List
- Container security status
- Risk scores per container
- Quarantine controls
- Network activity

#### Alert Panel
- Alert list with filtering
- Alert details view
- Acknowledge/Resolve actions
- Alert statistics

### 3. Backend API

**REST Endpoints:**
- `GET /api/security/status` - Overall security status
- `GET /api/alerts` - List alerts
- `POST /api/alerts/:id/acknowledge` - Acknowledge alert
- `POST /api/alerts/:id/resolve` - Resolve alert
- `GET /api/containers` - List containers
- `POST /api/containers/:id/quarantine` - Quarantine container
- `GET /api/threats` - List threats
- `GET /api/statistics` - Security statistics

**WebSocket Events:**
- `threat:detected` - New threat detected
- `alert:created` - New alert created
- `alert:updated` - Alert status changed
- `container:quarantined` - Container quarantined
- `stats:updated` - Statistics updated

### 4. UI/UX Requirements

- Responsive design (desktop, tablet, mobile)
- Dark/Light theme support
- Real-time updates (WebSocket)
- Accessible (WCAG 2.1 AA)
- Loading states
- Error handling

---

## TDD Tests to Create

### Test File: `web/src/components/__tests__/Dashboard.test.tsx`

```typescript
test('displays security score correctly')
test('shows active threats count')
test('updates in real-time via WebSocket')
test('displays system status indicators')
test('quick action buttons work')
```

### Test File: `web/src/components/__tests__/AlertPanel.test.tsx`

```typescript
test('lists alerts correctly')
test('filters alerts by severity')
test('acknowledge alert works')
test('resolve alert works')
test('displays alert statistics')
```

### Test File: `web/src/components/__tests__/ContainerList.test.tsx`

```typescript
test('displays container list')
test('shows security status per container')
test('quarantine button works')
test('displays risk scores')
test('shows network activity')
```

### Test File: `web/src/services/__tests__/security.test.ts`

```typescript
test('fetches security status from API')
test('fetches alerts from API')
test('acknowledges alert via API')
test('resolves alert via API')
test('quarantines container via API')
```

### Test File: `web/src/services/__tests__/websocket.test.ts`

```typescript
test('connects to WebSocket server')
test('receives real-time updates')
test('handles connection errors')
test('reconnects on disconnect')
test('subscribes to events')
```

---

## Implementation Files

### Frontend Structure (`web/`)

```
web/
├── src/
│   ├── components/
│   │   ├── Dashboard.tsx
│   │   ├── ThreatMap.tsx
│   │   ├── AlertPanel.tsx
│   │   ├── ContainerList.tsx
│   │   ├── SecurityScore.tsx
│   │   └── common/
│   ├── services/
│   │   ├── security.ts
│   │   ├── websocket.ts
│   │   └── api.ts
│   ├── hooks/
│   │   ├── useSecurityStatus.ts
│   │   ├── useAlerts.ts
│   │   └── useWebSocket.ts
│   ├── types/
│   │   ├── security.ts
│   │   ├── alerts.ts
│   │   └── containers.ts
│   ├── styles/
│   │   └── main.css
│   ├── App.tsx
│   └── index.tsx
├── public/
├── package.json
├── tsconfig.json
└── webpack.config.ts
```

### Backend API (`src/api/`)

```
src/api/
├── security.rs              (NEW - security endpoints)
├── alerts.rs                (NEW - alert endpoints)
├── containers.rs            (NEW - container endpoints)
└── websocket.rs             (NEW - WebSocket handler)
```

---

## Acceptance Criteria

- [ ] Dashboard displays security status
- [ ] Real-time updates via WebSocket
- [ ] Alert management (acknowledge, resolve)
- [ ] Container list with quarantine
- [ ] Threat visualization
- [ ] Responsive design
- [ ] All tests passing (target: 25+ tests)
- [ ] Documentation complete

---

*Created: 2026-03-14*
