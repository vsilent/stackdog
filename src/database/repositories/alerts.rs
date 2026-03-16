//! Alert repository using rusqlite

use rusqlite::params;
use anyhow::Result;
use crate::database::connection::DbPool;
use crate::database::models::Alert;
use uuid::Uuid;
use chrono::Utc;

/// Alert filter
#[derive(Debug, Clone, Default)]
pub struct AlertFilter {
    pub severity: Option<String>,
    pub status: Option<String>,
}

/// Alert statistics
#[derive(Debug, Clone, Default)]
pub struct AlertStats {
    pub total_count: i64,
    pub new_count: i64,
    pub acknowledged_count: i64,
    pub resolved_count: i64,
}

fn map_alert_row(row: &rusqlite::Row) -> Result<Alert, rusqlite::Error> {
    Ok(Alert {
        id: row.get(0)?,
        alert_type: row.get(1)?,
        severity: row.get(2)?,
        message: row.get(3)?,
        status: row.get(4)?,
        timestamp: row.get(5)?,
        metadata: row.get(6)?,
    })
}

/// Create a new alert
pub async fn create_alert(pool: &DbPool, alert: Alert) -> Result<Alert> {
    let conn = pool.get()?;
    
    conn.execute(
        "INSERT INTO alerts (id, alert_type, severity, message, status, timestamp, metadata)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            alert.id,
            alert.alert_type,
            alert.severity,
            alert.message,
            alert.status,
            alert.timestamp,
            alert.metadata
        ],
    )?;
    
    Ok(alert)
}

/// List alerts with filter
pub async fn list_alerts(pool: &DbPool, filter: AlertFilter) -> Result<Vec<Alert>> {
    let conn = pool.get()?;
    
    let mut alerts = Vec::new();
    
    match (&filter.severity, &filter.status) {
        (Some(severity), Some(status)) => {
            let mut stmt = conn.prepare(
                "SELECT id, alert_type, severity, message, status, timestamp, metadata 
                 FROM alerts WHERE severity = ?1 AND status = ?2 ORDER BY timestamp DESC"
            )?;
            let rows = stmt.query_map(params![severity, status], map_alert_row)?;
            for row in rows {
                alerts.push(row?);
            }
        }
        (Some(severity), None) => {
            let mut stmt = conn.prepare(
                "SELECT id, alert_type, severity, message, status, timestamp, metadata 
                 FROM alerts WHERE severity = ?1 ORDER BY timestamp DESC"
            )?;
            let rows = stmt.query_map(params![severity], map_alert_row)?;
            for row in rows {
                alerts.push(row?);
            }
        }
        (None, Some(status)) => {
            let mut stmt = conn.prepare(
                "SELECT id, alert_type, severity, message, status, timestamp, metadata 
                 FROM alerts WHERE status = ?1 ORDER BY timestamp DESC"
            )?;
            let rows = stmt.query_map(params![status], map_alert_row)?;
            for row in rows {
                alerts.push(row?);
            }
        }
        (None, None) => {
            let mut stmt = conn.prepare(
                "SELECT id, alert_type, severity, message, status, timestamp, metadata 
                 FROM alerts ORDER BY timestamp DESC"
            )?;
            let rows = stmt.query_map([], map_alert_row)?;
            for row in rows {
                alerts.push(row?);
            }
        }
    }
    
    Ok(alerts)
}

/// Get alert by ID
pub async fn get_alert(pool: &DbPool, alert_id: &str) -> Result<Option<Alert>> {
    let conn = pool.get()?;
    
    let mut stmt = conn.prepare(
        "SELECT id, alert_type, severity, message, status, timestamp, metadata 
         FROM alerts WHERE id = ?"
    )?;
    
    let result = stmt.query_row(params![alert_id], map_alert_row);
    
    match result {
        Ok(alert) => Ok(Some(alert)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("Database error: {}", e)),
    }
}

/// Update alert status
pub async fn update_alert_status(pool: &DbPool, alert_id: &str, status: &str) -> Result<()> {
    let conn = pool.get()?;
    
    conn.execute(
        "UPDATE alerts SET status = ?1 WHERE id = ?2",
        params![status, alert_id],
    )?;
    
    Ok(())
}

/// Get alert statistics
pub async fn get_alert_stats(pool: &DbPool) -> Result<AlertStats> {
    let conn = pool.get()?;
    
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM alerts", [], |row| row.get(0))?;
    let new: i64 = conn.query_row("SELECT COUNT(*) FROM alerts WHERE status = 'New'", [], |row| row.get(0))?;
    let ack: i64 = conn.query_row("SELECT COUNT(*) FROM alerts WHERE status = 'Acknowledged'", [], |row| row.get(0))?;
    let resolved: i64 = conn.query_row("SELECT COUNT(*) FROM alerts WHERE status = 'Resolved'", [], |row| row.get(0))?;
    
    Ok(AlertStats {
        total_count: total,
        new_count: new,
        acknowledged_count: ack,
        resolved_count: resolved,
    })
}

/// Create a sample alert (for testing)
pub fn create_sample_alert() -> Alert {
    Alert {
        id: Uuid::new_v4().to_string(),
        alert_type: "ThreatDetected".to_string(),
        severity: "High".to_string(),
        message: "Suspicious activity detected".to_string(),
        status: "New".to_string(),
        timestamp: Utc::now().to_rfc3339(),
        metadata: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::connection::create_pool;
    use crate::database::connection::init_database;

    #[actix_rt::test]
    async fn test_create_and_list_alerts() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        
        let alert = create_sample_alert();
        let result = create_alert(&pool, alert.clone()).await;
        assert!(result.is_ok());
        
        let alerts = list_alerts(&pool, AlertFilter::default()).await.unwrap();
        assert_eq!(alerts.len(), 1);
    }
    
    #[actix_rt::test]
    async fn test_update_alert_status() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        
        let alert = create_sample_alert();
        create_alert(&pool, alert.clone()).await.unwrap();
        
        update_alert_status(&pool, &alert.id, "Acknowledged").await.unwrap();
        
        let updated = get_alert(&pool, &alert.id).await.unwrap().unwrap();
        assert_eq!(updated.status, "Acknowledged");
    }
    
    #[actix_rt::test]
    async fn test_get_alert_stats() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        
        // Create some alerts
        for _ in 0..3 {
            create_alert(&pool, create_sample_alert()).await.unwrap();
        }
        
        let stats = get_alert_stats(&pool).await.unwrap();
        assert_eq!(stats.total_count, 3);
        assert_eq!(stats.new_count, 3);
    }
}
