//! Persistent IP ban offense tracking.

use crate::database::connection::DbPool;
use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::params;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OffenseStatus {
    Active,
    Blocked,
    Released,
}

impl std::fmt::Display for OffenseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Blocked => write!(f, "Blocked"),
            Self::Released => write!(f, "Released"),
        }
    }
}

impl std::str::FromStr for OffenseStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "Active" => Ok(Self::Active),
            "Blocked" => Ok(Self::Blocked),
            "Released" => Ok(Self::Released),
            _ => Err(format!("unknown offense status: {value}")),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OffenseMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_line: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpOffenseRecord {
    pub id: String,
    pub ip_address: String,
    pub source_type: String,
    pub container_id: Option<String>,
    pub offense_count: u32,
    pub first_seen: String,
    pub last_seen: String,
    pub blocked_until: Option<String>,
    pub status: OffenseStatus,
    pub reason: String,
    pub metadata: Option<OffenseMetadata>,
}

#[derive(Debug, Clone)]
pub struct NewIpOffense {
    pub id: String,
    pub ip_address: String,
    pub source_type: String,
    pub container_id: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub reason: String,
    pub metadata: Option<OffenseMetadata>,
}

fn serialize_metadata(metadata: Option<&OffenseMetadata>) -> Result<Option<String>> {
    match metadata {
        Some(metadata) => Ok(Some(serde_json::to_string(metadata)?)),
        None => Ok(None),
    }
}

fn parse_metadata(value: Option<String>) -> Option<OffenseMetadata> {
    value.and_then(|raw| serde_json::from_str(&raw).ok())
}

fn parse_status(value: String) -> Result<OffenseStatus, rusqlite::Error> {
    value.parse().map_err(|err: String| {
        rusqlite::Error::FromSqlConversionFailure(
            8,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, err)),
        )
    })
}

fn map_row(row: &rusqlite::Row) -> Result<IpOffenseRecord, rusqlite::Error> {
    Ok(IpOffenseRecord {
        id: row.get(0)?,
        ip_address: row.get(1)?,
        source_type: row.get(2)?,
        container_id: row.get(3)?,
        offense_count: row.get::<_, i64>(4)?.max(0) as u32,
        first_seen: row.get(5)?,
        last_seen: row.get(6)?,
        blocked_until: row.get(7)?,
        status: parse_status(row.get(8)?)?,
        reason: row.get(9)?,
        metadata: parse_metadata(row.get(10)?),
    })
}

pub fn insert_offense(pool: &DbPool, offense: &NewIpOffense) -> Result<()> {
    let conn = pool.get()?;
    conn.execute(
        "INSERT INTO ip_offenses (
            id, ip_address, source_type, container_id, offense_count,
            first_seen, last_seen, blocked_until, status, reason, metadata
         ) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5, NULL, 'Active', ?6, ?7)",
        params![
            offense.id,
            offense.ip_address,
            offense.source_type,
            offense.container_id,
            offense.first_seen.to_rfc3339(),
            offense.reason,
            serialize_metadata(offense.metadata.as_ref())?,
        ],
    )?;
    Ok(())
}

pub fn find_recent_offenses(
    pool: &DbPool,
    ip_address: &str,
    source_type: &str,
    since: DateTime<Utc>,
) -> Result<Vec<IpOffenseRecord>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT
            id, ip_address, source_type, container_id, offense_count,
            first_seen, last_seen, blocked_until, status, reason, metadata
         FROM ip_offenses
         WHERE ip_address = ?1
           AND source_type = ?2
           AND last_seen >= ?3
         ORDER BY last_seen DESC",
    )?;

    let rows = stmt.query_map(
        params![ip_address, source_type, since.to_rfc3339()],
        map_row,
    )?;
    let mut offenses = Vec::new();
    for row in rows {
        offenses.push(row?);
    }
    Ok(offenses)
}

pub fn active_block_for_ip(pool: &DbPool, ip_address: &str) -> Result<Option<IpOffenseRecord>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT
            id, ip_address, source_type, container_id, offense_count,
            first_seen, last_seen, blocked_until, status, reason, metadata
         FROM ip_offenses
         WHERE ip_address = ?1 AND status = 'Blocked'
         ORDER BY last_seen DESC
         LIMIT 1",
    )?;

    match stmt.query_row(params![ip_address], map_row) {
        Ok(record) => Ok(Some(record)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

pub fn mark_blocked(
    pool: &DbPool,
    ip_address: &str,
    source_type: &str,
    blocked_until: DateTime<Utc>,
) -> Result<()> {
    let conn = pool.get()?;
    conn.execute(
        "UPDATE ip_offenses
         SET status = 'Blocked', blocked_until = ?1
         WHERE ip_address = ?2 AND source_type = ?3 AND status = 'Active'",
        params![blocked_until.to_rfc3339(), ip_address, source_type],
    )?;
    Ok(())
}

pub fn expired_blocks(pool: &DbPool, now: DateTime<Utc>) -> Result<Vec<IpOffenseRecord>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT
            id, ip_address, source_type, container_id, offense_count,
            first_seen, last_seen, blocked_until, status, reason, metadata
         FROM ip_offenses
         WHERE status = 'Blocked'
           AND blocked_until IS NOT NULL
           AND blocked_until <= ?1
         ORDER BY blocked_until ASC",
    )?;

    let rows = stmt.query_map(params![now.to_rfc3339()], map_row)?;
    let mut offenses = Vec::new();
    for row in rows {
        offenses.push(row?);
    }
    Ok(offenses)
}

pub fn mark_released(pool: &DbPool, offense_id: &str) -> Result<()> {
    let conn = pool.get()?;
    conn.execute(
        "UPDATE ip_offenses SET status = 'Released' WHERE id = ?1",
        params![offense_id],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{create_pool, init_database};
    use chrono::Duration;

    #[test]
    fn test_insert_and_find_offense() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        insert_offense(
            &pool,
            &NewIpOffense {
                id: "o1".into(),
                ip_address: "192.0.2.10".into(),
                source_type: "sniff".into(),
                container_id: None,
                first_seen: Utc::now(),
                reason: "Repeated ssh failures".into(),
                metadata: Some(OffenseMetadata {
                    source_path: Some("/var/log/auth.log".into()),
                    sample_line: None,
                }),
            },
        )
        .unwrap();

        let offenses = find_recent_offenses(
            &pool,
            "192.0.2.10",
            "sniff",
            Utc::now() - Duration::minutes(1),
        )
        .unwrap();
        assert_eq!(offenses.len(), 1);
        assert_eq!(offenses[0].status, OffenseStatus::Active);
    }

    #[test]
    fn test_mark_blocked_and_released() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let now = Utc::now();

        insert_offense(
            &pool,
            &NewIpOffense {
                id: "o2".into(),
                ip_address: "192.0.2.20".into(),
                source_type: "sniff".into(),
                container_id: None,
                first_seen: now,
                reason: "test".into(),
                metadata: None,
            },
        )
        .unwrap();

        mark_blocked(&pool, "192.0.2.20", "sniff", now + Duration::minutes(5)).unwrap();
        assert!(active_block_for_ip(&pool, "192.0.2.20").unwrap().is_some());

        let expired = expired_blocks(&pool, now + Duration::minutes(10)).unwrap();
        assert_eq!(expired.len(), 1);
        mark_released(&pool, &expired[0].id).unwrap();
        assert!(active_block_for_ip(&pool, "192.0.2.20").unwrap().is_none());
    }
}
