use rusqlite::{Connection, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: Option<i64>,
    pub ip: String,
    pub port: u16,
    pub status: String,
    pub os: String,
    pub location: String,
    pub country: String,
    pub city: String,
    pub isp: String,
    pub nla_disabled: bool,
    pub bluekeep_vulnerable: bool,
    pub critical_vulnerability: bool,
    pub scan_date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackedRecord {
    pub id: Option<i64>,
    pub ip: String,
    pub username: String,
    pub password: String,
    pub os: String,
    pub location: String,
    pub crack_date: String,
}

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new() -> Result<Self> {
        let db_path = Self::get_db_path();
        let conn = Connection::open(db_path)?;
        
        // Create tables
        conn.execute(
            "CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                status TEXT,
                os TEXT,
                location TEXT,
                country TEXT,
                city TEXT,
                isp TEXT,
                nla_disabled INTEGER,
                bluekeep_vulnerable INTEGER,
                critical_vulnerability INTEGER,
                scan_date TEXT NOT NULL
            )",
            [],
        )?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS cracked (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                os TEXT,
                location TEXT,
                crack_date TEXT NOT NULL
            )",
            [],
        )?;
        
        // Create indexes
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_ip ON scans(ip)",
            [],
        )?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_country ON scans(country)",
            [],
        )?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cracked_ip ON cracked(ip)",
            [],
        )?;
        
        Ok(Database { conn })
    }
    
    fn get_db_path() -> PathBuf {
        let mut path = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push("SentinelRDP");
        std::fs::create_dir_all(&path).ok();
        path.push("scanner.db");
        path
    }
    
    pub fn insert_scan(&self, record: &ScanRecord) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO scans (ip, port, status, os, location, country, city, isp, 
                               nla_disabled, bluekeep_vulnerable, critical_vulnerability, scan_date)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                record.ip,
                record.port,
                record.status,
                record.os,
                record.location,
                record.country,
                record.city,
                record.isp,
                record.nla_disabled as i32,
                record.bluekeep_vulnerable as i32,
                record.critical_vulnerability as i32,
                record.scan_date,
            ],
        )?;
        
        Ok(self.conn.last_insert_rowid())
    }
    
    pub fn insert_cracked(&self, record: &CrackedRecord) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO cracked (ip, username, password, os, location, crack_date)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                record.ip,
                record.username,
                record.password,
                record.os,
                record.location,
                record.crack_date,
            ],
        )?;
        
        Ok(self.conn.last_insert_rowid())
    }
    
    pub fn get_all_scans(&self) -> Result<Vec<ScanRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ip, port, status, os, location, country, city, isp,
                    nla_disabled, bluekeep_vulnerable, critical_vulnerability, scan_date
             FROM scans ORDER BY scan_date DESC"
        )?;
        
        let records = stmt.query_map([], |row| {
            Ok(ScanRecord {
                id: Some(row.get(0)?),
                ip: row.get(1)?,
                port: row.get(2)?,
                status: row.get(3)?,
                os: row.get(4)?,
                location: row.get(5)?,
                country: row.get(6)?,
                city: row.get(7)?,
                isp: row.get(8)?,
                nla_disabled: row.get::<_, i32>(9)? != 0,
                bluekeep_vulnerable: row.get::<_, i32>(10)? != 0,
                critical_vulnerability: row.get::<_, i32>(11)? != 0,
                scan_date: row.get(12)?,
            })
        })?;
        
        records.collect()
    }
    
    pub fn get_scans_by_country(&self, country: &str) -> Result<Vec<ScanRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ip, port, status, os, location, country, city, isp,
                    nla_disabled, bluekeep_vulnerable, critical_vulnerability, scan_date
             FROM scans WHERE country = ?1 ORDER BY scan_date DESC"
        )?;
        
        let records = stmt.query_map([country], |row| {
            Ok(ScanRecord {
                id: Some(row.get(0)?),
                ip: row.get(1)?,
                port: row.get(2)?,
                status: row.get(3)?,
                os: row.get(4)?,
                location: row.get(5)?,
                country: row.get(6)?,
                city: row.get(7)?,
                isp: row.get(8)?,
                nla_disabled: row.get::<_, i32>(9)? != 0,
                bluekeep_vulnerable: row.get::<_, i32>(10)? != 0,
                critical_vulnerability: row.get::<_, i32>(11)? != 0,
                scan_date: row.get(12)?,
            })
        })?;
        
        records.collect()
    }
    
    pub fn search_scans(&self, query: &str) -> Result<Vec<ScanRecord>> {
        let search_pattern = format!("%{}%", query);
        let mut stmt = self.conn.prepare(
            "SELECT id, ip, port, status, os, location, country, city, isp,
                    nla_disabled, bluekeep_vulnerable, critical_vulnerability, scan_date
             FROM scans 
             WHERE ip LIKE ?1 OR location LIKE ?1 OR country LIKE ?1 OR isp LIKE ?1
             ORDER BY scan_date DESC"
        )?;
        
        let records = stmt.query_map([&search_pattern], |row| {
            Ok(ScanRecord {
                id: Some(row.get(0)?),
                ip: row.get(1)?,
                port: row.get(2)?,
                status: row.get(3)?,
                os: row.get(4)?,
                location: row.get(5)?,
                country: row.get(6)?,
                city: row.get(7)?,
                isp: row.get(8)?,
                nla_disabled: row.get::<_, i32>(9)? != 0,
                bluekeep_vulnerable: row.get::<_, i32>(10)? != 0,
                critical_vulnerability: row.get::<_, i32>(11)? != 0,
                scan_date: row.get(12)?,
            })
        })?;
        
        records.collect()
    }
    
    pub fn get_stats(&self) -> Result<DatabaseStats> {
        let total_scans: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM scans",
            [],
            |row| row.get(0)
        )?;
        
        let total_cracked: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM cracked",
            [],
            |row| row.get(0)
        )?;
        
        let nla_disabled: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM scans WHERE nla_disabled = 1",
            [],
            |row| row.get(0)
        )?;
        
        let bluekeep_vulnerable: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM scans WHERE bluekeep_vulnerable = 1",
            [],
            |row| row.get(0)
        )?;
        
        Ok(DatabaseStats {
            total_scans,
            total_cracked,
            nla_disabled,
            bluekeep_vulnerable,
        })
    }
    
    pub fn clear_all_data(&self) -> Result<()> {
        self.conn.execute("DELETE FROM scans", [])?;
        self.conn.execute("DELETE FROM cracked", [])?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub total_scans: i64,
    pub total_cracked: i64,
    pub nla_disabled: i64,
    pub bluekeep_vulnerable: i64,
}
