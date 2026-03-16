use std::fs::File;
use std::io::Write;
use chrono::Local;
use csv::Writer;
use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct CheckedResult {
    pub ip: String,
    pub status: String,
    pub os: String,
    pub location: String,
    pub isp: String,
    pub country: String,
    pub city: String,
    pub region: String,
    pub bluekeep_vulnerable: bool,
    pub nla_disabled: bool,
    pub has_critical_vulnerability: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CrackedResult {
    pub ip: String,
    pub username: String,
    pub password: String,
    pub os: String,
    pub location: String,
}

pub fn export_to_csv(results: &[CheckedResult], filename: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut wtr = Writer::from_path(filename)?;
    
    // Write header
    wtr.write_record(&[
        "IP:Port",
        "Status",
        "OS",
        "Country",
        "City",
        "Region",
        "ISP",
        "NLA Disabled",
        "BlueKeep Vulnerable",
        "Critical Vulnerability",
    ])?;
    
    // Write data
    for result in results {
        wtr.write_record(&[
            &result.ip,
            &result.status,
            &result.os,
            &result.country,
            &result.city,
            &result.region,
            &result.isp,
            &(if result.nla_disabled { "Yes".to_string() } else { "No".to_string() }),
            &(if result.bluekeep_vulnerable { "Yes".to_string() } else { "No".to_string() }),
            &(if result.has_critical_vulnerability { "Yes".to_string() } else { "No".to_string() }),
        ])?;
    }
    
    wtr.flush()?;
    Ok(())
}

pub fn export_to_json(results: &[CheckedResult], filename: &str) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(results)?;
    let mut file = File::create(filename)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

pub fn export_to_txt(results: &[CheckedResult], filename: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(filename)?;
    
    writeln!(file, "RDP Scanner - Export Results")?;
    writeln!(file, "================================")?;
    writeln!(file, "Total Results: {}", results.len())?;
    writeln!(file, "Export Date: {}", Local::now().format("%Y-%m-%d %H:%M:%S"))?;
    writeln!(file, "================================\n")?;
    
    for (idx, result) in results.iter().enumerate() {
        writeln!(file, "Result #{}", idx + 1)?;
        writeln!(file, "IP:Port: {}", result.ip)?;
        writeln!(file, "Status: {}", result.status)?;
        writeln!(file, "Operating System: {}", result.os)?;
        writeln!(file, "Country: {}", result.country)?;
        writeln!(file, "City: {}", result.city)?;
        writeln!(file, "Region: {}", result.region)?;
        writeln!(file, "ISP: {}", result.isp)?;
        writeln!(file, "NLA Disabled: {}", if result.nla_disabled { "Yes" } else { "No" })?;
        writeln!(file, "BlueKeep Vulnerable: {}", if result.bluekeep_vulnerable { "Yes" } else { "No" })?;
        writeln!(file, "Critical Vulnerability: {}", if result.has_critical_vulnerability { "Yes" } else { "No" })?;
        writeln!(file, "--------------------------------\n")?;
    }
    
    Ok(())
}

pub fn export_cracked_to_csv(results: &[CrackedResult], filename: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut wtr = Writer::from_path(filename)?;
    
    // Write header
    wtr.write_record(&["IP:Port", "Username", "Password", "OS", "Location"])?;
    
    // Write data
    for result in results {
        wtr.write_record(&[
            &result.ip,
            &result.username,
            &result.password,
            &result.os,
            &result.location,
        ])?;
    }
    
    wtr.flush()?;
    Ok(())
}

pub fn export_cracked_to_txt(results: &[CrackedResult], filename: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(filename)?;
    
    writeln!(file, "RDP Scanner - Cracked Credentials")?;
    writeln!(file, "================================")?;
    writeln!(file, "Total Cracked: {}", results.len())?;
    writeln!(file, "Export Date: {}", Local::now().format("%Y-%m-%d %H:%M:%S"))?;
    writeln!(file, "================================\n")?;
    
    for (idx, result) in results.iter().enumerate() {
        writeln!(file, "Credential #{}", idx + 1)?;
        writeln!(file, "IP:Port: {}", result.ip)?;
        writeln!(file, "Username: {}", result.username)?;
        writeln!(file, "Password: {}", if result.password.is_empty() { "(empty)" } else { &result.password })?;
        writeln!(file, "OS: {}", result.os)?;
        writeln!(file, "Location: {}", result.location)?;
        writeln!(file, "--------------------------------\n")?;
    }
    
    Ok(())
}

pub fn export_ips_only(results: &[CheckedResult], filename: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(filename)?;
    
    for result in results {
        writeln!(file, "{}", result.ip)?;
    }
    
    Ok(())
}
