-- ============================================================================
-- Vulnerability Scanner Database Schema
-- Ubuntu deployment
-- ============================================================================

DROP SCHEMA IF EXISTS vuln_scanner CASCADE;
CREATE SCHEMA vuln_scanner;
SET search_path TO vuln_scanner;

-- ============================================================================
-- ORGANIZATIONS & USERS
-- ============================================================================

CREATE TABLE organizations (
    id SERIAL PRIMARY KEY,
    org_name VARCHAR(200) NOT NULL UNIQUE,
    org_domain VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    access_level VARCHAR(20) NOT NULL CHECK (access_level IN ('admin', 'read_only')),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_user_org ON users(org_id);
CREATE INDEX idx_user_email ON users(email);

-- ============================================================================
-- OPERATING SYSTEMS & USE CASES
-- ============================================================================

CREATE TABLE operating_systems (
    id SERIAL PRIMARY KEY,
    os_family VARCHAR(50) NOT NULL,
    os_name VARCHAR(100) NOT NULL,
    os_version VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(os_family, os_name, os_version)
);

CREATE INDEX idx_os_family ON operating_systems(os_family);

CREATE TABLE use_cases (
    id SERIAL PRIMARY KEY,
    use_case_name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    category VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- EXPLOITS
-- ============================================================================

CREATE TABLE exploits (
    id SERIAL PRIMARY KEY,
    exploit_id VARCHAR(100) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    cve_id VARCHAR(50),
    metasploit_module VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_exploit_severity ON exploits(severity);
CREATE INDEX idx_exploit_cve ON exploits(cve_id) WHERE cve_id IS NOT NULL;

-- ============================================================================
-- EXPLOIT ASSOCIATIONS (OS and Use Case Filtering)
-- ============================================================================

CREATE TABLE exploit_os_compatibility (
    id SERIAL PRIMARY KEY,
    exploit_id INTEGER NOT NULL REFERENCES exploits(id) ON DELETE CASCADE,
    os_id INTEGER NOT NULL REFERENCES operating_systems(id) ON DELETE CASCADE,
    os_family_match VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(exploit_id, os_id)
);

CREATE INDEX idx_compat_exploit ON exploit_os_compatibility(exploit_id);
CREATE INDEX idx_compat_os ON exploit_os_compatibility(os_id);
CREATE INDEX idx_compat_family ON exploit_os_compatibility(os_family_match);

CREATE TABLE exploit_use_case_relevance (
    id SERIAL PRIMARY KEY,
    exploit_id INTEGER NOT NULL REFERENCES exploits(id) ON DELETE CASCADE,
    use_case_id INTEGER NOT NULL REFERENCES use_cases(id) ON DELETE CASCADE,
    relevance_score INTEGER DEFAULT 100,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(exploit_id, use_case_id)
);

CREATE INDEX idx_relevance_exploit ON exploit_use_case_relevance(exploit_id);
CREATE INDEX idx_relevance_use_case ON exploit_use_case_relevance(use_case_id);

-- ============================================================================
-- ASSETS (Scan Targets)
-- ============================================================================

CREATE TABLE assets (
    id SERIAL PRIMARY KEY,
    org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    ip_address INET NOT NULL,
    hostname VARCHAR(255),
    domain VARCHAR(255),
    os_id INTEGER REFERENCES operating_systems(id) ON DELETE SET NULL,
    os_detected BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    last_seen TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, ip_address)
);

CREATE INDEX idx_asset_org ON assets(org_id);
CREATE INDEX idx_asset_ip ON assets(ip_address);
CREATE INDEX idx_asset_os ON assets(os_id);
CREATE INDEX idx_asset_active ON assets(is_active) WHERE is_active = TRUE;

CREATE TABLE asset_use_cases (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    use_case_id INTEGER NOT NULL REFERENCES use_cases(id) ON DELETE CASCADE,
    confidence INTEGER DEFAULT 100,
    detected_method VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(asset_id, use_case_id)
);

CREATE INDEX idx_asset_use_case_asset ON asset_use_cases(asset_id);
CREATE INDEX idx_asset_use_case_use_case ON asset_use_cases(use_case_id);

-- ============================================================================
-- SCANS
-- ============================================================================

CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    scan_name VARCHAR(255) NOT NULL,
    org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    initiated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    status VARCHAR(50) NOT NULL,
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    total_assets INTEGER DEFAULT 0,
    scanned_assets INTEGER DEFAULT 0,
    total_exploits_tested INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    critical_findings INTEGER DEFAULT 0,
    high_findings INTEGER DEFAULT 0,
    medium_findings INTEGER DEFAULT 0,
    low_findings INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_scan_org ON scans(org_id);
CREATE INDEX idx_scan_status ON scans(status);
CREATE INDEX idx_scan_times ON scans(start_time, end_time);

CREATE TABLE scan_targets (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_status VARCHAR(50) DEFAULT 'pending',
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    exploits_tested INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    UNIQUE(scan_id, asset_id)
);

CREATE INDEX idx_scan_target_scan ON scan_targets(scan_id);
CREATE INDEX idx_scan_target_asset ON scan_targets(asset_id);

CREATE TABLE scan_exploits (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    exploit_id INTEGER NOT NULL REFERENCES exploits(id) ON DELETE CASCADE,
    tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    result VARCHAR(50) NOT NULL,
    execution_time_ms INTEGER
);

CREATE INDEX idx_scan_exploit_scan ON scan_exploits(scan_id);
CREATE INDEX idx_scan_exploit_asset ON scan_exploits(asset_id);
CREATE INDEX idx_scan_exploit_result ON scan_exploits(result);

-- ============================================================================
-- FINDINGS
-- ============================================================================

CREATE TABLE findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    exploit_id INTEGER NOT NULL REFERENCES exploits(id) ON DELETE CASCADE,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(50) DEFAULT 'open',
    confidence INTEGER DEFAULT 100,
    evidence TEXT,
    remediation_notes TEXT,
    remediated_at TIMESTAMP,
    remediated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_finding_scan ON findings(scan_id);
CREATE INDEX idx_finding_asset ON findings(asset_id);
CREATE INDEX idx_finding_exploit ON findings(exploit_id);
CREATE INDEX idx_finding_severity ON findings(severity);
CREATE INDEX idx_finding_status ON findings(status);

CREATE TABLE reports (
    id SERIAL PRIMARY KEY,
    report_name VARCHAR(255) NOT NULL,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    generated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    report_type VARCHAR(50),
    report_format VARCHAR(20),
    report_data JSONB,
    file_path VARCHAR(500),
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_report_scan ON reports(scan_id);
CREATE INDEX idx_report_org ON reports(org_id);

-- ============================================================================
-- CRITICAL VIEW: Pre-filtered exploits for each asset
-- ============================================================================

CREATE OR REPLACE VIEW vw_asset_applicable_exploits AS
SELECT DISTINCT
    a.id AS asset_id,
    a.ip_address,
    a.hostname,
    e.id AS exploit_id,
    e.exploit_id AS exploit_code,
    e.name AS exploit_name,
    e.severity,
    e.metasploit_module,
    os.os_family,
    os.os_name,
    uc.use_case_name,
    COALESCE(eur.relevance_score, 50) AS relevance_score
FROM assets a
INNER JOIN operating_systems os ON a.os_id = os.id
INNER JOIN exploit_os_compatibility eoc ON (
    eoc.os_id = os.id OR eoc.os_family_match = os.os_family
)
INNER JOIN exploits e ON eoc.exploit_id = e.id
LEFT JOIN asset_use_cases auc ON a.id = auc.asset_id
LEFT JOIN exploit_use_case_relevance eur ON (
    eur.exploit_id = e.id AND eur.use_case_id = auc.use_case_id
)
WHERE a.is_active = TRUE
ORDER BY a.id, 
    CASE e.severity
        WHEN 'Critical' THEN 1
        WHEN 'High' THEN 2
        WHEN 'Medium' THEN 3
        WHEN 'Low' THEN 4
        ELSE 5
    END,
    relevance_score DESC;

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

CREATE OR REPLACE FUNCTION get_exploits_for_asset(p_asset_id INTEGER)
RETURNS TABLE (
    exploit_id INTEGER,
    exploit_code VARCHAR,
    exploit_name VARCHAR,
    severity VARCHAR,
    metasploit_module VARCHAR,
    relevance_score INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        vw.exploit_id,
        vw.exploit_code,
        vw.exploit_name,
        vw.severity,
        vw.metasploit_module,
        vw.relevance_score::INTEGER
    FROM vw_asset_applicable_exploits vw
    WHERE vw.asset_id = p_asset_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_scan_queue(p_scan_id INTEGER)
RETURNS TABLE (
    asset_id INTEGER,
    ip_address INET,
    hostname VARCHAR,
    os_family VARCHAR,
    exploit_count BIGINT,
    exploit_list JSONB
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        st.asset_id,
        a.ip_address,
        a.hostname,
        os.os_family,
        COUNT(DISTINCT vw.exploit_id) AS exploit_count,
        jsonb_agg(
            jsonb_build_object(
                'exploit_id', vw.exploit_id,
                'exploit_code', vw.exploit_code,
                'severity', vw.severity,
                'module', vw.metasploit_module
            )
            ORDER BY 
                CASE vw.severity
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 4
                END
        ) AS exploit_list
    FROM scan_targets st
    INNER JOIN assets a ON st.asset_id = a.id
    INNER JOIN operating_systems os ON a.os_id = os.id
    LEFT JOIN vw_asset_applicable_exploits vw ON st.asset_id = vw.asset_id
    WHERE st.scan_id = p_scan_id
        AND st.target_status IN ('pending', 'scanning')
    GROUP BY st.asset_id, a.ip_address, a.hostname, os.os_family
    ORDER BY st.asset_id;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- SAMPLE DATA
-- ============================================================================

INSERT INTO operating_systems (os_family, os_name, os_version) VALUES
('Linux', 'Ubuntu', '22.04'),
('Linux', 'Ubuntu', '20.04'),
('Linux', 'Debian', '11'),
('Windows', 'Windows Server', '2019'),
('Windows', 'Windows Server', '2022'),
('Windows', 'Windows 10', 'Pro');

INSERT INTO use_cases (use_case_name, description, category) VALUES
('web_server', 'Web application server', 'server'),
('database_server', 'Database server', 'server'),
('file_server', 'File sharing server', 'server'),
('workstation', 'End-user workstation', 'endpoint'),
('ssh_server', 'SSH remote access', 'server'),
('rdp_server', 'Remote Desktop Protocol', 'server');

INSERT INTO exploits (exploit_id, name, description, severity, cve_id, metasploit_module) VALUES
('CVE-2021-44228', 'Log4Shell', 'Log4j Remote Code Execution', 'Critical', 'CVE-2021-44228', 'exploit/multi/http/log4shell'),
('CVE-2020-0796', 'SMBGhost', 'Windows SMBv3 RCE', 'Critical', 'CVE-2020-0796', 'exploit/windows/smb/cve_2020_0796'),
('CVE-2017-0144', 'EternalBlue', 'Windows SMB RCE', 'Critical', 'CVE-2017-0144', 'exploit/windows/smb/ms17_010_eternalblue'),
('CVE-2019-0708', 'BlueKeep', 'Windows RDP RCE', 'Critical', 'CVE-2019-0708', 'exploit/windows/rdp/cve_2019_0708');

INSERT INTO exploit_os_compatibility (exploit_id, os_id, os_family_match) VALUES
(1, 1, 'Linux'), (1, 2, 'Linux'), (1, 3, 'Linux'),
(1, 4, 'Windows'), (1, 5, 'Windows'), (1, 6, 'Windows'),
(2, 4, 'Windows'), (2, 5, 'Windows'), (2, 6, 'Windows'),
(3, 4, 'Windows'), (3, 5, 'Windows'), (3, 6, 'Windows'),
(4, 4, 'Windows'), (4, 5, 'Windows'), (4, 6, 'Windows');

INSERT INTO exploit_use_case_relevance (exploit_id, use_case_id, relevance_score) VALUES
(1, 1, 100),
(2, 3, 100),
(3, 3, 100), (3, 4, 90),
(4, 6, 100), (4, 4, 80);

INSERT INTO organizations (org_name, org_domain) VALUES
('Demo Corporation', 'demo.local');
