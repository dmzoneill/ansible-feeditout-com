-- fail2counter database schema
-- All tables use CREATE TABLE IF NOT EXISTS for idempotent deployment

CREATE TABLE IF NOT EXISTS hosts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    hostname VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    host_id INT NOT NULL,
    scan_time DATETIME NOT NULL,
    scan_type VARCHAR(50),
    latency_seconds FLOAT,
    duration_seconds FLOAT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    port_number INT NOT NULL,
    protocol VARCHAR(10) DEFAULT 'tcp',
    state VARCHAR(20) DEFAULT 'open',
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS services (
    id INT AUTO_INCREMENT PRIMARY KEY,
    port_id INT NOT NULL,
    service_name VARCHAR(100),
    product VARCHAR(255),
    version VARCHAR(100),
    extra_info VARCHAR(255),
    is_ssl BOOLEAN DEFAULT FALSE,
    recognized BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS exploits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    host_id INT NOT NULL,
    module_path VARCHAR(500) NOT NULL,
    rhosts VARCHAR(45),
    rport INT,
    rc_file_path VARCHAR(500),
    status ENUM(
        'suggested', 'running', 'success', 'completed',
        'failed', 'timeout', 'invalid_module', 'error'
    ) DEFAULT 'suggested',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    INDEX idx_exploits_host (host_id),
    INDEX idx_exploits_status (status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS exploit_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    exploit_id INT NOT NULL,
    output_text LONGTEXT,
    exit_code INT,
    duration_seconds FLOAT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (exploit_id) REFERENCES exploits(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    host_id INT NOT NULL,
    exploit_id INT,
    notification_type ENUM('email', 'abuse_contact') DEFAULT 'email',
    status ENUM('pending', 'sent', 'acknowledged') DEFAULT 'pending',
    contact_info VARCHAR(500),
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent_at DATETIME,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    FOREIGN KEY (exploit_id) REFERENCES exploits(id) ON DELETE SET NULL,
    INDEX idx_notifications_status (status),
    INDEX idx_notifications_host (host_id)
) ENGINE=InnoDB;
