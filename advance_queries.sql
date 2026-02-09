-- Advanced SQL Queries for SIEM Analysis
-- Direct database queries for custom analysis

-- ============================================================================
-- TIME-BASED QUERIES
-- ============================================================================

-- Events in last hour
SELECT * FROM events
WHERE timestamp > datetime('now', '-1 hour')
ORDER BY timestamp DESC;

-- Events by hour of day (identify patterns)
SELECT 
    strftime('%H', timestamp) as hour,
    COUNT(*) as event_count,
    severity
FROM events
GROUP BY hour, severity
ORDER BY hour;

-- Events by day of week
SELECT 
    CASE CAST(strftime('%w', timestamp) AS INTEGER)
        WHEN 0 THEN 'Sunday'
        WHEN 1 THEN 'Monday'
        WHEN 2 THEN 'Tuesday'
        WHEN 3 THEN 'Wednesday'
        WHEN 4 THEN 'Thursday'
        WHEN 5 THEN 'Friday'
        WHEN 6 THEN 'Saturday'
    END as day_of_week,
    COUNT(*) as event_count
FROM events
GROUP BY day_of_week
ORDER BY CAST(strftime('%w', timestamp) AS INTEGER);

-- Peak activity periods
SELECT 
    strftime('%Y-%m-%d %H:00:00', timestamp) as time_bucket,
    COUNT(*) as event_count
FROM events
GROUP BY time_bucket
HAVING event_count > (
    SELECT AVG(cnt) * 2 FROM (
        SELECT COUNT(*) as cnt
        FROM events
        GROUP BY strftime('%Y-%m-%d %H:00:00', timestamp)
    )
)
ORDER BY event_count DESC;


-- ============================================================================
-- IP ANALYSIS
-- ============================================================================

-- Most active IPs
SELECT 
    ip_address,
    COUNT(*) as total_events,
    COUNT(CASE WHEN severity = 'ERROR' THEN 1 END) as errors,
    COUNT(CASE WHEN severity = 'WARNING' THEN 1 END) as warnings,
    MIN(timestamp) as first_seen,
    MAX(timestamp) as last_seen
FROM events
WHERE ip_address IS NOT NULL
GROUP BY ip_address
ORDER BY total_events DESC
LIMIT 20;

-- Suspicious IPs (high failure rate)
SELECT 
    ip_address,
    COUNT(*) as total_attempts,
    COUNT(CASE WHEN event_type LIKE '%FAILURE%' THEN 1 END) as failures,
    COUNT(CASE WHEN event_type LIKE '%SUCCESS%' THEN 1 END) as successes,
    ROUND(COUNT(CASE WHEN event_type LIKE '%FAILURE%' THEN 1 END) * 100.0 / COUNT(*), 2) as failure_rate
FROM events
WHERE ip_address IS NOT NULL
GROUP BY ip_address
HAVING failure_rate > 50 AND total_attempts > 5
ORDER BY failure_rate DESC;

-- IPs with geographic diversity (accessing multiple systems)
SELECT 
    ip_address,
    COUNT(DISTINCT source) as system_count,
    GROUP_CONCAT(DISTINCT source) as systems,
    COUNT(*) as total_events
FROM events
WHERE ip_address IS NOT NULL
GROUP BY ip_address
HAVING system_count > 3
ORDER BY system_count DESC;


-- ============================================================================
-- USER ANALYSIS
-- ============================================================================

-- User activity summary
SELECT 
    user,
    COUNT(*) as total_events,
    COUNT(DISTINCT source) as systems_accessed,
    COUNT(DISTINCT ip_address) as unique_ips,
    MIN(timestamp) as first_activity,
    MAX(timestamp) as last_activity
FROM events
WHERE user IS NOT NULL
GROUP BY user
ORDER BY total_events DESC;

-- Users with authentication failures
SELECT 
    user,
    COUNT(CASE WHEN event_type LIKE '%FAILURE%' THEN 1 END) as failures,
    COUNT(CASE WHEN event_type LIKE '%SUCCESS%' THEN 1 END) as successes,
    COUNT(DISTINCT ip_address) as unique_ips
FROM events
WHERE user IS NOT NULL
GROUP BY user
HAVING failures > 5
ORDER BY failures DESC;

-- Users active outside business hours (9 AM - 5 PM)
SELECT 
    user,
    COUNT(*) as after_hours_events,
    MIN(timestamp) as earliest,
    MAX(timestamp) as latest
FROM events
WHERE user IS NOT NULL
    AND (CAST(strftime('%H', timestamp) AS INTEGER) < 9 
         OR CAST(strftime('%H', timestamp) AS INTEGER) >= 17)
GROUP BY user
HAVING after_hours_events > 10
ORDER BY after_hours_events DESC;


-- ============================================================================
-- CORRELATION QUERIES
-- ============================================================================

-- Find sequences: Failed auth followed by success from same IP
WITH auth_events AS (
    SELECT 
        event_id,
        timestamp,
        ip_address,
        user,
        event_type,
        LAG(event_type) OVER (PARTITION BY ip_address ORDER BY timestamp) as prev_event,
        LAG(timestamp) OVER (PARTITION BY ip_address ORDER BY timestamp) as prev_time
    FROM events
    WHERE event_type LIKE 'AUTH_%'
)
SELECT 
    ip_address,
    user,
    timestamp as success_time,
    prev_time as last_failure_time,
    ROUND((julianday(timestamp) - julianday(prev_time)) * 24 * 60, 2) as minutes_between
FROM auth_events
WHERE event_type = 'AUTH_SUCCESS'
    AND prev_event = 'AUTH_FAILURE'
    AND (julianday(timestamp) - julianday(prev_time)) * 24 * 60 < 5
ORDER BY timestamp DESC;

-- Events from same IP across multiple systems within time window
WITH ip_activity AS (
    SELECT 
        ip_address,
        source,
        timestamp,
        event_type,
        LAG(source) OVER (PARTITION BY ip_address ORDER BY timestamp) as prev_source,
        LAG(timestamp) OVER (PARTITION BY ip_address ORDER BY timestamp) as prev_time
    FROM events
    WHERE ip_address IS NOT NULL
)
SELECT 
    ip_address,
    source as current_system,
    prev_source as previous_system,
    timestamp,
    prev_time,
    ROUND((julianday(timestamp) - julianday(prev_time)) * 24 * 60 * 60, 2) as seconds_between
FROM ip_activity
WHERE prev_source IS NOT NULL
    AND source != prev_source
    AND (julianday(timestamp) - julianday(prev_time)) * 24 * 60 * 60 < 300
ORDER BY ip_address, timestamp;

-- Rapid-fire events (potential DoS or scanning)
SELECT 
    source,
    ip_address,
    event_type,
    COUNT(*) as event_count,
    MIN(timestamp) as start_time,
    MAX(timestamp) as end_time,
    ROUND((julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 24 * 60 * 60, 2) as duration_seconds
FROM events
WHERE timestamp > datetime('now', '-1 hour')
GROUP BY source, ip_address, event_type
HAVING event_count > 50 AND duration_seconds < 300
ORDER BY event_count DESC;


-- ============================================================================
-- THREAT DETECTION QUERIES
-- ============================================================================

-- Port scan detection (multiple denied connections)
SELECT 
    ip_address,
    COUNT(*) as deny_count,
    COUNT(DISTINCT source) as systems_targeted,
    MIN(timestamp) as scan_start,
    MAX(timestamp) as scan_end,
    ROUND((julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 24 * 60 * 60, 2) as duration_seconds
FROM events
WHERE event_type LIKE '%DENY%' OR event_type LIKE '%DROP%'
    AND timestamp > datetime('now', '-30 minutes')
GROUP BY ip_address
HAVING deny_count > 20 AND duration_seconds < 600
ORDER BY deny_count DESC;

-- Brute force detection (multiple auth failures)
SELECT 
    ip_address,
    user,
    COUNT(*) as failure_count,
    MIN(timestamp) as attack_start,
    MAX(timestamp) as attack_end,
    MAX(CASE WHEN event_type = 'AUTH_SUCCESS' THEN timestamp END) as breach_time
FROM events
WHERE event_type LIKE 'AUTH_%'
    AND timestamp > datetime('now', '-1 hour')
GROUP BY ip_address, user
HAVING failure_count > 5
ORDER BY failure_count DESC;

-- Privilege escalation attempts
SELECT 
    user,
    ip_address,
    event_type,
    message,
    timestamp
FROM events
WHERE (message LIKE '%sudo%' OR message LIKE '%su %' OR message LIKE '%privilege%')
    AND severity IN ('WARNING', 'ERROR')
ORDER BY timestamp DESC;

-- Data exfiltration indicators (large transfers)
SELECT 
    source,
    ip_address,
    user,
    COUNT(*) as request_count,
    SUM(CAST(SUBSTR(message, INSTR(message, ' ') + 1) AS INTEGER)) as total_bytes
FROM events
WHERE event_type = 'HTTP_REQUEST'
    AND message LIKE '%200%'
    AND timestamp > datetime('now', '-1 hour')
GROUP BY source, ip_address, user
HAVING total_bytes > 100000000  -- 100 MB
ORDER BY total_bytes DESC;


-- ============================================================================
-- STATISTICAL QUERIES
-- ============================================================================

-- Event rate by source (events per minute)
SELECT 
    source,
    COUNT(*) as total_events,
    ROUND((julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 24 * 60, 2) as duration_minutes,
    ROUND(COUNT(*) * 1.0 / ((julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 24 * 60), 2) as events_per_minute
FROM events
GROUP BY source
ORDER BY events_per_minute DESC;

-- Error rate by source
SELECT 
    source,
    COUNT(*) as total_events,
    COUNT(CASE WHEN severity = 'ERROR' THEN 1 END) as error_count,
    ROUND(COUNT(CASE WHEN severity = 'ERROR' THEN 1 END) * 100.0 / COUNT(*), 2) as error_rate
FROM events
GROUP BY source
HAVING error_rate > 5
ORDER BY error_rate DESC;

-- Most common event types
SELECT 
    event_type,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM events), 2) as percentage
FROM events
GROUP BY event_type
ORDER BY count DESC
LIMIT 20;

-- Severity distribution
SELECT 
    severity,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM events), 2) as percentage
FROM events
GROUP BY severity
ORDER BY 
    CASE severity
        WHEN 'ERROR' THEN 1
        WHEN 'WARNING' THEN 2
        WHEN 'INFO' THEN 3
        WHEN 'DEBUG' THEN 4
        ELSE 5
    END;


-- ============================================================================
-- COMPLIANCE & AUDIT QUERIES
-- ============================================================================

-- Administrative actions log
SELECT 
    timestamp,
    user,
    source,
    event_type,
    message
FROM events
WHERE user IN ('root', 'admin', 'administrator')
    OR message LIKE '%admin%'
    OR event_type LIKE '%ADMIN%'
ORDER BY timestamp DESC;

-- Access to sensitive resources
SELECT 
    timestamp,
    user,
    ip_address,
    source,
    message
FROM events
WHERE message LIKE '%/admin%'
    OR message LIKE '%/api%'
    OR message LIKE '%database%'
ORDER BY timestamp DESC;

-- Failed access attempts (compliance audit)
SELECT 
    DATE(timestamp) as date,
    COUNT(*) as failed_attempts,
    COUNT(DISTINCT user) as unique_users,
    COUNT(DISTINCT ip_address) as unique_ips
FROM events
WHERE event_type LIKE '%FAILURE%' OR event_type LIKE '%DENY%'
GROUP BY date
ORDER BY date DESC;


-- ============================================================================
-- CLEANUP & MAINTENANCE QUERIES
-- ============================================================================

-- Database size and statistics
SELECT 
    COUNT(*) as total_events,
    COUNT(DISTINCT source) as unique_sources,
    COUNT(DISTINCT ip_address) as unique_ips,
    COUNT(DISTINCT user) as unique_users,
    MIN(timestamp) as oldest_event,
    MAX(timestamp) as newest_event,
    ROUND((julianday(MAX(timestamp)) - julianday(MIN(timestamp))), 2) as days_of_data
FROM events;

-- Delete old events (older than 90 days)
-- DELETE FROM events WHERE timestamp < datetime('now', '-90 days');

-- Delete events from specific source
-- DELETE FROM events WHERE source = 'old-server';

-- Archive old events to separate table
-- CREATE TABLE archived_events AS SELECT * FROM events WHERE timestamp < datetime('now', '-90 days');
-- DELETE FROM events WHERE timestamp < datetime('now', '-90 days');

-- Rebuild indexes (after large deletions)
-- REINDEX events;
-- VACUUM;


-- ============================================================================
-- CUSTOM ALERT QUERIES
-- ============================================================================

-- Create a view for high-priority events
CREATE VIEW IF NOT EXISTS high_priority_events AS
SELECT *
FROM events
WHERE severity IN ('ERROR', 'WARNING')
    OR event_type LIKE '%FAILURE%'
    OR event_type LIKE '%DENY%'
ORDER BY timestamp DESC;

-- Query the view
-- SELECT * FROM high_priority_events LIMIT 100;

-- Create a view for security events
CREATE VIEW IF NOT EXISTS security_events AS
SELECT 
    timestamp,
    source,
    event_type,
    ip_address,
    user,
    message,
    CASE 
        WHEN event_type LIKE '%FAILURE%' THEN 'Authentication Issue'
        WHEN event_type LIKE '%DENY%' THEN 'Access Denied'
        WHEN event_type LIKE '%DROP%' THEN 'Network Block'
        ELSE 'Other Security Event'
    END as category
FROM events
WHERE event_type IN (
    'AUTH_FAILURE', 'AUTH_SUCCESS',
    'FIREWALL_DENY', 'FIREWALL_DROP',
    'FIREWALL_ALLOW'
)
ORDER BY timestamp DESC;


-- ============================================================================
-- PERFORMANCE OPTIMIZATION
-- ============================================================================

-- Analyze query performance
-- EXPLAIN QUERY PLAN SELECT * FROM events WHERE timestamp > datetime('now', '-1 hour');

-- Check index usage
-- PRAGMA index_list('events');
-- PRAGMA index_info('idx_timestamp');

-- Database statistics
-- ANALYZE events;
-- SELECT * FROM sqlite_stat1 WHERE tbl = 'events';