#!/usr/bin/env python3
"""
SIEM Mini Tool - Log Aggregation & Time Correlation
Collects and correlates logs from multiple sources with focus on temporal analysis
"""

import sqlite3
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import hashlib


@dataclass
class LogEvent:
    """Represents a normalized log event"""
    timestamp: datetime
    source: str
    severity: str
    event_type: str
    message: str
    user: Optional[str] = None
    ip_address: Optional[str] = None
    raw_log: str = ""
    event_id: str = ""
    
    def __post_init__(self):
        if not self.event_id:
            # Generate unique event ID
            content = f"{self.timestamp}{self.source}{self.message}"
            self.event_id = hashlib.md5(content.encode()).hexdigest()[:16]


class LogParser:
    """Parse various log formats into normalized LogEvent objects"""
    
    # Common log patterns
    PATTERNS = {
        'apache': r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d+) (?P<size>\S+)',
        'syslog': r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+(?P<process>\S+?)(\[(?P<pid>\d+)\])?: (?P<message>.+)',
        'json': r'\{.+\}',
        'windows': r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<level>\w+)\s+(?P<source>\S+)\s+(?P<message>.+)',
        'auth': r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*(?P<event>Failed password|Accepted password|authentication failure).*for (?P<user>\S+) from (?P<ip>\S+)',
        'firewall': r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*(?P<action>ALLOW|DENY|DROP).*SRC=(?P<src_ip>\S+).*DST=(?P<dst_ip>\S+).*PROTO=(?P<proto>\S+)',
    }
    
    @staticmethod
    def parse_timestamp(ts_str: str) -> datetime:
        """Parse various timestamp formats"""
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%d/%b/%Y:%H:%M:%S %z',
            '%b %d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(ts_str.strip(), fmt)
                # For syslog without year, add current year
                if fmt == '%b %d %H:%M:%S':
                    dt = dt.replace(year=datetime.now().year)
                return dt
            except ValueError:
                continue
        
        # Default to now if parsing fails
        return datetime.now()
    
    @staticmethod
    def parse_apache(line: str, source: str) -> Optional[LogEvent]:
        """Parse Apache/Nginx access logs"""
        match = re.search(LogParser.PATTERNS['apache'], line)
        if match:
            data = match.groupdict()
            timestamp = LogParser.parse_timestamp(data['timestamp'])
            
            # Determine severity from status code
            status = int(data['status'])
            if status >= 500:
                severity = 'ERROR'
            elif status >= 400:
                severity = 'WARNING'
            else:
                severity = 'INFO'
            
            return LogEvent(
                timestamp=timestamp,
                source=source,
                severity=severity,
                event_type='HTTP_REQUEST',
                message=f"{data['request']} - {data['status']}",
                ip_address=data['ip'],
                raw_log=line
            )
        return None
    
    @staticmethod
    def parse_syslog(line: str, source: str) -> Optional[LogEvent]:
        """Parse syslog format"""
        match = re.search(LogParser.PATTERNS['syslog'], line)
        if match:
            data = match.groupdict()
            timestamp = LogParser.parse_timestamp(data['timestamp'])
            
            return LogEvent(
                timestamp=timestamp,
                source=source,
                severity='INFO',
                event_type='SYSLOG',
                message=data['message'],
                raw_log=line
            )
        return None
    
    @staticmethod
    def parse_auth(line: str, source: str) -> Optional[LogEvent]:
        """Parse authentication logs"""
        match = re.search(LogParser.PATTERNS['auth'], line)
        if match:
            data = match.groupdict()
            timestamp = LogParser.parse_timestamp(data['timestamp'])
            
            event = data['event']
            severity = 'WARNING' if 'Failed' in event else 'INFO'
            event_type = 'AUTH_FAILURE' if 'Failed' in event else 'AUTH_SUCCESS'
            
            return LogEvent(
                timestamp=timestamp,
                source=source,
                severity=severity,
                event_type=event_type,
                message=event,
                user=data.get('user'),
                ip_address=data.get('ip'),
                raw_log=line
            )
        return None
    
    @staticmethod
    def parse_firewall(line: str, source: str) -> Optional[LogEvent]:
        """Parse firewall logs"""
        match = re.search(LogParser.PATTERNS['firewall'], line)
        if match:
            data = match.groupdict()
            timestamp = LogParser.parse_timestamp(data['timestamp'])
            
            action = data['action']
            severity = 'WARNING' if action in ['DENY', 'DROP'] else 'INFO'
            
            return LogEvent(
                timestamp=timestamp,
                source=source,
                severity=severity,
                event_type=f'FIREWALL_{action}',
                message=f"{action}: {data['src_ip']} -> {data['dst_ip']} ({data['proto']})",
                ip_address=data['src_ip'],
                raw_log=line
            )
        return None
    
    @staticmethod
    def parse_json(line: str, source: str) -> Optional[LogEvent]:
        """Parse JSON formatted logs"""
        try:
            data = json.loads(line)
            
            # Extract common fields
            timestamp_str = data.get('timestamp') or data.get('time') or data.get('@timestamp')
            timestamp = LogParser.parse_timestamp(timestamp_str) if timestamp_str else datetime.now()
            
            return LogEvent(
                timestamp=timestamp,
                source=source,
                severity=data.get('level', data.get('severity', 'INFO')).upper(),
                event_type=data.get('event_type', 'JSON_LOG'),
                message=data.get('message', str(data)),
                user=data.get('user'),
                ip_address=data.get('ip', data.get('source_ip')),
                raw_log=line
            )
        except json.JSONDecodeError:
            return None
    
    @staticmethod
    def parse_line(line: str, source: str, log_type: str = 'auto') -> Optional[LogEvent]:
        """Auto-detect and parse log line"""
        line = line.strip()
        if not line:
            return None
        
        # Try specific parser if type is known
        if log_type == 'apache':
            return LogParser.parse_apache(line, source)
        elif log_type == 'syslog':
            return LogParser.parse_syslog(line, source)
        elif log_type == 'auth':
            return LogParser.parse_auth(line, source)
        elif log_type == 'firewall':
            return LogParser.parse_firewall(line, source)
        elif log_type == 'json':
            return LogParser.parse_json(line, source)
        
        # Auto-detect
        if line.startswith('{'):
            result = LogParser.parse_json(line, source)
            if result:
                return result
        
        # Try parsers in order
        for parser in [
            LogParser.parse_auth,
            LogParser.parse_firewall,
            LogParser.parse_apache,
            LogParser.parse_syslog,
        ]:
            result = parser(line, source)
            if result:
                return result
        
        # Fallback: create basic event
        return LogEvent(
            timestamp=datetime.now(),
            source=source,
            severity='INFO',
            event_type='UNKNOWN',
            message=line[:200],
            raw_log=line
        )


class SIEMDatabase:
    """SQLite database for storing and querying logs"""
    
    def __init__(self, db_path: str = 'siem_logs.db'):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._initialize_db()
    
    def _initialize_db(self):
        """Create database schema"""
        cursor = self.conn.cursor()
        
        # Main events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp DATETIME NOT NULL,
                source TEXT NOT NULL,
                severity TEXT NOT NULL,
                event_type TEXT NOT NULL,
                message TEXT NOT NULL,
                user TEXT,
                ip_address TEXT,
                raw_log TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes for common queries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_source ON events(source)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_type ON events(event_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip ON events(ip_address)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user ON events(user)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON events(severity)')
        
        # Correlation rules table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS correlation_rules (
                rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                event_pattern TEXT NOT NULL,
                time_window_seconds INTEGER NOT NULL,
                threshold INTEGER DEFAULT 1,
                active BOOLEAN DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER,
                triggered_at DATETIME NOT NULL,
                event_count INTEGER,
                description TEXT,
                event_ids TEXT,
                FOREIGN KEY(rule_id) REFERENCES correlation_rules(rule_id)
            )
        ''')
        
        self.conn.commit()
    
    def insert_event(self, event: LogEvent):
        """Insert a log event into the database"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO events 
            (event_id, timestamp, source, severity, event_type, message, user, ip_address, raw_log)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.event_id,
            event.timestamp,
            event.source,
            event.severity,
            event.event_type,
            event.message,
            event.user,
            event.ip_address,
            event.raw_log
        ))
        
        self.conn.commit()
    
    def insert_events_bulk(self, events: List[LogEvent]):
        """Bulk insert events for better performance"""
        cursor = self.conn.cursor()
        
        data = [
            (e.event_id, e.timestamp, e.source, e.severity, e.event_type, 
             e.message, e.user, e.ip_address, e.raw_log)
            for e in events
        ]
        
        cursor.executemany('''
            INSERT OR REPLACE INTO events 
            (event_id, timestamp, source, severity, event_type, message, user, ip_address, raw_log)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', data)
        
        self.conn.commit()
    
    def search_events(self, 
                     start_time: Optional[datetime] = None,
                     end_time: Optional[datetime] = None,
                     source: Optional[str] = None,
                     severity: Optional[str] = None,
                     event_type: Optional[str] = None,
                     user: Optional[str] = None,
                     ip_address: Optional[str] = None,
                     keyword: Optional[str] = None,
                     limit: int = 1000) -> List[Dict]:
        """Search events with various filters"""
        cursor = self.conn.cursor()
        
        query = "SELECT * FROM events WHERE 1=1"
        params = []
        
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)
        
        if source:
            query += " AND source = ?"
            params.append(source)
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        
        if user:
            query += " AND user = ?"
            params.append(user)
        
        if ip_address:
            query += " AND ip_address = ?"
            params.append(ip_address)
        
        if keyword:
            query += " AND (message LIKE ? OR raw_log LIKE ?)"
            params.extend([f'%{keyword}%', f'%{keyword}%'])
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        cursor = self.conn.cursor()
        
        stats = {}
        
        # Total events
        cursor.execute("SELECT COUNT(*) as count FROM events")
        stats['total_events'] = cursor.fetchone()['count']
        
        # Events by source
        cursor.execute("SELECT source, COUNT(*) as count FROM events GROUP BY source")
        stats['by_source'] = {row['source']: row['count'] for row in cursor.fetchall()}
        
        # Events by severity
        cursor.execute("SELECT severity, COUNT(*) as count FROM events GROUP BY severity")
        stats['by_severity'] = {row['severity']: row['count'] for row in cursor.fetchall()}
        
        # Events by type
        cursor.execute("SELECT event_type, COUNT(*) as count FROM events GROUP BY event_type ORDER BY count DESC LIMIT 10")
        stats['top_event_types'] = {row['event_type']: row['count'] for row in cursor.fetchall()}
        
        # Time range
        cursor.execute("SELECT MIN(timestamp) as min_time, MAX(timestamp) as max_time FROM events")
        row = cursor.fetchone()
        stats['time_range'] = {
            'earliest': row['min_time'],
            'latest': row['max_time']
        }
        
        return stats
    
    def close(self):
        """Close database connection"""
        self.conn.close()


class TimeCorrelationEngine:
    """Engine for correlating events based on time proximity"""
    
    def __init__(self, db: SIEMDatabase):
        self.db = db
    
    def find_correlated_events(self, 
                               event_types: List[str],
                               time_window: timedelta,
                               min_events: int = 2,
                               max_gap: Optional[timedelta] = None) -> List[Dict]:
        """
        Find sequences of events that occur within a time window
        
        Args:
            event_types: List of event types to correlate
            time_window: Maximum time window for correlation
            min_events: Minimum number of events required
            max_gap: Maximum allowed gap between consecutive events
        """
        cursor = self.db.conn.cursor()
        
        # Get all relevant events ordered by time
        placeholders = ','.join(['?' for _ in event_types])
        query = f'''
            SELECT event_id, timestamp, source, event_type, message, user, ip_address
            FROM events
            WHERE event_type IN ({placeholders})
            ORDER BY timestamp
        '''
        
        cursor.execute(query, event_types)
        events = [dict(row) for row in cursor.fetchall()]
        
        correlations = []
        
        # Sliding window approach
        for i in range(len(events)):
            window_events = [events[i]]
            start_time = datetime.fromisoformat(events[i]['timestamp'])
            
            for j in range(i + 1, len(events)):
                current_time = datetime.fromisoformat(events[j]['timestamp'])
                time_diff = current_time - start_time
                
                # Check if within time window
                if time_diff <= time_window:
                    # Check max gap if specified
                    if max_gap:
                        last_time = datetime.fromisoformat(window_events[-1]['timestamp'])
                        gap = current_time - last_time
                        if gap > max_gap:
                            continue
                    
                    window_events.append(events[j])
                else:
                    break
            
            # Check if we have enough events
            if len(window_events) >= min_events:
                # Check if we have all required event types
                found_types = set(e['event_type'] for e in window_events)
                if len(found_types) >= min(len(event_types), min_events):
                    correlations.append({
                        'start_time': window_events[0]['timestamp'],
                        'end_time': window_events[-1]['timestamp'],
                        'duration': str(current_time - start_time),
                        'event_count': len(window_events),
                        'event_types': list(found_types),
                        'events': window_events
                    })
        
        return correlations
    
    def find_suspicious_patterns(self, time_window: timedelta = timedelta(minutes=5)) -> List[Dict]:
        """Identify common suspicious patterns"""
        patterns = []
        
        # Pattern 1: Multiple failed auth followed by success
        failed_then_success = self.find_correlated_events(
            ['AUTH_FAILURE', 'AUTH_SUCCESS'],
            time_window=time_window,
            min_events=2
        )
        
        for corr in failed_then_success:
            # Count failures before success
            failure_count = sum(1 for e in corr['events'] if e['event_type'] == 'AUTH_FAILURE')
            if failure_count >= 3:
                patterns.append({
                    'pattern': 'Brute Force Attack',
                    'severity': 'HIGH',
                    'description': f'{failure_count} failed auth attempts followed by success',
                    'correlation': corr
                })
        
        # Pattern 2: Rapid firewall denies from same IP
        cursor = self.db.conn.cursor()
        cursor.execute('''
            SELECT ip_address, COUNT(*) as count
            FROM events
            WHERE event_type LIKE 'FIREWALL_DENY%'
            AND timestamp > datetime('now', '-5 minutes')
            GROUP BY ip_address
            HAVING count >= 10
        ''')
        
        for row in cursor.fetchall():
            patterns.append({
                'pattern': 'Port Scan Detection',
                'severity': 'MEDIUM',
                'description': f'Multiple firewall denies from {row["ip_address"]} ({row["count"]} attempts)',
                'ip': row['ip_address']
            })
        
        return patterns
    
    def timeline_analysis(self, 
                         start_time: datetime,
                         end_time: datetime,
                         bucket_size: timedelta = timedelta(minutes=1)) -> Dict:
        """
        Create a timeline of events grouped by time buckets
        """
        cursor = self.db.conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, event_type, severity, source
            FROM events
            WHERE timestamp BETWEEN ? AND ?
            ORDER BY timestamp
        ''', (start_time, end_time))
        
        events = [dict(row) for row in cursor.fetchall()]
        
        # Group events into time buckets
        buckets = defaultdict(lambda: {'events': [], 'count': 0, 'types': defaultdict(int)})
        
        for event in events:
            event_time = datetime.fromisoformat(event['timestamp'])
            
            # Calculate bucket
            seconds_since_start = (event_time - start_time).total_seconds()
            bucket_num = int(seconds_since_start // bucket_size.total_seconds())
            bucket_time = start_time + (bucket_num * bucket_size)
            
            bucket_key = bucket_time.isoformat()
            buckets[bucket_key]['events'].append(event)
            buckets[bucket_key]['count'] += 1
            buckets[bucket_key]['types'][event['event_type']] += 1
        
        # Convert to sorted list
        timeline = [
            {
                'time': k,
                'count': v['count'],
                'event_types': dict(v['types']),
                'sample_events': v['events'][:5]  # Include sample events
            }
            for k, v in sorted(buckets.items())
        ]
        
        return {
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'bucket_size': str(bucket_size),
            'total_buckets': len(timeline),
            'timeline': timeline
        }


class LogAggregator:
    """Main log aggregation and management class"""
    
    def __init__(self, db_path: str = 'siem_logs.db'):
        self.db = SIEMDatabase(db_path)
        self.parser = LogParser()
        self.correlator = TimeCorrelationEngine(self.db)
    
    def ingest_file(self, filepath: str, source: str = None, log_type: str = 'auto'):
        """Ingest a log file"""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")
        
        source = source or path.name
        events = []
        
        print(f"Ingesting {filepath} as '{source}'...")
        
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                event = self.parser.parse_line(line, source, log_type)
                if event:
                    events.append(event)
                
                # Bulk insert every 1000 events
                if len(events) >= 1000:
                    self.db.insert_events_bulk(events)
                    print(f"  Processed {line_num} lines, inserted {len(events)} events...")
                    events = []
        
        # Insert remaining events
        if events:
            self.db.insert_events_bulk(events)
        
        print(f"✓ Completed ingestion of {filepath}")
    
    def ingest_directory(self, directory: str, pattern: str = '*.log', log_type: str = 'auto'):
        """Ingest all log files in a directory"""
        path = Path(directory)
        if not path.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")
        
        files = list(path.glob(pattern))
        print(f"Found {len(files)} log files in {directory}")
        
        for filepath in files:
            try:
                self.ingest_file(str(filepath), log_type=log_type)
            except Exception as e:
                print(f"✗ Error processing {filepath}: {e}")
    
    def search(self, **kwargs) -> List[Dict]:
        """Search for events"""
        return self.db.search_events(**kwargs)
    
    def correlate(self, event_types: List[str], time_window: timedelta, **kwargs) -> List[Dict]:
        """Find correlated events"""
        return self.correlator.find_correlated_events(event_types, time_window, **kwargs)
    
    def detect_threats(self) -> List[Dict]:
        """Run threat detection"""
        return self.correlator.find_suspicious_patterns()
    
    def get_timeline(self, start_time: datetime, end_time: datetime, bucket_size: timedelta = timedelta(minutes=1)) -> Dict:
        """Get timeline analysis"""
        return self.correlator.timeline_analysis(start_time, end_time, bucket_size)
    
    def get_stats(self) -> Dict:
        """Get statistics"""
        return self.db.get_statistics()
    
    def close(self):
        """Close database connection"""
        self.db.close()


def main():
    """Example usage"""
    print("=== SIEM Mini Tool - Log Aggregation & Time Correlation ===\n")
    
    # Initialize
    siem = LogAggregator('siem_demo.db')
    
    print("Example usage:")
    print("1. siem.ingest_file('access.log', source='webserver', log_type='apache')")
    print("2. siem.ingest_file('auth.log', source='auth_server', log_type='auth')")
    print("3. events = siem.search(severity='WARNING', limit=100)")
    print("4. correlated = siem.correlate(['AUTH_FAILURE', 'AUTH_SUCCESS'], timedelta(minutes=5))")
    print("5. threats = siem.detect_threats()")
    print("6. timeline = siem.get_timeline(start_time, end_time, timedelta(minutes=5))")
    print("7. stats = siem.get_stats()")
    
    return siem


if __name__ == '__main__':
    siem = main()