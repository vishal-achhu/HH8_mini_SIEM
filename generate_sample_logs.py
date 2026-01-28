#!/usr/bin/env python3
"""
Generate sample log files for SIEM demonstration
"""

from datetime import datetime, timedelta
import random

# Sample data
IPS = [
    '192.168.1.10', '192.168.1.15', '192.168.1.20',
    '10.0.0.5', '10.0.0.8', '203.0.113.42',
    '198.51.100.23', '192.0.2.156'
]

USERS = ['alice', 'bob', 'charlie', 'david', 'eve', 'frank', 'admin', 'root']

PATHS = [
    '/index.html', '/about.html', '/login', '/api/users',
    '/api/data', '/admin', '/dashboard', '/upload'
]

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    'curl/7.68.0',
    'Python-requests/2.25.1'
]


def generate_apache_logs(filename='sample_apache.log', num_events=500):
    """Generate sample Apache access logs"""
    print(f"Generating {filename}...")
    
    base_time = datetime.now() - timedelta(hours=2)
    
    with open(filename, 'w') as f:
        for i in range(num_events):
            timestamp = base_time + timedelta(seconds=i * 10 + random.randint(-5, 5))
            ip = random.choice(IPS)
            path = random.choice(PATHS)
            
            # Generate some errors
            if random.random() < 0.05:
                status = random.choice([404, 500, 503])
            elif path == '/admin' and random.random() < 0.3:
                status = 403
            else:
                status = 200
            
            size = random.randint(200, 50000)
            
            log_line = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" {status} {size}\n'
            f.write(log_line)
    
    print(f"✓ Created {filename}")


def generate_auth_logs(filename='sample_auth.log', num_events=300):
    """Generate sample authentication logs with attack patterns"""
    print(f"Generating {filename}...")
    
    base_time = datetime.now() - timedelta(hours=2)
    
    with open(filename, 'w') as f:
        time_offset = 0
        
        # Normal activity
        for i in range(100):
            timestamp = base_time + timedelta(seconds=time_offset)
            user = random.choice(USERS[:4])  # Legitimate users
            ip = random.choice(IPS[:3])
            
            log_line = f'{timestamp.strftime("%b %d %H:%M:%S")} auth-server sshd[{random.randint(1000, 9999)}]: Accepted password for {user} from {ip} port 22 ssh2\n'
            f.write(log_line)
            time_offset += random.randint(30, 180)
        
        # Brute force attack simulation
        attacker_ip = '203.0.113.42'
        attack_start = base_time + timedelta(minutes=45)
        
        # Multiple failed attempts
        for i in range(15):
            timestamp = attack_start + timedelta(seconds=i * 2)
            user = random.choice(['admin', 'root', 'test', 'oracle'])
            
            log_line = f'{timestamp.strftime("%b %d %H:%M:%S")} auth-server sshd[{random.randint(1000, 9999)}]: Failed password for {user} from {attacker_ip} port 22 ssh2\n'
            f.write(log_line)
        
        # Successful breach
        timestamp = attack_start + timedelta(seconds=32)
        log_line = f'{timestamp.strftime("%b %d %H:%M:%S")} auth-server sshd[{random.randint(1000, 9999)}]: Accepted password for admin from {attacker_ip} port 22 ssh2\n'
        f.write(log_line)
        
        # Another attack pattern
        attack_start2 = base_time + timedelta(minutes=90)
        attacker_ip2 = '198.51.100.23'
        
        for i in range(10):
            timestamp = attack_start2 + timedelta(seconds=i * 3)
            user = random.choice(['admin', 'root'])
            
            log_line = f'{timestamp.strftime("%b %d %H:%M:%S")} auth-server sshd[{random.randint(1000, 9999)}]: Failed password for {user} from {attacker_ip2} port 22 ssh2\n'
            f.write(log_line)
        
        # More normal activity
        for i in range(100):
            timestamp = base_time + timedelta(hours=1, seconds=i * 20)
            user = random.choice(USERS[:4])
            ip = random.choice(IPS[:3])
            
            log_line = f'{timestamp.strftime("%b %d %H:%M:%S")} auth-server sshd[{random.randint(1000, 9999)}]: Accepted password for {user} from {ip} port 22 ssh2\n'
            f.write(log_line)
    
    print(f"✓ Created {filename}")


def generate_firewall_logs(filename='sample_firewall.log', num_events=400):
    """Generate sample firewall logs with port scan"""
    print(f"Generating {filename}...")
    
    base_time = datetime.now() - timedelta(hours=2)
    
    with open(filename, 'w') as f:
        time_offset = 0
        
        # Normal traffic
        for i in range(200):
            timestamp = base_time + timedelta(seconds=time_offset)
            src_ip = random.choice(IPS[:3])
            dst_ip = '10.0.0.100'
            action = random.choice(['ALLOW'] * 8 + ['DENY'] * 2)
            proto = random.choice(['TCP', 'UDP', 'ICMP'])
            dst_port = random.choice([80, 443, 22, 53, 3306])
            
            log_line = f'{timestamp.strftime("%Y-%m-%dT%H:%M:%S")} firewall-01 kernel: FIREWALL {action} IN=eth0 OUT= SRC={src_ip} DST={dst_ip} PROTO={proto} DPT={dst_port}\n'
            f.write(log_line)
            time_offset += random.randint(5, 30)
        
        # Port scan simulation
        scanner_ip = '203.0.113.42'
        scan_start = base_time + timedelta(minutes=50)
        
        # Scan multiple ports quickly
        ports = list(range(20, 100)) + [443, 8080, 3306, 5432, 6379, 27017]
        for i, port in enumerate(ports):
            timestamp = scan_start + timedelta(seconds=i * 0.5)
            
            log_line = f'{timestamp.strftime("%Y-%m-%dT%H:%M:%S")} firewall-01 kernel: FIREWALL DENY IN=eth0 OUT= SRC={scanner_ip} DST=10.0.0.100 PROTO=TCP DPT={port}\n'
            f.write(log_line)
        
        # More normal traffic
        for i in range(100):
            timestamp = base_time + timedelta(hours=1, seconds=i * 15)
            src_ip = random.choice(IPS[:3])
            dst_ip = '10.0.0.100'
            action = random.choice(['ALLOW'] * 9 + ['DENY'])
            proto = random.choice(['TCP', 'UDP'])
            dst_port = random.choice([80, 443, 22])
            
            log_line = f'{timestamp.strftime("%Y-%m-%dT%H:%M:%S")} firewall-01 kernel: FIREWALL {action} IN=eth0 OUT= SRC={src_ip} DST={dst_ip} PROTO={proto} DPT={dst_port}\n'
            f.write(log_line)
    
    print(f"✓ Created {filename}")


def generate_syslog(filename='sample_syslog.log', num_events=200):
    """Generate sample syslog entries"""
    print(f"Generating {filename}...")
    
    base_time = datetime.now() - timedelta(hours=2)
    
    services = ['cron', 'systemd', 'kernel', 'postfix', 'apache2']
    messages = [
        'Starting user session',
        'Service started successfully',
        'Configuration reloaded',
        'Disk usage at 75%',
        'Network interface up',
        'Backup completed',
        'Certificate will expire in 30 days',
    ]
    
    with open(filename, 'w') as f:
        for i in range(num_events):
            timestamp = base_time + timedelta(seconds=i * 30)
            service = random.choice(services)
            message = random.choice(messages)
            pid = random.randint(1000, 9999)
            
            log_line = f'{timestamp.strftime("%b %d %H:%M:%S")} server-01 {service}[{pid}]: {message}\n'
            f.write(log_line)
    
    print(f"✓ Created {filename}")


def generate_json_logs(filename='sample_app.json', num_events=150):
    """Generate sample JSON application logs"""
    print(f"Generating {filename}...")
    
    base_time = datetime.now() - timedelta(hours=2)
    
    import json
    
    events = [
        {'event_type': 'USER_LOGIN', 'level': 'INFO'},
        {'event_type': 'USER_LOGOUT', 'level': 'INFO'},
        {'event_type': 'API_REQUEST', 'level': 'INFO'},
        {'event_type': 'DATABASE_QUERY', 'level': 'DEBUG'},
        {'event_type': 'CACHE_MISS', 'level': 'WARNING'},
        {'event_type': 'ERROR_OCCURRED', 'level': 'ERROR'},
    ]
    
    with open(filename, 'w') as f:
        for i in range(num_events):
            timestamp = base_time + timedelta(seconds=i * 40)
            event = random.choice(events)
            
            log_entry = {
                'timestamp': timestamp.isoformat(),
                'level': event['level'],
                'event_type': event['event_type'],
                'message': f"Application event: {event['event_type']}",
                'user': random.choice(USERS) if random.random() > 0.3 else None,
                'ip': random.choice(IPS),
                'request_id': f'req-{random.randint(10000, 99999)}'
            }
            
            f.write(json.dumps(log_entry) + '\n')
    
    print(f"✓ Created {filename}")


if __name__ == '__main__':
    print("=== Generating Sample Log Files ===\n")
    
    generate_apache_logs()
    generate_auth_logs()
    generate_firewall_logs()
    generate_syslog()
    generate_json_logs()
    
    print("\n✓ All sample log files generated!")
    print("\nFiles created:")
    print("  - sample_apache.log (Web server access logs)")
    print("  - sample_auth.log (Authentication logs with brute force attacks)")
    print("  - sample_firewall.log (Firewall logs with port scan)")
    print("  - sample_syslog.log (System logs)")
    print("  - sample_app.json (Application logs in JSON format)")