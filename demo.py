#!/usr/bin/env python3
"""
SIEM Tool - Comprehensive Demonstration
Shows log aggregation, time correlation, and threat detection
"""

from datetime import datetime, timedelta
from siem_tool import LogAggregator
import json


def print_header(title):
    """Print a formatted header"""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


def print_section(title):
    """Print a section header"""
    print(f"\n{'─'*70}")
    print(f"  {title}")
    print(f"{'─'*70}\n")


def demo_ingestion(siem):
    """Demonstrate log ingestion"""
    print_header("DEMO 1: LOG INGESTION")
    
    print("Ingesting multiple log sources...")
    
    # Ingest all sample logs
    siem.ingest_file('sample_apache.log', source='webserver-01', log_type='apache')
    siem.ingest_file('sample_auth.log', source='auth-server', log_type='auth')
    siem.ingest_file('sample_firewall.log', source='firewall-01', log_type='firewall')
    siem.ingest_file('sample_syslog.log', source='server-01', log_type='syslog')
    siem.ingest_file('sample_app.json', source='application-01', log_type='json')
    
    # Show stats
    stats = siem.get_stats()
    print(f"\n✓ Total events ingested: {stats['total_events']:,}")
    print(f"\nEvents by source:")
    for source, count in stats['by_source'].items():
        print(f"  • {source:20s}: {count:5,} events")


def demo_basic_search(siem):
    """Demonstrate basic search capabilities"""
    print_header("DEMO 2: BASIC SEARCH")
    
    # Search for errors
    print_section("Searching for ERROR events")
    errors = siem.search(severity='ERROR', limit=10)
    print(f"Found {len(errors)} error events:\n")
    for event in errors[:5]:
        print(f"  [{event['timestamp']}] {event['source']}: {event['message'][:60]}")
    
    # Search for warnings
    print_section("Searching for WARNING events")
    warnings = siem.search(severity='WARNING', limit=10)
    print(f"Found {len(warnings)} warning events:\n")
    for event in warnings[:5]:
        print(f"  [{event['timestamp']}] {event['source']}: {event['message'][:60]}")
    
    # Search by IP
    print_section("Searching for events from specific IP: 203.0.113.42")
    ip_events = siem.search(ip_address='203.0.113.42', limit=20)
    print(f"Found {len(ip_events)} events from this IP:\n")
    for event in ip_events[:5]:
        print(f"  [{event['timestamp']}] {event['event_type']}: {event['message'][:50]}")


def demo_time_correlation(siem):
    """Demonstrate time correlation of events"""
    print_header("DEMO 3: TIME CORRELATION")
    
    # Correlate authentication events
    print_section("Correlating AUTH_FAILURE and AUTH_SUCCESS events")
    print("Looking for failed login attempts followed by successful login...")
    print("(Potential brute force attacks)\n")
    
    correlations = siem.correlate(
        event_types=['AUTH_FAILURE', 'AUTH_SUCCESS'],
        time_window=timedelta(minutes=5),
        min_events=3
    )
    
    print(f"Found {len(correlations)} suspicious authentication patterns:\n")
    
    for i, corr in enumerate(correlations[:3], 1):
        print(f"Pattern #{i}:")
        print(f"  Time: {corr['start_time']} → {corr['end_time']}")
        print(f"  Duration: {corr['duration']}")
        print(f"  Events: {corr['event_count']}")
        
        # Count failures and successes
        failures = sum(1 for e in corr['events'] if e['event_type'] == 'AUTH_FAILURE')
        successes = sum(1 for e in corr['events'] if e['event_type'] == 'AUTH_SUCCESS')
        
        print(f"  Breakdown: {failures} failures, {successes} successes")
        
        # Show sequence
        print("  Event sequence:")
        for event in corr['events'][:8]:
            print(f"    • [{event['timestamp']}] {event['event_type']} - {event['message']}")
        
        if len(corr['events']) > 8:
            print(f"    ... and {len(corr['events']) - 8} more events")
        print()


def demo_multi_source_correlation(siem):
    """Demonstrate correlation across multiple sources"""
    print_header("DEMO 4: MULTI-SOURCE CORRELATION")
    
    print_section("Correlating events across Firewall and Auth systems")
    print("Looking for firewall denies followed by auth attempts from same IP...\n")
    
    # This is a more complex correlation - find IPs that were blocked by firewall
    # but later attempted authentication
    
    # Get recent firewall denies
    firewall_events = siem.search(
        event_type='FIREWALL_DENY',
        limit=100
    )
    
    blocked_ips = set()
    for event in firewall_events:
        if event['ip_address']:
            blocked_ips.add(event['ip_address'])
    
    print(f"Found {len(blocked_ips)} unique IPs with firewall denies")
    
    # Check if these IPs attempted authentication
    suspicious_activity = []
    for ip in blocked_ips:
        auth_events = siem.search(
            ip_address=ip,
            event_type='AUTH_FAILURE',
            limit=10
        )
        
        if len(auth_events) > 0:
            suspicious_activity.append({
                'ip': ip,
                'firewall_blocks': len([e for e in firewall_events if e['ip_address'] == ip]),
                'auth_attempts': len(auth_events)
            })
    
    print(f"\nFound {len(suspicious_activity)} IPs with both firewall blocks and auth attempts:\n")
    
    for activity in suspicious_activity[:5]:
        print(f"  IP: {activity['ip']}")
        print(f"    Firewall blocks: {activity['firewall_blocks']}")
        print(f"    Auth attempts: {activity['auth_attempts']}")
        print(f"    ⚠️  Potential unauthorized access attempt")
        print()


def demo_threat_detection(siem):
    """Demonstrate automated threat detection"""
    print_header("DEMO 5: AUTOMATED THREAT DETECTION")
    
    print("Running automated threat detection patterns...\n")
    
    threats = siem.detect_threats()
    
    print(f"🚨 Detected {len(threats)} potential security threats:\n")
    
    for i, threat in enumerate(threats, 1):
        print(f"Threat #{i}: {threat['pattern']}")
        print(f"  Severity: {threat['severity']}")
        print(f"  Description: {threat['description']}")
        
        if 'ip' in threat:
            print(f"  Source IP: {threat['ip']}")
        
        if 'correlation' in threat:
            corr = threat['correlation']
            print(f"  Time: {corr['start_time']} → {corr['end_time']}")
            print(f"  Events: {corr['event_count']}")
        
        print()


def demo_timeline_analysis(siem):
    """Demonstrate timeline analysis"""
    print_header("DEMO 6: TIMELINE ANALYSIS")
    
    stats = siem.get_stats()
    start_time = datetime.fromisoformat(stats['time_range']['earliest'])
    end_time = datetime.fromisoformat(stats['time_range']['latest'])
    
    print(f"Creating timeline from {start_time} to {end_time}")
    print("Bucket size: 5 minutes\n")
    
    timeline = siem.get_timeline(
        start_time=start_time,
        end_time=end_time,
        bucket_size=timedelta(minutes=5)
    )
    
    print(f"Timeline with {timeline['total_buckets']} time buckets:\n")
    
    # Find max for scaling
    max_count = max((b['count'] for b in timeline['timeline']), default=0)
    
    # Show timeline
    for i, bucket in enumerate(timeline['timeline'][:20]):  # Show first 20 buckets
        bar_length = int((bucket['count'] / max_count) * 40) if max_count > 0 else 0
        bar = '█' * bar_length
        
        time_str = bucket['time'][:16]  # Shorter timestamp
        print(f"{time_str} | {bucket['count']:4d} events | {bar}")
    
    if len(timeline['timeline']) > 20:
        print(f"\n... and {len(timeline['timeline']) - 20} more buckets")
    
    # Show event spikes
    print_section("Event Spikes Detection")
    
    avg_count = sum(b['count'] for b in timeline['timeline']) / len(timeline['timeline'])
    print(f"Average events per bucket: {avg_count:.1f}\n")
    
    spikes = [b for b in timeline['timeline'] if b['count'] > avg_count * 2]
    
    if spikes:
        print(f"Found {len(spikes)} time periods with unusual activity (>2x average):\n")
        for spike in spikes[:5]:
            print(f"  Time: {spike['time']}")
            print(f"  Events: {spike['count']} (avg: {avg_count:.1f})")
            print(f"  Top event types:")
            for event_type, count in sorted(spike['event_types'].items(), key=lambda x: -x[1])[:3]:
                print(f"    • {event_type}: {count}")
            print()


def demo_search_patterns(siem):
    """Demonstrate common search patterns"""
    print_header("DEMO 7: COMMON SEARCH PATTERNS")
    
    # Recent high-severity events
    print_section("Recent Critical Events (last hour)")
    
    one_hour_ago = datetime.now() - timedelta(hours=1)
    critical = siem.search(
        start_time=one_hour_ago,
        severity='ERROR',
        limit=10
    )
    
    print(f"Found {len(critical)} critical events:\n")
    for event in critical[:5]:
        print(f"  [{event['timestamp']}] {event['source']}")
        print(f"    {event['event_type']}: {event['message'][:60]}")
    
    # User activity summary
    print_section("User Activity Summary")
    
    # Get all events with users
    user_events = siem.search(limit=10000)
    user_activity = {}
    
    for event in user_events:
        if event['user']:
            if event['user'] not in user_activity:
                user_activity[event['user']] = {
                    'total': 0,
                    'failures': 0,
                    'successes': 0
                }
            user_activity[event['user']]['total'] += 1
            if 'FAILURE' in event['event_type']:
                user_activity[event['user']]['failures'] += 1
            elif 'SUCCESS' in event['event_type']:
                user_activity[event['user']]['successes'] += 1
    
    print("User activity statistics:\n")
    for user, stats in sorted(user_activity.items(), key=lambda x: -x[1]['total'])[:8]:
        print(f"  {user:15s}: {stats['total']:3d} events "
              f"({stats['successes']} success, {stats['failures']} failure)")


def demo_export(siem):
    """Demonstrate data export"""
    print_header("DEMO 8: DATA EXPORT")
    
    print("Exporting high-severity events to JSON...\n")
    
    # Export warnings and errors
    events = siem.search(severity='WARNING', limit=1000)
    events.extend(siem.search(severity='ERROR', limit=1000))
    
    export_file = 'security_events_export.json'
    with open(export_file, 'w') as f:
        json.dump(events, f, indent=2, default=str)
    
    print(f"✓ Exported {len(events)} events to {export_file}")
    print(f"  File size: {len(json.dumps(events)) / 1024:.1f} KB")


def main():
    """Run comprehensive demonstration"""
    print("\n" + "="*70)
    print("  SIEM MINI TOOL - COMPREHENSIVE DEMONSTRATION")
    print("  Log Aggregation & Time Correlation")
    print("="*70)
    
    print("\nInitializing SIEM system...")
    siem = LogAggregator('siem_demo.db')
    
    try:
        # Run all demos
        demo_ingestion(siem)
        demo_basic_search(siem)
        demo_time_correlation(siem)
        demo_multi_source_correlation(siem)
        demo_threat_detection(siem)
        demo_timeline_analysis(siem)
        demo_search_patterns(siem)
        demo_export(siem)
        
        # Final summary
        print_header("DEMONSTRATION COMPLETE")
        
        stats = siem.get_stats()
        print("Final Statistics:")
        print(f"  Total Events: {stats['total_events']:,}")
        print(f"  Sources: {len(stats['by_source'])}")
        print(f"  Time Range: {stats['time_range']['earliest']} → {stats['time_range']['latest']}")
        print("\nKey Features Demonstrated:")
        print("  ✓ Multi-format log parsing (Apache, Auth, Firewall, Syslog, JSON)")
        print("  ✓ Centralized log aggregation")
        print("  ✓ Time-based event correlation")
        print("  ✓ Cross-system event analysis")
        print("  ✓ Automated threat detection")
        print("  ✓ Timeline analysis and visualization")
        print("  ✓ Advanced search and filtering")
        print("  ✓ Data export capabilities")
        
        print("\n" + "="*70)
        print("  Use the CLI tool for interactive exploration:")
        print("  python siem_cli.py --help")
        print("="*70 + "\n")
        
    finally:
        siem.close()


if __name__ == '__main__':
    main()