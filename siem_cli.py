#!/usr/bin/env python3
"""
SIEM CLI - Command Line Interface for Log Aggregation
"""

import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path
import json
from siem_tool import LogAggregator


def format_event(event: dict) -> str:
    """Format event for display"""
    return (f"[{event['timestamp']}] {event['source']:15s} "
            f"{event['severity']:8s} {event['event_type']:20s} "
            f"{event['message'][:60]}")


def cmd_ingest(args):
    """Ingest log files"""
    siem = LogAggregator(args.database)
    
    if args.file:
        for filepath in args.file:
            siem.ingest_file(filepath, source=args.source, log_type=args.type)
    
    if args.directory:
        siem.ingest_directory(args.directory, pattern=args.pattern, log_type=args.type)
    
    # Show stats after ingestion
    stats = siem.get_stats()
    print(f"\n📊 Database now contains {stats['total_events']} events")
    
    siem.close()


def cmd_search(args):
    """Search for events"""
    siem = LogAggregator(args.database)
    
    # Parse time range
    start_time = None
    end_time = None
    
    if args.start:
        start_time = datetime.fromisoformat(args.start)
    elif args.last:
        end_time = datetime.now()
        if args.last.endswith('h'):
            hours = int(args.last[:-1])
            start_time = end_time - timedelta(hours=hours)
        elif args.last.endswith('m'):
            minutes = int(args.last[:-1])
            start_time = end_time - timedelta(minutes=minutes)
        elif args.last.endswith('d'):
            days = int(args.last[:-1])
            start_time = end_time - timedelta(days=days)
    
    if args.end:
        end_time = datetime.fromisoformat(args.end)
    
    # Search
    events = siem.search(
        start_time=start_time,
        end_time=end_time,
        source=args.source,
        severity=args.severity,
        event_type=args.event_type,
        user=args.user,
        ip_address=args.ip,
        keyword=args.keyword,
        limit=args.limit
    )
    
    print(f"\n🔍 Found {len(events)} events:\n")
    
    for event in events[:args.limit]:
        print(format_event(event))
    
    if len(events) > args.limit:
        print(f"\n... and {len(events) - args.limit} more (use --limit to see more)")
    
    siem.close()


def cmd_correlate(args):
    """Find correlated events"""
    siem = LogAggregator(args.database)
    
    # Parse event types
    event_types = args.event_types.split(',')
    
    # Parse time window
    if args.window.endswith('s'):
        seconds = int(args.window[:-1])
        time_window = timedelta(seconds=seconds)
    elif args.window.endswith('m'):
        minutes = int(args.window[:-1])
        time_window = timedelta(minutes=minutes)
    elif args.window.endswith('h'):
        hours = int(args.window[:-1])
        time_window = timedelta(hours=hours)
    else:
        minutes = int(args.window)
        time_window = timedelta(minutes=minutes)
    
    correlations = siem.correlate(
        event_types=event_types,
        time_window=time_window,
        min_events=args.min_events
    )
    
    print(f"\n🔗 Found {len(correlations)} correlated event sequences:\n")
    
    for i, corr in enumerate(correlations[:args.limit], 1):
        print(f"\n━━━ Correlation #{i} ━━━")
        print(f"Time Range: {corr['start_time']} → {corr['end_time']}")
        print(f"Duration: {corr['duration']}")
        print(f"Event Count: {corr['event_count']}")
        print(f"Event Types: {', '.join(corr['event_types'])}")
        print(f"\nEvents in sequence:")
        for event in corr['events'][:10]:  # Show first 10
            print(f"  • {format_event(event)}")
        if len(corr['events']) > 10:
            print(f"  ... and {len(corr['events']) - 10} more events")
    
    siem.close()


def cmd_detect(args):
    """Detect suspicious patterns"""
    siem = LogAggregator(args.database)
    
    patterns = siem.detect_threats()
    
    print(f"\n⚠️  Found {len(patterns)} suspicious patterns:\n")
    
    for i, pattern in enumerate(patterns, 1):
        print(f"\n━━━ Pattern #{i} ━━━")
        print(f"Type: {pattern['pattern']}")
        print(f"Severity: {pattern['severity']}")
        print(f"Description: {pattern['description']}")
        
        if 'correlation' in pattern:
            corr = pattern['correlation']
            print(f"Time Range: {corr['start_time']} → {corr['end_time']}")
            print(f"Events involved: {corr['event_count']}")
        
        if 'ip' in pattern:
            print(f"Source IP: {pattern['ip']}")
    
    siem.close()


def cmd_timeline(args):
    """Show timeline analysis"""
    siem = LogAggregator(args.database)
    
    # Parse time range
    if args.start:
        start_time = datetime.fromisoformat(args.start)
    else:
        start_time = datetime.now() - timedelta(hours=1)
    
    if args.end:
        end_time = datetime.fromisoformat(args.end)
    else:
        end_time = datetime.now()
    
    # Parse bucket size
    if args.bucket.endswith('s'):
        seconds = int(args.bucket[:-1])
        bucket_size = timedelta(seconds=seconds)
    elif args.bucket.endswith('m'):
        minutes = int(args.bucket[:-1])
        bucket_size = timedelta(minutes=minutes)
    elif args.bucket.endswith('h'):
        hours = int(args.bucket[:-1])
        bucket_size = timedelta(hours=hours)
    else:
        minutes = int(args.bucket)
        bucket_size = timedelta(minutes=minutes)
    
    timeline = siem.get_timeline(start_time, end_time, bucket_size)
    
    print(f"\n📅 Timeline Analysis")
    print(f"Time Range: {timeline['start_time']} → {timeline['end_time']}")
    print(f"Bucket Size: {timeline['bucket_size']}")
    print(f"Total Buckets: {timeline['total_buckets']}\n")
    
    # Find max count for scaling
    max_count = max((b['count'] for b in timeline['timeline']), default=0)
    
    for bucket in timeline['timeline']:
        # Create a simple bar chart
        bar_length = int((bucket['count'] / max_count) * 50) if max_count > 0 else 0
        bar = '█' * bar_length
        
        print(f"{bucket['time'][:19]} | {bucket['count']:5d} | {bar}")
        
        # Show event type breakdown
        if args.verbose:
            for event_type, count in sorted(bucket['event_types'].items(), key=lambda x: -x[1])[:3]:
                print(f"  └─ {event_type}: {count}")
    
    siem.close()


def cmd_stats(args):
    """Show database statistics"""
    siem = LogAggregator(args.database)
    
    stats = siem.get_stats()
    
    print("\n📊 Database Statistics\n")
    print(f"Total Events: {stats['total_events']:,}")
    
    if stats['time_range']['earliest']:
        print(f"Time Range: {stats['time_range']['earliest']} → {stats['time_range']['latest']}")
    
    print("\nEvents by Source:")
    for source, count in sorted(stats['by_source'].items(), key=lambda x: -x[1]):
        print(f"  • {source:30s} {count:8,}")
    
    print("\nEvents by Severity:")
    for severity, count in sorted(stats['by_severity'].items(), key=lambda x: -x[1]):
        print(f"  • {severity:15s} {count:8,}")
    
    print("\nTop Event Types:")
    for event_type, count in stats['top_event_types'].items():
        print(f"  • {event_type:30s} {count:8,}")
    
    siem.close()


def cmd_export(args):
    """Export events to JSON"""
    siem = LogAggregator(args.database)
    
    # Parse time range
    start_time = None
    end_time = None
    
    if args.start:
        start_time = datetime.fromisoformat(args.start)
    if args.end:
        end_time = datetime.fromisoformat(args.end)
    
    events = siem.search(
        start_time=start_time,
        end_time=end_time,
        source=args.source,
        severity=args.severity,
        event_type=args.event_type,
        limit=args.limit
    )
    
    # Export
    output_file = args.output or 'export.json'
    
    with open(output_file, 'w') as f:
        json.dump(events, f, indent=2, default=str)
    
    print(f"✓ Exported {len(events)} events to {output_file}")
    
    siem.close()


def main():
    parser = argparse.ArgumentParser(
        description='SIEM Mini Tool - Log Aggregation & Time Correlation',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-d', '--database', default='siem_logs.db',
                       help='Database file path (default: siem_logs.db)')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Ingest command
    ingest_parser = subparsers.add_parser('ingest', help='Ingest log files')
    ingest_parser.add_argument('-f', '--file', action='append', help='Log file to ingest')
    ingest_parser.add_argument('-D', '--directory', help='Directory containing log files')
    ingest_parser.add_argument('-p', '--pattern', default='*.log', help='File pattern (default: *.log)')
    ingest_parser.add_argument('-s', '--source', help='Source name')
    ingest_parser.add_argument('-t', '--type', default='auto',
                             choices=['auto', 'apache', 'syslog', 'auth', 'firewall', 'json'],
                             help='Log type (default: auto)')
    ingest_parser.set_defaults(func=cmd_ingest)
    
    # Search command
    search_parser = subparsers.add_parser('search', help='Search for events')
    search_parser.add_argument('--start', help='Start time (ISO format)')
    search_parser.add_argument('--end', help='End time (ISO format)')
    search_parser.add_argument('--last', help='Last N time (e.g., 1h, 30m, 2d)')
    search_parser.add_argument('-s', '--source', help='Filter by source')
    search_parser.add_argument('-S', '--severity', help='Filter by severity')
    search_parser.add_argument('-e', '--event-type', help='Filter by event type')
    search_parser.add_argument('-u', '--user', help='Filter by user')
    search_parser.add_argument('-i', '--ip', help='Filter by IP address')
    search_parser.add_argument('-k', '--keyword', help='Keyword search')
    search_parser.add_argument('-l', '--limit', type=int, default=100, help='Limit results (default: 100)')
    search_parser.set_defaults(func=cmd_search)
    
    # Correlate command
    correlate_parser = subparsers.add_parser('correlate', help='Find correlated events')
    correlate_parser.add_argument('event_types', help='Comma-separated event types to correlate')
    correlate_parser.add_argument('-w', '--window', default='5m',
                                 help='Time window (e.g., 30s, 5m, 1h) (default: 5m)')
    correlate_parser.add_argument('-m', '--min-events', type=int, default=2,
                                 help='Minimum events required (default: 2)')
    correlate_parser.add_argument('-l', '--limit', type=int, default=10,
                                 help='Limit results (default: 10)')
    correlate_parser.set_defaults(func=cmd_correlate)
    
    # Detect command
    detect_parser = subparsers.add_parser('detect', help='Detect suspicious patterns')
    detect_parser.set_defaults(func=cmd_detect)
    
    # Timeline command
    timeline_parser = subparsers.add_parser('timeline', help='Show timeline analysis')
    timeline_parser.add_argument('--start', help='Start time (ISO format)')
    timeline_parser.add_argument('--end', help='End time (ISO format)')
    timeline_parser.add_argument('-b', '--bucket', default='1m',
                                help='Bucket size (e.g., 30s, 1m, 5m) (default: 1m)')
    timeline_parser.add_argument('-v', '--verbose', action='store_true',
                                help='Show event type breakdown')
    timeline_parser.set_defaults(func=cmd_timeline)
    
    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show database statistics')
    stats_parser.set_defaults(func=cmd_stats)
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export events to JSON')
    export_parser.add_argument('-o', '--output', help='Output file (default: export.json)')
    export_parser.add_argument('--start', help='Start time (ISO format)')
    export_parser.add_argument('--end', help='End time (ISO format)')
    export_parser.add_argument('-s', '--source', help='Filter by source')
    export_parser.add_argument('-S', '--severity', help='Filter by severity')
    export_parser.add_argument('-e', '--event-type', help='Filter by event type')
    export_parser.add_argument('-l', '--limit', type=int, default=10000, help='Limit results')
    export_parser.set_defaults(func=cmd_export)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    try:
        args.func(args)
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())