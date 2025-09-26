#!/usr/bin/env python3
"""
GREENWIRE Log Viewer - Human-readable analysis of protocol logs
Provides operator-friendly viewing of NFC, ATR, and APDU logs
"""

import argparse, datetime, json
from pathlib import Path
from typing import Any, Dict, List, Optional  # noqa: F401

class LogViewer:
    """Human-readable log analysis and reporting tool."""
    
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        
    def list_sessions(self) -> List[Dict]:
        """List all available log sessions."""
        sessions = []
        
        # Find all session summary files
        for summary_file in self.log_dir.glob("session_summary_*.json"):
            try:
                with open(summary_file, 'r') as f:
                    session_data = json.load(f)
                sessions.append(session_data)
            except Exception as e:
                print(f"Warning: Could not read {summary_file}: {e}")
                
        # Sort by session ID (timestamp)
        sessions.sort(key=lambda x: x.get('session_id', ''))
        return sessions
        
    def analyze_session(self, session_id: str) -> Dict:
        """Analyze a specific session and provide summary."""
        log_files = {
            'protocol': self.log_dir / f"protocol_{session_id}.log",
            'nfc': self.log_dir / f"nfc_{session_id}.log",
            'atr': self.log_dir / f"atr_{session_id}.log",
            'apdu': self.log_dir / f"apdu_{session_id}.log"
        }
        
        analysis = {
            'session_id': session_id,
            'files': {},
            'statistics': {
                'nfc_transactions': 0,
                'atr_analyses': 0,
                'apdu_exchanges': 0,
                'errors': 0
            },
            'timeline': []
        }
        
        # Analyze each log file
        for log_type, log_file in log_files.items():
            if log_file.exists():
                file_analysis = self._analyze_log_file(log_file, log_type)
                analysis['files'][log_type] = file_analysis
                
                # Update statistics
                if log_type == 'nfc':
                    analysis['statistics']['nfc_transactions'] += file_analysis['entry_count']
                elif log_type == 'atr':
                    analysis['statistics']['atr_analyses'] += file_analysis['entry_count']
                elif log_type == 'apdu':
                    analysis['statistics']['apdu_exchanges'] += file_analysis['entry_count']
                    
        return analysis
        
    def _analyze_log_file(self, log_file: Path, log_type: str) -> Dict:
        """Analyze individual log file."""
        analysis = {
            'file_path': str(log_file),
            'file_size': log_file.stat().st_size,
            'entry_count': 0,
            'first_entry': None,
            'last_entry': None,
            'entries': []
        }
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                        
                    # Parse log entry
                    entry = self._parse_log_entry(line)
                    if entry:
                        analysis['entries'].append(entry)
                        analysis['entry_count'] += 1
                        
                        if not analysis['first_entry']:
                            analysis['first_entry'] = entry['timestamp']
                        analysis['last_entry'] = entry['timestamp']
                        
        except Exception as e:
            analysis['error'] = str(e)
            
        return analysis
        
    def _parse_log_entry(self, log_line: str) -> Optional[Dict]:
        """Parse a single log entry."""
        try:
            # Extract timestamp and message
            parts = log_line.split(' | ', 3)
            if len(parts) >= 4:
                timestamp_str, level, logger, message = parts
                
                # Try to parse JSON content if present
                json_data = None
                if message.startswith('{') or 'NFC Transaction:' in message or 'ATR Analysis:' in message or 'APDU Exchange:' in message:
                    try:
                        # Extract JSON part
                        json_start = message.find('{')
                        if json_start >= 0:
                            json_str = message[json_start:]
                            json_data = json.loads(json_str)
                    except:
                        pass
                
                return {
                    'timestamp': timestamp_str,
                    'level': level.strip(),
                    'logger': logger.strip(),
                    'message': message,
                    'json_data': json_data
                }
        except Exception:
            pass
            
        return None
        
    def generate_report(self, session_id: str, output_format: str = 'text') -> str:
        """Generate human-readable report for a session."""
        analysis = self.analyze_session(session_id)
        
        if output_format == 'text':
            return self._generate_text_report(analysis)
        elif output_format == 'html':
            return self._generate_html_report(analysis)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
            
    def _generate_text_report(self, analysis: Dict) -> str:
        """Generate plain text report."""
        report = []
        
        # Header
        report.append("="*80)
        report.append("GREENWIRE Protocol Analysis Report")
        report.append("="*80)
        report.append(f"Session ID: {analysis['session_id']}")
        report.append(f"Generated: {datetime.datetime.now().isoformat()}")
        report.append("")
        
        # Statistics
        stats = analysis['statistics']
        report.append("Session Statistics:")
        report.append(f"  • NFC Transactions: {stats['nfc_transactions']}")
        report.append(f"  • ATR Analyses: {stats['atr_analyses']}")
        report.append(f"  • APDU Exchanges: {stats['apdu_exchanges']}")
        report.append(f"  • Errors: {stats['errors']}")
        report.append("")
        
        # File Analysis
        report.append("Log Files Analysis:")
        for log_type, file_info in analysis['files'].items():
            if 'error' not in file_info:
                report.append(f"  📄 {log_type.upper()} Log:")
                report.append(f"     Path: {file_info['file_path']}")
                report.append(f"     Size: {file_info['file_size']} bytes")
                report.append(f"     Entries: {file_info['entry_count']}")
                if file_info['first_entry'] and file_info['last_entry']:
                    report.append(f"     Duration: {file_info['first_entry']} → {file_info['last_entry']}")
                report.append("")
            else:
                report.append(f"  ❌ {log_type.upper()} Log: {file_info['error']}")
                report.append("")
        
        # Detailed Analysis
        self._add_detailed_analysis(report, analysis)
        
        return "\\n".join(report)
        
    def _add_detailed_analysis(self, report: List[str], analysis: Dict):
        """Add detailed analysis sections to report."""
        
        # ATR Analysis Section
        if 'atr' in analysis['files'] and analysis['files']['atr']['entries']:
            report.append("ATR (Answer to Reset) Analysis:")
            report.append("-" * 40)
            
            for entry in analysis['files']['atr']['entries'][:10]:  # Show first 10
                if entry['json_data']:
                    data = entry['json_data']
                    report.append(f"  🕐 {entry['timestamp']}")
                    report.append(f"     ATR: {data.get('atr_hex', 'N/A')}")
                    report.append(f"     Length: {data.get('atr_length', 0)} bytes")
                    
                    if 'analysis' in data:
                        analysis_data = data['analysis']
                        if 'ts' in analysis_data:
                            report.append(f"     Convention: {analysis_data['ts'].get('meaning', 'Unknown')}")
                        if 'historical_bytes' in analysis_data:
                            hist = analysis_data['historical_bytes']
                            report.append(f"     Historical: {hist.get('hex', '')} ('{hist.get('ascii', '')}')") 
                    report.append("")
                    
            report.append("")
            
        # NFC Transactions Section
        if 'nfc' in analysis['files'] and analysis['files']['nfc']['entries']:
            report.append("NFC Transaction Analysis:")
            report.append("-" * 40)
            
            transaction_types = {}
            for entry in analysis['files']['nfc']['entries']:
                if entry['json_data']:
                    tx_type = entry['json_data'].get('transaction_type', 'unknown')
                    transaction_types[tx_type] = transaction_types.get(tx_type, 0) + 1
            
            report.append("  Transaction Type Summary:")
            for tx_type, count in transaction_types.items():
                report.append(f"     {tx_type}: {count}")
            report.append("")
            
        # APDU Exchanges Section
        if 'apdu' in analysis['files'] and analysis['files']['apdu']['entries']:
            report.append("APDU Exchange Analysis:")
            report.append("-" * 40)
            
            successful_commands = 0
            failed_commands = 0
            avg_timing = 0
            timing_samples = []
            
            for entry in analysis['files']['apdu']['entries'][:5]:  # Show first 5 detailed
                if entry['json_data']:
                    data = entry['json_data']
                    report.append(f"  🕐 {entry['timestamp']}")
                    
                    if 'command' in data:
                        cmd = data['command']
                        report.append(f"     Command: {cmd.get('hex', 'N/A')}")
                        if 'analysis' in cmd:
                            analysis_data = cmd['analysis']
                            report.append(f"     CLA: {analysis_data.get('cla', 'N/A')} | INS: {analysis_data.get('ins_name', 'N/A')}")
                            
                    if 'response' in data:
                        resp = data['response']
                        report.append(f"     Response: {resp.get('hex', 'N/A')}")
                        if 'analysis' in resp:
                            analysis_data = resp['analysis']
                            status = analysis_data.get('status', 'Unknown')
                            report.append(f"     Status: {status}")
                            if 'SUCCESS' in status:
                                successful_commands += 1
                            else:
                                failed_commands += 1
                                
                    if 'timing_ms' in data and data['timing_ms']:
                        timing = data['timing_ms']
                        timing_samples.append(timing)
                        report.append(f"     Timing: {timing:.2f} ms")
                        
                    report.append("")
                    
            # APDU Summary
            if timing_samples:
                avg_timing = sum(timing_samples) / len(timing_samples)
                
            report.append("  APDU Summary:")
            report.append(f"     Successful: {successful_commands}")
            report.append(f"     Failed: {failed_commands}")
            if avg_timing > 0:
                report.append(f"     Average Timing: {avg_timing:.2f} ms")
            report.append("")
        
    def _generate_html_report(self, analysis: Dict) -> str:
        """Generate HTML report."""
        html = f"""
        <html>
        <head>
            <title>GREENWIRE Protocol Report - {analysis['session_id']}</title>
            <style>
                body {{ font-family: 'Courier New', monospace; margin: 20px; }}
                .header {{ background: #2d3748; color: white; padding: 20px; margin-bottom: 20px; }}
                .stats {{ background: #f7fafc; padding: 15px; margin-bottom: 20px; border-left: 4px solid #4299e1; }}
                .section {{ margin-bottom: 30px; }}
                .log-entry {{ background: #edf2f7; padding: 10px; margin: 5px 0; font-size: 12px; }}
                .success {{ color: #38a169; }}
                .error {{ color: #e53e3e; }}
                .timestamp {{ color: #718096; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔍 GREENWIRE Protocol Analysis</h1>
                <p>Session: {analysis['session_id']}</p>
                <p>Generated: {datetime.datetime.now().isoformat()}</p>
            </div>
            
            <div class="stats">
                <h2>📊 Session Statistics</h2>
                <ul>
                    <li>NFC Transactions: {analysis['statistics']['nfc_transactions']}</li>
                    <li>ATR Analyses: {analysis['statistics']['atr_analyses']}</li>
                    <li>APDU Exchanges: {analysis['statistics']['apdu_exchanges']}</li>
                    <li>Errors: {analysis['statistics']['errors']}</li>
                </ul>
            </div>
            
            <!-- Add more sections as needed -->
            
        </body>
        </html>
        """
        return html

def main():
    parser = argparse.ArgumentParser(description="GREENWIRE Protocol Log Viewer")
    parser.add_argument("--log-dir", default="logs", help="Log directory path")
    parser.add_argument("--list-sessions", action="store_true", help="List available sessions")
    parser.add_argument("--session", help="Analyze specific session")
    parser.add_argument("--format", choices=['text', 'html'], default='text', help="Output format")
    parser.add_argument("--output", help="Output file (default: stdout)")
    
    args = parser.parse_args()
    
    viewer = LogViewer(args.log_dir)
    
    if args.list_sessions:
        sessions = viewer.list_sessions()
        print("Available Sessions:")
        print("-" * 40)
        for session in sessions:
            print(f"  {session['session_id']}")
            print(f"    Files: {len(session.get('files_created', []))}")
            print()
    elif args.session:
        try:
            report = viewer.generate_report(args.session, args.format)
            
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(report)
                print(f"Report saved to: {args.output}")
            else:
                print(report)
        except Exception as e:
            print(f"Error generating report: {e}")
    else:
        print("Use --list-sessions to see available sessions or --session <id> to analyze")

if __name__ == "__main__":
    main()