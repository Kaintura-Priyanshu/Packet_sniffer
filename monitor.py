##Create this optional script for real-time monitoring:

#!/usr/bin/env python3
"""
Real-time packet statistics display
"""

import time
import curses
from sniffer import PacketSniffer

class NetworkMonitor:
    """
    Real-time network traffic monitor with curses interface
    """
    
    def __init__(self, interface=None):
        self.sniffer = PacketSniffer(interface=interface, verbose=False)
        self.running = False
        
    def run(self):
        """
        Start the monitor with curses interface
        """
        curses.wrapper(self.monitor_loop)
        
    def monitor_loop(self, stdscr):
        """
        Main monitor loop with curses
        """
        # Setup curses
        curses.curs_set(0)  # Hide cursor
        stdscr.nodelay(1)   # Non-blocking input
        stdscr.clear()
        
        # Start sniffing in background
        import threading
        self.running = True
        sniff_thread = threading.Thread(
            target=self.sniffer.start_capture,
            daemon=True
        )
        sniff_thread.start()
        
        try:
            while self.running:
                # Clear screen
                stdscr.clear()
                
                # Get current statistics
                stats = self.sniffer.stats
                packet_count = self.sniffer.packet_count
                start_time = self.sniffer.start_time
                
                if start_time:
                    duration = (datetime.now() - start_time).total_seconds()
                    rate = packet_count / duration if duration > 0 else 0
                else:
                    duration = 0
                    rate = 0
                
                # Display header
                height, width = stdscr.getmaxyx()
                header = f" Network Monitor - {datetime.now().strftime('%H:%M:%S')} "
                stdscr.addstr(0, (width - len(header)) // 2, header, curses.A_REVERSE)
                
                # Display statistics
                stdscr.addstr(2, 2, f"Packets: {packet_count}")
                stdscr.addstr(3, 2, f"Duration: {duration:.1f}s")
                stdscr.addstr(4, 2, f"Rate: {rate:.1f} pps")
                
                # Display protocol distribution
                stdscr.addstr(6, 2, "Protocol Distribution:")
                y = 7
                for protocol, count in sorted(stats.items(), key=lambda x: x[1], reverse=True)[:10]:
                    if not protocol.startswith(('src_', 'dst_')):
                        percentage = (count / packet_count * 100) if packet_count > 0 else 0
                        stdscr.addstr(y, 4, f"{protocol}: {count} ({percentage:.1f}%)")
                        y += 1
                
                # Refresh and wait
                stdscr.refresh()
                time.sleep(1)
                
                # Check for quit
                if stdscr.getch() == ord('q'):
                    break
                    
        finally:
            self.running = False
            self.sniffer.stop_capture()
            stdscr.clear()
            stdscr.addstr(0, 0, "Monitor stopped. Press any key to exit.")
            stdscr.refresh()
            stdscr.getch()

if __name__ == "__main__":
    import sys
    from datetime import datetime
    import argparse
    
    parser = argparse.ArgumentParser(description="Real-time Network Monitor")
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    args = parser.parse_args()
    
    monitor = NetworkMonitor(interface=args.interface)
    try:
        monitor.run()
    except KeyboardInterrupt:
        print("\nMonitor stopped")