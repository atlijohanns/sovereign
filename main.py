#!/usr/bin/env python3
"""
Main entry point for Icelandic government agency DNS analysis.

This script orchestrates the full analysis pipeline:
1. Scrape organization data from island.is
2. Perform DNS lookups on all domains
3. Classify and analyze the results

All output is logged to logs/timestamp.log
"""

import subprocess
import sys
from pathlib import Path
from datetime import datetime
import argparse


def setup_logging():
    """Create logs directory and setup log file."""
    log_dir = Path(__file__).parent / "logs"
    log_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"{timestamp}.log"
    
    return log_file


def run_script(script_name, log_file, description):
    """Run a Python script and log all output."""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"{'='*60}\n")
    
    script_path = Path(__file__).parent / "scripts" / script_name
    
    with open(log_file, "a", encoding="utf-8") as log:
        log.write(f"\n{'='*60}\n")
        log.write(f"Running: {description}\n")
        log.write(f"Script: {script_name}\n")
        log.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        log.write(f"{'='*60}\n\n")
        
        process = subprocess.Popen(
            [sys.executable, str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        
        # Stream output to both console and log file
        if process.stdout:
            for line in process.stdout:
                print(line, end="")
                log.write(line)
        
        process.wait()
        
        if process.returncode != 0:
            error_msg = f"\n❌ ERROR: Script failed with exit code {process.returncode}\n"
            print(error_msg)
            log.write(error_msg)
            return False
        else:
            success_msg = f"\n✓ Script completed successfully\n"
            print(success_msg)
            log.write(success_msg)
            return True


def main():
    parser = argparse.ArgumentParser(
        description="Icelandic government agency DNS analysis pipeline"
    )
    parser.add_argument(
        "--skip-scrape",
        action="store_true",
        help="Skip scraping island.is (use existing data)"
    )
    parser.add_argument(
        "--skip-dns",
        action="store_true",
        help="Skip DNS lookups (use existing data)"
    )
    parser.add_argument(
        "--classify-only",
        action="store_true",
        help="Only run classification on existing DNS data"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    log_file = setup_logging()
    print(f"Logging to: {log_file}")
    
    # Write header to log
    with open(log_file, "w", encoding="utf-8") as log:
        log.write(f"Icelandic Government Agency DNS Analysis\n")
        log.write(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        log.write(f"Options: skip_scrape={args.skip_scrape}, skip_dns={args.skip_dns}, classify_only={args.classify_only}\n")
        log.write(f"{'='*60}\n")
    
    success = True
    
    # Step 1: Scrape island.is organizations
    if args.classify_only or args.skip_scrape:
        print("\nSkipping island.is scrape (using existing data)")
        with open(log_file, "a", encoding="utf-8") as log:
            log.write("\nSkipping island.is scrape (using existing data)\n")
    else:
        success = run_script(
            "scrape_island_is.py",
            log_file,
            "Step 1: Scraping island.is organizations"
        )
        if not success:
            print("\n❌ Pipeline failed at scraping step")
            sys.exit(1)
    
    # Step 2: DNS lookups
    if args.classify_only or args.skip_dns:
        print("\nSkipping DNS lookups (using existing data)")
        with open(log_file, "a", encoding="utf-8") as log:
            log.write("\nSkipping DNS lookups (using existing data)\n")
    else:
        success = run_script(
            "dns_lookup.py",
            log_file,
            "Step 2: Performing DNS lookups"
        )
        if not success:
            print("\n❌ Pipeline failed at DNS lookup step")
            sys.exit(1)
    
    # Step 3: Classification and analysis
    success = run_script(
        "dns_classify.py",
        log_file,
        "Step 3: Classifying and analyzing DNS data"
    )
    if not success:
        print("\n❌ Pipeline failed at classification step")
        sys.exit(1)
    
    # Step 4: Effective provider determination
    success = run_script(
        "dns_effective.py",
        log_file,
        "Step 4: Determining effective providers"
    )
    if not success:
        print("\n❌ Pipeline failed at effective provider step")
        sys.exit(1)
    
    # Summary
    print(f"\n{'='*60}")
    print("✓ Pipeline completed successfully!")
    print(f"{'='*60}")
    print(f"\nLog file: {log_file}")
    print("Check the 'output' directory for final results.")
    
    with open(log_file, "a", encoding="utf-8") as log:
        log.write(f"\n{'='*60}\n")
        log.write(f"Pipeline completed successfully!\n")
        log.write(f"Ended: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        log.write(f"{'='*60}\n")


if __name__ == "__main__":
    main()
