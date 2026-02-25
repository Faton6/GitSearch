#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitSearch CLI - Command Line Interface

Allows running GitSearch without Docker for local development
and quick searches.

Usage:
    python cli.py search --query "api_key" --language python --days 7
    python cli.py scan --repo "owner/repo" --scanners gitleaks trufflehog
    python cli.py status
    python cli.py metrics

For full usage: python cli.py --help
"""

import argparse
import sys
import os
from datetime import datetime


def setup_environment():
    """Setup environment for running outside Docker."""
    # Add project root to path
    project_root = os.path.dirname(os.path.abspath(__file__))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    # Set default environment variables if not set
    defaults = {
        "DB_HOST": "localhost",
        "DB_PORT": "3306",
        "DB_NAME": "Gitsearch",
        "DB_USER": "root",
        "DB_PASSWORD": "",
        "TEMP_FOLDER": os.path.join(project_root, "temp"),
        "REPORTS_FOLDER": os.path.join(project_root, "reports"),
        "LOGS_FOLDER": os.path.join(project_root, "logs"),
    }

    for key, value in defaults.items():
        if key not in os.environ:
            os.environ[key] = value


def cmd_search(args):
    """Execute search command."""
    from src.api_client import GitSearchAPIClient
    from src.logger import logger

    search_query = args.query
    logger.info(f"Starting search: query='{args.query}', language='{args.language}', days={args.days}")

    try:
        _ = GitSearchAPIClient()  # Initialize API client

        print(f"\n🔍 Searching GitHub for: {search_query}")
        print(f"   Time range: last {args.days} days")
        print(f"   Max results: {args.max_results}")
        print("-" * 50)

        # Execute search
        from src.utils import get_gh_request
        from src.github_rate_limiter import initialize_rate_limiter

        # Initialize rate limiter with tokens from config
        tokens = os.environ.get("GH_TOKENS", "").split(",")
        tokens = [t.strip() for t in tokens if t.strip()]

        if not tokens:
            print("⚠️  No GitHub tokens configured. Set GH_TOKENS environment variable.")
            return 1

        initialize_rate_limiter(tokens)

        # Perform code search
        results_count = 0
        repos_found = set()

        from datetime import timedelta

        end_date = datetime.now()
        start_date = end_date - timedelta(days=args.days)

        date_range = f"{start_date.strftime('%Y-%m-%d')}..{end_date.strftime('%Y-%m-%d')}"
        full_query = f"{search_query} pushed:{date_range}"

        print(f"\n📊 Full query: {full_query}\n")

        # Simple search via REST API
        url = f"https://api.github.com/search/code?q={full_query}&per_page={min(args.max_results, 100)}"

        response = get_gh_request(url, resource="search_code")

        if response and "items" in response:
            results_count = len(response["items"])
            print(f"✅ Found {response.get('total_count', 0)} total matches")
            print(f"   Showing {results_count} results:\n")

            for i, item in enumerate(response["items"][: args.max_results], 1):
                repo = item.get("repository", {})
                repo_name = repo.get("full_name", "unknown")
                repos_found.add(repo_name)

                print(f"{i}. {item.get('path', 'unknown')}")
                print(f"   Repo: {repo_name}")
                print(f"   URL: {item.get('html_url', 'N/A')}")
                print()
        else:
            print("❌ No results found or search failed")
            if response:
                print(f"   Response: {response}")

        print("-" * 50)
        print(f"📈 Summary: {results_count} results from {len(repos_found)} repositories")

        return 0

    except Exception as e:
        logger.error(f"Search failed: {e}")
        print(f"❌ Error: {e}")
        return 1


def cmd_scan(args):
    """Execute scan command."""
    from src.logger import logger
    from src.scanner import scan_repository

    logger.info(f"Starting scan: repo='{args.repo}', scanners={args.scanners}")

    try:
        print(f"\n🔬 Scanning repository: {args.repo}")
        print(f"   Scanners: {', '.join(args.scanners)}")
        print("-" * 50)

        # Clone and scan
        from src.utils import clone_repository

        # Get clone URL
        repo_url = f"https://github.com/{args.repo}"

        print(f"📦 Cloning from: {repo_url}")

        # Clone
        clone_path = clone_repository(args.repo, repo_url)

        if not clone_path:
            print("❌ Failed to clone repository")
            return 1

        print(f"✅ Cloned to: {clone_path}")

        # Run scanners
        all_findings = []

        for scanner_name in args.scanners:
            print(f"\n🔍 Running {scanner_name}...")

            findings = scan_repository(clone_path, scanner_name)

            if findings:
                print(f"   Found {len(findings)} potential secrets")
                all_findings.extend(findings)
            else:
                print("   No findings")

        print("\n" + "=" * 50)
        print(f"📊 Total findings: {len(all_findings)}")

        if all_findings and args.output:
            # Save to file
            with open(args.output, "w") as f:
                json.dump(all_findings, f, indent=2, default=str)
            print(f"💾 Results saved to: {args.output}")

        # Show findings
        if all_findings and args.verbose:
            print("\n📋 Findings:")
            for i, finding in enumerate(all_findings[:20], 1):
                print(f"\n{i}. {finding.get('type', 'unknown')}")
                print(f"   File: {finding.get('file', 'N/A')}")
                print(f"   Line: {finding.get('line', 'N/A')}")
                if "secret" in finding:
                    secret = finding["secret"]
                    # Mask secret
                    if len(secret) > 8:
                        secret = secret[:4] + "*" * (len(secret) - 8) + secret[-4:]
                    print(f"   Secret: {secret}")

        return 0 if not all_findings else 2  # Return 2 if secrets found

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        print(f"❌ Error: {e}")
        return 1


def cmd_status(args):
    """Show system status."""
    print("\n📊 GitSearch Status")
    print("=" * 50)

    # Check modules
    print("\n🔧 Modules:")
    modules = [
        ("src.api_client", "API Client"),
        ("src.scanner", "Scanner"),
        ("src.ai_analyzer", "AI Analyzer"),
        ("src.github_rate_limiter", "Rate Limiter"),
        ("src.metrics", "Metrics"),
        ("src.temp_manager", "Temp Manager"),
    ]

    for module_name, display_name in modules:
        try:
            __import__(module_name)
            print(f"   ✅ {display_name}")
        except ImportError as e:
            print(f"   ❌ {display_name}: {e}")

    # Check database
    print("\n🗄️  Database:")
    try:
        from src.api_client import GitSearchAPIClient

        client = GitSearchAPIClient()
        conn = client._get_connection()
        if conn:
            print(f"   ✅ Connected to {os.environ.get('DB_HOST', 'localhost')}")
        else:
            print("   ❌ Connection failed")
    except Exception as e:
        print(f"   ❌ {e}")

    # Check GitHub tokens
    print("\n🔑 GitHub Tokens:")
    tokens = os.environ.get("GH_TOKENS", "").split(",")
    tokens = [t.strip() for t in tokens if t.strip()]
    if tokens:
        print(f"   ✅ {len(tokens)} token(s) configured")
        for i, token in enumerate(tokens, 1):
            prefix = token[:6] if len(token) > 6 else token
            print(f"      {i}. {prefix}...")
    else:
        print("   ⚠️  No tokens configured")

    # Check scanners
    print("\n🔬 Scanners:")
    import shutil

    scanners = ["gitleaks", "trufflehog", "detect-secrets", "git-secrets"]
    for scanner in scanners:
        path = shutil.which(scanner)
        if path:
            print(f"   ✅ {scanner}: {path}")
        else:
            print(f"   ❌ {scanner}: not found")

    # Check AI
    print("\n🤖 AI Providers:")
    ai_keys = [
        ("TOGETHER_API_KEY", "Together AI"),
        ("OPENROUTER_API_KEY", "OpenRouter"),
        ("FIREWORKS_API_KEY", "Fireworks"),
    ]
    for key, name in ai_keys:
        if os.environ.get(key):
            print(f"   ✅ {name}: configured")
        else:
            print(f"   ⚪ {name}: not configured")

    # Check folders
    print("\n📁 Folders:")
    folders = [
        ("TEMP_FOLDER", "temp"),
        ("REPORTS_FOLDER", "reports"),
        ("LOGS_FOLDER", "logs"),
    ]
    for env_key, default in folders:
        path = os.environ.get(env_key, default)
        exists = os.path.exists(path)
        status = "✅" if exists else "❌"
        print(f"   {status} {env_key}: {path}")

    print("\n" + "=" * 50)
    return 0


def cmd_metrics(args):
    """Show metrics."""
    try:
        from src.metrics import get_metrics_collector

        metrics = get_metrics_collector()

        if args.format == "prometheus":
            print(metrics.to_prometheus())
        else:
            print(metrics.to_json())

        return 0
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="gitsearch",
        description="GitSearch CLI - Search GitHub for secrets and vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s search -q "api_key" -l python -d 7
  %(prog)s scan -r "owner/repo" -s gitleaks trufflehog
  %(prog)s status
  %(prog)s metrics
        """,
    )

    parser.add_argument("--version", action="version", version="GitSearch 1.0.0")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Search command
    search_parser = subparsers.add_parser("search", help="Search GitHub for code")
    search_parser.add_argument("-q", "--query", required=True, help="Search query")
    search_parser.add_argument("-l", "--language", help="Programming language filter")
    search_parser.add_argument("-d", "--days", type=int, default=7, help="Search last N days (default: 7)")
    search_parser.add_argument("-m", "--max-results", type=int, default=100, help="Max results (default: 100)")
    search_parser.add_argument("-o", "--output", help="Output file for results (JSON)")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan repository for secrets")
    scan_parser.add_argument("-r", "--repo", required=True, help="Repository (owner/repo)")
    scan_parser.add_argument(
        "-s", "--scanners", nargs="+", default=["gitleaks"], help="Scanners to use (default: gitleaks)"
    )
    scan_parser.add_argument("-o", "--output", help="Output file for results (JSON)")
    scan_parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed findings")

    # Status command
    _ = subparsers.add_parser("status", help="Show system status")  # noqa: F841

    # Metrics command
    metrics_parser = subparsers.add_parser("metrics", help="Show metrics")
    metrics_parser.add_argument("-f", "--format", choices=["json", "prometheus"], default="json", help="Output format")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    # Setup environment
    setup_environment()

    # Dispatch to command handler
    commands = {
        "search": cmd_search,
        "scan": cmd_scan,
        "status": cmd_status,
        "metrics": cmd_metrics,
    }

    handler = commands.get(args.command)
    if handler:
        return handler(args)
    else:
        print(f"Unknown command: {args.command}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
