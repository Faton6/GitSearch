#!/usr/bin/env python3
"""
GitSearch Benchmark and Metrics Collection Tool

This script performs comprehensive benchmarking and metrics collection for GitSearch
on real bug bounty program companies from the database.

Usage:
    python benchmark_gitsearch.py [options]
    
Options:
    --companies     Comma-separated company IDs to test (default: all from DB)
    --max-repos     Maximum repositories to scan per company (default: 100)
    --skip-ai       Skip AI analysis to speed up testing
    --output        Output directory for results (default: ./benchmark_results/)
    --db-host       Database host (default: from config.json)
    --db-token      Database token (default: from config.json)
"""

import sys
import os
import json
import time
import argparse
import base64
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from collections import defaultdict
import traceback

# Add project root to path
SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))

# Project imports
from src import constants
from src import Connector
from src.logger import logger
from src.searcher.scanner import Scanner
from src.glist.glist_scan import GlistScan
from src import deepscan
from src import utils
from src.LeakObj import RepoObj, CodeObj, CommitObj


class BenchmarkMetrics:
    """Container for all benchmark metrics"""
    
    def __init__(self):
        # Timing metrics
        self.start_time = time.time()
        self.end_time = None
        self.phase_times = {}  # {phase_name: duration_seconds}
        
        # Search metrics
        self.dorks_tested = 0
        self.api_requests = 0
        self.api_errors = 0
        self.rate_limit_hits = 0
        
        # Discovery metrics
        self.repos_found = 0
        self.repos_scanned = 0
        self.repos_too_large = 0
        self.repos_clone_failed = 0
        
        # Detection metrics
        self.total_findings = 0  # Raw findings from scanners
        self.findings_by_scanner = defaultdict(int)  # {scanner_name: count}
        self.findings_by_type = defaultdict(int)  # {secret_type: count}
        self.real_secrets = 0
        self.false_positives = 0
        self.needs_review = 0
        
        # AI metrics (if enabled)
        self.ai_analyses = 0
        self.ai_successes = 0
        self.ai_failures = 0
        self.ai_costs = 0.0
        self.ai_time = 0.0
        
        # Per-company results
        self.company_results = {}  # {company_id: CompanyMetrics}
        
        # Resource metrics
        self.peak_memory_mb = 0
        self.disk_usage_mb = 0
        self.temp_files_created = 0
        
    def record_phase_time(self, phase_name: str, duration: float):
        """Record timing for a specific phase"""
        self.phase_times[phase_name] = duration
        
    def total_time(self) -> float:
        """Get total benchmark execution time"""
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time
    
    def to_dict(self) -> Dict:
        """Convert metrics to dictionary for JSON export"""
        return {
            'timestamp': datetime.now().isoformat(),
            'total_time_seconds': self.total_time(),
            'phase_times': self.phase_times,
            'search_metrics': {
                'dorks_tested': self.dorks_tested,
                'api_requests': self.api_requests,
                'api_errors': self.api_errors,
                'rate_limit_hits': self.rate_limit_hits
            },
            'discovery_metrics': {
                'repos_found': self.repos_found,
                'repos_scanned': self.repos_scanned,
                'repos_too_large': self.repos_too_large,
                'repos_clone_failed': self.repos_clone_failed,
                'scan_success_rate': self.repos_scanned / max(1, self.repos_found)
            },
            'detection_metrics': {
                'total_findings': self.total_findings,
                'findings_by_scanner': dict(self.findings_by_scanner),
                'findings_by_type': dict(self.findings_by_type),
                'real_secrets': self.real_secrets,
                'false_positives': self.false_positives,
                'needs_review': self.needs_review,
                'precision': self.real_secrets / max(1, self.total_findings) if self.total_findings > 0 else 0
            },
            'ai_metrics': {
                'analyses_performed': self.ai_analyses,
                'successes': self.ai_successes,
                'failures': self.ai_failures,
                'total_cost_usd': self.ai_costs,
                'avg_time_per_analysis': self.ai_time / max(1, self.ai_analyses),
                'success_rate': self.ai_successes / max(1, self.ai_analyses)
            },
            'resource_metrics': {
                'peak_memory_mb': self.peak_memory_mb,
                'disk_usage_mb': self.disk_usage_mb,
                'temp_files_created': self.temp_files_created
            },
            'company_results': self.company_results,
            'performance': {
                'repos_per_hour': self.repos_scanned / max(0.001, self.total_time() / 3600),
                'secrets_per_hour': self.real_secrets / max(0.001, self.total_time() / 3600),
                'cost_per_secret': self.ai_costs / max(1, self.real_secrets) if self.real_secrets > 0 else 0
            }
        }


class CompanyMetrics:
    """Metrics for a single company"""
    
    def __init__(self, company_id: int, company_name: str):
        self.company_id = company_id
        self.company_name = company_name
        self.dorks_count = 0
        self.repos_found = 0
        self.repos_scanned = 0
        self.real_secrets = 0
        self.false_positives = 0
        self.start_time = time.time()
        self.end_time = None
        
    def to_dict(self) -> Dict:
        duration = (self.end_time or time.time()) - self.start_time
        return {
            'company_id': self.company_id,
            'company_name': self.company_name,
            'dorks_count': self.dorks_count,
            'repos_found': self.repos_found,
            'repos_scanned': self.repos_scanned,
            'real_secrets': self.real_secrets,
            'false_positives': self.false_positives,
            'scan_duration_seconds': duration,
            'repos_per_minute': self.repos_scanned / max(0.001, duration / 60)
        }


class GitSearchBenchmark:
    """Main benchmark orchestrator"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.metrics = BenchmarkMetrics()
        self.output_dir = Path(config.get('output_dir', './benchmark_results'))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize constants from config
        self._init_constants()
        
        logger.info('='*80)
        logger.info('GitSearch Benchmark Tool')
        logger.info('='*80)
        logger.info(f'Output directory: {self.output_dir}')
        logger.info(f'Skip AI: {config.get("skip_ai", False)}')
        logger.info(f'Max repos per company: {config.get("max_repos", 100)}')
        
    def _init_constants(self):
        """Initialize constants and configuration"""
        # Override AI setting if requested
        if self.config.get('skip_ai', False):
            constants.AI_ANALYSIS_ENABLED = False
            logger.info('AI analysis disabled for benchmark')
        
        # Load configuration
        try:
            with open(SCRIPT_DIR / 'config.json', 'r') as f:
                constants.CONFIG_FILE = json.load(f)
        except Exception as e:
            logger.error(f'Failed to load config.json: {e}')
            constants.CONFIG_FILE = {}
        
        # Override DB connection if provided
        if self.config.get('db_host'):
            constants.url_DB = self.config['db_host']
        elif 'url_DB' in constants.CONFIG_FILE:
            constants.url_DB = constants.CONFIG_FILE['url_DB']
        
        if self.config.get('db_token'):
            constants.token_DB = self.config['db_token']
        elif 'token_DB' in constants.CONFIG_FILE:
            constants.token_DB = constants.CONFIG_FILE['token_DB']
            
        # Initialize rate limiter
        try:
            constants._init_rate_limiter()
            logger.info('GitHub Rate Limiter initialized')
        except Exception as e:
            logger.warning(f'Failed to initialize Rate Limiter: {e}')
    
    def get_test_companies(self) -> List[Tuple[int, str]]:
        """Get list of companies to test from database"""
        try:
            # Get companies from database
            companies = Connector.get_all_companies()
            
            # Filter by config if specified
            if self.config.get('companies'):
                company_ids = [int(x) for x in self.config['companies'].split(',')]
                companies = [(id, name) for id, name in companies if id in company_ids]
            
            logger.info(f'Found {len(companies)} companies to test: {[name for _, name in companies]}')
            return companies
            
        except Exception as e:
            logger.error(f'Failed to get companies from database: {e}')
            # Fallback to hardcoded test companies
            return [(1, 'VK'), (2, 'Ozon'), (3, 'Tinkoff'), (4, 'Azbuka-Vkusa')]
    
    def get_company_dorks(self, company_id: int) -> List[str]:
        """Get dorks for a company from database"""
        try:
            dorks_dict = Connector.dump_target_from_DB()
            
            # Find company name
            companies = Connector.get_all_companies()
            company_name = next((name for id, name in companies if id == company_id), None)
            
            if not company_name:
                logger.error(f'Company ID {company_id} not found')
                return []
            
            # Decode base64 dorks if needed
            dorks = dorks_dict.get(company_name, [])
            decoded_dorks = []
            
            for dork in dorks:
                try:
                    # Try to decode if it's base64
                    if len(dork) > 50 and ',' in base64.b64decode(dork).decode('utf-8', errors='ignore'):
                        decoded = base64.b64decode(dork).decode('utf-8')
                        decoded_dorks.extend([d.strip() for d in decoded.split(',')])
                    else:
                        decoded_dorks.append(dork)
                except:
                    decoded_dorks.append(dork)
            
            logger.info(f'Loaded {len(decoded_dorks)} dorks for company {company_name}')
            return decoded_dorks[:self.config.get('max_dorks', 50)]  # Limit dorks for benchmark
            
        except Exception as e:
            logger.error(f'Failed to get dorks for company {company_id}: {e}')
            return []
    
    def benchmark_company(self, company_id: int, company_name: str) -> CompanyMetrics:
        """Benchmark scanning for a single company"""
        logger.info('='*80)
        logger.info(f'Starting benchmark for company: {company_name} (ID: {company_id})')
        logger.info('='*80)
        
        company_metrics = CompanyMetrics(company_id, company_name)
        
        try:
            # Phase 1: Load dorks
            phase_start = time.time()
            dorks = self.get_company_dorks(company_id)
            company_metrics.dorks_count = len(dorks)
            
            if not dorks:
                logger.warning(f'No dorks found for {company_name}, skipping')
                return company_metrics
            
            self.metrics.record_phase_time(f'{company_name}_load_dorks', time.time() - phase_start)
            
            # Phase 2: GitHub search
            phase_start = time.time()
            scanner = Scanner(organization=company_id)
            
            # Override dork dict for this company
            constants.dork_dict_from_DB = {company_name: dorks}
            self.metrics.dorks_tested += len(dorks)
            
            # Collect results
            found_repos = set()
            dork_counter = 0
            
            for obj_list, scan_type in scanner.search():
                dork_counter += 1
                self.metrics.api_requests += 1
                
                logger.info(f'Dork {dork_counter}/{len(dorks)}: Found {len(obj_list)} results in {scan_type}')
                
                for obj in obj_list:
                    if hasattr(obj, 'repo_url'):
                        found_repos.add(obj.repo_url)
                        constants.RESULT_MASS[scan_type][obj.repo_url] = obj
                
                company_metrics.repos_found = len(found_repos)
                self.metrics.repos_found = len(found_repos)
                
                # Limit repos for benchmark
                if len(found_repos) >= self.config.get('max_repos', 100):
                    logger.info(f'Reached max repos limit ({self.config.get("max_repos", 100)}), stopping search')
                    break
            
            self.metrics.record_phase_time(f'{company_name}_github_search', time.time() - phase_start)
            logger.info(f'Search complete: Found {len(found_repos)} unique repositories')
            
            # Phase 3: Deep scanning
            if found_repos:
                phase_start = time.time()
                self._benchmark_deep_scan(company_metrics, found_repos, company_name)
                self.metrics.record_phase_time(f'{company_name}_deep_scan', time.time() - phase_start)
            
            # Phase 4: Save results to database
            phase_start = time.time()
            self._save_results(company_id)
            self.metrics.record_phase_time(f'{company_name}_save_results', time.time() - phase_start)
            
        except Exception as e:
            logger.error(f'Error benchmarking company {company_name}: {e}')
            logger.error(traceback.format_exc())
        
        finally:
            company_metrics.end_time = time.time()
            self.metrics.company_results[company_name] = company_metrics.to_dict()
        
        return company_metrics
    
    def _benchmark_deep_scan(self, company_metrics: CompanyMetrics, repos: set, company_name: str):
        """Perform deep scanning on found repositories"""
        logger.info(f'Starting deep scan of {len(repos)} repositories')
        
        from src.filters import Checker
        
        scanned_count = 0
        
        for repo_url in list(repos)[:self.config.get('max_repos', 100)]:
            try:
                # Get leak object
                leak_obj = None
                for scan_type in constants.RESULT_MASS:
                    if repo_url in constants.RESULT_MASS[scan_type]:
                        leak_obj = constants.RESULT_MASS[scan_type][repo_url]
                        break
                
                if not leak_obj:
                    continue
                
                # Fetch stats
                if hasattr(leak_obj, 'stats'):
                    leak_obj.stats.fetch_repository_stats()
                    
                    # Check size
                    if leak_obj.stats.size > constants.REPO_MAX_SIZE:
                        logger.warning(f'Repository {repo_url} too large ({leak_obj.stats.size} KB), skipping')
                        self.metrics.repos_too_large += 1
                        continue
                
                # Create checker and scan
                checker = Checker(url=repo_url, dork=company_name, obj=leak_obj, mode=1)
                
                # Clone
                clone_start = time.time()
                clone_success = checker.clone()
                clone_time = time.time() - clone_start
                
                if not clone_success:
                    logger.warning(f'Failed to clone {repo_url}')
                    self.metrics.repos_clone_failed += 1
                    continue
                
                # Scan
                scan_start = time.time()
                checker.run()
                scan_time = time.time() - scan_start
                
                scanned_count += 1
                company_metrics.repos_scanned += 1
                self.metrics.repos_scanned += 1
                
                # Collect findings
                if hasattr(leak_obj, 'secrets') and leak_obj.secrets:
                    self._process_findings(leak_obj, company_metrics)
                
                # AI analysis if enabled
                if constants.AI_ANALYSIS_ENABLED and hasattr(leak_obj, 'run_ai_analysis'):
                    ai_start = time.time()
                    try:
                        leak_obj.run_ai_analysis()
                        self.metrics.ai_analyses += 1
                        self.metrics.ai_successes += 1
                        self.metrics.ai_time += time.time() - ai_start
                        
                        if hasattr(leak_obj, 'ai_analysis') and leak_obj.ai_analysis:
                            if 'cost' in leak_obj.ai_analysis:
                                self.metrics.ai_costs += leak_obj.ai_analysis['cost']
                    except Exception as e:
                        logger.error(f'AI analysis failed for {repo_url}: {e}')
                        self.metrics.ai_failures += 1
                
                logger.info(f'[{scanned_count}/{len(repos)}] Scanned {repo_url}: '
                          f'clone={clone_time:.1f}s, scan={scan_time:.1f}s')
                
                # Update resource metrics
                self._update_resource_metrics()
                
            except Exception as e:
                logger.error(f'Error scanning {repo_url}: {e}')
                logger.error(traceback.format_exc())
    
    def _process_findings(self, leak_obj, company_metrics: CompanyMetrics):
        """Process findings from a leak object"""
        if not hasattr(leak_obj, 'secrets'):
            return
        
        for scanner_name, findings in leak_obj.secrets.items():
            if isinstance(findings, dict):
                finding_count = len(findings)
                self.metrics.findings_by_scanner[scanner_name] += finding_count
                self.metrics.total_findings += finding_count
                
                # Count by type
                for finding in findings.values():
                    if isinstance(finding, dict) and 'type' in finding:
                        self.metrics.findings_by_type[finding['type']] += 1
        
        # Determine if real secret or FP
        if hasattr(leak_obj, 'res_check'):
            if leak_obj.res_check in [constants.RESULT_CODE_STILL_ACCESS, 
                                       constants.RESULT_CODE_TO_SEND]:
                self.metrics.real_secrets += 1
                company_metrics.real_secrets += 1
            elif leak_obj.res_check == constants.RESULT_CODE_LEAK_NOT_FOUND:
                self.metrics.false_positives += 1
                company_metrics.false_positives += 1
            else:
                self.metrics.needs_review += 1
    
    def _save_results(self, company_id: int):
        """Save scan results to database"""
        try:
            Connector.dump_to_DB()
            logger.info('Results saved to database')
        except Exception as e:
            logger.error(f'Failed to save results to database: {e}')
    
    def _update_resource_metrics(self):
        """Update resource usage metrics"""
        try:
            import psutil
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            self.metrics.peak_memory_mb = max(self.metrics.peak_memory_mb, memory_mb)
        except:
            pass
        
        # Check temp folder size
        try:
            temp_size = sum(
                f.stat().st_size for f in Path(constants.TEMP_FOLDER).rglob('*') if f.is_file()
            ) / 1024 / 1024
            self.metrics.disk_usage_mb = temp_size
        except:
            pass
    
    def run(self) -> BenchmarkMetrics:
        """Run the complete benchmark"""
        try:
            # Get companies to test
            companies = self.get_test_companies()
            
            if not companies:
                logger.error('No companies to test!')
                return self.metrics
            
            # Benchmark each company
            for company_id, company_name in companies:
                company_metrics = self.benchmark_company(company_id, company_name)
                logger.info(f'\nCompany {company_name} results:')
                logger.info(f'  Repos found: {company_metrics.repos_found}')
                logger.info(f'  Repos scanned: {company_metrics.repos_scanned}')
                logger.info(f'  Real secrets: {company_metrics.real_secrets}')
                logger.info(f'  False positives: {company_metrics.false_positives}')
            
            # Finalize metrics
            self.metrics.end_time = time.time()
            
            # Generate reports
            self._generate_reports()
            
            return self.metrics
            
        except Exception as e:
            logger.error(f'Benchmark failed: {e}')
            logger.error(traceback.format_exc())
            return self.metrics
    
    def _generate_reports(self):
        """Generate benchmark reports"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # JSON report
        json_path = self.output_dir / f'benchmark_{timestamp}.json'
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.metrics.to_dict(), f, indent=2, ensure_ascii=False)
        logger.info(f'JSON report saved: {json_path}')
        
        # Text summary
        summary_path = self.output_dir / f'benchmark_{timestamp}_summary.txt'
        with open(summary_path, 'w', encoding='utf-8') as f:
            self._write_summary(f)
        logger.info(f'Summary report saved: {summary_path}')
        
        # Markdown report for documentation
        md_path = self.output_dir / f'benchmark_{timestamp}_report.md'
        with open(md_path, 'w', encoding='utf-8') as f:
            self._write_markdown_report(f)
        logger.info(f'Markdown report saved: {md_path}')
    
    def _write_summary(self, f):
        """Write text summary report"""
        m = self.metrics
        
        f.write('='*80 + '\n')
        f.write('GitSearch Benchmark Summary\n')
        f.write('='*80 + '\n\n')
        
        f.write(f'Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
        f.write(f'Total Duration: {m.total_time():.2f} seconds ({m.total_time()/60:.2f} minutes)\n\n')
        
        f.write('SEARCH METRICS\n')
        f.write('-'*40 + '\n')
        f.write(f'  Dorks tested: {m.dorks_tested}\n')
        f.write(f'  API requests: {m.api_requests}\n')
        f.write(f'  API errors: {m.api_errors}\n')
        f.write(f'  Rate limit hits: {m.rate_limit_hits}\n\n')
        
        f.write('DISCOVERY METRICS\n')
        f.write('-'*40 + '\n')
        f.write(f'  Repositories found: {m.repos_found}\n')
        f.write(f'  Repositories scanned: {m.repos_scanned}\n')
        f.write(f'  Repositories too large: {m.repos_too_large}\n')
        f.write(f'  Clone failures: {m.repos_clone_failed}\n')
        f.write(f'  Scan success rate: {m.repos_scanned/max(1,m.repos_found)*100:.1f}%\n\n')
        
        f.write('DETECTION METRICS\n')
        f.write('-'*40 + '\n')
        f.write(f'  Total findings: {m.total_findings}\n')
        f.write(f'  Real secrets: {m.real_secrets}\n')
        f.write(f'  False positives: {m.false_positives}\n')
        f.write(f'  Needs review: {m.needs_review}\n')
        f.write(f'  Precision: {m.real_secrets/max(1,m.total_findings)*100:.1f}%\n\n')
        
        if m.findings_by_scanner:
            f.write('  Findings by scanner:\n')
            for scanner, count in sorted(m.findings_by_scanner.items(), key=lambda x: x[1], reverse=True):
                f.write(f'    {scanner}: {count}\n')
            f.write('\n')
        
        if m.findings_by_type:
            f.write('  Top secret types:\n')
            for secret_type, count in sorted(m.findings_by_type.items(), key=lambda x: x[1], reverse=True)[:10]:
                f.write(f'    {secret_type}: {count}\n')
            f.write('\n')
        
        if constants.AI_ANALYSIS_ENABLED:
            f.write('AI ANALYSIS METRICS\n')
            f.write('-'*40 + '\n')
            f.write(f'  Analyses performed: {m.ai_analyses}\n')
            f.write(f'  Successes: {m.ai_successes}\n')
            f.write(f'  Failures: {m.ai_failures}\n')
            f.write(f'  Total cost: ${m.ai_costs:.2f}\n')
            f.write(f'  Avg time per analysis: {m.ai_time/max(1,m.ai_analyses):.2f}s\n')
            f.write(f'  Success rate: {m.ai_successes/max(1,m.ai_analyses)*100:.1f}%\n\n')
        
        f.write('PERFORMANCE METRICS\n')
        f.write('-'*40 + '\n')
        f.write(f'  Repos per hour: {m.repos_scanned/(m.total_time()/3600):.1f}\n')
        f.write(f'  Secrets per hour: {m.real_secrets/(m.total_time()/3600):.1f}\n')
        if m.real_secrets > 0:
            f.write(f'  Cost per secret: ${m.ai_costs/m.real_secrets:.2f}\n')
        f.write('\n')
        
        f.write('RESOURCE USAGE\n')
        f.write('-'*40 + '\n')
        f.write(f'  Peak memory: {m.peak_memory_mb:.1f} MB\n')
        f.write(f'  Disk usage: {m.disk_usage_mb:.1f} MB\n\n')
        
        f.write('PER-COMPANY RESULTS\n')
        f.write('-'*40 + '\n')
        for company_name, metrics in m.company_results.items():
            f.write(f'\n{company_name}:\n')
            f.write(f'  Dorks: {metrics["dorks_count"]}\n')
            f.write(f'  Repos found: {metrics["repos_found"]}\n')
            f.write(f'  Repos scanned: {metrics["repos_scanned"]}\n')
            f.write(f'  Real secrets: {metrics["real_secrets"]}\n')
            f.write(f'  False positives: {metrics["false_positives"]}\n')
            f.write(f'  Duration: {metrics["scan_duration_seconds"]:.1f}s\n')
            f.write(f'  Repos/min: {metrics["repos_per_minute"]:.1f}\n')
    
    def _write_markdown_report(self, f):
        """Write markdown report for documentation"""
        m = self.metrics
        
        f.write('# GitSearch Benchmark Report\n\n')
        f.write(f'**Date:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n\n')
        f.write(f'**Total Duration:** {m.total_time():.2f} seconds ({m.total_time()/60:.2f} minutes)\n\n')
        
        f.write('## Executive Summary\n\n')
        f.write(f'- **Repositories Scanned:** {m.repos_scanned}\n')
        f.write(f'- **Real Secrets Found:** {m.real_secrets}\n')
        f.write(f'- **False Positive Rate:** {m.false_positives/max(1,m.total_findings)*100:.1f}%\n')
        f.write(f'- **Scanning Speed:** {m.repos_scanned/(m.total_time()/3600):.1f} repos/hour\n\n')
        
        f.write('## Detailed Metrics\n\n')
        
        f.write('### Search Performance\n\n')
        f.write('| Metric | Value |\n')
        f.write('|--------|-------|\n')
        f.write(f'| Dorks Tested | {m.dorks_tested} |\n')
        f.write(f'| API Requests | {m.api_requests} |\n')
        f.write(f'| Repositories Found | {m.repos_found} |\n')
        f.write(f'| Scan Success Rate | {m.repos_scanned/max(1,m.repos_found)*100:.1f}% |\n\n')
        
        f.write('### Detection Accuracy\n\n')
        f.write('| Metric | Value |\n')
        f.write('|--------|-------|\n')
        f.write(f'| Total Findings | {m.total_findings} |\n')
        f.write(f'| Real Secrets | {m.real_secrets} |\n')
        f.write(f'| False Positives | {m.false_positives} |\n')
        f.write(f'| Precision | {m.real_secrets/max(1,m.total_findings)*100:.1f}% |\n\n')
        
        if m.findings_by_scanner:
            f.write('### Findings by Scanner\n\n')
            f.write('| Scanner | Findings |\n')
            f.write('|---------|----------|\n')
            for scanner, count in sorted(m.findings_by_scanner.items(), key=lambda x: x[1], reverse=True):
                f.write(f'| {scanner} | {count} |\n')
            f.write('\n')
        
        if constants.AI_ANALYSIS_ENABLED:
            f.write('### AI Analysis Performance\n\n')
            f.write('| Metric | Value |\n')
            f.write('|--------|-------|\n')
            f.write(f'| Analyses Performed | {m.ai_analyses} |\n')
            f.write(f'| Success Rate | {m.ai_successes/max(1,m.ai_analyses)*100:.1f}% |\n')
            f.write(f'| Total Cost | ${m.ai_costs:.2f} |\n')
            f.write(f'| Avg Time | {m.ai_time/max(1,m.ai_analyses):.2f}s |\n\n')
        
        f.write('### Per-Company Results\n\n')
        f.write('| Company | Repos Scanned | Real Secrets | Duration (s) |\n')
        f.write('|---------|---------------|--------------|-------------|\n')
        for company_name, metrics in m.company_results.items():
            f.write(f'| {company_name} | {metrics["repos_scanned"]} | '
                   f'{metrics["real_secrets"]} | {metrics["scan_duration_seconds"]:.1f} |\n')


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='GitSearch Benchmark and Metrics Collection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--companies', type=str, 
                       help='Comma-separated company IDs to test (default: all)')
    parser.add_argument('--max-repos', type=int, default=100,
                       help='Maximum repositories to scan per company (default: 100)')
    parser.add_argument('--max-dorks', type=int, default=50,
                       help='Maximum dorks to test per company (default: 50)')
    parser.add_argument('--skip-ai', action='store_true',
                       help='Skip AI analysis to speed up testing')
    parser.add_argument('--output', type=str, default='./benchmark_results',
                       help='Output directory for results (default: ./benchmark_results/)')
    parser.add_argument('--db-host', type=str,
                       help='Database host (default: from config.json)')
    parser.add_argument('--db-token', type=str,
                       help='Database token (default: from config.json)')
    
    args = parser.parse_args()
    
    # Build config
    config = {
        'companies': args.companies,
        'max_repos': args.max_repos,
        'max_dorks': args.max_dorks,
        'skip_ai': args.skip_ai,
        'output_dir': args.output,
        'db_host': args.db_host,
        'db_token': args.db_token,
    }
    
    # Run benchmark
    benchmark = GitSearchBenchmark(config)
    metrics = benchmark.run()
    
    # Print summary
    print('\n' + '='*80)
    print('BENCHMARK COMPLETE')
    print('='*80)
    print(f'Total time: {metrics.total_time():.2f}s ({metrics.total_time()/60:.2f} min)')
    print(f'Repositories scanned: {metrics.repos_scanned}')
    print(f'Real secrets found: {metrics.real_secrets}')
    print(f'False positives: {metrics.false_positives}')
    print(f'Precision: {metrics.real_secrets/max(1,metrics.total_findings)*100:.1f}%')
    print(f'\nResults saved to: {benchmark.output_dir}')
    print('='*80)


if __name__ == '__main__':
    main()
