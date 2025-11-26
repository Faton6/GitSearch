# -*- coding: utf-8 -*-
"""
Health Check HTTP Server for GitSearch

Provides HTTP endpoints for monitoring:
- /health - Basic health check (liveness probe)
- /ready - Readiness check (readiness probe) 
- /metrics - Prometheus metrics
- /status - Detailed status JSON

Can run standalone or as a background thread.
"""

import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, Optional, Callable
from datetime import datetime
import socket

from src.logger import logger


class HealthStatus:
    """Health status constants."""
    HEALTHY = 'healthy'
    DEGRADED = 'degraded'
    UNHEALTHY = 'unhealthy'


class HealthCheckHandler(BaseHTTPRequestHandler):
    """HTTP request handler for health check endpoints."""
    
    # Class-level reference to health checker
    health_checker: Optional['HealthChecker'] = None
    
    def log_message(self, format, *args):
        """Override to use our logger instead of stderr."""
        logger.debug(f"HealthCheck: {format % args}")
    
    def _send_response(self, status_code: int, content_type: str, body: str):
        """Send HTTP response."""
        self.send_response(status_code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', len(body.encode()))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body.encode())
    
    def _send_json(self, data: Dict, status_code: int = 200):
        """Send JSON response."""
        body = json.dumps(data, indent=2, default=str)
        self._send_response(status_code, 'application/json', body)
    
    def do_GET(self):
        """Handle GET requests."""
        if self.health_checker is None:
            self._send_json({'error': 'Health checker not initialized'}, 500)
            return
        
        path = self.path.split('?')[0]  # Remove query string
        
        if path == '/health' or path == '/healthz':
            self._handle_health()
        elif path == '/ready' or path == '/readyz':
            self._handle_ready()
        elif path == '/metrics':
            self._handle_metrics()
        elif path == '/status':
            self._handle_status()
        elif path == '/':
            self._handle_index()
        else:
            self._send_json({'error': 'Not found'}, 404)
    
    def _handle_health(self):
        """Handle /health endpoint (liveness probe)."""
        health = self.health_checker.check_health()
        status_code = 200 if health['status'] == HealthStatus.HEALTHY else 503
        self._send_json(health, status_code)
    
    def _handle_ready(self):
        """Handle /ready endpoint (readiness probe)."""
        ready = self.health_checker.check_readiness()
        status_code = 200 if ready['ready'] else 503
        self._send_json(ready, status_code)
    
    def _handle_metrics(self):
        """Handle /metrics endpoint (Prometheus format)."""
        try:
            from src.metrics import get_metrics_collector
            metrics = get_metrics_collector()
            prometheus_output = metrics.to_prometheus()
            self._send_response(200, 'text/plain; charset=utf-8', prometheus_output)
        except ImportError:
            self._send_response(200, 'text/plain', '# Metrics module not available\n')
    
    def _handle_status(self):
        """Handle /status endpoint (detailed JSON status)."""
        status = self.health_checker.get_detailed_status()
        self._send_json(status)
    
    def _handle_index(self):
        """Handle / endpoint (index page)."""
        html = """<!DOCTYPE html>
<html>
<head><title>GitSearch Health</title></head>
<body>
<h1>GitSearch Health Check</h1>
<ul>
<li><a href="/health">/health</a> - Liveness probe</li>
<li><a href="/ready">/ready</a> - Readiness probe</li>
<li><a href="/metrics">/metrics</a> - Prometheus metrics</li>
<li><a href="/status">/status</a> - Detailed status</li>
</ul>
</body>
</html>"""
        self._send_response(200, 'text/html', html)


class HealthChecker:
    """
    Health checker for GitSearch service.
    
    Monitors:
    - Database connectivity
    - GitHub API availability
    - AI service availability
    - Disk space
    - Memory usage
    
    Usage:
        checker = HealthChecker()
        checker.start_server(port=8080)
        
        # Or check programmatically
        health = checker.check_health()
        print(health['status'])
    """
    
    def __init__(self):
        self._checks: Dict[str, Callable[[], tuple]] = {}
        self._server: Optional[HTTPServer] = None
        self._server_thread: Optional[threading.Thread] = None
        self._start_time = time.time()
        
        # Register default checks
        self._register_default_checks()
    
    def _register_default_checks(self):
        """Register default health checks."""
        self.register_check('database', self._check_database)
        self.register_check('github_api', self._check_github_api)
        self.register_check('disk_space', self._check_disk_space)
        self.register_check('ai_service', self._check_ai_service)
    
    def register_check(self, name: str, check_fn: Callable[[], tuple]):
        """
        Register a health check function.
        
        Args:
            name: Check name
            check_fn: Function returning (healthy: bool, message: str)
        """
        self._checks[name] = check_fn
    
    def _check_database(self) -> tuple:
        """Check database connectivity."""
        try:
            from src.api_client import GitSearchAPIClient
            client = GitSearchAPIClient()
            conn = client._get_connection()
            if conn:
                conn.ping()
                return True, 'Connected'
            return False, 'Connection failed'
        except Exception as e:
            return False, str(e)
    
    def _check_github_api(self) -> tuple:
        """Check GitHub API availability."""
        try:
            from src.github_rate_limiter import get_rate_limiter, is_initialized
            if not is_initialized():
                return True, 'Rate limiter not initialized (OK for startup)'
            
            limiter = get_rate_limiter()
            status = limiter.get_all_tokens_status()
            
            if not status:
                return False, 'No tokens configured'
            
            healthy_tokens = sum(1 for s in status if not s.get('is_blocked', False))
            total_tokens = len(status)
            
            if healthy_tokens == 0:
                return False, f'All {total_tokens} tokens blocked'
            elif healthy_tokens < total_tokens:
                return True, f'{healthy_tokens}/{total_tokens} tokens available'
            else:
                return True, f'All {total_tokens} tokens available'
        except Exception as e:
            return True, f'Check skipped: {e}'
    
    def _check_disk_space(self) -> tuple:
        """Check disk space for temp folder."""
        try:
            import shutil
            from src import constants
            
            total, used, free = shutil.disk_usage(constants.TEMP_FOLDER)
            free_gb = free / (1024 ** 3)
            free_pct = (free / total) * 100
            
            if free_pct < 5 or free_gb < 1:
                return False, f'Low disk space: {free_gb:.1f}GB ({free_pct:.1f}%) free'
            elif free_pct < 15:
                return True, f'Warning: {free_gb:.1f}GB ({free_pct:.1f}%) free'
            else:
                return True, f'{free_gb:.1f}GB ({free_pct:.1f}%) free'
        except Exception as e:
            return True, f'Check skipped: {e}'
    
    def _check_ai_service(self) -> tuple:
        """Check AI service availability."""
        try:
            from src import constants
            import os
            
            if not constants.AI_ANALYSIS_ENABLED:
                return True, 'AI analysis disabled'
            
            # Check if any AI API key is configured
            keys = ['TOGETHER_API_KEY', 'OPENROUTER_API_KEY', 'FIREWORKS_API_KEY']
            configured_keys = [k for k in keys if os.environ.get(k)]
            
            if not configured_keys:
                return True, 'No AI keys configured (AI will be skipped)'
            
            return True, f'{len(configured_keys)} AI provider(s) configured'
        except Exception as e:
            return True, f'Check skipped: {e}'
    
    def check_health(self) -> Dict[str, Any]:
        """
        Perform health check (liveness probe).
        
        Returns:
            Dict with status and check results
        """
        results = {}
        overall_healthy = True
        
        for name, check_fn in self._checks.items():
            try:
                healthy, message = check_fn()
                results[name] = {
                    'healthy': healthy,
                    'message': message
                }
                if not healthy:
                    overall_healthy = False
            except Exception as e:
                results[name] = {
                    'healthy': False,
                    'message': f'Check failed: {e}'
                }
                overall_healthy = False
        
        return {
            'status': HealthStatus.HEALTHY if overall_healthy else HealthStatus.UNHEALTHY,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'checks': results
        }
    
    def check_readiness(self) -> Dict[str, Any]:
        """
        Check if service is ready to accept requests (readiness probe).
        
        Returns:
            Dict with ready status
        """
        # For readiness, we mainly check database
        try:
            db_healthy, db_message = self._check_database()
            github_healthy, github_message = self._check_github_api()
            
            ready = db_healthy  # Database is required
            
            return {
                'ready': ready,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'checks': {
                    'database': {'ready': db_healthy, 'message': db_message},
                    'github_api': {'ready': github_healthy, 'message': github_message}
                }
            }
        except Exception as e:
            return {
                'ready': False,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'error': str(e)
            }
    
    def get_detailed_status(self) -> Dict[str, Any]:
        """
        Get detailed service status.
        
        Returns:
            Comprehensive status dictionary
        """
        health = self.check_health()
        
        status = {
            'service': 'gitsearch',
            'version': self._get_version(),
            'uptime_seconds': round(time.time() - self._start_time, 1),
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'health': health,
        }
        
        # Add metrics summary if available
        try:
            from src.metrics import get_metrics_collector
            metrics = get_metrics_collector()
            all_metrics = metrics.get_all_metrics()
            status['metrics'] = {
                'counters': all_metrics.get('counters', {}),
                'gauges': all_metrics.get('gauges', {}),
            }
        except ImportError:
            pass
        
        # Add rate limiter status if available
        try:
            from src.github_rate_limiter import get_rate_limiter, is_initialized
            if is_initialized():
                limiter = get_rate_limiter()
                tokens_status = limiter.get_all_tokens_status()
                status['rate_limits'] = {
                    'tokens_count': len(tokens_status),
                    'tokens_blocked': sum(1 for t in tokens_status if t.get('is_blocked', False)),
                    'total_remaining': sum(t.get('remaining', 0) for t in tokens_status),
                }
        except Exception:
            pass
        
        # Add temp folder status if available
        try:
            from src.temp_manager import get_temp_manager
            manager = get_temp_manager()
            status['temp_folder'] = manager.get_stats()
        except Exception:
            pass
        
        return status
    
    def _get_version(self) -> str:
        """Get service version."""
        try:
            from src import constants
            return constants.__VERSION__
        except:
            return 'unknown'
    
    def start_server(self, host: str = '0.0.0.0', port: int = 8080, background: bool = True):
        """
        Start health check HTTP server.
        
        Args:
            host: Bind address
            port: Port number
            background: Run in background thread
        """
        # Set handler's reference to this checker
        HealthCheckHandler.health_checker = self
        
        try:
            self._server = HTTPServer((host, port), HealthCheckHandler)
            logger.info(f"Health check server starting on http://{host}:{port}")
            
            if background:
                self._server_thread = threading.Thread(
                    target=self._server.serve_forever,
                    daemon=True,
                    name='HealthCheckServer'
                )
                self._server_thread.start()
                logger.info(f"Health check server running in background on port {port}")
            else:
                logger.info(f"Health check server running on port {port}")
                self._server.serve_forever()
                
        except socket.error as e:
            logger.warning(f"Could not start health check server on port {port}: {e}")
    
    def stop_server(self):
        """Stop health check server."""
        if self._server:
            self._server.shutdown()
            self._server = None
            logger.info("Health check server stopped")


# Global instance
_health_checker: Optional[HealthChecker] = None


def get_health_checker() -> HealthChecker:
    """Get or create global HealthChecker instance."""
    global _health_checker
    if _health_checker is None:
        _health_checker = HealthChecker()
    return _health_checker


def start_health_server(port: int = 8080):
    """Convenience function to start health server."""
    checker = get_health_checker()
    checker.start_server(port=port, background=True)
    return checker


__all__ = [
    'HealthChecker',
    'HealthStatus',
    'get_health_checker',
    'start_health_server',
]
