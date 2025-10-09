# Руководство по разработке и деплою

## Содержание

- [Настройка окружения разработки](#настройка-окружения-разработки)
- [Стандарты кодирования](#стандарты-кодирования)
- [Git workflow](#git-workflow)
- [Тестирование](#тестирование)
- [Деплой](#деплой)
- [CI/CD](#cicd)
- [Troubleshooting](#troubleshooting)

## Настройка окружения разработки

### Требования

- Python 3.8+
- Git
- Docker и Docker Compose
- MySQL/MariaDB (для локальной разработки)
- Visual Studio Code (рекомендуется) или другая IDE

### Шаг 1: Клонирование репозитория

```bash
git clone https://github.com/Faton6/GitSearch.git
cd GitSearch
```

### Шаг 2: Создание виртуального окружения

```bash
# Linux/MacOS
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

### Шаг 3: Установка зависимостей

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Если есть dev зависимости
```

### Шаг 4: Настройка конфигурации

Создайте `.env` файл:

```env
# GitHub токены для разработки
GITHUB_TOKEN_1=ghp_your_dev_token
GITHUB_CLONE_TOKEN=ghp_your_clone_token

# Локальная БД
URL_DB=localhost
TOKEN_DB=dev_token

# AI провайдеры (опционально)
OPENAI_API_KEY=sk-test-key
```

Создайте `config.json`:

```json
{
    "target_list": {"TestCompany": ["test"]},
    "leak_check_list": ["password"],
    "url_DB": "localhost",
    "token_DB": "-",
    "token_list": ["-"],
    "create_report": "no"
}
```

### Шаг 5: Настройка IDE (VS Code)

Создайте `.vscode/settings.json`:

```json
{
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": true,
    "python.linting.flake8Enabled": true,
    "python.formatting.provider": "black",
    "python.testing.pytestEnabled": true,
    "python.testing.pytestArgs": [
        "test"
    ],
    "editor.formatOnSave": true,
    "editor.rulers": [88, 120],
    "[python]": {
        "editor.tabSize": 4
    }
}
```

Создайте `.vscode/launch.json`:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: GitSearch",
            "type": "python",
            "request": "launch",
            "program": "${workspaceFolder}/gitsearch.py",
            "console": "integratedTerminal",
            "env": {
                "PYTHONPATH": "${workspaceFolder}"
            }
        },
        {
            "name": "Python: Current File",
            "type": "python",
            "request": "launch",
            "program": "${file}",
            "console": "integratedTerminal"
        },
        {
            "name": "Python: Pytest",
            "type": "python",
            "request": "launch",
            "module": "pytest",
            "args": ["-v"],
            "console": "integratedTerminal"
        }
    ]
}
```

### Шаг 6: Локальная БД (опционально)

Запустите MySQL/MariaDB через Docker:

```bash
docker run --name gitsearch-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=GitSearch \
  -e MYSQL_USER=gitsearch \
  -e MYSQL_PASSWORD=gitsearch_pass \
  -p 3306:3306 \
  -d mariadb:latest
```

Импортируйте схему:

```bash
mysql -h localhost -u gitsearch -p GitSearch < Gitsearch_DB.sql
```

## Стандарты кодирования

### PEP 8 и Black

Следуйте [PEP 8](https://pep8.org/) с использованием Black formatter:

```bash
# Форматирование кода
black src/ gitsearch.py

# Проверка линтером
flake8 src/ gitsearch.py

# Pylint
pylint src/ gitsearch.py
```

### Naming Conventions

```python
# Классы: PascalCase
class LeakAnalyzer:
    pass

# Функции и методы: snake_case
def analyze_leak_data():
    pass

# Константы: UPPER_SNAKE_CASE
MAX_TIMEOUT = 300

# Приватные методы: _leading_underscore
def _internal_method():
    pass

# Переменные: snake_case
leak_count = 0
```

### Type Hints

Всегда используйте type hints:

```python
from typing import Dict, List, Optional, Tuple, Union

def process_leak(
    leak_data: Dict[str, Any],
    company_id: int,
    strict: bool = False
) -> Tuple[bool, Optional[str]]:
    """
    Process leak data.
    
    Args:
        leak_data: Dictionary containing leak information
        company_id: Target company identifier
        strict: Enable strict validation
        
    Returns:
        Tuple of (success status, error message if any)
    """
    pass
```

### Docstrings

Используйте Google Style docstrings:

```python
def complex_function(param1: str, param2: int) -> Dict[str, Any]:
    """
    Brief description of function.
    
    Longer description with more details about what the function does,
    edge cases, and any important notes.
    
    Args:
        param1: Description of param1
        param2: Description of param2
        
    Returns:
        Dictionary containing:
            - key1: Description
            - key2: Description
            
    Raises:
        ValueError: When param2 is negative
        RuntimeError: When external API fails
        
    Example:
        >>> result = complex_function("test", 42)
        >>> print(result['key1'])
        'value1'
    """
    pass
```

### Imports

Организуйте imports в следующем порядке:

```python
# 1. Standard library imports
import os
import sys
from typing import Dict, List

# 2. Third-party imports
import requests
from bs4 import BeautifulSoup

# 3. Local application imports
from src import constants
from src.logger import logger
from src.LeakObj import LeakObj
```

### Комментарии

```python
# Good: Объясняет ПОЧЕМУ, не ЧТО
# We use exponential backoff because GitHub API has rate limits
retry_delay = 2 ** attempt

# Bad: Повторяет то, что очевидно из кода
# Increment counter
counter += 1

# Good: TODO с контекстом
# TODO(username): Refactor this when Python 3.10+ match/case is available

# Good: FIXME с объяснением
# FIXME: This breaks for repos with >10k commits. Need pagination
```

### Error Handling

```python
# Good: Специфичные исключения
try:
    result = api_call()
except requests.Timeout:
    logger.warning("API timeout, will retry")
    return None
except requests.HTTPError as e:
    logger.error(f"HTTP error: {e}")
    raise
except Exception as e:
    logger.critical(f"Unexpected error: {e}")
    # Graceful degradation
    return fallback_value()

# Bad: Bare except
try:
    dangerous_operation()
except:  # Never do this!
    pass
```

### Logging

```python
from src.logger import logger

# Levels:
logger.debug("Detailed diagnostic info")      # DEBUG
logger.info("General information")            # INFO
logger.warning("Warning message")             # WARNING
logger.error("Error occurred")                # ERROR
logger.critical("Critical failure")           # CRITICAL

# Good: Context в логах
logger.info(f"Processing leak {leak_id} for company {company_name}")

# Good: Structured logging
logger.error(
    "Failed to clone repository",
    extra={
        'repo_url': url,
        'error_code': error.code,
        'attempt': retry_count
    }
)
```

## Git Workflow

### Branching Strategy

Используем Git Flow:

```
master (production)
  └── develop (integration)
        ├── feature/new-feature
        ├── bugfix/fix-something
        └── hotfix/critical-fix
```

### Feature Development

```bash
# 1. Создать feature branch от develop
git checkout develop
git pull origin develop
git checkout -b feature/my-new-feature

# 2. Разработка с частыми коммитами
git add .
git commit -m "feat: add new scanning algorithm"

# 3. Push в remote
git push origin feature/my-new-feature

# 4. Создать Pull Request в develop
```

### Commit Messages

Следуйте [Conventional Commits](https://www.conventionalcommits.org/):

```bash
# Format: <type>(<scope>): <subject>

# Types:
feat:     # New feature
fix:      # Bug fix
docs:     # Documentation
style:    # Code style (formatting, no logic change)
refactor: # Code refactoring
test:     # Adding tests
chore:    # Maintenance tasks

# Examples:
git commit -m "feat(scanner): add GraphQL support for GitHub API"
git commit -m "fix(ai): handle timeout in OpenAI requests"
git commit -m "docs: update API documentation"
git commit -m "refactor(connector): simplify database encoding logic"
git commit -m "test: add tests for rate limiter"
git commit -m "chore: update dependencies"
```

### Code Review

Checklist для reviewer:

- [ ] Код следует стандартам проекта
- [ ] Добавлены/обновлены тесты
- [ ] Обновлена документация
- [ ] Нет явных багов или проблем безопасности
- [ ] Производительность приемлема
- [ ] Commit messages информативны

## Тестирование

### Структура тестов

```
test/
├── unit/              # Unit tests
├── integration/       # Integration tests
├── fixtures/          # Test data
└── conftest.py       # Pytest configuration
```

### Запуск тестов

```bash
# Все тесты
pytest

# С покрытием
pytest --cov=src --cov-report=html

# Конкретный файл
pytest test/test_ai_final.py

# Конкретный тест
pytest test/test_ai_final.py::test_company_relevance

# С verbose output
pytest -v

# Остановиться на первой ошибке
pytest -x
```

### Написание тестов

```python
import pytest
from src.LeakObj import LeakObj
from src import constants

class TestLeakObj:
    """Tests for LeakObj class"""
    
    @pytest.fixture
    def sample_leak(self):
        """Fixture providing a sample leak object"""
        return LeakObj(
            obj_type='Repo',
            url='https://github.com/test/repo',
            responce={'repository': {...}},
            dork='test password',
            company_id=1
        )
    
    def test_leak_creation(self, sample_leak):
        """Test that leak object is created correctly"""
        assert sample_leak.obj_type == 'Repo'
        assert 'github.com' in sample_leak.url
        assert sample_leak.company_id == 1
    
    def test_level_calculation(self, sample_leak):
        """Test leak level calculation"""
        sample_leak.lvl = 5
        level = sample_leak.level()
        assert isinstance(level, int)
        assert 0 <= level <= 20
    
    @pytest.mark.asyncio
    async def test_ai_analysis(self, sample_leak):
        """Test AI analysis execution"""
        if not constants.AI_ANALYSIS_ENABLED:
            pytest.skip("AI analysis not enabled")
        
        await sample_leak.run_ai_analysis()
        assert sample_leak.ai_analysis is not None
        assert 'company_relevance' in sample_leak.ai_analysis
```

### Mocking

```python
from unittest.mock import Mock, patch, MagicMock

def test_github_api_call():
    """Test GitHub API call with mock"""
    with patch('requests.get') as mock_get:
        # Setup mock
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': 'test'}
        mock_get.return_value = mock_response
        
        # Test
        from src.api_client import make_request
        result = make_request('https://api.github.com/test')
        
        # Assertions
        assert result['data'] == 'test'
        mock_get.assert_called_once()
```

### Integration Tests

```python
@pytest.mark.integration
def test_full_scan_workflow():
    """Test complete scanning workflow"""
    # Setup
    config = load_test_config()
    
    # Execute
    from src.searcher.scanner import Scanner
    scanner = Scanner('TestCompany')
    results = scanner.gitscan()
    
    # Verify
    assert len(results) > 0
    assert all(hasattr(r, 'repo_url') for r in results)
```

## Деплой

### Docker Build

```bash
# Build image
docker build -t gitsearch:latest .

# Build with tag
docker build -t gitsearch:v1.0.0 .

# Build multi-platform
docker buildx build --platform linux/amd64,linux/arm64 -t gitsearch:latest .
```

### Docker Compose

#### Разработка

```yaml
# docker-compose.yml
version: '3.8'

services:
  gitsearch:
    build: .
    volumes:
      - ./src:/app/src
      - ./logs:/app/logs
      - ./reports:/app/reports
    environment:
      - ENV=development
    env_file:
      - .env
    depends_on:
      - db
  
  db:
    image: mariadb:latest
    environment:
      MYSQL_ROOT_PASSWORD: rootpass
      MYSQL_DATABASE: GitSearch
    volumes:
      - db_data:/var/lib/mysql
      - ./Gitsearch_DB.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "3306:3306"

volumes:
  db_data:
```

Запуск:

```bash
docker-compose up -d
docker-compose logs -f gitsearch
docker-compose down
```

#### Production

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  gitsearch:
    image: gitsearch:latest
    restart: always
    volumes:
      - /opt/gitsearch/logs:/app/logs
      - /opt/gitsearch/reports:/app/reports
    environment:
      - ENV=production
    env_file:
      - /opt/gitsearch/.env
    networks:
      - gitsearch_network
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G

networks:
  gitsearch_network:
    driver: bridge
```

Запуск:

```bash
docker-compose -f docker-compose.prod.yml up -d
```

### Kubernetes (опционально)

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gitsearch
spec:
  replicas: 2
  selector:
    matchLabels:
      app: gitsearch
  template:
    metadata:
      labels:
        app: gitsearch
    spec:
      containers:
      - name: gitsearch
        image: gitsearch:latest
        resources:
          requests:
            memory: "2Gi"
            cpu: "1"
          limits:
            memory: "4Gi"
            cpu: "2"
        envFrom:
        - secretRef:
            name: gitsearch-secrets
        volumeMounts:
        - name: logs
          mountPath: /app/logs
        - name: reports
          mountPath: /app/reports
      volumes:
      - name: logs
        persistentVolumeClaim:
          claimName: gitsearch-logs
      - name: reports
        persistentVolumeClaim:
          claimName: gitsearch-reports
```

### Мониторинг

#### Healthcheck

Добавьте healthcheck endpoint:

```python
# src/health.py
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'timestamp': time.time()
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

#### Prometheus Metrics

```python
# src/metrics.py
from prometheus_client import Counter, Histogram, Gauge

# Metrics
scans_total = Counter('gitsearch_scans_total', 'Total scans')
scan_duration = Histogram('gitsearch_scan_duration_seconds', 'Scan duration')
active_scans = Gauge('gitsearch_active_scans', 'Active scans')
leaks_found = Counter('gitsearch_leaks_found_total', 'Leaks found')

def track_scan():
    scans_total.inc()
    with scan_duration.time():
        # Scan logic
        pass
```

## CI/CD

### GitHub Actions

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [ develop, master ]
  pull_request:
    branches: [ develop ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.9
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install pytest pytest-cov
    
    - name: Run tests
      run: |
        pytest --cov=src --cov-report=xml
    
    - name: Upload coverage
      uses: codecov/codecov-action@v2
      with:
        files: ./coverage.xml
  
  lint:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.9
    
    - name: Lint with flake8
      run: |
        pip install flake8
        flake8 src/ --count --select=E9,F63,F7,F82 --show-source --statistics
    
    - name: Check with black
      run: |
        pip install black
        black --check src/
  
  build:
    needs: [test, lint]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/master'
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Build Docker image
      run: |
        docker build -t gitsearch:${{ github.sha }} .
        docker tag gitsearch:${{ github.sha }} gitsearch:latest
    
    - name: Push to registry
      run: |
        echo ${{ secrets.DOCKER_PASSWORD }} | docker login -u ${{ secrets.DOCKER_USERNAME }} --password-stdin
        docker push gitsearch:latest
```

### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - test
  - build
  - deploy

test:
  stage: test
  image: python:3.9
  script:
    - pip install -r requirements.txt
    - pytest --cov=src
  coverage: '/TOTAL.*\s+(\d+%)$/'

build:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  only:
    - master

deploy:
  stage: deploy
  script:
    - ssh user@server "cd /opt/gitsearch && docker-compose pull && docker-compose up -d"
  only:
    - master
  when: manual
```

## Troubleshooting

### Проблема: Rate Limit Exceeded

**Симптомы**: 
```
ERROR: GitHub API rate limit exceeded
```

**Решение**:
1. Добавьте больше токенов в `.env`
2. Увеличьте `GITHUB_REQUEST_COOLDOWN` в `constants.py`
3. Проверьте статус: `limiter.print_status()`

### Проблема: Memory Leak

**Симптомы**:
```
MemoryError: Unable to allocate memory
```

**Решение**:
1. Уменьшите `MAX_SEARCH_BEFORE_DUMP`
2. Очистите temp folder: `utils.check_temp_folder_size()`
3. Увеличьте Docker memory limit

### Проблема: Database Connection Failed

**Симптомы**:
```
ERROR: Could not connect to database
```

**Решение**:
1. Проверьте credentials в `.env`
2. Убедитесь что БД доступна: `ping $URL_DB`
3. Проверьте firewall rules
4. Проверьте логи БД

### Проблема: AI Provider Timeout

**Симптомы**:
```
WARNING: AI analysis timeout
```

**Решение**:
1. Увеличьте `AI_ANALYSIS_TIMEOUT` в `constants.py`
2. Проверьте API key: `echo $OPENAI_API_KEY`
3. Попробуйте другого провайдера
4. Отключите AI: `AI_ANALYSIS_ENABLED = False`

### Отладка

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
python gitsearch.py

# Trace specific component
export PYTHONVERBOSE=1
python -m trace --trace gitsearch.py

# Memory profiling
python -m memory_profiler gitsearch.py

# CPU profiling
python -m cProfile -o profile.stats gitsearch.py
python -m pstats profile.stats
```

## Performance Tips

1. **Используйте кэш**: Включите API cache для частых запросов
2. **Batch operations**: Группируйте DB операции
3. **Async где возможно**: Используйте asyncio для I/O операций
4. **Ограничьте глубину**: Настройте `REPO_MAX_SIZE` и timeouts
5. **Мониторьте память**: Регулярно вызывайте `trace_monitor()`

## Контрибьюция

Перед созданием PR убедитесь:

- [ ] Код отформатирован (black, flake8)
- [ ] Тесты написаны и проходят
- [ ] Документация обновлена
- [ ] CHANGELOG.md обновлен
- [ ] Commit messages соответствуют стандарту
- [ ] PR description информативен

## Полезные ссылки

- [GitHub API Documentation](https://docs.github.com/en/rest)
- [Python Best Practices](https://docs.python-guide.org/)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [pytest Documentation](https://docs.pytest.org/)
