# Архитектура GitSearch

## Обзор

GitSearch построен на модульной архитектуре с четким разделением ответственности между компонентами. Система следует принципам SOLID и использует объектно-ориентированный подход для максимальной гибкости и расширяемости.

## Архитектурная диаграмма

```
┌─────────────────────────────────────────────────────────────────┐
│                          gitsearch.py                            │
│                     (Main Entry Point)                           │
└────────────────────────────┬────────────────────────────────────┘
                             │
                ┌────────────┴────────────┐
                │                         │
┌───────────────▼──────────────┐  ┌──────▼──────────────────────┐
│      Scanner Module           │  │   Configuration Module       │
│  ┌─────────────────────┐     │  │  ┌────────────────────┐     │
│  │   scanner.py        │     │  │  │  constants.py      │     │
│  │   GitStats.py       │     │  │  │  config.json       │     │
│  │   glist_scan.py     │     │  │  │  .env              │     │
│  └─────────────────────┘     │  │  └────────────────────┘     │
└───────────────┬──────────────┘  └─────────────┬────────────────┘
                │                               │
                │         ┌─────────────────────┘
                │         │
┌───────────────▼─────────▼──────────────────────────────────────┐
│                     Core Processing Layer                       │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │  LeakObj.py  │  │  AIObj.py    │  │  LeakAnalyzer.py   │  │
│  │  (Base Class)│  │  (AI Engine) │  │  (Analyzer)        │  │
│  └──────────────┘  └──────────────┘  └────────────────────┘  │
└────────────────────────────┬────────────────────────────────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
┌────────▼────────┐  ┌───────▼────────┐  ┌──────▼───────────┐
│  Database Layer │  │  Cache Layer   │  │  Report Layer    │
│  ┌───────────┐  │  │  ┌──────────┐  │  │  ┌────────────┐  │
│  │Connector  │  │  │  │api_cache │  │  │  │report_gen  │  │
│  │api_client │  │  │  └──────────┘  │  │  │report_tmpl │  │
│  └───────────┘  │  └────────────────┘  │  └────────────┘  │
└─────────────────┘                      └──────────────────┘
         │
         │
┌────────▼─────────────────────────────────────────────────────┐
│                   External Services                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  GitHub API  │  │  MySQL/DB    │  │  AI Providers    │  │
│  │  (REST/GQL)  │  │              │  │  (OpenAI, etc)   │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└───────────────────────────────────────────────────────────────┘
```

## Ключевые компоненты

### 1. Entry Point Layer (gitsearch.py)

**Назначение**: Координация всего процесса сканирования.

**Ответственности**:
- Инициализация системы
- Загрузка конфигурации
- Управление жизненным циклом приложения
- Координация этапов сканирования
- Обработка сигналов и graceful shutdown

**Поток выполнения**:
```python
1. Инициализация rate limiter
2. Загрузка конфигурации (config.json/.env)
3. Инициализация БД подключения
4. Запуск тестов (опционально)
5. Генерация отчета (если настроено) или сканирование:
   a. List scan (deepscan.list_search)
   b. Gist scan (GlistScan.run)
   c. GitHub scan (Scanner.gitscan)
   d. Deep scan (DeepScanManager.run)
   e. Re-scan (DeepScanManager.run mode=1)
6. Сохранение результатов
7. Генерация итоговых отчетов
```

### 2. Scanner Module

#### scanner.py - Основной сканер GitHub

**Класс**: `Scanner`

**Назначение**: Поиск потенциальных утечек в GitHub репозиториях, коммитах и коде.

**Методы**:
- `gitscan()`: Главный метод сканирования
- `_search_repos()`: Поиск по репозиториям
- `_search_code()`: Поиск в коде
- `_search_commits()`: Поиск в коммитах

**Алгоритм работы**:
```python
for each dork in company_dorks:
    for search_type in ['repositories', 'code', 'commits']:
        rate_limiter.wait_if_needed()
        results = github_search(dork, search_type)
        for result in results:
            leak_obj = create_leak_object(result)
            if not in_exclude_list(leak_obj):
                RESULT_MASS.add(leak_obj)
```

#### GitStats.py - Сбор статистики репозиториев

**Класс**: `GitParserStats`

**Назначение**: Получение детальной информации о репозиториях.

**Источники данных**:
- GitHub REST API
- GitHub GraphQL API (приоритет)
- Web scraping (fallback)

**Собираемые метрики**:
- Размер репозитория
- Количество форков, звезд, issues
- Контрибьюторы и их вклад
- Коммитеры (имена, email, компании)
- Языки программирования
- Темы и описание

**Стратегия fallback**:
```python
try:
    stats = fetch_via_graphql()  # Самый эффективный
except:
    try:
        stats = fetch_via_rest_api()  # Стандартный путь
    except:
        stats = scrape_from_web()  # Последний вариант
```

#### glist_scan.py - Сканирование GitHub Gist

**Класс**: `GlistScan`

**Назначение**: Поиск утечек в публичных Gist.

**Особенности**:
- Отдельный API endpoint
- Специфичная обработка результатов
- Фильтрация по дате обновления

### 3. Core Processing Layer

#### LeakObj.py - Базовый класс утечек

**Класс**: `LeakObj` (Abstract Base Class)

**Наследники**:
- `RepoObj` - Утечки в репозиториях
- `CodeObj` - Утечки в коде
- `CommitObj` - Утечки в коммитах
- `GlistObj` - Утечки в Gist

**Ключевые атрибуты**:
```python
class LeakObj(ABC):
    url: str                    # URL источника
    obj_type: str              # Тип объекта
    repo_url: str              # URL репозитория
    dork: str                  # Поисковый запрос
    company_id: int            # ID компании
    secrets: dict              # Найденные секреты
    ai_analysis: dict          # Результаты AI анализа
    ai_confidence: float       # Уверенность AI (0-1)
    lvl: int                   # Уровень критичности
    res_check: int             # Финальный статус
    stats: GitParserStats      # Статистика репозитория
```

**Методы**:
- `_create_ai_obj()`: Создание AI объекта
- `run_ai_analysis()`: Запуск AI анализа
- `level()`: Расчет уровня критичности
- `write_obj()`: Подготовка данных для БД
- `get_stats()`: Получение статистики для БД

**Жизненный цикл объекта**:
```python
1. Создание: LeakObj(obj_type, url, response, dork, company_id)
2. Инициализация статистики: GitParserStats(repo_url)
3. Первичная проверка: _check_status()
4. AI анализ (опционально): run_ai_analysis()
5. Расчет уровня критичности: level()
6. Подготовка к сохранению: write_obj()
7. Сохранение в БД: Connector.dump_to_DB()
```

#### AIObj.py - AI анализ утечек

**Класс**: `AIObj`

**Назначение**: Интеллектуальный анализ утечек с использованием LLM.

**Поддерживаемые провайдеры**:
- OpenAI (GPT-4, GPT-3.5)
- Anthropic (Claude)
- Local models (опционально)

**Типы анализа**:

1. **Company Relevance Analysis**
   - Определяет связь утечки с целевой компанией
   - Анализирует контекст, имена файлов, email домены
   - Возвращает уверенность (0-1)

2. **True Positive Analysis**
   - Оценивает вероятность реальной утечки
   - Анализирует контекст секретов
   - Определяет уровень риска

3. **Country Profile Analysis**
   - Определяет географическую принадлежность
   - Анализирует языки, email домены, имена
   - Используется для фильтрации

4. **Profitability Score**
   - Комплексная оценка ценности утечки
   - Учитывает множество факторов
   - Помогает в приоритизации

**Механизм работы**:
```python
1. Подготовка контекста (secrets + stats + leak_info)
2. Выбор доступного AI провайдера
3. Формирование промпта под тип анализа
4. Отправка запроса к LLM
5. Парсинг JSON ответа
6. Валидация и нормализация результата
7. Кэширование (опционально)
```

**Provider Selection Strategy**:
```python
def select_provider():
    for provider in [openai, anthropic, local]:
        if provider.is_available() and provider.check_health():
            return provider
    return None  # Fallback to rule-based
```

#### LeakAnalyzer.py - Статический анализ

**Класс**: `LeakAnalyzer`

**Назначение**: Анализ утечек без использования AI.

**Методы анализа**:
- Pattern matching (regex)
- Entropy calculation
- Context analysis
- File path analysis
- IOC extraction

**Используемые инструменты**:
- `ioc_finder` - Поиск индикаторов компрометации
- `pywhat` - Идентификация типов данных
- `detect-secrets` - Обнаружение секретов
- `deepsecrets` - Глубокий анализ

### 4. Database Layer

#### Connector.py - Интерфейс БД

**Функции**:
- `dump_to_DB()` - Сохранение результатов
- `dump_from_DB()` - Загрузка данных
- `update_existing_leak()` - Обновление записей
- `safe_encode_data()` - Безопасное кодирование
- `safe_decode_data()` - Декодирование данных

**Структура данных в БД**:
```sql
GitSearch Database
├── leak (основная таблица)
├── raw_report (детальные отчеты)
├── leak_stats_table (статистика репозиториев)
├── accounts_table (контрибьюторы)
├── commiters_table (коммитеры)
└── target_company (целевые компании)
```

**Транзакционная модель**:
```python
# Атомарная операция сохранения
def dump_to_DB():
    with transaction:
        save_leak_record()
        save_raw_report()
        save_stats()
        save_accounts()
        save_commiters()
    if success:
        commit()
    else:
        rollback()
```

#### api_client.py - API клиент

**Класс**: `GitSearchAPIClient`

**Назначение**: Абстракция над HTTP запросами к БД API.

**Особенности**:
- Retry механизм
- Timeout handling
- Error handling и logging
- SSL/TLS поддержка

### 5. Supporting Layers

#### Rate Limiter (github_rate_limiter.py)

**Класс**: `GitHubRateLimiter` (Singleton)

**Назначение**: Управление GitHub API rate limits.

**Алгоритм**:
```python
1. Отслеживание лимитов для каждого токена
2. При исчерпании лимита:
   a. Переключение на следующий токен
   b. Если все токены исчерпаны - ожидание
3. Логирование статистики использования
```

**Endpoints tracking**:
- Search API: 30 requests/min
- Core API: 5000 requests/hour
- GraphQL API: 5000 points/hour

#### Cache Layer (api_cache.py)

**Класс**: `APICache`

**Назначение**: Кэширование API ответов.

**Стратегии кэширования**:
- In-memory cache (LRU)
- File-based cache (для больших данных)
- TTL-based expiration

**Кэшируемые данные**:
- Repository stats
- User profiles
- Search results (с коротким TTL)

#### Report Generator (report_generator.py)

**Функции**:
- `generate_business_report()` - Бизнес отчет
- `generate_technical_report()` - Технический отчет
- `generate_consolidated_report()` - Сводный отчет

**Шаблонизация**:
- HTML templates (report_template.py)
- CSS styling
- JavaScript для интерактивности
- Chart.js для графиков

### 6. Utility Layer

#### utils.py

**Функции**:
- `dumping_data()` - Сохранение и очистка данных
- `exclude_list_update()` - Обновление списка исключений
- `safe_encode_decode()` - Безопасная работа с UTF-8
- `check_temp_folder_size()` - Управление временными файлами
- `trace_monitor()` - Мониторинг памяти

#### logger.py

**Настройка логирования**:
```python
Handlers:
├── FileHandler (daily rotation)
├── ConsoleHandler (colored output)
└── ErrorHandler (separate error log)

Levels:
├── DEBUG (детальная информация)
├── INFO (общая информация)
├── WARNING (предупреждения)
├── ERROR (ошибки)
└── CRITICAL (критические ошибки)
```

## Потоки данных

### 1. Основной поток сканирования

```
User Config → Constants → Scanner
                ↓
        GitHub API ← Rate Limiter
                ↓
        Search Results → LeakObj creation
                ↓
        GitStats collection
                ↓
        AI Analysis (optional)
                ↓
        LeakAnalyzer
                ↓
        Result filtering
                ↓
        Database storage
                ↓
        Report generation
```

### 2. Поток Deep Scan

```
Database → Load leaks (status=5)
        ↓
Clone repositories
        ↓
Run scanning tools:
├── detect-secrets
├── deepsecrets
├── trufflehog
└── custom scanners
        ↓
Aggregate results
        ↓
AI re-analysis
        ↓
Update database
```

### 3. Поток AI Analysis

```
LeakObj → Prepare context
        ↓
Select AI provider
        ↓
Format prompt
        ↓
Send request
        ↓
Parse response
        ↓
Validate & normalize
        ↓
Update leak object
```

## Паттерны проектирования

### Используемые паттерны

1. **Singleton** - GitHubRateLimiter, APICache
2. **Factory** - LeakObj создание (RepoObj, CodeObj, etc.)
3. **Strategy** - AI Provider selection
4. **Observer** - Logging system
5. **Facade** - Connector (упрощает работу с БД)
6. **Template Method** - Report generation
7. **Lazy Initialization** - AI объекты, статистика

### Пример: Factory Pattern для LeakObj

```python
def create_leak_obj(obj_type, url, response, dork, company_id):
    """Factory для создания правильного типа LeakObj"""
    if 'repository' in response:
        return RepoObj(url, response, dork, company_id)
    elif 'code' in response:
        return CodeObj(url, response, dork, company_id)
    elif 'commit' in response:
        return CommitObj(url, response, dork, company_id)
    elif 'gist' in response:
        return GlistObj(url, response, dork, company_id)
    else:
        raise ValueError(f"Unknown object type: {obj_type}")
```

## Масштабируемость

### Горизонтальное масштабирование

- **Множественные токены**: Распределение нагрузки между токенами
- **Distributed scanning**: Возможность запуска на нескольких машинах
- **Database sharding**: Разделение данных по компаниям

### Вертикальное масштабирование

- **Async operations**: Использование asyncio для параллельных задач
- **Thread pooling**: Параллельное клонирование репозиториев
- **Memory optimization**: Очистка временных данных

### Оптимизации

1. **Кэширование**:
   - API responses
   - Repository stats
   - AI analysis results

2. **Rate limiting**:
   - Token rotation
   - Adaptive delays
   - Priority queuing

3. **Database**:
   - Indexed queries
   - Batch inserts
   - Connection pooling

4. **Memory**:
   - Streaming для больших файлов
   - Periodic cleanup
   - Lazy loading

## Безопасность

### Защита данных

1. **Токены и credentials**:
   - Хранение в .env (не в git)
   - Encryption at rest
   - Limited scope tokens

2. **База данных**:
   - SSL/TLS соединения
   - Prepared statements (SQL injection защита)
   - Encoding чувствительных данных (BZ2 + Base64)

3. **Логирование**:
   - Sanitization секретов
   - Rotation логов
   - Access control

### Обработка ошибок

```python
try:
    operation()
except SpecificException as e:
    logger.error(f"Specific error: {e}")
    # Recovery logic
except Exception as e:
    logger.critical(f"Unexpected error: {e}")
    # Graceful degradation
finally:
    cleanup()
```

## Тестирование

### Тестовые уровни

1. **Unit tests** - Отдельные функции и методы
2. **Integration tests** - Взаимодействие компонентов
3. **E2E tests** - Полный цикл сканирования

### Тестовые файлы

```
test/
├── test_ai_final.py
├── test_deepscan_debug.py
├── test_graphql.py
├── test_integration.py
├── test_provider_cache.py
└── test_reports.py
```

## Расширение системы

### Добавление нового типа сканирования

```python
# 1. Создать новый класс LeakObj
class NewScanObj(LeakObj):
    def __init__(self, url, response, dork, company_id):
        super().__init__('NewScan', url, response, dork, company_id)
        # Специфичная инициализация

# 2. Добавить scanner метод
def new_scan_search(dork):
    # Логика поиска
    pass

# 3. Интегрировать в gitsearch.py
def run_new_scan():
    for company in targets:
        results = new_scan_search(company_dorks)
        for result in results:
            leak = NewScanObj(...)
            RESULT_MASS.add(leak)
```

### Добавление нового AI провайдера

```python
# В AIObj.py
class NewAIProvider(AIProvider):
    def __init__(self, api_key):
        self.api_key = api_key
    
    def check_availability(self):
        # Проверка доступности
        pass
    
    def send_request(self, prompt):
        # Отправка запроса
        pass
    
    def parse_response(self, response):
        # Парсинг ответа
        pass

# Регистрация провайдера
AI_PROVIDERS['new_provider'] = NewAIProvider
```

## Мониторинг и метрики

### Ключевые метрики

- Количество сканирований в час
- API rate limit usage
- Процент true positives
- Среднее время обработки leak
- Размер базы данных
- AI provider availability

### Logging points

- Start/end каждого этапа
- API requests и responses
- Ошибки и warnings
- Performance metrics
- Memory usage

## Заключение

Архитектура GitSearch обеспечивает:
- ✅ Модульность и расширяемость
- ✅ Отказоустойчивость
- ✅ Масштабируемость
- ✅ Безопасность
- ✅ Поддерживаемость

Система спроектирована с учетом best practices и готова к дальнейшему развитию.
