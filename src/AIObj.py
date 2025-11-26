# Standart libs import
import time
from abc import ABC
import json
from typing import Optional, Dict, List, Any
import re
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Опциональные импорты для AI функционала
try:
    import tiktoken
    TIKTOKEN_AVAILABLE = True
except ImportError:
    TIKTOKEN_AVAILABLE = False
    tiktoken = None

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    OpenAI = None

from src import constants
from src.logger import logger
from src.exceptions import (
    LLMAPIError, LLMProviderUnavailableError, RateLimitError, AIAnalysisError
)


class AIObj(ABC):
    base_prompt_text = 'None'
    
    def __init__(self, secrets: dict, stats_data: dict, leak_info: dict, company_info: Optional[Dict[str, Any]] = None):
        if TIKTOKEN_AVAILABLE and tiktoken:
            try:
                self.tokenizer = tiktoken.get_encoding("cl100k_base")
            except Exception as e:
                logger.warning(f"tiktoken initialization failed: {e}, using simple tokenizer")
                self.tokenizer = None
        else:
            logger.debug("tiktoken not available, using simple tokenizer")
            self.tokenizer = None
        
        self.ai_requested = False
        self.ai_analysis_completed = False
        
        self.ai_result = -1
        
        self.ai_analysis = None
        self.ai_report = None
        
        self.company_info = company_info or {}
        
        self._llm_manager = None
        
        self._prepare_analysis_data(secrets, stats_data, leak_info)
    
    def _prepare_analysis_data(self, secrets: dict, stats_data: dict, leak_info: dict):
        secrets_str = json.dumps(secrets) if secrets else "-"
        
        if self.tokenizer:
            token_limit = constants.AI_CONFIG.get('token_limit', 4000) - 1000
            if len(self.tokenizer.encode(secrets_str)) > token_limit:
                secrets_str = self.tokenizer.decode(self.tokenizer.encode(secrets_str)[:token_limit])
                secrets_str += '...Cutted, token limit reached.'
        else:
            if len(secrets_str) > 10000:
                secrets_str = secrets_str[:10000] + '...Cutted, char limit reached.'
        
        if secrets:
            raw_report_str = "\n".join(str(item) for item in secrets)
        else:
            raw_report_str = "-"
        
        size_value = self.safe_val(stats_data.get("size"))
        forks_value = self.safe_val(stats_data.get("forks_count"))
        stargazers_value = self.safe_val(stats_data.get("stargazers_count"))
        description_value = self.safe_val(stats_data.get("description"))
        
        contributers_list = leak_info.get("contributers") or []
        commiters_list = leak_info.get("commiters") or []
        
        self.repo_name = self.safe_val(leak_info.get("repo_name"))
        self.author = self.safe_val(leak_info.get("author"))
        self.dork = self.safe_val(leak_info.get("dork"))
        self.created_at = self.safe_val(leak_info.get("created_at"))
        self.updated_at = self.safe_val(leak_info.get("updated_at"))
        
        self.processed_data = {
            "secrets": secrets,
            "secrets_str": secrets_str,
            "raw_report_str": raw_report_str,
            "stats": {
                "size": size_value,
                "forks": forks_value,
                "stargazers": stargazers_value,
                "description": description_value
            },
            "contributors": contributers_list,
            "commiters": commiters_list
        }
        
        # Формирование базового промпта для обратной совместимости
        self.base_prompt_text = (
            "### Data:\n"
            f"Repository name: {self.repo_name}\n"
            f"Author: {self.author}\n"
            f"Last updated at: {self.updated_at}\n"
            f"Repository created at: {self.created_at}\n"
            f"Stats of repo -> Size: {size_value}, Forks: {forks_value}, Stargazers: {stargazers_value}\n"
            f"Description of repo: {description_value}\n\n"
            f"Contributers:\n{contributers_list}\n\n"
            f"Commiters:\n{commiters_list}\n\n"
            f"Company related dork: {self.dork}\n\n"
            f"Raw_report (may cut off):\n{raw_report_str.replace('\t', '').replace('\n', '')}...\n\n"
        )
                      
    def safe_val(self, val):
        if val is None or val == "":
            return "-"
        return str(val)

    @property
    def llm_manager(self):
        """Ленивая инициализация LLM менеджера"""
        if self._llm_manager is None:
            # Импортируем глобальный менеджер
            global llm_manager
            self._llm_manager = llm_manager
        return self._llm_manager

    def analyze_leak_comprehensive(self):
        """Полноценный анализ утечки с использованием доступных LLM провайдеров"""

        # Быстрая проверка с кешированием перед началом анализа
        if not self.llm_manager.has_available_providers():
            return None
        
        if not self.llm_manager.providers:
            logger.warning("Нет доступных LLM провайдеров")
            return None

        system_prompt = (
            "You are a security analyst. "
            "Analyse provided repository information and return JSON with the "
            "following structure: {\n"
            "  'company_relevance': { 'is_related': bool, 'confidence': float },\n"
            "  'severity_assessment': { 'level': str, 'score': float },\n"
            "  'classification': { 'true_positive_probability': float },\n"
            "  'summary': str,\n"
            "  'recommendations': str\n"
            "}."
        )

        user_prompt = self.base_prompt_text
        if self.company_info:
            try:
                user_prompt += f"Company info: {json.dumps(self.company_info)}\n"
            except Exception:
                user_prompt += f"Company info: {self.company_info}\n"

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        response = self.llm_manager.make_request(
            messages,
            max_tokens=1024,
            temperature=constants.AI_CONFIG.get("temperature", 0.1),
        )

        if not response:
            return None

        try:
            content = response["choices"][0]["message"]["content"].strip()
        except Exception as e:  # pragma: no cover - defensive
            logger.error(f"Error in respone LLM: {e}")
            return None

        analysis_data = None
        try:
            analysis_data = json.loads(content)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", content, re.DOTALL)
            if match:
                try:
                    analysis_data = json.loads(match.group(0))
                except Exception:
                    analysis_data = None

        if analysis_data:
            self.ai_analysis = analysis_data
            self.ai_result = 1 if analysis_data.get("company_relevance", {}).get("is_related") else 0
            self.ai_analysis_completed = True
            self.ai_requested = True
            return analysis_data

        if content in {"0", "1"}:
            self.ai_result = int(content)
        else:
            self.ai_result = -1

        self.ai_requested = True
        return None
    
    def safe_generate(
        self,
        prompt: str,
        ctx_size: int = 8192,
        max_new_tokens: int = 1024,
        safety_margin: int = 256
    ) -> tuple[str, int]:
        
        prompt_tokens = self.tokenizer.encode(prompt)
        
        max_prompt_tokens = ctx_size - max_new_tokens - safety_margin
        logger.info(f"Количество токенов: {len(prompt_tokens)}")
        
        if len(prompt_tokens) > max_prompt_tokens:
            prompt_tokens = prompt_tokens[:max_prompt_tokens]
            logger.info(f"Предупреждение: Промпт обрезан до {max_prompt_tokens} токенов")
        
        max_tokens = ctx_size-len(prompt_tokens)-5
        prompt = self.tokenizer.decode(prompt_tokens)

        if max_tokens < 0:
            logger.error(f"Предупреждение: недостаточно токенов для ответа, промпт не будет выполняться. Промпт: {prompt}")
            return ""
        else:
            return prompt, max_tokens

    def lm_studio_request(self, prompt: str, client: str, max_tokens: int, temperature: float, model: str):
        system_prompt = (            
                "### Instruction:\n"
                "You are a data leak detection expert. Analyze the data and respond ONLY with '1' (leak found) or '0' (no leak).\n"
                "Strict response rules:\n"
                "- Output must be single character: 1 or 0\n"
                
                "### Examples:\n"
                "Good: 1\n"
                "Good: 0\n"
                "Bad: I think it's 1 because...\n"
                
                "### Assessment Criteria:\n"
                "Return 1 if the leak may be related to the company\n"
                "Often in leaks very low stars quantity and/or russian related description/authors names/domains (ru)"
                
        )
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "GitSearch_chech",
                    "description": "Function to analyze gitsearch incidents",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                                "description": "The incident classification"
                            }
                        },
                        "required": ["data"]
                    }
                }
            }
        ]
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=max_tokens,
                #tools=tools,
                stop=["</answer>", "<|im_end|>"]
            )
        except Exception as ex:
            logger.error(f'Api request error: {ex}')
            return None

        return response
    
    def ai_request(self):
        """Оригинальный метод для обратной совместимости"""
        if self.ai_requested:
            return
        
        # Попытка использования нового комплексного анализа
        if constants.AI_ANALYSIS_ENABLED and self.llm_manager.providers:
            try:
                analysis = self.analyze_leak_comprehensive()
                if analysis:
                    self.ai_requested = True
                    return
            except Exception as e:
                logger.warning(f"Комплексный анализ не удался, используется старый метод: {str(e)}")
        
        # Fallback к оригинальному методу
        result_promt, max_tokens = self.safe_generate(prompt=self.base_prompt_text,
                                                      ctx_size=constants.AI_CONFIG['token_limit'])
        if not result_promt:
            self.ai_result = -1
            self.ai_requested = True
            return

        try:
            client = OpenAI(base_url=constants.AI_CONFIG['url'], api_key=constants.AI_CONFIG['api_key'])
        except Exception as ex:
            logger.error(f'Error in connection to AI API: {ex}')
            self.ai_requested = True
            return
        
        try:
            ai_response = self.lm_studio_request(prompt=result_promt, 
                                                client=client,
                                                max_tokens=max_tokens,
                                                temperature=constants.AI_CONFIG['temperature'],
                                                model=constants.AI_CONFIG['model'])
            if ai_response and ai_response.choices:
                self.ai_analysis = ai_response.choices[0].message.content.strip()
                if self.ai_analysis == '0':
                    self.ai_result = 0
                elif self.ai_analysis == '1':
                    self.ai_result = 1
                else:
                    logger.warning(f"AI returned unexpected output: {self.ai_analysis}")
                    self.ai_result = -1
            else:
                logger.warning("AI response was empty or malformed.")
                self.ai_result = -1
            self.ai_requested = True
        except Exception as ex:
            logger.error(f'Error in AI API request: {ex}')
            self.ai_requested = True
        
    def set_company_info(self, company_info: Dict[str, Any]):
        """Установка информации о компании для анализа"""
        self.company_info = company_info
        
    def get_comprehensive_analysis(self) -> Dict[str, Any]:
        """Получение комплексного анализа утечки"""
        if not self.ai_analysis_completed:
            return self.analyze_leak_comprehensive()
        return self.ai_analysis
    
    def is_company_related(self) -> bool:
        """Проверка связи утечки с компанией"""
        if self.ai_analysis:
            return self.ai_analysis.get('company_relevance', {}).get('is_related', False)
        return False
    
    def get_severity_level(self) -> str:
        """Получение уровня серьезности утечки"""
        if self.ai_analysis:
            return self.ai_analysis.get('severity_assessment', {}).get('level', 'unknown')
        return 'unknown'
    
    def get_true_positive_probability(self) -> float:
        """Получение вероятности истинной утечки"""
        if self.ai_analysis:
            return self.ai_analysis.get('classification', {}).get('true_positive_probability', 0.0)
        return 0.0
    
    def get_recommendations(self) -> Dict[str, Any]:
        """Получение рекомендаций по утечке"""
        if self.ai_analysis:
            return self.ai_analysis.get('recommendations', {})
        return {}
    
    def get_analysis_summary(self) -> str:
        """Получение краткого описания анализа"""
        if self.ai_analysis:
            return self.ai_analysis.get('summary', 'Анализ не выполнен')
        return 'Анализ не выполнен'


class LLMProviderManager:
    """
    Менеджер для работы с множественными LLM провайдерами.
    
    Оптимизации:
    - Пул HTTP-соединений с keep-alive
    - Автоматические повторные попытки с экспоненциальным backoff
    - Кеширование доступности провайдеров
    """
    
    # Конфигурация повторных попыток
    RETRY_CONFIG = {
        'total': 3,
        'backoff_factor': 0.5,
        'status_forcelist': [429, 500, 502, 503, 504],
        'allowed_methods': ['POST', 'GET']
    }
    
    def __init__(self):
        self.providers = {}
        self.usage_stats = {}
        self._providers_available = None  # Кеш доступности провайдеров
        self._request_counter = 0  # Счетчик запросов для периодической проверки
        self._last_check_time = 0  # Время последней проверки
        
        # Инициализируем сессию с пулом соединений и retry-логикой
        self._session = self._create_session()
        
        self._load_providers()
    
    def _create_session(self) -> requests.Session:
        """
        Создает сессию с пулом соединений и автоматическими повторами.
        
        Returns:
            requests.Session с настроенными адаптерами
        """
        session = requests.Session()
        
        # Настраиваем retry-стратегию
        retry_strategy = Retry(
            total=self.RETRY_CONFIG['total'],
            backoff_factor=self.RETRY_CONFIG['backoff_factor'],
            status_forcelist=self.RETRY_CONFIG['status_forcelist'],
            allowed_methods=self.RETRY_CONFIG['allowed_methods'],
            raise_on_status=False  # Не выбрасываем исключение, обрабатываем сами
        )
        
        # Создаем адаптер с пулом соединений
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,  # Максимум соединений в пуле
            pool_maxsize=10,      # Максимум соединений в keep-alive
            pool_block=False      # Не блокировать при переполнении пула
        )
        
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        logger.info("🔌 HTTP connection pool initialized with retry strategy")
        return session
    
    def close(self):
        """Закрывает сессию и освобождает ресурсы."""
        if self._session:
            self._session.close()
            logger.info("🔌 HTTP connection pool closed")
    
    def _load_providers(self):
        """Загрузка провайдеров из конфигурации"""
        # Получаем переменные из constants (уже загружены из .env)
        env_vars = constants.env_variables
        
        for provider_config in constants.LLM_PROVIDERS:
            api_key = env_vars.get(provider_config["api_key_env"])
            if api_key and api_key.strip():  # Проверяем что ключ не пустой
                self.providers[provider_config["name"]] = {
                    **provider_config,
                    "api_key": api_key,
                    "requests_count": 0,
                    "last_request_time": 0,
                    "error_count": 0
                }
                logger.info(f"Uploaded LLM provider: {provider_config['name']}")
            else:
                logger.warning(f"API key for {provider_config['name']} not found or empty")
    
    def _check_providers_available(self) -> bool:
        """Проверить наличие доступных провайдеров"""
        current_time = time.time()
        
        for name, provider in self.providers.items():
            # Простая проверка лимитов
            if provider["error_count"] < 3:
                if provider.get("requests_count", 0) >= provider.get("daily_limit", float("inf")) - 50:
                    continue
                if current_time - provider["last_request_time"] > 60 / provider["rpm"]:
                    return True
        
        return False
    
    def get_available_provider(self) -> Optional[Dict[str, Any]]:
        """Получить доступного провайдера"""
        current_time = time.time()
        
        for name, provider in self.providers.items():
            # Простая проверка лимитов
            if provider["error_count"] < 3:
                if provider.get("requests_count", 0) >= provider.get("daily_limit", float("inf")) - 50:
                    continue
                if current_time - provider["last_request_time"] > 60 / provider["rpm"]:
                    return provider
        
        return None
    
    def has_available_providers(self) -> bool:
        """Проверить наличие доступных провайдеров с учетом кеширования"""
        check_interval = constants.AI_PROVIDER_CHECK_INTERVAL
        
        # Если интервал 0, всегда проверяем
        if check_interval == 0:
            available = self._check_providers_available()
            self._providers_available = available
            return available
        
        # Увеличиваем счетчик запросов
        self._request_counter += 1
        
        # Проверяем, нужно ли обновить кеш
        if self._providers_available is None or self._request_counter >= check_interval:
            available = self._check_providers_available()
            self._providers_available = available
            self._request_counter = 0
            self._last_check_time = time.time()
            
            if not available:
                logger.warning(f"ZERO Available LLM providers. Next check after {check_interval} requests")
            else:
                logger.info(f"LLM providers are available. Next check after {check_interval} requests")
        
        return self._providers_available
    
    def make_request(self, messages: List[Dict[str, str]], 
                    max_tokens: int = 2000, 
                    temperature: float = 0.1) -> Optional[Dict[str, Any]]:
        """Выполнить запрос к доступному провайдеру"""
        
        # Быстрая проверка с кешированием
        if not self.has_available_providers():
            return None
        
        provider = self.get_available_provider()
        if not provider:
            logger.error("ZERO Available LLM providers")
            # Сбрасываем кеш, т.к. провайдеры недоступны
            self._providers_available = False
            return None
        
        headers = {
            "Authorization": f"Bearer {provider['api_key']}",
            "Content-Type": "application/json"
        }
        
        # Специальные заголовки для OpenRouter
        if provider["name"] == "openrouter":
            headers["HTTP-Referer"] = "https://github.com/gitsearch"
            headers["X-Title"] = "GitSearch AI Analyzer"
        
        payload = {
            "model": provider["model"],
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature
        }
        
        try:
            # Используем сессию с пулом соединений и автоматическими повторами
            response = self._session.post(
                f"{provider['base_url']}/chat/completions",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                provider["requests_count"] += 1
                provider["last_request_time"] = time.time()
                provider["error_count"] = 0
                logger.debug(f"✅ LLM request successful via {provider['name']}")
                return response.json()
            elif response.status_code == 429:
                logger.warning(f"⚠️ Provider {provider['name']} rate limited (429)")
                provider["error_count"] += 1
                # Увеличиваем время ожидания для этого провайдера
                provider["last_request_time"] = time.time() + 60  # Блокируем на минуту
                return None
            else:
                logger.error(f"❌ Provider {provider['name']} returned status: {response.status_code}: {response.text[:200]}")
                provider["error_count"] += 1
                return None
        
        except requests.exceptions.Timeout:
            logger.error(f"⏱️ Timeout for provider {provider['name']}")
            provider["error_count"] += 1
            return None
        except requests.exceptions.ConnectionError as e:
            logger.error(f"🔌 Connection error for provider {provider['name']}: {str(e)}")
            provider["error_count"] += 1
            return None
        except Exception as e:
            logger.error(f"💥 Unexpected error for provider {provider['name']}: {str(e)}")
            provider["error_count"] += 1
            return None


# Глобальный экземпляр менеджера провайдеров
llm_manager = LLMProviderManager()
