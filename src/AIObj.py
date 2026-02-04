"""AI Object Module for analyzing leaked data using LLM services."""
# Standart libs import
import json
import re
import time
from abc import ABC
from typing import Any, Dict, List, Optional, Tuple

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


class AIObj(ABC):
    """Base class for AI-powered analysis of leaked data."""

    base_prompt_text = "None"

    def __init__(self, secrets: dict, stats_data: dict, leak_info: dict, company_info: Optional[Dict[str, Any]] = None):
        if TIKTOKEN_AVAILABLE and tiktoken:
            try:
                self.tokenizer = tiktoken.get_encoding("cl100k_base")
            except Exception as e:
                logger.warning("tiktoken initialization failed: %s, using simple tokenizer", e)
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
            token_limit = constants.AI_CONFIG.get("token_limit", 4000) - 1000
            if len(self.tokenizer.encode(secrets_str)) > token_limit:
                secrets_str = self.tokenizer.decode(self.tokenizer.encode(secrets_str)[:token_limit])
                secrets_str += "...Cutted, token limit reached."
        else:
            if len(secrets_str) > 10000:
                secrets_str = secrets_str[:10000] + "...Cutted, char limit reached."

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
                "description": description_value,
            },
            "contributors": contributers_list,
            "commiters": commiters_list,
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

    def _parse_llm_json(self, content: str) -> Optional[Dict[str, Any]]:
        """
        Parse JSON from LLM response, tolerating code fences and extra text.
        """
        if not content:
            return None

        cleaned = content.strip()

        # Strip markdown code fences if present
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            if "\n" in cleaned:
                cleaned = cleaned.split("\n", 1)[1]

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except Exception:
                return None

        return None

    def _normalize_analysis(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensure the analysis payload has a consistent shape and sane defaults.
        """
        default_payload = {
            "company_relevance": {"is_related": False, "confidence": 0.0},
            "severity_assessment": {"level": "unknown", "score": 0.0},
            "classification": {"true_positive_probability": 0.0},
            "summary": "",
            "recommendations": "",
        }

        if not isinstance(analysis, dict):
            return default_payload

        normalized = default_payload.copy()

        comp_rel = analysis.get("company_relevance", {})
        if isinstance(comp_rel, dict):
            normalized["company_relevance"]["is_related"] = bool(comp_rel.get("is_related", False))
            try:
                normalized["company_relevance"]["confidence"] = float(comp_rel.get("confidence", 0.0))
            except (TypeError, ValueError):
                pass

        severity = analysis.get("severity_assessment", {})
        if isinstance(severity, dict):
            level = severity.get("level")
            if isinstance(level, str):
                normalized["severity_assessment"]["level"] = level
            try:
                normalized["severity_assessment"]["score"] = float(severity.get("score", 0.0))
            except (TypeError, ValueError):
                pass

        classification = analysis.get("classification", {})
        if isinstance(classification, dict):
            try:
                normalized["classification"]["true_positive_probability"] = float(
                    classification.get("true_positive_probability", 0.0)
                )
            except (TypeError, ValueError):
                pass

        summary = analysis.get("summary")
        if isinstance(summary, str):
            normalized["summary"] = summary

        recommendations = analysis.get("recommendations")
        if isinstance(recommendations, str):
            normalized["recommendations"] = recommendations

        return normalized

    def safe_val(self, val):
        """Convert value to string, returning '-' for None or empty strings."""
        if val is None or val == "":
            return "-"
        return str(val)

    @property
    def llm_manager(self):
        """Ленивая инициализация LLM менеджера"""
        if self._llm_manager is None:
            # Импортируем глобальный менеджер
            try:
                from src import ai_worker

                if hasattr(ai_worker, "llm_manager"):
                    self._llm_manager = ai_worker.llm_manager
            except (ImportError, AttributeError):
                self._llm_manager = None
        return self._llm_manager

    def analyze_leak_comprehensive(self):
        """Полноценный анализ утечки с использованием доступных LLM провайдеров"""

        if not constants.AI_ANALYSIS_ENABLED:
            logger.debug("AI analysis is disabled by configuration")
            return None

        # Быстрая проверка с кешированием перед началом анализа
        if not self.llm_manager.has_available_providers():
            return None

        if not self.llm_manager.providers:
            logger.warning("Нет доступных LLM провайдеров")
            return None

        system_prompt = (
            "You are a senior incident responder assessing potential source-code leaks.\n"
            "Return ONLY a single JSON object (no Markdown, no prose) with keys exactly:\n"
            "{\n"
            '  "company_relevance": { "is_related": bool, "confidence": float },\n'
            '  "severity_assessment": { "level": str, "score": float },\n'
            '  "classification": { "true_positive_probability": float },\n'
            '  "summary": str,\n'
            '  "recommendations": str\n'
            "}\n"
            "Scoring rules:\n"
            "- confidence/score/probability must be 0.0-1.0; use one decimal when uncertain, two decimals when confident.\n"
            "- severity level must be one of: low, medium, high, critical.\n"
            "- Treat corporate committers/emails, company tokens in paths, and matching dorks as strong signals of relation.\n"
            "- Penalize tutorial/demo/test content, public/free email domains, and placeholder/example secrets.\n"
            "Output JSON only; if data is insufficient, set probabilities near 0.25 and explain gaps in summary."
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
            self.ai_requested = True
            return None

        try:
            content = response["choices"][0]["message"]["content"].strip()
        except Exception as e:  # pragma: no cover - defensive
            logger.error("Error in response LLM: %s", e)
            self.ai_requested = True
            return None

        analysis_data = self._parse_llm_json(content)

        if analysis_data:
            normalized = self._normalize_analysis(analysis_data)
            self.ai_analysis = normalized
            self.ai_result = 1 if normalized.get("company_relevance", {}).get("is_related") else 0
            self.ai_analysis_completed = True
            self.ai_requested = True
            return normalized

        if content in {"0", "1"}:
            self.ai_result = int(content)
        else:
            self.ai_result = -1

        self.ai_requested = True
        return None

    def safe_generate(
        self, prompt: str, ctx_size: int = 8192, max_new_tokens: int = 1024, safety_margin: int = 256
    ) -> Tuple[str, int]:
        """Safely generate response with token limit checks."""

        if self.tokenizer:
            prompt_tokens = self.tokenizer.encode(prompt)

            max_prompt_tokens = ctx_size - max_new_tokens - safety_margin
            logger.info("Количество токенов: %d", len(prompt_tokens))

            if len(prompt_tokens) > max_prompt_tokens:
                prompt_tokens = prompt_tokens[:max_prompt_tokens]
                logger.info("Предупреждение: Промпт обрезан до %d токенов", max_prompt_tokens)

            max_tokens = ctx_size - len(prompt_tokens) - 5
            prompt = self.tokenizer.decode(prompt_tokens)
        else:
            # Tokenizer can be optional in minimal installations; fall back to character-based trimming
            max_prompt_chars = max(ctx_size - max_new_tokens - safety_margin, 0)
            if max_prompt_chars and len(prompt) > max_prompt_chars:
                prompt = prompt[:max_prompt_chars]
                logger.info("Prompt truncated to %d characters (tokenizer unavailable)", max_prompt_chars)
            max_tokens = max_new_tokens

        if max_tokens < 0:
            logger.error(
                "Предупреждение: недостаточно токенов для ответа, промпт не будет выполняться. Промпт: %s", prompt
            )
            return "", 0
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
        _ = [  # noqa: F841
            {
                "type": "function",
                "function": {
                    "name": "GitSearch_chech",
                    "description": "Function to analyze gitsearch incidents",
                    "parameters": {
                        "type": "object",
                        "properties": {"name": {"type": "string", "description": "The incident classification"}},
                        "required": ["data"],
                    },
                },
            }
        ]
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=max_tokens,
                # tools=tools,
                stop=["</answer>", "<|im_end|>"],
            )
        except Exception as ex:
            logger.error(f"Api request error: {ex}")
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
                logger.warning("Комплексный анализ не удался, используется старый метод: %s", str(e))

        # Fallback к оригинальному методу
        result_promt, max_tokens = self.safe_generate(
            prompt=self.base_prompt_text, ctx_size=constants.AI_CONFIG["token_limit"]
        )
        if not result_promt:
            self.ai_result = -1
            self.ai_requested = True
            return

        try:
            client = OpenAI(base_url=constants.AI_CONFIG["url"], api_key=constants.AI_CONFIG["api_key"])
        except Exception as ex:
            logger.error("Error in connection to AI API: %s", ex)
            self.ai_requested = True
            return

        try:
            ai_response = self.lm_studio_request(
                prompt=result_promt,
                client=client,
                max_tokens=max_tokens,
                temperature=constants.AI_CONFIG["temperature"],
                model=constants.AI_CONFIG["model"],
            )
            if ai_response and ai_response.choices:
                self.ai_analysis = ai_response.choices[0].message.content.strip()
                if self.ai_analysis == "0":
                    self.ai_result = 0
                elif self.ai_analysis == "1":
                    self.ai_result = 1
                else:
                    logger.warning("AI returned unexpected output: %s", self.ai_analysis)
                    self.ai_result = -1
            else:
                logger.warning("AI response was empty or malformed.")
                self.ai_result = -1
            self.ai_requested = True
        except Exception as ex:
            logger.error(f"Error in AI API request: {ex}")
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
            return self.ai_analysis.get("company_relevance", {}).get("is_related", False)
        return False

    def get_severity_level(self) -> str:
        """Получение уровня серьезности утечки"""
        if self.ai_analysis:
            return self.ai_analysis.get("severity_assessment", {}).get("level", "unknown")
        return "unknown"

    def get_true_positive_probability(self) -> float:
        """Получение вероятности истинной утечки"""
        if self.ai_analysis:
            return self.ai_analysis.get("classification", {}).get("true_positive_probability", 0.0)
        return 0.0

    def get_recommendations(self) -> Dict[str, Any]:
        """Получение рекомендаций по утечке"""
        if self.ai_analysis:
            return self.ai_analysis.get("recommendations", {})
        return {}

    def get_analysis_summary(self) -> str:
        """Получение краткого описания анализа"""
        if self.ai_analysis:
            return self.ai_analysis.get("summary", "Анализ не выполнен")
        return "Анализ не выполнен"


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
        "total": 3,
        "backoff_factor": 0.5,
        "status_forcelist": [429, 500, 502, 503, 504],
        "allowed_methods": ["POST", "GET"],
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
            total=self.RETRY_CONFIG["total"],
            backoff_factor=self.RETRY_CONFIG["backoff_factor"],
            status_forcelist=self.RETRY_CONFIG["status_forcelist"],
            allowed_methods=self.RETRY_CONFIG["allowed_methods"],
            raise_on_status=False,  # Не выбрасываем исключение, обрабатываем сами
        )

        # Создаем адаптер с пулом соединений
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,  # Максимум соединений в пуле
            pool_maxsize=10,  # Максимум соединений в keep-alive
            pool_block=False,  # Не блокировать при переполнении пула
        )

        session.mount("http://", adapter)
        session.mount("https://", adapter)

        logger.info("HTTP connection pool initialized with retry strategy")
        return session

    def close(self):
        """Закрывает сессию и освобождает ресурсы."""
        if self._session:
            self._session.close()
            logger.info("HTTP connection pool closed")

    def _load_providers(self):
        """Загрузка провайдеров из конфигурации"""
        for provider_config in constants.LLM_PROVIDERS:
            # API ключи уже загружены в constants.LLM_PROVIDERS из env_variables
            api_key = provider_config.get("api_key", "")
            if api_key and api_key.strip():  # Проверяем что ключ не пустой
                self.providers[provider_config["name"]] = {
                    **provider_config,
                    "requests_count": 0,
                    "last_request_time": 0,
                    "error_count": 0,
                }
                logger.info("Uploaded LLM provider: %s", provider_config["name"])
            else:
                logger.warning("API key for %s not found or empty", provider_config["name"])

    def _check_providers_available(self) -> bool:
        """Проверить наличие доступных провайдеров"""
        current_time = time.time()

        for provider in self.providers.values():
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

        for provider in self.providers.values():
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
                logger.warning("ZERO Available LLM providers. Next check after %d requests", check_interval)
            else:
                logger.info("LLM providers are available. Next check after %d requests", check_interval)

        return self._providers_available

    def _iter_ready_providers(self) -> List[Dict[str, Any]]:
        """
        Return providers that are currently eligible for a request.
        Filters out providers that hit error or request limits and respects RPM.
        """
        current_time = time.time()
        ready = []
        for provider in self.providers.values():
            if provider.get("error_count", 0) >= 3:
                continue
            if provider.get("requests_count", 0) >= provider.get("daily_limit", float("inf")) - 50:
                continue
            rpm = max(provider.get("rpm", 1), 1)
            if current_time - provider.get("last_request_time", 0) < 60 / rpm:
                continue
            ready.append(provider)
        return sorted(ready, key=lambda p: p.get("last_request_time", 0))

    def make_request(
        self, messages: List[Dict[str, str]], max_tokens: int = 2000, temperature: float = 0.1
    ) -> Optional[Dict[str, Any]]:
        """Выполнить запрос к доступному провайдеру"""

        if not self.has_available_providers():
            return None

        candidates = self._iter_ready_providers()
        if not candidates:
            logger.error("ZERO Available LLM providers")
            self._providers_available = False
            return None

        for provider in candidates:
            headers = {"Authorization": f"Bearer {provider['api_key']}", "Content-Type": "application/json"}

            if provider["name"] == "openrouter":
                headers["HTTP-Referer"] = "https://github.com/gitsearch"
                headers["X-Title"] = "GitSearch AI Analyzer"

            payload = {
                "model": provider["model"],
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }

            try:
                response = self._session.post(
                    f"{provider['base_url']}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=constants.AI_ANALYSIS_TIMEOUT,
                )

                if response.status_code == 200:
                    provider["requests_count"] += 1
                    provider["last_request_time"] = time.time()
                    provider["error_count"] = 0
                    logger.debug("LLM request successful via %s", provider["name"])
                    return response.json()
                elif response.status_code == 429:
                    logger.warning("Provider %s rate limited (429)", provider["name"])
                    provider["error_count"] += 1
                    provider["last_request_time"] = time.time() + 60
                    continue
                else:
                    logger.error(
                        "Provider %s returned status: %d: %s",
                        provider["name"],
                        response.status_code,
                        response.text[:200],
                    )
                    provider["error_count"] += 1
                    continue

            except requests.exceptions.Timeout:
                logger.error("Timeout for provider %s", provider["name"])
                provider["error_count"] += 1
            except requests.exceptions.ConnectionError as e:
                logger.error("Connection error for provider %s: %s", provider["name"], str(e))
                provider["error_count"] += 1
            except Exception as e:
                logger.error("Unexpected error for provider %s: %s", provider["name"], str(e))
                provider["error_count"] += 1

        logger.error("All configured LLM providers failed for this request")
        self._providers_available = False
        return None


# Глобальный экземпляр менеджера провайдеров
llm_manager = LLMProviderManager()
