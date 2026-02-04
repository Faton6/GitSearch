#!/usr/bin/env python3
"""
Pytest тесты для AI-анализа в GitSearch
Запуск: pytest test/test_ai_analysis.py -v
"""

import pytest


class TestAIAnalysis:
    """Тестовый класс для AI-анализа GitSearch"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Настройка для каждого теста"""
        # Импорты модулей, которые будут использоваться в тестах
        from src import constants
        from src.AIObj import llm_manager

        self.constants = constants
        self.llm_manager = llm_manager

    def test_imports(self):
        """Тест успешного импорта всех необходимых модулей"""
        try:
            from src import constants
            from src.LeakObj import RepoObj
            from src.AIObj import AIObj, llm_manager

            assert constants is not None
            assert RepoObj is not None
            assert AIObj is not None
            assert llm_manager is not None

        except ImportError as e:
            pytest.fail(f"Ошибка импорта: {e}")

    def test_llm_providers_configuration(self):
        """Тест конфигурации LLM провайдеров"""
        # Проверяем, что LLM_PROVIDERS определен и содержит данные
        assert hasattr(self.constants, "LLM_PROVIDERS")
        assert len(self.constants.LLM_PROVIDERS) > 0

        # Проверяем структуру каждого провайдера
        required_fields = ["name", "base_url", "model", "api_key_env"]
        for provider in self.constants.LLM_PROVIDERS:
            for field in required_fields:
                assert field in provider, f"Поле '{field}' отсутствует в провайдере {provider.get('name', 'unknown')}"

    def test_ai_config_presence(self):
        """Тест наличия AI конфигурации"""
        assert hasattr(self.constants, "AI_ANALYSIS_ENABLED")
        assert hasattr(self.constants, "AI_ANALYSIS_TIMEOUT")
        assert hasattr(self.constants, "AI_MAX_CONTEXT_LENGTH")
        assert hasattr(self.constants, "AI_COMPANY_RELEVANCE_THRESHOLD")
        assert hasattr(self.constants, "AI_TRUE_POSITIVE_THRESHOLD")

    def test_llm_manager_initialization(self):
        """Тест инициализации LLM менеджера"""
        assert self.llm_manager is not None
        assert hasattr(self.llm_manager, "providers")
        assert hasattr(self.llm_manager, "usage_stats")
        assert hasattr(self.llm_manager, "get_available_provider")
        assert hasattr(self.llm_manager, "make_request")

    def test_repo_obj_creation(self):
        """Тест создания RepoObj с корректными параметрами"""
        from src.LeakObj import RepoObj

        test_response = {
            "html_url": "https://github.com/test-user/test-repo",
            "name": "test-repo",
            "full_name": "test-user/test-repo",
            "description": "Test repository",
            "created_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-06-15T14:20:00Z",
            "owner": {"login": "test-user", "type": "User"},
        }

        repo_obj = RepoObj(
            url="https://github.com/test-user/test-repo", responce=test_response, dork="api_key", company_id=1
        )

        assert repo_obj is not None
        assert repo_obj.repo_name == "test-user/test-repo"
        assert repo_obj.dork == "api_key"
        assert repo_obj.company_id == 1

    def test_ai_obj_creation(self):
        """Тест создания AIObj через LeakObj"""
        from src.LeakObj import RepoObj

        test_response = {
            "html_url": "https://github.com/test-user/test-repo",
            "name": "test-repo",
            "full_name": "test-user/test-repo",
            "description": "Test repository",
            "owner": {"login": "test-user"},
        }

        repo_obj = RepoObj(url="https://github.com/test-user/test-repo", responce=test_response, dork="api_key")

        # Устанавливаем тестовые секреты
        repo_obj.secrets = {"api_key": "test-key-123"}

        # Создаем AI объект
        repo_obj._create_ai_obj()

        assert repo_obj.ai_obj is not None
        assert hasattr(repo_obj.ai_obj, "ai_result")
        assert hasattr(repo_obj.ai_obj, "ai_report")  # Уже добавлено в AIObj
        assert hasattr(repo_obj.ai_obj, "ai_analysis")  # Основной атрибут
        # llm_manager - это property, проверяем через callable
        assert hasattr(type(repo_obj.ai_obj), "llm_manager")

    def test_company_info_integration(self):
        """Тест интеграции информации о компании"""
        from src.LeakObj import RepoObj

        test_response = {
            "html_url": "https://github.com/test-user/test-repo",
            "name": "test-repo",
            "owner": {"login": "test-user"},
        }

        repo_obj = RepoObj(url="https://github.com/test-user/test-repo", responce=test_response, dork="google")

        company_info = {
            "name": "Google",
            "keywords": ["google", "gmail", "android"],
            "domains": ["google.com", "gmail.com"],
            "country": "us",
        }

        repo_obj.set_company_info(company_info)

        assert repo_obj.company_info == company_info

        # Создаем AI объект и проверяем передачу информации о компании
        repo_obj._create_ai_obj()
        assert repo_obj.ai_obj.company_info == company_info

    def test_ai_analysis_methods(self):
        """Тест методов AI-анализа"""
        from src.LeakObj import RepoObj

        test_response = {
            "html_url": "https://github.com/test-user/test-repo",
            "name": "test-repo",
            "owner": {"login": "test-user"},
        }

        repo_obj = RepoObj(url="https://github.com/test-user/test-repo", responce=test_response, dork="api_key")

        repo_obj.secrets = {"secrets": ["API_KEY=test123"]}
        repo_obj._create_ai_obj()

        # Проверяем наличие методов анализа
        assert hasattr(repo_obj.ai_obj, "ai_request")
        assert hasattr(repo_obj.ai_obj, "analyze_leak_comprehensive")
        assert hasattr(repo_obj.ai_obj, "get_comprehensive_analysis")
        assert hasattr(repo_obj.ai_obj, "get_analysis_summary")

    def test_aiobj_parsing_and_normalization(self):
        """????????? ?????? JSON ? code fence ? ???????????? ??????"""
        from src.AIObj import AIObj

        ai_obj = AIObj(
            secrets={},
            stats_data={},
            leak_info={
                "repo_name": "demo",
                "author": "tester",
                "dork": "demo",
                "created_at": "2024-01-01",
                "updated_at": "2024-01-02",
                "contributers": [],
                "commiters": [],
            },
        )

        content = '```json\n{"company_relevance": {"is_related": true, "confidence": 0.9}}\n```'
        parsed = ai_obj._parse_llm_json(content)
        assert parsed is not None

        normalized = ai_obj._normalize_analysis(parsed)
        assert normalized["company_relevance"]["is_related"] is True
        assert normalized["company_relevance"]["confidence"] == 0.9

    def test_safe_generate_without_tokenizer(self):
        """??????????, ??? safe_generate ???????? ??? tiktoken"""
        from src.AIObj import AIObj

        ai_obj = AIObj(
            secrets={},
            stats_data={},
            leak_info={
                "repo_name": "demo",
                "author": "tester",
                "dork": "demo",
                "created_at": "2024-01-01",
                "updated_at": "2024-01-02",
                "contributers": [],
                "commiters": [],
            },
        )
        ai_obj.tokenizer = None  # ????????? ?????????? tiktoken

        prompt, max_tokens = ai_obj.safe_generate("test" * 500, ctx_size=200, max_new_tokens=50, safety_margin=10)
        assert max_tokens == 50
        assert len(prompt) <= 140

    @pytest.mark.live
    def test_live_llm_request(self, request):
        """Тест реального запроса к LLM (только с флагом --run-live)"""
        # Пропускаем тест если не указан флаг --run-live
        if not request.config.getoption("--run-live", default=False):
            pytest.skip("Требуется флаг --run-live для выполнения реальных API запросов")

        if not self.llm_manager.providers:
            pytest.skip("Нет доступных LLM провайдеров")

        available_provider = self.llm_manager.get_available_provider()
        if not available_provider:
            pytest.skip("Нет доступных провайдеров для тестирования")

        test_prompt = "Please respond with exactly 'TEST SUCCESSFUL' to confirm API connectivity."

        try:
            messages = [{"role": "user", "content": test_prompt}]
            response = self.llm_manager.make_request(messages)
            assert response is not None
            assert len(response) > 0
            print(f"LLM ответ получен: {response[:50]}...")

        except Exception as e:
            pytest.fail(f"Ошибка реального API запроса: {str(e)}")

    def test_full_ai_analysis_workflow(self):
        """Тест полного workflow AI-анализа (без реальных API вызовов)"""
        from src.LeakObj import RepoObj

        # Создаем полный тестовый объект
        test_response = {
            "html_url": "https://github.com/test-user/leaked-secrets",
            "name": "leaked-secrets",
            "full_name": "test-user/leaked-secrets",
            "description": "Repository with potential leaks",
            "created_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-06-15T14:20:00Z",
            "size": 1500,
            "stargazers_count": 3,
            "forks_count": 1,
            "owner": {"login": "test-user"},
        }

        repo_obj = RepoObj(
            url="https://github.com/test-user/leaked-secrets",
            responce=test_response,
            dork="api_key OR secret",
            company_id=1,
        )

        # Устанавливаем найденные секреты
        repo_obj.secrets = {
            "api_keys": ["OPENAI_API_KEY=sk-test123", "AWS_KEY=AKIA123"],
            "passwords": ["PASSWORD=secret123"],
        }

        # Устанавливаем информацию о компании
        company_info = {"name": "TestCorp", "keywords": ["testcorp", "test"], "domains": ["testcorp.com"]}
        repo_obj.set_company_info(company_info)

        # Создаем AI объект
        repo_obj._create_ai_obj()

        # Проверяем, что все данные корректно переданы
        assert repo_obj.ai_obj is not None
        assert repo_obj.ai_obj.company_info == company_info
        assert repo_obj.ai_obj.processed_data["secrets"] == repo_obj.secrets

        # Тестируем комплексный анализ (заглушка)
        analysis = repo_obj.ai_obj.analyze_leak_comprehensive()
        # Анализ может вернуть None если нет провайдеров, это нормально
        if analysis is not None:
            assert "company_relevance" in analysis
            assert "classification" in analysis
            assert "severity_assessment" in analysis
            assert "summary" in analysis
            assert "recommendations" in analysis
            assert "is_related" in analysis["company_relevance"]
            assert "confidence" in analysis["company_relevance"]

    def test_write_obj_with_ai_data(self):
        """Тест записи объекта с AI данными"""
        from src.LeakObj import RepoObj

        test_response = {
            "html_url": "https://github.com/test-user/test-repo",
            "name": "test-repo",
            "owner": {"login": "test-user"},
        }

        repo_obj = RepoObj(url="https://github.com/test-user/test-repo", responce=test_response, dork="test")

        repo_obj.secrets = {"test": "data"}

        # Мокируем stats для избежания AttributeError с coll_stats_getted
        repo_obj.stats.coll_stats_getted = True
        repo_obj.stats.comm_stats_getted = True
        repo_obj.stats.repo_stats_getted = True

        repo_obj._create_ai_obj()

        # Имитируем результаты AI анализа
        repo_obj.ai_obj.ai_result = 1
        repo_obj.ai_obj.ai_analysis = (
            "{\n"
            "  'company_relevance': { 'is_related': bool, 'confidence': 0.5 },\n"
            "  'severity_assessment': { 'level': str, 'score': 0.5 },\n"
            "  'classification': { 'true_positive_probability': 0.5 },\n"
            "  'summary': str,\n"
            "  'recommendations': str\n"
            "}."
        )

        # Генерируем данные для БД
        obj_data = repo_obj.write_obj()

        assert obj_data is not None
        assert len(obj_data) > 0

        # Проверяем, что AI данные включены в результат
        # (конкретная проверка зависит от структуры write_obj)


def test_env_variables_loading():
    """Тест загрузки переменных окружения"""
    from src import constants

    # Проверяем, что функция загрузки существует
    assert hasattr(constants, "load_env_variables")
    assert hasattr(constants, "env_variables")

    # Проверяем структуру env_variables
    assert isinstance(constants.env_variables, dict)


def test_backward_compatibility():
    """Тест обратной совместимости с существующим кодом"""
    from src import constants

    # Проверяем, что старые конфигурации все еще доступны
    assert hasattr(constants, "AI_CONFIG")
    assert "ai_enable" in constants.AI_CONFIG
    assert "token_limit" in constants.AI_CONFIG


def pytest_configure(config):
    """Конфигурация pytest"""
    config.addinivalue_line("markers", "live: mark test as requiring live API calls")


def pytest_addoption(parser):
    """Добавление опций командной строки"""
    parser.addoption("--run-live", action="store_true", default=False, help="Запустить тесты с реальными API вызовами")


if __name__ == "__main__":
    # Запуск как обычный Python скрипт для демонстрации
    print("🚀 Для запуска pytest тестов используйте:")
    print("   pytest test/test_ai_analysis.py -v")
    print("   pytest test/test_ai_analysis.py -v --run-live  # для тестов с API")
    print("\n⚡ Запуск быстрой демонстрации...")

    # Быстрая демонстрация основной функциональности
    try:
        from src import constants
        from src.LeakObj import RepoObj
        from src.AIObj import llm_manager

        print("✅ Модули загружены")
        print(f"📊 LLM провайдеров в конфигурации: {len(constants.LLM_PROVIDERS)}")
        print(f"🔧 Инициализированных провайдеров: {len(llm_manager.providers)}")
        print(f"⚙️ AI анализ: {'✅ Включен' if constants.AI_ANALYSIS_ENABLED else '❌ Выключен'}")

        # Создание тестового объекта
        test_response = {"html_url": "https://github.com/test/repo", "owner": {"login": "test"}}
        repo_obj = RepoObj(url="https://github.com/test/repo", responce=test_response, dork="test")
        repo_obj.secrets = {"test": "data"}
        repo_obj._create_ai_obj()

        print("✅ LeakObj создан и AI объект инициализирован")
        print("🎉 Все базовые компоненты работают корректно!")

    except Exception as e:
        print(f"❌ Ошибка в демонстрации: {e}")
        import traceback

        traceback.print_exc()
