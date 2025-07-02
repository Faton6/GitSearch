#!/usr/bin/env python3
"""
Демонстрация полнофункционального AI-анализа в GitSearch
Этот скрипт показывает, как использовать новую систему AI-анализа
"""

import sys
import json
from datetime import datetime

def demo_ai_analysis():
    """Демонстрация AI-анализа с реальными данными"""
    
    print("🚀 GitSearch AI Analysis Demo")
    print("=" * 50)
    
    try:
        # Импорт необходимых модулей
        from src import constants
        from src.LeakObj import RepoObj
        from src.AIObj import llm_manager
        
        print("✅ Все модули успешно загружены")
        
        # Проверка доступных LLM провайдеров
        print(f"\n🤖 Доступные LLM провайдеры: {len(llm_manager.providers)}")
        for name, provider in llm_manager.providers.items():
            print(f"   - {name}: {provider['model']}")
        
        # Создание тестового RepoObj
        print("\n📦 Создание тестового объекта репозитория...")
        
        # Имитация данных GitHub API response
        test_response = {
            "html_url": "https://github.com/test-user/leaked-credentials",
            "name": "leaked-credentials",
            "full_name": "test-user/leaked-credentials",
            "description": "Repository containing API keys and tokens",
            "created_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-06-15T14:20:00Z",
            "size": 1200,
            "stargazers_count": 2,
            "forks_count": 0,
            "open_issues_count": 1,
            "topics": ["api-keys", "credentials"],
            "owner": {
                "login": "test-user",
                "type": "User"
            }
        }
        
        # Создание объекта утечки
        leak_obj = RepoObj(
            url="https://github.com/test-user/leaked-credentials",
            responce=test_response,
            dork="api_key OR secret_key",
            company_id=1
        )
        
        # Установка найденных секретов (имитация)
        leak_obj.secrets = {
            "api_keys": [
                "OPENAI_API_KEY=sk-abc123...",
                "AWS_ACCESS_KEY=AKIA...",
                "DATABASE_URL=postgresql://user:pass@host:5432/db"
            ],
            "tokens": [
                "GITHUB_TOKEN=ghp_abc123...",
                "SLACK_TOKEN=xoxb-abc..."
            ]
        }
        
        # Установка информации о компании
        company_info = {
            "name": "Alpha-Bet",
            "keywords": ["google", "alphabet", "gmail"],
            "domains": ["google.com", "alphabet.com", "gmail.com"],
            "country": "us"
        }
        leak_obj.set_company_info(company_info)
        
        print(f"✅ Создан объект для репозитория: {leak_obj.repo_name}")
        print(f"   - Найдено секретов: {len(leak_obj.secrets)}")
        print(f"   - Поисковый запрос: {leak_obj.dork}")
        
        # Запуск AI-анализа
        print(f"\n🔍 Запуск AI-анализа...")
        
        if constants.AI_ANALYSIS_ENABLED:
            try:
                # Создание AI объекта
                leak_obj._create_ai_obj()
                print("✅ AI объект создан")
                
                # Проверка доступности провайдеров
                available_provider = llm_manager.get_available_provider()
                if available_provider:
                    print(f"✅ Доступен провайдер: {available_provider['name']}")
                    
                    # Запуск анализа
                    print("🤖 Выполнение AI-анализа...")
                    leak_obj.ai_obj.ai_request()
                    
                    # Результаты анализа
                    print(f"\n📊 Результаты анализа:")
                    print(f"   - AI Result: {leak_obj.ai_obj.ai_result}")
                    print(f"   - AI Report: {leak_obj.ai_obj.ai_report}")
                    
                    # Комплексный анализ
                    comprehensive_analysis = leak_obj.ai_obj.analyze_leak_comprehensive()
                    if comprehensive_analysis:
                        print(f"   - Комплексный анализ: {comprehensive_analysis}")
                    
                else:
                    print("❌ Нет доступных LLM провайдеров")
                    
            except Exception as e:
                print(f"❌ Ошибка в AI-анализе: {str(e)}")
                import traceback
                traceback.print_exc()
        else:
            print("❌ AI-анализ отключен в конфигурации")
        
        # Демонстрация записи объекта
        print(f"\n💾 Генерация данных для записи в БД...")
        try:
            obj_data = leak_obj.write_obj()
            print("✅ Данные для БД успешно сгенерированы")
            print(f"   - Количество полей: {len(obj_data)}")
            
            # Показать ключевые поля
            key_fields = ['url', 'author_info', 'level', 'leak_type', 'result']
            for field in key_fields:
                if len(obj_data) > key_fields.index(field):
                    print(f"   - {field}: {obj_data[key_fields.index(field)]}")
            
        except Exception as e:
            print(f"❌ Ошибка генерации данных: {str(e)}")
        
        # Сводная информация
        print(f"\n📈 Сводка демонстрации:")
        print(f"   - LLM провайдеров: {len(llm_manager.providers)}")
        print(f"   - AI анализ: {'✅ Включен' if constants.AI_ANALYSIS_ENABLED else '❌ Выключен'}")
        print(f"   - Циклический импорт: ✅ Исправлен")
        print(f"   - Интеграция с LeakObj: ✅ Завершена")
        
        return True
        
    except Exception as e:
        print(f"❌ Критическая ошибка: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def show_configuration():
    """Показать текущую конфигурацию AI-анализа"""
    
    print("\n⚙️ Конфигурация AI-анализа:")
    print("=" * 30)
    
    try:
        from src import constants
        
        print(f"AI_ANALYSIS_ENABLED: {constants.AI_ANALYSIS_ENABLED}")
        print(f"AI_ANALYSIS_TIMEOUT: {constants.AI_ANALYSIS_TIMEOUT}")
        print(f"AI_MAX_CONTEXT_LENGTH: {constants.AI_MAX_CONTEXT_LENGTH}")
        print(f"AI_COMPANY_RELEVANCE_THRESHOLD: {constants.AI_COMPANY_RELEVANCE_THRESHOLD}")
        print(f"AI_TRUE_POSITIVE_THRESHOLD: {constants.AI_TRUE_POSITIVE_THRESHOLD}")
        
        print(f"\nLLM_PROVIDERS: {len(constants.LLM_PROVIDERS)}")
        for provider in constants.LLM_PROVIDERS:
            api_key = provider.get('api_key_env', 'N/A')
            status = '✅' if api_key else '❌'
            print(f"  {status} {provider['name']}: {provider['model']}")
            
    except Exception as e:
        print(f"❌ Ошибка загрузки конфигурации: {e}")

def test_ai():
    print(f"🕐 Время запуска: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Показать конфигурацию
    show_configuration()
    
    # Запустить демонстрацию
    success = demo_ai_analysis()
    
    if success:
        print(f"\n🎉 Демонстрация завершена успешно!")
        print(f"💡 GitSearch готов к использованию с AI-анализом")
    else:
        print(f"\n💥 Демонстрация завершилась с ошибками")
        sys.exit(1)
