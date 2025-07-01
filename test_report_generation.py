#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тестовый скрипт для проверки генерации отчетов GitSearch
"""

import os
import sys
import json
from datetime import datetime, timedelta

# Добавляем корневую папку проекта в путь
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src import reports, Connector, constants

def test_database_connection():
    """Тестирует подключение к базе данных"""
    print("🔗 Тестирование подключения к базе данных...")
    
    try:
        conn, cursor = Connector.connect_to_database()
        if conn and cursor:
            print("✅ Подключение к базе данных успешно!")
            
            # Проверяем наличие таблиц
            cursor.execute("SHOW TABLES")
            tables = cursor.fetchall()
            print(f"📊 Найдено таблиц: {len(tables)}")
            for table in tables:
                print(f"   - {table[0]}")
            
            # Проверяем данные в таблице leak
            cursor.execute("SELECT COUNT(*) FROM leak")
            leak_count = cursor.fetchone()[0]
            print(f"🔍 Записей в таблице leak: {leak_count}")
            
            if leak_count > 0:
                cursor.execute("SELECT MIN(DATE(created_at)), MAX(DATE(created_at)) FROM leak")
                date_range = cursor.fetchone()
                print(f"📅 Диапазон дат: {date_range[0]} - {date_range[1]}")
                
                # Показываем несколько примеров записей
                cursor.execute("SELECT url, leak_type, level, created_at FROM leak LIMIT 5")
                samples = cursor.fetchall()
                print("🔎 Примеры записей:")
                for sample in samples:
                    print(f"   - {sample[0]} | {sample[1]} | Уровень: {sample[2]} | {sample[3]}")
            
            conn.close()
            return True
            
    except Exception as e:
        print(f"❌ Ошибка подключения к базе данных: {e}")
        return False

def test_report_generation():
    """Тестирует генерацию отчетов"""
    print("\n📊 Тестирование генерации отчетов...")
    
    try:
        # Определяем период для отчета (последние 30 дней)
        end_date = datetime.now().strftime('%Y-%m-%d')
        start_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        
        print(f"📅 Период отчета: {start_date} - {end_date}")
        
        # Генерируем бизнес-отчет
        print("\n🏢 Генерация бизнес-отчета...")
        try:
            business_report = reports.generate_report(
                start_date=start_date,
                end_date=end_date,
                report_type="business"
            )
            print("✅ Бизнес-отчет успешно сгенерирован!")
            print(f"📁 Файл сохранен: {business_report.get('path', 'не указан')}")
            
            # Выводим основную статистику
            print("\n📈 Основная статистика:")
            print(f"   - Всего утечек: {business_report.get('total_leaks', 0)}")
            print(f"   - Средняя серьезность: {business_report.get('average_severity', 0):.2f}")
            print(f"   - Уникальных компаний: {business_report.get('unique_companies', 0)}")
            print(f"   - Высокосерьезных утечек: {business_report.get('high_severity_count', 0)}")
            print(f"   - Успешных сканирований: {business_report.get('successful_scans', 0)}")
            
        except Exception as e:
            print(f"❌ Ошибка генерации бизнес-отчета: {e}")
        
        # Генерируем технический отчет
        print("\n🔧 Генерация технического отчета...")
        try:
            technical_report = reports.generate_report(
                start_date=start_date,
                end_date=end_date,
                report_type="technical"
            )
            print("✅ Технический отчет успешно сгенерирован!")
            print(f"📁 Файл сохранен: {technical_report.get('path', 'не указан')}")
            
            # Выводим дополнительную техническую статистику
            print("\n🔧 Техническая статистика:")
            print(f"   - Отчетов с ошибками: {technical_report.get('error_reports', 0)}")
            print(f"   - Успешных отчетов: {technical_report.get('successful_reports', 0)}")
            print(f"   - Ошибок 'слишком большой репозиторий': {technical_report.get('too_large_repo_errors', 0)}")
            
            leak_stats = technical_report.get('leak_stats_summary', {})
            print(f"   - Средний размер репозитория: {leak_stats.get('avg_size', 0):.2f}")
            print(f"   - Среднее количество форков: {leak_stats.get('avg_forks', 0):.2f}")
            print(f"   - Среднее количество звезд: {leak_stats.get('avg_stars', 0):.2f}")
            
        except Exception as e:
            print(f"❌ Ошибка генерации технического отчета: {e}")
            
    except Exception as e:
        print(f"❌ Общая ошибка тестирования отчетов: {e}")

def test_with_specific_dates():
    """Тестирует генерацию отчета для конкретных дат из конфига"""
    print("\n📅 Тестирование с датами из конфига...")
    
    try:
        # Загружаем конфигурацию
        config_path = os.path.join(os.path.dirname(__file__), 'config.json')
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        start_date = config.get('start_date', '2025-06-19')
        end_date = config.get('end_date', '2025-06-19')
        report_type = config.get('report_type', 'business')
        
        print(f"📊 Генерация {report_type} отчета для {start_date} - {end_date}")
        
        report_result = reports.generate_report(
            start_date=start_date,
            end_date=end_date,
            report_type=report_type
        )
        
        print("✅ Отчет для конкретных дат успешно сгенерирован!")
        print(f"📁 Файл: {report_result.get('path', 'не указан')}")
        
        # Выводим краткую статистику
        print(f"📈 Всего утечек за период: {report_result.get('total_leaks', 0)}")
        
    except Exception as e:
        print(f"❌ Ошибка тестирования с конкретными датами: {e}")

def check_report_files():
    """Проверяет существующие файлы отчетов"""
    print("\n📁 Проверка существующих файлов отчетов...")
    
    reports_dir = os.path.join(constants.MAIN_FOLDER_PATH, "reports")
    
    if os.path.exists(reports_dir):
        files = os.listdir(reports_dir)
        html_files = [f for f in files if f.endswith('.html')]
        
        print(f"📊 Найдено HTML отчетов: {len(html_files)}")
        for file in html_files:
            file_path = os.path.join(reports_dir, file)
            file_size = os.path.getsize(file_path)
            file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
            print(f"   - {file} ({file_size} байт, {file_time.strftime('%Y-%m-%d %H:%M:%S')})")
    else:
        print("📁 Директория отчетов не существует")

def test_full_period_report():
    """Генерирует отчет за весь период с первой утечки в базе"""
    print("\n🗓️ Генерация отчета за весь период...")
    
    try:
        # Получаем диапазон дат из базы данных
        conn, cursor = Connector.connect_to_database()
        if not conn or not cursor:
            print("❌ Не удалось подключиться к базе данных")
            return
        
        cursor.execute("SELECT MIN(DATE(created_at)), MAX(DATE(created_at)) FROM leak")
        date_range = cursor.fetchone()
        conn.close()
        
        if not date_range or not date_range[0]:
            print("❌ Не удалось получить диапазон дат из базы")
            return
        
        start_date = str(date_range[0])
        end_date = str(date_range[1])
        
        print(f"📅 Полный период: {start_date} - {end_date}")
        
        # Генерируем бизнес-отчет за весь период
        print("\n🏢 Генерация бизнес-отчета за весь период...")
        try:
            business_report = reports.generate_report(
                start_date=start_date,
                end_date=end_date,
                report_type="business"
            )
            print("✅ Полный бизнес-отчет успешно сгенерирован!")
            print(f"📁 Файл: {business_report.get('path', 'не указан')}")
            
            # Выводим статистику за весь период
            print("\n📊 Статистика за весь период:")
            print(f"   - Всего утечек: {business_report.get('total_leaks', 0)}")
            print(f"   - Средняя серьезность: {business_report.get('average_severity', 0):.2f}")
            print(f"   - Уникальных компаний: {business_report.get('unique_companies', 0)}")
            print(f"   - Высокосерьезных утечек: {business_report.get('high_severity_count', 0)}")
            print(f"   - Успешных сканирований: {business_report.get('successful_scans', 0)}")
            
        except Exception as e:
            print(f"❌ Ошибка генерации полного бизнес-отчета: {e}")
        
        # Генерируем технический отчет за весь период
        print("\n🔧 Генерация технического отчета за весь период...")
        try:
            technical_report = reports.generate_report(
                start_date=start_date,
                end_date=end_date,
                report_type="technical"
            )
            print("✅ Полный технический отчет успешно сгенерирован!")
            print(f"📁 Файл: {technical_report.get('path', 'не указан')}")
            
            # Выводим техническую статистику за весь период
            print("\n🔧 Техническая статистика за весь период:")
            print(f"   - Отчетов с ошибками: {technical_report.get('error_reports', 0)}")
            print(f"   - Успешных отчетов: {technical_report.get('successful_reports', 0)}")
            print(f"   - Ошибок 'слишком большой репозиторий': {technical_report.get('too_large_repo_errors', 0)}")
            
            leak_stats = technical_report.get('leak_stats_summary', {})
            print(f"   - Средний размер репозитория: {leak_stats.get('avg_size', 0):.2f}")
            print(f"   - Среднее количество форков: {leak_stats.get('avg_forks', 0):.2f}")
            print(f"   - Среднее количество звезд: {leak_stats.get('avg_stars', 0):.2f}")
            
        except Exception as e:
            print(f"❌ Ошибка генерации полного технического отчета: {e}")
            
    except Exception as e:
        print(f"❌ Общая ошибка генерации отчета за весь период: {e}")

def main():
    """Основная функция тестирования"""
    print("🚀 Запуск тестирования генерации отчетов GitSearch")
    print("=" * 60)
    
    # 1. Тестируем подключение к БД
    if not test_database_connection():
        print("❌ Не удалось подключиться к базе данных. Завершение тестирования.")
        return
    
    # 2. Проверяем существующие отчеты
    check_report_files()
    
    # 3. Тестируем генерацию отчетов
    test_report_generation()
    
    # 4. Тестируем с датами из конфига
    test_with_specific_dates()
    
    # 5. Генерируем отчет за весь период
    test_full_period_report()
    
    print("\n" + "=" * 60)
    print("✅ Тестирование завершено!")

if __name__ == "__main__":
    main()
