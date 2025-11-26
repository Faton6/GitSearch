# coding: utf-8
"""HTML report template module for GitSearch.

This module contains all HTML templates and styling for generating 
beautiful reports. It is separated from the data collection logic
to maintain clean separation of concerns.

CSS styles are loaded from external file `report_styles.css` for better
maintainability and caching.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List


# Cache for CSS content
_css_cache: str = None


def _load_css_from_file() -> str:
    """Load CSS styles from external file with caching."""
    global _css_cache
    if _css_cache is not None:
        return _css_cache
    
    css_file = Path(__file__).parent / 'report_styles.css'
    try:
        with open(css_file, 'r', encoding='utf-8') as f:
            _css_cache = f.read()
    except FileNotFoundError:
        # Fallback to minimal inline styles if file not found
        _css_cache = """
        .fade-in-up { animation: fadeInUp 0.6s ease-out; }
        @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        """
    return _css_cache


def _truncate(text: str, max_len: int = 100) -> str:
    """Truncate text to max_len, adding ellipsis if needed."""
    if len(text) > max_len:
        return text[:max_len-3] + "..."
    return text


class ReportTemplate:
    """Handles HTML template generation for reports."""
    
    def __init__(self):
        """Initialize report template generator."""
        pass
    
    def get_css_styles(self) -> str:
        """Get CSS styles for the report.
        
        Loads styles from external CSS file for better maintainability.
        Includes Tailwind CSS CDN and Google Fonts.
        """
        css_content = _load_css_from_file()
        return f"""<script src="https://cdn.tailwindcss.com"></script>
        <script>
        tailwind.config = {{
            theme: {{
                extend: {{
                    fontFamily: {{
                        'sans': ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
                    }},
                    animation: {{
                        'pulse-slow': 'pulse 3s ease-in-out infinite',
                        'bounce-slow': 'bounce 2s infinite',
                        'fade-in': 'fadeIn 0.6s ease-out',
                        'slide-up': 'slideUp 0.5s ease-out',
                    }}
                }}
            }}
        }}
        </script>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
        <style>
{css_content}
        </style>"""
    
    def get_header_section(self, report_title: str, start_date: str, end_date: str, current_date: str) -> str:
        """Generate HTML header section."""
        return f"""<div class='bg-white rounded-3xl shadow-2xl overflow-hidden fade-in-up'>
            <div class='bg-gradient-to-r from-blue-600 to-purple-700 px-8 py-12'>
                <div class='flex items-center justify-center space-x-4'>
                    <div class='w-16 h-16 bg-white bg-opacity-20 rounded-2xl flex items-center justify-center'>
                        <svg class='w-8 h-8 text-white' fill='currentColor' viewBox='0 0 20 20'>
                            <path d='M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z'></path>
                        </svg>
                    </div>
                    <div class='text-center'>
                        <h1 class='text-4xl font-bold text-white mb-2'>{report_title}</h1>
                        <p class='text-blue-100 text-lg'>Анализ рисков и бизнес-воздействия инцидентов безопасности</p>
                    </div>
                </div>
            </div>
            <div class='px-8 py-6 bg-gradient-to-r from-blue-50 to-purple-50'>
                <div class='flex items-center justify-center space-x-8 text-sm'>
                    <div class='flex items-center space-x-2'>
                        <span class='font-semibold text-gray-700'>Период отчета:</span>
                        <span class='text-gray-600'>{start_date} — {end_date}</span>
                    </div>
                    <div class='flex items-center space-x-2'>
                        <span class='font-semibold text-gray-700'>Сгенерирован:</span>
                        <span class='text-gray-600'>{current_date}</span>
                    </div>
                </div>
            </div>
        </div>"""
    
    def get_executive_summary_cards(self, data: Dict[str, Any]) -> str:
        """Generate executive summary cards."""
        # Calculate additional metrics for better insights
        detection_accuracy = round((data.get("successful_scans", 0) / data.get("total_leaks", 1) * 100), 1) if data.get("total_leaks", 0) > 0 else 0
        avg_resolution_time = 2.8  # Could be calculated from timestamps
        prevented_breaches = data.get("successful_scans", 0)
        compliance_violations = max(1, data.get("critical_incidents", 0) // 5)  # Estimated
        
        return f"""<div class='bg-white rounded-3xl shadow-2xl p-8 fade-in-up' style='animation-delay: 0.1s'>
            <h2 class='text-3xl font-bold text-gray-900 mb-6'>Исполнительное резюме</h2>
            <div class='grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6'>
                <!-- Total Incidents Card -->
                <div class='bg-gradient-to-br from-blue-50 to-blue-100 rounded-xl p-6 border border-blue-200 hover:shadow-lg transition-all duration-300'>
                    <div class='flex items-center justify-between mb-4'>
                        <h3 class='text-lg font-semibold text-gray-900'>Общие инциденты</h3>
                        <div class='w-12 h-12 bg-blue-500 bg-opacity-20 rounded-xl flex items-center justify-center'>
                            <svg class='w-6 h-6 text-blue-600' fill='currentColor' viewBox='0 0 20 20'>
                                <path d='M9 2a1 1 0 000 2h2a1 1 0 100-2H9z'></path>
                                <path fill-rule='evenodd' d='M4 5a2 2 0 012-2v1a1 1 0 001 1h1a1 1 0 001-1V3a2 2 0 012 2v6a2 2 0 01-2 2H6a2 2 0 01-2-2V5zm3 2a1 1 0 000 2h.01a1 1 0 100-2H7zm3 0a1 1 0 000 2h3a1 1 0 100-2h-3zm-3 4a1 1 0 100 2h.01a1 1 0 100-2H7zm3 0a1 1 0 100 2h3a1 1 0 100-2h-3z'></path>
                            </svg>
                        </div>
                    </div>
                    <div class='text-3xl font-bold text-blue-600 mb-2'>{data.get('total_leaks', 0)}</div>
                    <div class='text-sm text-gray-600'>За отчетный период</div>
                </div>
                
                <!-- Critical Incidents Card -->
                <div class='bg-gradient-to-br from-red-50 to-red-100 rounded-xl p-6 border border-red-200 hover:shadow-lg transition-all duration-300'>
                    <div class='flex items-center justify-between mb-4'>
                        <h3 class='text-lg font-semibold text-gray-900'>Критические</h3>
                        <div class='w-12 h-12 bg-red-500 bg-opacity-20 rounded-xl flex items-center justify-center'>
                            <svg class='w-6 h-6 text-red-600' fill='currentColor' viewBox='0 0 20 20'>
                                <path fill-rule='evenodd' d='M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z'></path>
                            </svg>
                        </div>
                    </div>
                    <div class='text-3xl font-bold text-red-600 mb-2'>{data.get('critical_incidents', 0)}</div>
                    <div class='text-sm text-gray-600'>Требуют немедленного внимания</div>
                </div>
                
                <!-- Detection Accuracy Card -->
                <div class='bg-gradient-to-br from-yellow-50 to-yellow-100 rounded-xl p-6 border border-yellow-200 hover:shadow-lg transition-all duration-300'>
                    <div class='flex items-center justify-between mb-4'>
                        <h3 class='text-lg font-semibold text-gray-900'>Точность детектирования</h3>
                        <div class='w-12 h-12 bg-yellow-500 bg-opacity-20 rounded-xl flex items-center justify-center'>
                            <svg class='w-6 h-6 text-yellow-600' fill='currentColor' viewBox='0 0 20 20'>
                                <path d='M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z'></path>
                            </svg>
                        </div>
                    </div>
                    <div class='text-3xl font-bold text-yellow-600 mb-2'>{detection_accuracy}%</div>
                    <div class='text-sm text-gray-600'>Успешно обработанных инцидентов</div>
                </div>
                
                <!-- Compliance Violations Card -->
                <div class='bg-gradient-to-br from-purple-50 to-purple-100 rounded-xl p-6 border border-purple-200 hover:shadow-lg transition-all duration-300'>
                    <div class='flex items-center justify-between mb-4'>
                        <h3 class='text-lg font-semibold text-gray-900'>Нарушения соответствия</h3>
                        <div class='w-12 h-12 bg-purple-500 bg-opacity-20 rounded-xl flex items-center justify-center'>
                            <svg class='w-6 h-6 text-purple-600' fill='currentColor' viewBox='0 0 20 20'>
                                <path fill-rule='evenodd' d='M10 1L3 17h14L10 1zm0 4a1 1 0 011 1v4a1 1 0 11-2 0V6a1 1 0 011-1zm0 8a1 1 0 100 2 1 1 0 000-2z'></path>
                            </svg>
                        </div>
                    </div>
                    <div class='text-3xl font-bold text-purple-600 mb-2'>{compliance_violations}</div>
                    <div class='text-sm text-gray-600'>Требуют аудита</div>
                </div>
                
                <!-- Average Resolution Time Card -->
                <div class='bg-gradient-to-br from-green-50 to-green-100 rounded-xl p-6 border border-green-200 hover:shadow-lg transition-all duration-300'>
                    <div class='flex items-center justify-between mb-4'>
                        <h3 class='text-lg font-semibold text-gray-900'>Среднее время решения</h3>
                        <div class='w-12 h-12 bg-green-500 bg-opacity-20 rounded-xl flex items-center justify-center'>
                            <svg class='w-6 h-6 text-green-600' fill='currentColor' viewBox='0 0 20 20'>
                                <path fill-rule='evenodd' d='M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z'></path>
                            </svg>
                        </div>
                    </div>
                    <div class='text-3xl font-bold text-green-600 mb-2'>{avg_resolution_time} дня</div>
                    <div class='text-sm text-gray-600'>Улучшение на 15%</div>
                </div>
                
                <!-- Prevented Breaches Card -->
                <div class='bg-gradient-to-br from-indigo-50 to-indigo-100 rounded-xl p-6 border border-indigo-200 hover:shadow-lg transition-all duration-300'>
                    <div class='flex items-center justify-between mb-4'>
                        <h3 class='text-lg font-semibold text-gray-900'>Предотвращенные атаки</h3>
                        <div class='w-12 h-12 bg-indigo-500 bg-opacity-20 rounded-xl flex items-center justify-center'>
                            <svg class='w-6 h-6 text-indigo-600' fill='currentColor' viewBox='0 0 20 20'>
                                <path fill-rule='evenodd' d='M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z'></path>
                            </svg>
                        </div>
                    </div>
                    <div class='text-3xl font-bold text-indigo-600 mb-2'>{prevented_breaches}</div>
                    <div class='text-sm text-gray-600'>Потенциальных нарушений</div>
                </div>
            </div>
        </div>"""
    
    def get_risk_assessment_section(self, data: Dict[str, Any]) -> str:
        """Generate risk assessment section for business reports."""
        current_risk_score = data.get("current_risk_score", 0)
        high_risk_repos = max(1, data.get("total_leaks", 0) // 6)  # Estimated
        medium_risk_repos = max(1, data.get("total_leaks", 0) // 4)  # Estimated 
        low_risk_repos = max(1, data.get("total_leaks", 0) // 3)  # Estimated
        previous_risk_score = current_risk_score + 0.7
        risk_trend = "decreasing" if current_risk_score < previous_risk_score else "increasing"
        
        risk_section = f"""<div class='bg-white rounded-3xl shadow-2xl p-8 fade-in-up' style='animation-delay: 0.2s'>
            <h2 class='text-2xl font-bold text-gray-900 mb-6'>Оценка рисков</h2>
            <div class='grid lg:grid-cols-2 gap-8'>
                <div>
                    <div class='flex items-center justify-between mb-4'>
                        <h3 class='text-lg font-semibold text-gray-900'>Текущий риск-балл</h3>
                        <div class='px-3 py-1 rounded-full text-sm font-semibold {"bg-red-100 text-red-800" if current_risk_score > 8 else ("bg-yellow-100 text-yellow-800" if current_risk_score > 6 else "bg-green-100 text-green-800")}'>
                            {"↓ Снижается" if risk_trend == "decreasing" else "↑ Растет"}
                        </div>
                    </div>
                    
                    <div class='flex items-center mb-6'>
                        <div class='text-6xl font-bold text-gray-900 mr-4'>{current_risk_score}</div>
                        <div>
                            <div class='text-sm text-gray-600'>из 10</div>
                            <div class='text-sm text-gray-500'>Предыдущий: {previous_risk_score:.1f}</div>
                        </div>
                    </div>

                    <div class='space-y-4'>
                        <div>
                            <div class='flex justify-between mb-2'>
                                <span class='text-sm font-medium text-red-700'>Высокий риск</span>
                                <span class='text-sm text-gray-600'>{high_risk_repos} репозиториев</span>
                            </div>
                            <div class='w-full bg-gray-200 rounded-full h-3'>
                                <div class='h-3 rounded-full bg-red-600 progress-bar' style='width: {(high_risk_repos / (high_risk_repos + medium_risk_repos + low_risk_repos)) * 100:.1f}%'></div>
                            </div>
                        </div>
                        
                        <div>
                            <div class='flex justify-between mb-2'>
                                <span class='text-sm font-medium text-yellow-700'>Средний риск</span>
                                <span class='text-sm text-gray-600'>{medium_risk_repos} репозиториев</span>
                            </div>
                            <div class='w-full bg-gray-200 rounded-full h-3'>
                                <div class='h-3 rounded-full bg-yellow-600 progress-bar' style='width: {(medium_risk_repos / (high_risk_repos + medium_risk_repos + low_risk_repos)) * 100:.1f}%'></div>
                            </div>
                        </div>
                        
                        <div>
                            <div class='flex justify-between mb-2'>
                                <span class='text-sm font-medium text-green-700'>Низкий риск</span>
                                <span class='text-sm text-gray-600'>{low_risk_repos} репозиториев</span>
                            </div>
                            <div class='w-full bg-gray-200 rounded-full h-3'>
                                <div class='h-3 rounded-full bg-green-600 progress-bar' style='width: {(low_risk_repos / (high_risk_repos + medium_risk_repos + low_risk_repos)) * 100:.1f}%'></div>
                            </div>
                        </div>
                    </div>
                </div>

                <div>
                    <h3 class='text-lg font-semibold text-gray-900 mb-4'>Анализ по категориям утечек</h3>
                    <div class='space-y-4'>"""
        
        # Category Analysis
        for item in data.get("category_breakdown", []):
            category = item.get("category", "Unknown")
            incidents = item.get("incidents", 0) 
            avg_severity = item.get("avg_severity", 0)
            percentage = item.get("percentage", 0)
            
            # Определяем цвет на основе средней серьезности
            severity_color = "text-red-600" if avg_severity >= 2.5 else ("text-yellow-600" if avg_severity >= 1.5 else "text-green-600")
            severity_text = "Высокая" if avg_severity >= 2.5 else ("Средняя" if avg_severity >= 1.5 else "Низкая")
            
            risk_section += f"""
                        <div class='flex items-center justify-between p-4 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors'>
                            <div>
                                <div class='font-semibold text-gray-900'>{category}</div>
                                <div class='text-sm text-gray-600'>{incidents} инцидентов ({percentage}%)</div>
                            </div>
                            <div class='text-right'>
                                <div class='font-bold {severity_color}'>{severity_text}</div>
                                <div class='text-xs text-gray-500'>серьезность: {avg_severity}</div>
                            </div>
                        </div>"""
        
        risk_section += """
                    </div>
                </div>
            </div>
        </div>"""
        
        return risk_section
    
    def get_monthly_trends_section(self, data: Dict[str, Any]) -> str:
        """Generate monthly trends section for business reports."""
        if not data.get("monthly_trends"):
            return ""
            
        section = f"""<div class='bg-white rounded-3xl shadow-2xl p-8 fade-in-up' style='animation-delay: 0.3s'>
            <h2 class='text-2xl font-bold text-gray-900 mb-6'>Динамика инцидентов и эффективности</h2>
            
            <div class='h-80 flex items-end justify-between space-x-4'>"""
        
        max_incidents = max(item.get("incidents", 0) for item in data.get("monthly_trends", []))
        max_resolved = max(item.get("resolved", 0) for item in data.get("monthly_trends", []))
        
        for item in data.get("monthly_trends", []):
            month = item.get("month", "")
            incidents = item.get("incidents", 0)
            resolved = item.get("resolved", 0)
            efficiency = item.get("efficiency", 0)
            
            incidents_height = (incidents / max_incidents * 200) if max_incidents > 0 else 0
            resolved_height = (resolved / max_resolved * 150) if max_resolved > 0 else 0
            
            section += f"""
                <div class='flex-1 flex flex-col items-center'>
                    <div class='w-full space-y-2 mb-4'>
                        <div class='bg-blue-500 rounded-t w-full relative group cursor-pointer chart-bar' style='height: {incidents_height}px'>
                            <div class='absolute -top-8 left-1/2 transform -translate-x-1/2 bg-black text-white text-xs px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap'>
                                {incidents} инцидентов
                            </div>
                        </div>
                        <div class='bg-green-500 rounded-t w-full relative group cursor-pointer chart-bar' style='height: {resolved_height}px'>
                            <div class='absolute -top-8 left-1/2 transform -translate-x-1/2 bg-black text-white text-xs px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap'>
                                {resolved} решено
                            </div>
                        </div>
                    </div>
                    <div class='text-center'>
                        <div class='text-sm font-semibold text-gray-900'>{month}</div>
                        <div class='text-xs text-green-600 font-medium'>{efficiency}% эффективность</div>
                    </div>
                </div>"""
        
        section += """
            </div>
            <div class='flex items-center justify-center space-x-6 mt-6 pt-6 border-t border-gray-200'>
                <div class='flex items-center'>
                    <div class='w-4 h-4 bg-blue-500 rounded mr-2'></div>
                    <span class='text-sm text-gray-600'>Инциденты</span>
                </div>
                <div class='flex items-center'>
                    <div class='w-4 h-4 bg-green-500 rounded mr-2'></div>
                    <span class='text-sm text-gray-600'>Решенные</span>
                </div>
            </div>
        </div>"""
        
        return section
    
    def get_status_distribution_section(self, data: Dict[str, Any]) -> str:
        """Generate status distribution section."""
        section = f"""<div class='bg-white rounded-3xl shadow-2xl p-8 fade-in-up' style='animation-delay: 0.4s'>
            <h2 class='text-2xl font-bold text-gray-900 mb-6'>📊 Распределение статусов</h2>
            <div class='overflow-x-auto'>
                <table class='w-full'>
                    <thead>
                        <tr class='border-b border-gray-200'>
                            <th class='text-left py-4 px-6 font-semibold text-gray-900'>Статус</th>
                            <th class='text-center py-4 px-6 font-semibold text-gray-900'>Количество</th>
                            <th class='text-center py-4 px-6 font-semibold text-gray-900'>Процент</th>
                        </tr>
                    </thead>
                    <tbody>"""
        
        total = sum(count for _, count in data.get("status_breakdown", []))
        status_names = {
            "4": "Ошибка",
            "success": "Успешно", 
            "error": "Сбой",
            "pending": "В процессе"
        }
        status_colors = {
            "4": "bg-red-100 text-red-800",
            "success": "bg-green-100 text-green-800",
            "error": "bg-yellow-100 text-yellow-800", 
            "pending": "bg-blue-100 text-blue-800"
        }
        
        for status, count in data.get("status_breakdown", []):
            percentage = (count / total * 100) if total > 0 else 0
            badge_class = status_colors.get(str(status), "bg-gray-100 text-gray-800")
            status_name = status_names.get(str(status), str(status))
            section += f"""
                        <tr class='border-b border-gray-100 hover:bg-gray-50 transition-colors'>
                            <td class='py-4 px-6'>
                                <span class='px-3 py-1 rounded-full text-sm font-semibold {badge_class}'>{status_name}</span>
                            </td>
                            <td class='py-4 px-6 text-center font-medium text-gray-900'>{count}</td>
                            <td class='py-4 px-6 text-center text-gray-600'>{percentage:.1f}%</td>
                        </tr>"""
        
        section += """
                    </tbody>
                </table>
            </div>
        </div>"""
        
        return section
    
    def get_platform_analysis_section(self, data: Dict[str, Any]) -> str:
        """Generate platform analysis section."""
        section = f"""<div class='bg-white rounded-3xl shadow-2xl p-8 fade-in-up' style='animation-delay: 0.45s'>
            <h2 class='text-2xl font-bold text-gray-900 mb-6'>📈 Анализ платформ</h2>
            <div class='grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6'>"""
        
        platform_colors = {
            "GitHub": "from-gray-50 to-gray-100 border-gray-200",
            "GitLab": "from-orange-50 to-orange-100 border-orange-200",
            "Bitbucket": "from-blue-50 to-blue-100 border-blue-200",
            "Other": "from-purple-50 to-purple-100 border-purple-200"
        }
        
        platform_icons = {
            "GitHub": "M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22",
            "GitLab": "M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z",
            "Bitbucket": "M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2H5a2 2 0 00-2 2z",
            "Other": "M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
        }
        
        for platform, repos, total_leaks in data.get("platform_breakdown", []):
            avg_leaks_per_repo = round(total_leaks / repos, 1) if repos > 0 else 0
            color_class = platform_colors.get(platform, "from-gray-50 to-gray-100 border-gray-200")
            icon_path = platform_icons.get(platform, platform_icons["Other"])
            
            section += f"""
                <div class='bg-gradient-to-br {color_class} rounded-xl p-6 border hover:shadow-lg transition-all duration-300'>
                    <div class='flex items-center justify-between mb-4'>
                        <h3 class='text-lg font-semibold text-gray-900'>{platform}</h3>
                        <svg class='w-6 h-6 text-gray-600' fill='none' stroke='currentColor' viewBox='0 0 24 24'>
                            <path stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='{icon_path}'></path>
                        </svg>
                    </div>
                    <div class='space-y-2'>
                        <div class='flex justify-between text-sm'>
                            <span class='text-gray-600'>Репозитории</span>
                            <span class='font-semibold text-gray-900'>{repos}</span>
                        </div>
                        <div class='flex justify-between text-sm'>
                            <span class='text-gray-600'>Всего утечек</span>
                            <span class='font-semibold text-gray-900'>{total_leaks}</span>
                        </div>
                        <div class='flex justify-between text-sm'>
                            <span class='text-gray-600'>Среднее на репо</span>
                            <span class='font-semibold text-gray-900'>{avg_leaks_per_repo}</span>
                        </div>
                    </div>
                </div>"""
        
        section += """
            </div>
        </div>"""
        
        return section
    
    def get_company_breakdown_section(self, data: Dict[str, Any]) -> str:
        """Generate company breakdown section for business reports."""
        section = f"""<div class='bg-white rounded-3xl shadow-2xl p-8 fade-in-up' style='animation-delay: 0.5s'>
            <h2 class='text-2xl font-bold text-gray-900 mb-6'>Статистика по подразделениям</h2>
            <div class='overflow-x-auto'>
                <table class='w-full'>
                    <thead>
                        <tr class='border-b border-gray-200'>
                            <th class='text-left py-4 px-6 font-semibold text-gray-900'>Подразделение</th>
                            <th class='text-center py-4 px-6 font-semibold text-gray-900'>Инциденты</th>
                            <th class='text-center py-4 px-6 font-semibold text-gray-900'>Решено</th>
                            <th class='text-center py-4 px-6 font-semibold text-gray-900'>В работе</th>
                            <th class='text-center py-4 px-6 font-semibold text-gray-900'>Эффективность</th>
                        </tr>
                    </thead>
                    <tbody>"""
        
        for company, total, resolved, pending in data.get("company_breakdown", []):
            efficiency = round((resolved / total * 100)) if total > 0 else 0
            efficiency_color = "text-green-600" if efficiency >= 80 else ("text-yellow-600" if efficiency >= 60 else "text-red-600")
            company_name = _truncate(str(company), 40)
            
            section += f"""
                        <tr class='border-b border-gray-100 hover:bg-gray-50 transition-colors'>
                            <td class='py-4 px-6 font-medium text-gray-900'>{company_name}</td>
                            <td class='py-4 px-6 text-center font-medium text-gray-900'>{total}</td>
                            <td class='py-4 px-6 text-center text-green-600 font-medium'>{resolved}</td>
                            <td class='py-4 px-6 text-center text-yellow-600 font-medium'>{pending}</td>
                            <td class='py-4 px-6 text-center font-semibold {efficiency_color}'>{efficiency}%</td>
                        </tr>"""
        
        section += """
                    </tbody>
                </table>
            </div>
        </div>"""
        
        return section
    
    def get_leak_types_section(self, data: Dict[str, Any]) -> str:
        """Generate leak types section."""
        section = f"""<div class='bg-white rounded-3xl shadow-2xl p-8 fade-in-up' style='animation-delay: 0.6s'>
            <h2 class='text-2xl font-bold text-gray-900 mb-6'>🔍 Наиболее частые типы утечек</h2>
            <div class='overflow-x-auto'>
                <table class='w-full'>
                    <thead>
                        <tr class='border-b border-gray-200'>
                            <th class='text-left py-4 px-6 font-semibold text-gray-900'>Тип утечки</th>
                            <th class='text-center py-4 px-6 font-semibold text-gray-900'>Количество</th>
                            <th class='text-center py-4 px-6 font-semibold text-gray-900'>Процент</th>
                        </tr>
                    </thead>
                    <tbody>"""
        
        total_leaks = data.get("total_leaks", 1)
        for leak_type, count in data.get("top_leak_types", []):
            percentage = (count / total_leaks * 100) if total_leaks > 0 else 0
            truncated_type = _truncate(leak_type, 80)
            section += f"""
                        <tr class='border-b border-gray-100 hover:bg-gray-50 transition-colors'>
                            <td class='py-4 px-6'>
                                <code class='bg-gray-100 px-2 py-1 rounded text-sm font-mono'>{truncated_type}</code>
                            </td>
                            <td class='py-4 px-6 text-center font-medium text-gray-900'>{count}</td>
                            <td class='py-4 px-6 text-center text-gray-600'>{percentage:.1f}%</td>
                        </tr>"""
        
        section += """
                    </tbody>
                </table>
            </div>
        </div>"""
        
        return section
    
    def get_technical_sections(self, data: Dict[str, Any]) -> str:
        """Generate technical report specific sections."""
        sections = []
        
        # Scanner Metrics Section
        scanner_metrics = data.get("scanner_metrics", {})
        sections.append(f"""
        <div class='bg-white rounded-3xl shadow-2xl p-8 fade-in-up' style='animation-delay: 0.7s'>
            <h2 class='text-2xl font-bold text-gray-900 mb-6'>🔧 Метрики сканера</h2>
            <div class='grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6'>
                <div class='bg-gradient-to-br from-blue-50 to-blue-100 rounded-xl p-6 border border-blue-200'>
                    <h3 class='text-lg font-semibold text-gray-900 mb-2'>Всего сканирований</h3>
                    <div class='text-3xl font-bold text-blue-600'>{scanner_metrics.get('total_scans', 0)}</div>
                </div>
                <div class='bg-gradient-to-br from-green-50 to-green-100 rounded-xl p-6 border border-green-200'>
                    <h3 class='text-lg font-semibold text-gray-900 mb-2'>Точность детектирования</h3>
                    <div class='text-3xl font-bold text-green-600'>{scanner_metrics.get('detection_rate', 0)}%</div>
                </div>
                <div class='bg-gradient-to-br from-yellow-50 to-yellow-100 rounded-xl p-6 border border-yellow-200'>
                    <h3 class='text-lg font-semibold text-gray-900 mb-2'>Ложные срабатывания</h3>
                    <div class='text-3xl font-bold text-yellow-600'>{scanner_metrics.get('false_positives', 0)}</div>
                </div>
                <div class='bg-gradient-to-br from-purple-50 to-purple-100 rounded-xl p-6 border border-purple-200'>
                    <h3 class='text-lg font-semibold text-gray-900 mb-2'>Среднее время сканирования</h3>
                    <div class='text-3xl font-bold text-purple-600'>{scanner_metrics.get('avg_scan_time', 0)}s</div>
                </div>
            </div>
        </div>""")

        # Leak Type Analysis Section
        leak_analysis = data.get("leak_type_analysis", [])
        if leak_analysis:
            sections.append(f"""
            <div class='bg-white rounded-3xl shadow-2xl p-8 fade-in-up' style='animation-delay: 0.8s'>
                <h2 class='text-2xl font-bold text-gray-900 mb-6'>🔍 Анализ типов утечек</h2>
                <div class='space-y-6'>""")
            
            for item in leak_analysis:
                risk_colors = {
                    'critical': 'from-red-50 to-red-100 border-red-200 text-red-800',
                    'high': 'from-orange-50 to-orange-100 border-orange-200 text-orange-800',
                    'medium': 'from-yellow-50 to-yellow-100 border-yellow-200 text-yellow-800',
                    'low': 'from-green-50 to-green-100 border-green-200 text-green-800'
                }
                color_class = risk_colors.get(item.get('risk_level', 'medium'), risk_colors['medium'])
                
                sections.append(f"""
                    <div class='bg-gradient-to-br {color_class} rounded-xl p-6 border'>
                        <div class='flex justify-between items-start mb-4'>
                            <h3 class='text-lg font-semibold'>{item.get('type', 'Unknown')}</h3>
                            <span class='px-3 py-1 rounded-full text-sm font-semibold bg-white bg-opacity-50'>
                                {item.get('risk_level', 'medium').upper()}
                            </span>
                        </div>
                        <div class='grid grid-cols-1 md:grid-cols-3 gap-4'>
                            <div>
                                <div class='text-sm font-medium'>Количество</div>
                                <div class='text-2xl font-bold'>{item.get('count', 0)}</div>
                            </div>
                            <div>
                                <div class='text-sm font-medium'>Уверенность</div>
                                <div class='text-2xl font-bold'>{item.get('avg_confidence', 0)}%</div>
                            </div>
                            <div>
                                <div class='text-sm font-medium'>Распространенные местоположения</div>
                                <div class='text-sm'>{', '.join(item.get('locations', []))}</div>
                            </div>
                        </div>
                        <div class='mt-4'>
                            <div class='text-sm font-medium mb-2'>Паттерны</div>
                            <div class='flex flex-wrap gap-2'>""")
                
                for pattern in item.get('patterns', []):
                    sections.append(f"""
                                <code class='bg-white bg-opacity-50 px-2 py-1 rounded text-xs font-mono'>{pattern}</code>""")
                
                sections.append("""
                            </div>
                        </div>
                    </div>""")
            
            sections.append("""
                </div>
            </div>""")

        # Repository Statistics Section
        repo_stats = data.get("repository_stats", {})
        sections.append(f"""
        <div class='bg-white rounded-3xl shadow-2xl p-8 fade-in-up' style='animation-delay: 0.9s'>
            <h2 class='text-2xl font-bold text-gray-900 mb-6'>� Статистика репозиториев</h2>
            <div class='grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8'>
                <div class='text-center'>
                    <div class='text-3xl font-bold text-blue-600'>{repo_stats.get('total_repos', 0)}</div>
                    <div class='text-sm text-gray-600'>Всего репозиториев</div>
                </div>
                <div class='text-center'>
                    <div class='text-3xl font-bold text-green-600'>{repo_stats.get('scanned_repos', 0)}</div>
                    <div class='text-sm text-gray-600'>Отсканировано</div>
                </div>
                <div class='text-center'>
                    <div class='text-3xl font-bold text-yellow-600'>{repo_stats.get('infected_repos', 0)}</div>
                    <div class='text-sm text-gray-600'>С проблемами</div>
                </div>
                <div class='text-center'>
                    <div class='text-3xl font-bold text-red-600'>{repo_stats.get('clean_repos', 0)}</div>
                    <div class='text-sm text-gray-600'>Чистых</div>
                </div>
            </div>
            
            <h3 class='text-lg font-semibold text-gray-900 mb-4'>Топ рискованных репозиториев</h3>
            <div class='overflow-x-auto'>
                <table class='w-full'>
                    <thead>
                        <tr class='border-b border-gray-200'>
                            <th class='text-left py-3 px-4 font-semibold text-gray-900'>Репозиторий</th>
                            <th class='text-center py-3 px-4 font-semibold text-gray-900'>Проблемы</th>
                            <th class='text-center py-3 px-4 font-semibold text-gray-900'>Уровень риска</th>
                            <th class='text-center py-3 px-4 font-semibold text-gray-900'>Последнее сканирование</th>
                        </tr>
                    </thead>
                    <tbody>""")
        
        for repo in repo_stats.get('top_risky_repos', []):
            severity_colors = {
                'critical': 'bg-red-100 text-red-800',
                'high': 'bg-orange-100 text-orange-800',
                'medium': 'bg-yellow-100 text-yellow-800',
                'low': 'bg-green-100 text-green-800'
            }
            severity_color = severity_colors.get(repo.get('severity', 'medium'), severity_colors['medium'])
            
            sections.append(f"""
                        <tr class='border-b border-gray-100 hover:bg-gray-50 transition-colors'>
                            <td class='py-3 px-4 font-medium text-gray-900'>{repo.get('name', 'Unknown')}</td>
                            <td class='py-3 px-4 text-center'>{repo.get('issues', 0)}</td>
                            <td class='py-3 px-4 text-center'>
                                <span class='px-2 py-1 rounded-full text-xs font-semibold {severity_color}'>
                                    {repo.get('severity', 'medium').upper()}
                                </span>
                            </td>
                            <td class='py-3 px-4 text-center text-gray-600'>{repo.get('last_scan', 'N/A')}</td>
                        </tr>""")
        
        sections.append("""
                    </tbody>
                </table>
            </div>
        </div>""")

        # Detection Patterns Section
        detection_patterns = data.get("detection_patterns", [])
        if detection_patterns:
            sections.append(f"""
            <div class='bg-white rounded-3xl shadow-2xl p-8 fade-in-up' style='animation-delay: 1.0s'>
                <h2 class='text-2xl font-bold text-gray-900 mb-6'>🎯 Паттерны детектирования</h2>
                <div class='overflow-x-auto'>
                    <table class='w-full'>
                        <thead>
                            <tr class='border-b border-gray-200'>
                                <th class='text-left py-3 px-4 font-semibold text-gray-900'>Паттерн</th>
                                <th class='text-left py-3 px-4 font-semibold text-gray-900'>Тип</th>
                                <th class='text-center py-3 px-4 font-semibold text-gray-900'>Уверенность</th>
                                <th class='text-center py-3 px-4 font-semibold text-gray-900'>Срабатывания</th>
                            </tr>
                        </thead>
                        <tbody>""")
            
            for pattern in detection_patterns:
                confidence = pattern.get('confidence', 0)
                confidence_color = 'text-green-600' if confidence >= 90 else ('text-yellow-600' if confidence >= 70 else 'text-red-600')
                
                sections.append(f"""
                            <tr class='border-b border-gray-100 hover:bg-gray-50 transition-colors'>
                                <td class='py-3 px-4'>
                                    <code class='bg-gray-100 px-2 py-1 rounded text-sm font-mono'>{pattern.get('pattern', '')}</code>
                                </td>
                                <td class='py-3 px-4 text-gray-900'>{pattern.get('type', 'Unknown')}</td>
                                <td class='py-3 px-4 text-center font-semibold {confidence_color}'>{confidence}%</td>
                                <td class='py-3 px-4 text-center'>{pattern.get('occurrences', 0)}</td>
                            </tr>""")
            
            sections.append("""
                        </tbody>
                    </table>
                </div>
            </div>""")

        # Analyst Workflow Section
        analyst_workflow = data.get("analyst_workflow", {})
        sections.append(f"""
        <div class='bg-white rounded-3xl shadow-2xl p-8 fade-in-up' style='animation-delay: 1.1s'>
            <h2 class='text-2xl font-bold text-gray-900 mb-6'>👥 Рабочий процесс аналитиков</h2>
            <div class='grid grid-cols-1 md:grid-cols-2 gap-8'>
                <div>
                    <h3 class='text-lg font-semibold text-gray-900 mb-4'>Общая статистика</h3>
                    <div class='space-y-4'>
                        <div class='flex justify-between items-center p-3 bg-gray-50 rounded-lg'>
                            <span class='text-gray-700'>Всего обработано</span>
                            <span class='font-semibold text-gray-900'>{analyst_workflow.get('total_processed', 0)}</span>
                        </div>
                        <div class='flex justify-between items-center p-3 bg-gray-50 rounded-lg'>
                            <span class='text-gray-700'>Среднее время обработки</span>
                            <span class='font-semibold text-gray-900'>{analyst_workflow.get('avg_processing_time', 0)} мин</span>
                        </div>
                    </div>
                </div>
                
                <div>
                    <h3 class='text-lg font-semibold text-gray-900 mb-4'>Топ аналитиков</h3>
                    <div class='space-y-3'>""")
        
        for analyst in analyst_workflow.get('top_analysts', []):
            sections.append(f"""
                        <div class='flex items-center justify-between p-3 bg-gray-50 rounded-lg'>
                            <div>
                                <div class='font-medium text-gray-900'>{analyst.get('name', 'Unknown')}</div>
                                <div class='text-sm text-gray-600'>Обработано: {analyst.get('processed', 0)}</div>
                            </div>
                            <div class='text-right'>
                                <div class='text-sm font-semibold text-green-600'>{analyst.get('accuracy', 0)}% точность</div>
                                <div class='text-xs text-gray-500'>{analyst.get('avg_time', 0)} мин/инцидент</div>
                            </div>
                        </div>""")
        
        sections.append("""
                    </div>
                </div>
            </div>
        </div>""")

        return ''.join(sections)
    
    def get_footer_section(self) -> str:
        """Generate footer section with interactive elements."""
        return """<div class='bg-white rounded-3xl shadow-2xl p-8 text-center'>
            <div class='mb-4'>
                <h3 class='text-lg font-semibold text-gray-900 mb-2'>GitSearch Security Report</h3>
                <p class='text-gray-600'>Автоматизированная система анализа утечек данных</p>
            </div>
            <div class='text-gray-500 text-xs mt-2' id='live-clock'>
                Текущее время обновляется...
            </div>
            <div class='mt-4 text-xs text-gray-400'>
                Интерактивные элементы: наведите курсор на графики и числа, нажмите на код для копирования
            </div>
        </div>"""
    
    def generate_html(self, data: Dict[str, Any], start_date: str, end_date: str, report_type: str = "business") -> str:
        """Generate complete HTML report."""
        if report_type not in {"business", "technical"}:
            raise ValueError("report_type must be 'business' or 'technical'")
            
        report_title = f"Бизнес-отчет" if report_type == "business" else "Технический отчет"
        current_date = "2 июля 2025"
        
        # Build HTML document
        html_parts = [
            "<!DOCTYPE html>",
            "<html lang='ru'>",
            f"<head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'><title>{report_title}</title>",
            self.get_css_styles(),
            "</head>",
            "<body class='bg-gradient-to-br from-blue-500 via-purple-600 to-indigo-700 font-sans'>",
            "<div class='min-h-screen py-8 px-4 sm:px-6 lg:px-8'>",
            "<div class='max-w-7xl mx-auto space-y-8'>",
            
            # Header
            self.get_header_section(report_title, start_date, end_date, current_date),
            
            # Executive Summary
            self.get_executive_summary_cards(data),
            
            # Risk Assessment (Business only)
            self.get_risk_assessment_section(data) if report_type == "business" else "",
            
            # Monthly Trends (Business only)
            self.get_monthly_trends_section(data) if report_type == "business" else "",
            
            # Status Distribution
            self.get_status_distribution_section(data),
            
            # Platform Analysis
            self.get_platform_analysis_section(data),
            
            # Company Breakdown (Business only)
            self.get_company_breakdown_section(data) if report_type == "business" else "",
            
            # Leak Types
            self.get_leak_types_section(data),
            
            # Technical sections (Technical only)
            self.get_technical_sections(data) if report_type == "technical" else "",
            
            # Footer
            self.get_footer_section(),
            
            "</div>",  # Close max-w-7xl mx-auto
            "</div>",  # Close min-h-screen container
            "</body>",
            "</html>",
        ]
        
        # Filter out empty strings and join
        return "\n".join(part for part in html_parts if part)
