"""
Утилита для управления информацией о компаниях в GitSearch
"""

class CompanyDB:
    """Класс для работы с информацией о компаниях из базы данных GitSearch"""
    
    def __init__(self):
        self.companies_cache = {}
        self._load_default_companies()
    
    def _load_default_companies(self):
        """Загрузка компаний по умолчанию"""
        # Можно расширить для загрузки из базы данных
        self.companies_cache[1] = {
            "id": 1,
            "name": "Default Company",
            "domain": "",
            "keywords": [],
            "industry": "Technology",
            "description": "Default company profile"
        }
    
    def add_company(self, company_id: int, name: str, domain: str = "", 
                   keywords: list = None, industry: str = "", description: str = ""):
        """Добавление или обновление компании"""
        if keywords is None:
            keywords = []
        
        # Автоматическое создание ключевых слов из названия и домена
        auto_keywords = self._generate_keywords(name, domain)
        all_keywords = list(set(keywords + auto_keywords))
        
        self.companies_cache[company_id] = {
            "id": company_id,
            "name": name,
            "domain": domain.lower() if domain else "",
            "keywords": [kw.lower() for kw in all_keywords],
            "industry": industry,
            "description": description
        }
        
        return True
    
    def get_company(self, company_id: int):
        """Получение информации о компании"""
        return self.companies_cache.get(company_id)
    
    def _generate_keywords(self, name: str, domain: str):
        """Автоматическое создание ключевых слов"""
        import re
        
        keywords = []
        
        # Извлечение слов из названия компании
        name_words = re.findall(r'\\b\\w+\\b', name.lower())
        keywords.extend([word for word in name_words if len(word) > 2])
        
        # Извлечение частей домена
        if domain:
            domain_parts = domain.lower().split('.')
            for part in domain_parts:
                if part not in ['com', 'org', 'net', 'ru', 'www'] and len(part) > 2:
                    keywords.append(part)
        
        # Удаление общих слов
        common_words = {'company', 'corp', 'inc', 'ltd', 'llc', 'the', 'and', 'or', 'for', 'with'}
        keywords = [word for word in keywords if word not in common_words]
        
        return list(set(keywords))
    
    def search_companies(self, keyword: str):
        """Поиск компаний по ключевому слову"""
        keyword = keyword.lower()
        results = []
        
        for company in self.companies_cache.values():
            if (keyword in company["name"].lower() or
                keyword in company.get("domain", "").lower() or
                keyword in company["keywords"]):
                results.append(company)
        
        return results

# Глобальный экземпляр
company_db = CompanyDB()

def setup_companies_for_testing():
    """Настройка тестовых компаний"""
    
    # Пример российской технологической компании
    company_db.add_company(
        company_id=1,
        name="ТехКорп",
        domain="techcorp.ru",
        keywords=["техкорп", "tech", "корп", "api"],
        industry="Технологии",
        description="Российская технологическая компания"
    )
    
    # Пример банка
    company_db.add_company(
        company_id=2,
        name="БанкФинанс",
        domain="bankfinance.ru", 
        keywords=["банк", "финанс", "bank", "payment"],
        industry="Финансы",
        description="Финансовые услуги и банкинг"
    )
    
    # Пример международной компании
    company_db.add_company(
        company_id=3,
        name="GlobalTech Inc",
        domain="globaltech.com",
        keywords=["global", "tech", "international"],
        industry="Technology",
        description="International technology company"
    )
    
    return company_db
