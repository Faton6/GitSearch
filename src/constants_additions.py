# Additional messages for corporate committers
CORPORATE_COMMITTER_MESSAGES = {
    'en': {
        'corporate_committer_target': ' CRITICAL: Found committer with TARGET COMPANY email: {name} <{email}> - ALMOST CERTAIN relevance!',
        'corporate_committer_other': ' Corporate email committer: {name} <{email}> (domain: {domain})',
        'repo_credibility_high': ' Repository credibility: HIGH ({score:.2f}) - likely real project',
        'repo_credibility_medium': ' Repository credibility: MEDIUM ({score:.2f})',
        'repo_credibility_low': ' Repository credibility: LOW ({score:.2f}) - likely test/example project',
        'repo_is_tiny': ' Tiny repository (<10KB) - possible test project',
        'repo_is_personal': ' Personal project (single contributor, few commits)',
        'repo_is_popular_oss': ' Popular OSS repository - secrets may be examples',
        'gist_clone_error': 'Failed to clone gist repository',
        'grepscan_parsing_error': 'Error parsing grepscan results: {error}',
    },
    'ru': {
        'corporate_committer_target': ' ВАЖНО: Найден коммитер с email ЦЕЛЕВОЙ КОМПАНИИ: {name} <{email}> - ПОЧТИ 100% релевантность!',
        'corporate_committer_other': ' Коммитер с корпоративным email: {name} <{email}> (домен: {domain})',
        'repo_credibility_high': ' Достоверность репозитория: ВЫСОКАЯ ({score:.2f}) - вероятно реальный проект',
        'repo_credibility_medium': ' Достоверность репозитория: СРЕДНЯЯ ({score:.2f})',
        'repo_credibility_low': ' Достоверность репозитория: НИЗКАЯ ({score:.2f}) - вероятно тестовый/пример',
        'repo_is_tiny': ' Микро-репозиторий (<10KB) - возможно тестовый проект',
        'repo_is_personal': ' Персональный проект (один контрибутор, мало коммитов)',
        'repo_is_popular_oss': ' Популярный OSS репозиторий - секреты могут быть примерами',
        'gist_clone_error': 'Не удалось клонировать gist репозиторий',
        'grepscan_parsing_error': 'Ошибка парсинга результатов grepscan: {error}',
    }
}
