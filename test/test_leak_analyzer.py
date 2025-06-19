import pytest

from src.LeakAnalyzer import LeakAnalyzer
from src import constants
from src import Connector

class DummyStats:
    def __init__(self, desc="", stars=0, commiters=0, ai_result=0, committers_list=None):
        self.repo_stats_leak_stats_table = {
            "description": desc,
            "stargazers_count": stars,
            "commiters_count": commiters,
            "contributors_count": commiters,
        }
        self.commits_stats_commiters_table = committers_list or []
        self.ai_result = ai_result

class DummyLeakObj:
    def __init__(self, dork, repo_name, author_name, stats, company_id="Alpha-Bet"):
        self.dork = dork
        self.repo_name = repo_name
        self.author_name = author_name
        self.stats = stats
        self.secrets = {}
        self.company_id = company_id


@pytest.fixture(autouse=True)
def patch_company_name(monkeypatch):
    monkeypatch.setattr(Connector, "get_company_name", lambda cid: "Acme")
    yield


def test_basic_relevance():
    stats = DummyStats(desc="dork project", stars=10, commiters=1, ai_result=1,
                       committers_list=[{"commiter_name": "Alice", "commiter_email": "alice@example.com"}])
    leak = DummyLeakObj("dork", "my-dork-repo", "bob dork", stats)
    score = LeakAnalyzer(leak).calculate_organization_relevance_score()
    assert score > 0.5


def test_popularity_penalty():
    stats = DummyStats(desc="irrelevant", stars=5000, commiters=300, ai_result=0)
    leak = DummyLeakObj("dork", "repo", "bob", stats)
    score = LeakAnalyzer(leak).calculate_organization_relevance_score()
    assert score < 0.5


def test_country_profiling_ru():
    constants.COUNTRY_PROFILING = True
    stats_ru = DummyStats(desc="Описание", commiters=1,
                          committers_list=[{"commiter_name": "Павел Иванов", "commiter_email": "pavel@site.ru"}], ai_result=1)
    leak_ru = DummyLeakObj("яндекс", "some-repo", "Иван", stats_ru, company_id="Yandex")
    score_ru = LeakAnalyzer(leak_ru).calculate_organization_relevance_score()

    stats_en = DummyStats(desc="Description", commiters=1,
                          committers_list=[{"commiter_name": "Pavel Ivanov", "commiter_email": "pavel@site.com"}], ai_result=1)
    leak_en = DummyLeakObj("яндекс", "some-repo", "Ivan", stats_en, company_id="Yandex")
    score_en = LeakAnalyzer(leak_en).calculate_organization_relevance_score()
    assert score_ru > score_en


def test_company_name_heuristics():
    stats = DummyStats(desc="Company internal project", commiters=1,
                       committers_list=[{"commiter_name": "Acme Dev", "commiter_email": "dev@acme.com"}], ai_result=0)
    leak = DummyLeakObj("search", "acme-tool", "AcmeBot", stats)
    score = LeakAnalyzer(leak).calculate_organization_relevance_score()
    assert score > 0.2
    
    
