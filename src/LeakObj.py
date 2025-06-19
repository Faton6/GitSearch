# Standart libs import
import time
from abc import ABC

# Project lib's import
from src import constants
from src import filters
from src.searcher.GitStats import GitParserStats
from src.logger import logger
from src.LeakAnalyzer import LeakAnalyzer



class LeakObj(ABC):
    """
        Class LeakObj:
            TODO Need to update
            Fields:
            Url - link to repository
            responce - responce json
            dork - used dork for search in gihub
            author_name - repository author
            repo_name - repository name: author/repo
            found_time - time of object create (in scan process)
            created_date - repository created date
            updated_date - repository updated date
            lvl - Leak level (low, medium, high)
            secrets - dict of founded secrets by CheckRepo.Run
            status - list with founded types of leaks

            Methods:
            def _check_status - update status field
            def Level - get actual leak Level
            def write_obj_dict - get dict of object fields for write in json
            def write_obj - get list of object fields for write in DB
    """

    def __init__(self, obj_type: str, url: str, responce: dict, dork: str, company_id: int = 1):

        self.author_name = None
        self.url = url
        self.obj_type = obj_type
        self.repo_url = url.split('github.com/')[1]
        if obj_type == 'Glist':
            self.repo_url = 'https://gist.github.com/' + self.repo_url.split('/')[0] + '/' + self.repo_url.split('/')[1]
        else:
            self.repo_url = 'https://github.com/' + self.repo_url.split('/')[0] + '/' + self.repo_url.split('/')[1]
        self.responce = responce
        self.dork = dork
        self.company_id = company_id
        self.repo_name = self.repo_url.split('github.com/')[1]

        self.found_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        self.stats = GitParserStats(self.repo_url)

        self.secrets = {'Not state': 'Not state'}
        self.ai_report = {'Thinks': 'Not state'}
        self.status = []
        self.lvl = 0
        self.ready_to_send = False
        constants.quantity_obj_before_send += 1
        
        self.profitability_scores = None
        
    def _get_message(self, key: str, lang: str = "ru", **kwargs) -> str:
        template = constants.LEAK_OBJ_MESSAGES.get(
            lang, constants.LEAK_OBJ_MESSAGES["en"]
        ).get(key, "")
        try:
            return template.format(**kwargs)
        except Exception:
            return template
    
    def _check_status(self):
        self._check_stats()
        lang = constants.LANGUAGE # Assuming LANGUAGE is defined in constants.py

        self.status.insert(0, self._get_message("leak_found_in_section", lang, obj_type=self.obj_type, dork=self.dork))
        
        if 'status' in self.secrets:
            for i in self.secrets['status']:
                self.status.append(i)
        founded_commiters = [f'{comm["commiter_name"]}/{comm["commiter_email"]}' for comm in self.stats.commits_stats_commiters_table]
        for leak_type in constants.leak_check_list:
            if leak_type in self.author_name:
                self.status.append(self._get_message("leak_in_author_name", lang, leak_type=leak_type, author_name=self.author_name))
            if leak_type in ", ".join(founded_commiters):
                self.status.append(self._get_message("leak_in_committers", lang, leak_type=leak_type))
            if leak_type in self.repo_name:
                self.status.append(self._get_message("leak_in_repo_name", lang, leak_type=leak_type, repo_name=self.repo_name))
        
        description_value = self.stats.repo_stats_leak_stats_table.get("description")
        if isinstance(description_value, str) and description_value.strip() not in ["_", "", " "]:
            description = description_value
            if len(description) > constants.MAX_DESCRIPTION_LEN:
                description = description[:constants.MAX_DESCRIPTION_LEN] + "..."
            self.status.append(self._get_message("short_description", lang, description=description))
            if len(self.stats.repo_stats_leak_stats_table["description"]) > constants.MAX_DESCRIPTION_LEN:
                description = self.stats.repo_stats_leak_stats_table["description"]
            if len(description) > constants.MAX_DESCRIPTION_LEN:
                self.status.append(self._get_message("short_description", lang, description=description[:constants.MAX_DESCRIPTION_LEN] + "..."))
            else:
                self.status.append(self._get_message("short_description", lang, description=description))
        else:
            self.status.append(self._get_message("no_description", lang))
        topics = self.stats.repo_stats_leak_stats_table["topics"]
        self.status.append(self._get_message("topics", lang, topics=topics if topics not in ["_", "", " "] else self._get_message("no_topics", lang)))
        
        if len(founded_commiters) > constants.MAX_COMMITERS_DISPLAY:
            self.status.append(self._get_message("committers_found", lang,
                                                 committers=", ".join(founded_commiters[:constants.MAX_COMMITERS_DISPLAY]),
                                                 remaining=len(founded_commiters) - constants.MAX_COMMITERS_DISPLAY))
        else:
            self.status.append(self._get_message("committers_all", lang, committers=", ".join(founded_commiters)))


        scaners = [
            'gitleaks',
            'gitsecrets',
            'trufflehog',
            'grepscan',
            'deepsecrets'
        ]
        if ('grepscan' in self.secrets and isinstance(self.secrets['grepscan'], constants.AutoVivification)
                and len(self.secrets['grepscan'])):
            first_match = list(self.secrets["grepscan"].values())[0]["Match"]
            self.status.append(self._get_message("first_grepscan_line", lang, match=first_match))

        sum_leaks_count = 0
        for scan_type in scaners:
            if (scan_type in self.secrets and isinstance(self.secrets[scan_type], constants.AutoVivification)
                    and len(self.secrets[scan_type])):
                sum_leaks_count += len(self.secrets[scan_type])
                self.status.append(self._get_message("leaks_found_by_scanner", lang, count=len(self.secrets[scan_type]), scanner=scan_type))

        self.status.append(self._get_message("total_leaks_found", lang, total_count=sum_leaks_count))
        self.status.append(self._get_message("full_report_length", lang, length=filters.count_nested_dict_len(self.secrets)))
        
        self.profitability_scores = LeakAnalyzer(self).calculate_profitability()
        
        if self.profitability_scores:
            self.profitability_scores = LeakAnalyzer(self).calculate_profitability()
            self.status.append(self._get_message("profitability_scores", lang, 
                                                 org_rel=self.profitability_scores['org_relevance'],
                                                 sens_data=self.profitability_scores['sensitive_data'],
                                                 tp=self.profitability_scores['true_positive_chance'],
                                                 fp=self.profitability_scores['false_positive_chance']))
                                                 
            true_positive_chance = self.profitability_scores["true_positive_chance"]
        else:
            true_positive_chance = len(self.status) / 15.0 if len(self.status) > 0 else 0.0
        
        if true_positive_chance < 0.3: # Example thresholds, can be adjusted
            self.lvl = 0  # 'Low'
        elif 0.3 <= true_positive_chance < 0.7:
            self.lvl = 1  # 'Medium'
        else:
            self.lvl = 2  # 'High'
        
        temp = []
        for i in self.status:
            if i not in temp:
                temp.append(i)
        self.status = temp
        self.status = '\n- '.join(self.status)
        self.ready_to_send = True

    def _prepare_secrets(self):
        if len(self.secrets) > 10:
            for key in self.secrets.keys():
                pass  # TODO check secrets duplicates

    def write_obj(self):  # for write to DB

        # Human chech:
        # 0 - not seen result of scan
        # 1 - leaks aprove
        # 2 - leak doesn't found
        res_human_check = 0

        # Type of leak:
        # For example: password, API_key, source code, etc
        if not self.ready_to_send:
            self._check_status()
        if len(self.status) > 10000:
            founded_leak = str(self.status[:10000]) + '...'
        else:
            founded_leak = self.status

        self._prepare_secrets()
        # Result:
        # 0 - leaks doesn't found, add to exclude list
        # 1 - leaks found, sent request to block
        # 2 - leaks found, not yet sent request to block
        # 3 - leaks found, blocked
        # 4 - not set
        # 5 - need more scan
        res_check = constants.RESULT_CODE_TO_SEND

        ret_mass = {
            'url': self.repo_url,
            'level': self.lvl,
            'author_info': self.author_name,
            'found_at': self.found_time,
            'created_at': self.stats.created_at,
            'updated_at': self.stats.updated_at,
            'approval': res_human_check,
            'leak_type': founded_leak,
            'result': res_check,
            'company_id': self.company_id,

        }
        return ret_mass

    def _check_stats(self):
        if not self.stats.coll_stats_getted:
            self.stats.get_contributors_stats()
        if not self.stats.comm_stats_getted:
            self.stats.get_commits_stats()
        for contributor in self.stats.contributors_stats_accounts_table:
            contributor['company_id'] = self.company_id

        if 'trufflehog' in self.secrets and len(self.secrets['trufflehog']):
            commiter = {}
            for leak in self.secrets['trufflehog']:
                try:
                    if self.secrets['trufflehog'][leak]['SourceMetadata']['Data']['Git']['email'].split('<')[
                        0] not in commiter.keys():
                        commiter[
                            self.secrets['trufflehog'][leak]['SourceMetadata']['Data']['Git']['email'].split('<')[0]] \
                            = self.secrets['trufflehog'][leak]['SourceMetadata']['Data']['Git']['email'].split('<')[1]
                except Exception as ex:
                    logger.error('Not found acc_name/email in trufflehog scan in %s repository', self.repo_name)
            founded_commiters = [comm['commiter_name'] for comm in self.stats.commits_stats_commiters_table]
            for comm in commiter.keys():
                if comm not in founded_commiters:
                    self.stats.commits_stats_commiters_table.append({'commiter_name': comm,
                                                                     'commiter_email': commiter[comm],
                                                                     'need_monitor': 0,
                                                                     'related_account_id': 0
                                                                     })
                    founded_commiters.append(comm)

    def get_stats(self):
        return (self.stats.repo_stats_leak_stats_table,
                self.stats.contributors_stats_accounts_table, self.stats.commits_stats_commiters_table)


class RepoObj(LeakObj):
    obj_type: str = 'Repositories'

    def __init__(self, url: str, responce: dict, dork: str, company_id: int = 1):
        super().__init__(self.obj_type, url, responce, dork, company_id)
        self.author_name = self.responce['owner']['login']

    def __str__(self) -> str:
        return 'Repositories'


class CommitObj(LeakObj):
    obj_type: str = 'Commits'

    def __init__(self, url: str, responce: dict, dork: str, company_id: int = 0):
        super().__init__(self.obj_type, url, responce, dork, company_id)
        self.author_name = self.responce['commit']['author']['name']
        self.author_email = self.responce['commit']['author']['email']
        self.commit = self.responce['commit']['message']
        self.commit_date = self.responce['commit']['author']['date']
        self.commit_hash = self.responce['sha']
        self.status.append(self._get_message("commit_description", constants.LANGUAGE, commit=self.commit))

    def __str__(self) -> str:
        return 'Commits'


class CodeObj(LeakObj):
    obj_type: str = 'Code'

    def __init__(self, url: str, responce: dict, dork: str, company_id: int = 0):
        super().__init__(self.obj_type, url, responce, dork, company_id)
        self.author_name = self.responce['repository']['owner']['login']

    def __str__(self) -> str:
        return 'Code'


class GlistObj(LeakObj):
    obj_type: str = 'Glist'

    def __init__(self, url: str, dork: str, company_id: int = 0):
        super().__init__(self.obj_type, url, {}, dork, company_id)
        self.author_name = url.split('github.com/')[1].split('/')[0]

    def __str__(self) -> str:
        return 'Glist'
