# Standart libs import
import base64
import bz2
import datetime
from src.logger import logger

# Project lib's import
from src import constants
from src import filters


class GlistObj:
    """
        Class GlistObj:
            TODO Not actuall
            Fields:
            Url - link to gist
            dork - used dork for search in gihub
            author_name - gist author
            repo_name - gist name: author/repo
            found_time - time of object create (in scan process)
            created_date - gist created date
            updated_date - gist updated date
            lvl - Leak level (low, medium, high)
            secrets - dict of founded secrets by CheckRepo.Run
            status - list with founded types of leaks

            Specific for this Obj:
                self.whisper_log - in scans without any result will be only one
                    false leak - whisper.log
                    it check on this and don't up counter

            Methods:
            def _check_status - update status field
            def Level - get actual leak Level
            def write_obj_dict - get dict of object fields for write in json
            def write_obj - get list of object fields for write in DB
    """

    def __init__(self, url, dork, secrets, company_id):
        self.repo_url = url
        self.dork = dork
        self.company_id = company_id
        self.repo_name = url.split('/')[-2] + '/' + url.split('/')[-1]
        self.author_name = self.repo_name.split('/')[0]
        self.created_date = 'Not checked'
        self.updated_date = 'Not checked'
        self.found_time = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        self.secrets = secrets
        self.status = []
        self.lvl = 'None'
        self.ready_to_send = False
        constants.quantity_obj_before_send += 1
        #logger.info(f'Object {constants.quantity_obj_before_send}/{constants.MAX_OBJ_BEFORE_SEND} before dump.')

        if secrets['whispers'] is not None:
            if secrets['whispers']['Leak #1']['Match'] == 'file whispers.log':
                secrets['whispers'] = 'None'
        if secrets['deepsecrets'] is None:
            secrets['deepsecrets'] = 'None'
        if secrets['trufflehog'] is None:
            secrets['trufflehog'] = 'None'
        if secrets['gitleaks'] is None:
            secrets['gitleaks'] = 'None'

    def _check_status(self):
        # TODO Translate it
        self.status.append(f'Обнаружена утечка в разделе Gist по поиску {self.dork}')

        for leak_type in constants.leak_check_list:
            if leak_type in self.author_name:
                self.status.append(f'Утечка в имени автора, найдена по слову: {leak_type}, утечка: {self.author_name}.')
            if leak_type in self.repo_name:
                self.status.append(
                    f'Утечка в имени репозитория, найдена по слову: {leak_type}, утечка: {self.repo_name}.')
            if 'status' in self.secrets:
                for i in self.secrets['status']:
                    self.status.append(i)
            if ('grepscan' in self.secrets and type(self.secrets['grepscan']) is constants.AutoVivification
                    and len(self.secrets['grepscan'])):
                max_leaks = 5
                for leak in self.secrets['grepscan']:
                    if 12 < len(str(self.secrets['grepscan'][leak])) < 200:
                        self.status.append(f'Утечка в коде: {str(self.secrets["grepscan"][leak])}.')
                    max_leaks -= 1
                    if max_leaks == 0:
                        break
            if ('gitleaks' in self.secrets and type(self.secrets['gitleaks']) is constants.AutoVivification
                    and len(self.secrets['gitleaks'])):
                max_leaks = 5
                for leak in self.secrets['gitleaks']:
                    if 12 < len(str(self.secrets['gitleaks'][leak])) < 200:
                        self.status.append(f'Утечка в коде: {str(self.secrets["gitleaks"][leak])}.')
                    max_leaks -= 1
                    if max_leaks == 0:
                        break
            if ('gitsecrets' in self.secrets and type(self.secrets['gitsecrets']) is constants.AutoVivification
                    and len(self.secrets['gitsecrets'])):
                max_leaks = 5
                for leak in self.secrets['gitsecrets']:
                    if 12 < len(str(self.secrets['gitsecrets'][leak])) < 200:
                        self.status.append(f'Утечка в коде: {str(self.secrets["gitsecrets"][leak])}.')
                    max_leaks -= 1
                    if max_leaks == 0:
                        break
            if ('whispers' in self.secrets and type(self.secrets['whispers']) is constants.AutoVivification
                    and len(self.secrets['whispers'])):
                max_leaks = 5
                for leak in self.secrets['whispers']:
                    if 12 < len(str(self.secrets['whispers'][leak])) < 200:
                        self.status.append(f'Утечка в коде: {str(self.secrets["whispers"][leak])}.')
                    max_leaks -= 1
                    if max_leaks == 0:
                        break
            if ('trufflehog' in self.secrets and type(self.secrets['trufflehog']) is constants.AutoVivification
                    and len(self.secrets['trufflehog'])):
                max_leaks = 5
                for leak in self.secrets['trufflehog']:
                    if 12 < len(str(self.secrets['trufflehog'][leak])) < 200:
                        self.status.append(f'Утечка в коде: {str(self.secrets["trufflehog"][leak])}.')
                    max_leaks -= 1
                    if max_leaks == 0:
                        break
            if ('deepsecrets' in self.secrets and type(self.secrets['deepsecrets']) is constants.AutoVivification
                    and len(self.secrets['deepsecrets'])):
                max_leaks = 5
                for leak in self.secrets['deepsecrets']:
                    if 12 < len(str(self.secrets['deepsecrets'][leak])) < 200:
                        self.status.append(f'Утечка в коде: {str(self.secrets["deepsecrets"][leak])}.')
                    max_leaks -= 1
                    if max_leaks == 0:
                        break
            if ('ioc_finder' in self.secrets and type(self.secrets['ioc_finder']) is constants.AutoVivification
                    and len(self.secrets['ioc_finder'])):
                max_leaks = 5
                for leak in self.secrets['ioc_finder']:
                    if 12 < len(str(self.secrets['ioc_finder'][leak])) < 200:
                        self.status.append(f'Утечка в коде: {str(self.secrets["ioc_finder"][leak])}.')
                    max_leaks -= 1
                    if max_leaks == 0:
                        break
        temp = []
        for i in self.status:
            if i not in temp:
                temp.append(i)
        self.status = temp
        counter = len(self.status)
        if counter < constants.LOW_LVL_THRESHOLD:
            self.lvl = 0  # 'Low'
        if constants.LOW_LVL_THRESHOLD <= counter < constants.MEDIUM_LOW_THRESHOLD:
            self.lvl = 1  # 'Medium'
        if counter >= constants.MEDIUM_LOW_THRESHOLD:
            self.lvl = 2  # 'High'
        self.status = '\n'.join(self.status)
        self.ready_to_send = True

    def write_obj(self):  # for write to DB
        if self.secrets['created_at'] == 'Not checked' and 'created_at' in self.secrets.keys():
            self.created_date = self.secrets['created_at']
            self.updated_date = self.secrets['updated_at']
        elif self.created_date == 'Not checked':
            self.created_date = self.found_time
            self.updated_date = self.found_time
        # Human check:
        # 0 - not seen result of scan
        # 1 - leaks aprove
        # 2 - leak doesn't found
        res_human_check = 0
        # Type of leak:
        # For example: password, API_key, source code, etc
        if not self.ready_to_send:
            self._check_status()
        founded_leak = self.status[:1000] + '...'

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
            'created_at': self.created_date,
            'updated_at': self.updated_date,
            "approval": res_human_check,
            "leak_type": founded_leak,
            "result": res_check,
            'company_id': self.company_id
        }
        return ret_mass

    def write_to_mail(self):
        # TODO Translate it
        if (self.created_date == 'Not checked' and 'created_at' in self.secrets.keys()
                and filters.is_time_format(self.secrets['created_at']) and filters.is_time_format(
                    self.secrets['updated_at'])):
            self.created_date = self.secrets['created_at']
            self.updated_date = self.secrets['updated_at']
        elif self.created_date == 'Not checked':
            self.created_date = 'не обнаружена'
            self.updated_date = 'не обнаружена'

        if not self.ready_to_send:
            self._check_status()
        if len(self.status) > 30:
            status_list = self.status[:30] + '...'
        else:
            status_list = self.status
        status_string = "\n\t".join(status_list)
        result_str = (f'Обнаружена утечка в Gist по поиску {self.dork}:\n'
                      f'Уровень утечки: {self.lvl}\n'
                      f'Ссылка на репозиторий: {self.repo_url}\n'
                      f'Автор/ы утечки: {self.author_name}\n'
                      f'Дата создания репозитория: {self.created_date}\n'
                      f'Дата последнего обновления репозитория: {self.updated_date}\n'
                      f'Дата обнаружения: {self.found_time}\n'
                      f'Найдены упоминания следующих утечек:\n\t{status_string}\n'
                      f'Дополнительная информация в отчете об утечке.\n')
        return result_str
