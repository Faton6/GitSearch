# Standart libs import
import time
from abc import ABC
import json
import base64
import requests
from typing import Optional
import tiktoken
from openai import OpenAI

from src import constants
from src import filters
from src.searcher.GitStats import GitParserStats
from src.logger import logger


class AIObj(ABC):
    """
        Class AIObj:
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
    base_prompt_text = 'None'
    def __init__(self, secrets: dict, stats_data: dict, leak_info: dict):
        self.tokenizer = tiktoken.get_encoding("cl100k_base")
        
        self.ai_requested = False

        self.ai_result = -1
        self.ai_report = {'Thinks': 'Not state'}
        
        if len(secrets) > constants.AI_CONFIG['token_limit']-1000:
            secrets = secrets[:constants.AI_CONFIG['token_limit']-1000]
            secrets += '...Cutted, token limit reached.'

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
        repo_name = self.safe_val(leak_info.get("repo_name"))
        author_value = self.safe_val(leak_info.get("author"))
        dork_value = self.safe_val(leak_info.get("dork"))
        created_at_value = self.safe_val(leak_info.get("created_at"))
        updated_at_value = self.safe_val(leak_info.get("updated_at"))
        
        self.base_prompt_text = (
                "### Data:\n"
                f"Repository name: {repo_name}\n"
                f"Author: {author_value}\n"
                f"Last updated at: {updated_at_value}\n"
                f"Repository created at: {created_at_value}\n"
                f"Stats of repo -> Size: {size_value}, Forks: {forks_value}, Stargazers: {stargazers_value}\n"
                f"Description of repo: {description_value}\n\n"
                f"Contributers:\n{contributers_list}\n\n"
                f"Commiters:\n{commiters_list}\n\n"
                f"Company related dork: {dork_value}\n\n"
                f"Raw_report (may cut off):\n{raw_report_str.replace('\t', '').replace('\n', '')}...\n\n"
        )
                      
    def safe_val(self, val):
        if val is None or val == "":
            return "-"
        return str(val)

    def safe_generate(
        self,
        prompt: str,
        ctx_size: int = 8192,
        max_new_tokens: int = 1024,
        safety_margin: int = 256
    ) -> str:
        
        prompt_tokens = self.tokenizer.encode(prompt)
        
        max_prompt_tokens = ctx_size - max_new_tokens - safety_margin
        logger.info(f"Количество токенов: {len(prompt_tokens)}")
        
        if len(prompt_tokens) > max_prompt_tokens:
            prompt_tokens = prompt_tokens[:max_prompt_tokens]
            logger.info(f"Предупреждение: Промпт обрезан до {max_prompt_tokens} токенов")
        
        max_tokens = ctx_size-len(prompt_tokens)-5
        prompt = self.tokenizer.decode(prompt_tokens)

        if max_tokens < 0:
            logger.error(f"Предупреждение: недостаточно токенов для ответа, промпт не будет выполняться. Промпт: {prompt}")
            return ""
        else:
            return prompt, max_tokens

    def lm_studio_request(self, prompt: str, client: str, max_tokens: int = 1024, temperature: float = 0.01):
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
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "GitSearch_chech",
                    "description": "Function to analyze gitsearch incidents",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                                "description": "The incident classification"
                            }
                        },
                        "required": ["data"]
                    }
                }
            }
        ]
        try:
            response = client.chat.completions.create(
                model="bartowski/DeepSeek-R1-Distill-Qwen-14B-GGUF",
                messages=[{"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=max_tokens,
                #tools=tools,
                stop=["</answer>", "<|im_end|>"]
            )
        except Exception as ex:
            logger.error(f'Api request error: {ex}')

        return response
    
    def ai_request(self):
        if self.ai_requested:
            return
        
        
        result_promt, max_tokens = self.safe_generate(prompt=self.base_prompt_text,
                                                      ctx_size=constants.AI_CONFIG['token_limit'])
        try:
            client = OpenAI(base_url=constants.AI_CONFIG['url'], api_key=constants.AI_CONFIG['api_key'])
        except Exception as ex:
            logger.error(f'Error in connection to AI API: {ex}')
        
        try:
            ai_response = self.lm_studio_request(prompt=result_promt, 
                                                client=client,
                                                max_tokens=max_tokens,
                                                temperature=constants.AI_CONFIG['temperature'])
            self.ai_report = ai_response.choices[0].message.content.strip()
            if len(ai_response) >= 2:
                if '0' in self.ai_report[-2:-1]:
                    self.ai_result = 0
                elif '1' in self.ai_report[-2:-1]:
                    self.ai_result = 1
            elif len(ai_response) == 1:
                if '0' in self.ai_report:
                    self.ai_result = 0
                elif '1' in self.ai_report:
                    self.ai_result = 1
            self.ai_requested = True
        except Exception as ex:
            logger.error(f'Error in AI API request: {ex}')
        
        
        
    def get_ai_report(self):
        if not self.ai_requested:
            self.ai_request()
        return self.ai_report
    
    def get_ai_result(self):
        if not self.ai_requested:
            self.ai_request()
        return self.ai_result
