# Standard library imports
import time
from abc import ABC

# Project library imports
from src import constants
from src import utils
from src.logger import logger
from src.LeakAnalyzer import LeakAnalyzer


class LeakObj(ABC):
    def __init__(self, obj_type: str, url: str, responce: dict, dork: str, company_id: int = 1):
        self.author_name = None
        self.url = url
        self.obj_type = obj_type
        self.repo_url = url.split("github.com/")[1]
        if obj_type == "Glist":
            self.repo_url = "https://gist.github.com/" + self.repo_url.split("/")[0] + "/" + self.repo_url.split("/")[1]
        else:
            self.repo_url = "https://github.com/" + self.repo_url.split("/")[0] + "/" + self.repo_url.split("/")[1]
        self.responce = responce
        self.dork = dork
        self.company_id = company_id
        self.repo_name = self.repo_url.split("github.com/")[1]

        self.found_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        from src.searcher.GitStats import GitParserStats

        self.stats = GitParserStats(self.repo_url)

        self.secrets = {"Not state": "Not state"}
        self.ai_analysis = None  # Will store AI analysis results
        self.ai_confidence = 0.0  # Confidence score for AI analysis (0.0-1.0)
        self.company_info = None  # Will store company information for analysis
        self.ai_obj = None  # AIObj instance for analysis
        self.status = []
        self.lvl = 0
        self.ready_to_send = False
        constants.quantity_obj_before_send += 1
        self.final_leak = None
        self.res_check = constants.RESULT_CODE_TO_SEND
        self.profitability_scores = None

    def _get_message(self, key: str, lang: str = "ru", **kwargs) -> str:
        """Get localized message template."""
        messages = constants.LEAK_OBJ_MESSAGES.get(lang) or constants.LEAK_OBJ_MESSAGES.get("en", {})
        template = messages.get(key, "") if isinstance(messages, dict) else ""
        try:
            return template.format(**kwargs)
        except Exception:
            return template

    def set_company_info(self, company_info: dict):
        """Set company information for AI analysis"""
        self.company_info = company_info

    def _create_ai_obj(self):
        if self.ai_obj is None:
            from src.AIObj import AIObj

            self.ai_obj = AIObj(
                secrets=self.secrets,
                stats_data=getattr(self.stats, "repo_stats_leak_stats_table", {}),
                leak_info={
                    "repo_name": self.repo_name,
                    "author": self.author_name,
                    "dork": self.dork,
                    "created_at": getattr(self.stats, "created_at", "Unknown"),
                    "updated_at": getattr(self.stats, "updated_at", "Unknown"),
                    "contributers": getattr(self.stats, "contributors_stats_accounts_table", []),
                    "commiters": getattr(self.stats, "commits_stats_commiters_table", []),
                },
                company_info=self.company_info,
            )

    async def run_ai_analysis(self, force: bool = False):
        if not constants.AI_ANALYSIS_ENABLED or (self.ai_analysis and not force):
            return
        try:
            self._create_ai_obj()
            self.ai_analysis = self.ai_obj.analyze_leak_comprehensive()
        except Exception as e:
            logger.error(f"Error during AI analysis for {self.repo_name}: {str(e)}")

    def run_ai_analysis_sync(self, force: bool = False):
        if not constants.AI_ANALYSIS_ENABLED:
            return

        try:
            logger.info(f"Starting AI analysis for {self.repo_name}")

            self._create_ai_obj()
            self.ai_analysis = self.ai_obj.analyze_leak_comprehensive()

        except Exception as e:
            logger.error(f"Error during AI analysis for {self.repo_name}: {str(e)}")

    def _add_ai_analysis_to_status(self):
        """Add AI analysis results to status."""
        if not self.ai_analysis:
            return

        lang = constants.LANGUAGE
        try:
            # Company relevance
            company_rel = self.ai_analysis.get("company_relevance", {})
            if isinstance(company_rel, dict):
                self.ai_confidence = company_rel.get("confidence", 0.0)
                msg_key = (
                    "ai_analysis_company_related" if company_rel.get("is_related") else "ai_analysis_company_unrelated"
                )
                self.status.append(self._get_message(msg_key, lang, confidence=self.ai_confidence))

            # Severity
            severity = self.ai_analysis.get("severity_assessment", {})
            if isinstance(severity, dict) and severity.get("level") in ["high", "critical"]:
                self.status.append(
                    self._get_message("ai_analysis_high_severity", lang, score=severity.get("score", 0.0))
                )

            # Summary
            summary = (self.ai_analysis.get("summary", "") or "").strip()
            if summary:
                self.status.append(
                    self._get_message(
                        "ai_analysis_summary", lang, summary=summary[:200] + "..." if len(summary) > 200 else summary
                    )
                )
        except Exception as e:
            logger.error(f"Error adding AI analysis to status: {e}")
            self.status.append(self._get_message("ai_analysis_error", lang))

    def _submit_ai_analysis(self):
        """Submit AI analysis (async with fallback to sync) and wait for result."""
        if not constants.AI_ANALYSIS_ENABLED or self.ai_analysis:
            return
        try:
            from src.AIObj import submit_ai_analysis, AITask
            import threading

            priority = AITask.NORMAL
            for committer in getattr(self.stats, "commits_stats_commiters_table", None) or []:
                if committer.get("matches_company"):
                    priority = AITask.HIGH
                    break

            ai_done = threading.Event()
            submit_ai_analysis(self, callback=lambda *_: ai_done.set(), priority=priority)
            logger.debug(f"Submitted {self.repo_name} for async AI analysis")
            if not ai_done.wait(timeout=getattr(constants, "AI_ANALYSIS_TIMEOUT", 60)):
                logger.warning(f"AI analysis timed out for {self.repo_name}")
        except ImportError:
            self.run_ai_analysis_sync()
        except Exception as e:
            logger.warning(f"Failed to submit async AI analysis: {e}, using sync")
            self.run_ai_analysis_sync()

    def _scanner_results(self, scanner: str):
        """Return scanner results dict if present and valid, else None."""
        data = self.secrets.get(scanner)
        if isinstance(data, constants.AutoVivification) and data:
            return data
        return None

    def _check_status(self):
        if hasattr(self.stats, "is_inaccessible") and self.stats.is_inaccessible:
            self.lvl = 0
            self.res_check = constants.RESULT_CODE_LEAK_NOT_FOUND
            reason = getattr(self.stats, "inaccessibility_reason", "Unknown reason")
            self.status = [f"Not accessible: {reason}. Further analysis skipped."]
            if not getattr(self, '_inaccessible_logged', False):
                logger.info(f"Repository marked as inaccessible: {self.repo_name} - {reason}")
                self._inaccessible_logged = True
            return

        scan_error = self.secrets.get("Scan error")
        if (
            scan_error
            and any(kw in str(scan_error).lower() for kw in ["failed to clone", "clone"])
            and ("gist.github.com" in self.repo_url or int(self.stats.repo_stats_leak_stats_table["size"]) == 0)
        ):
            self.lvl = 0
            self.status = [self._get_message("gist_clone_error", constants.LANGUAGE)]
            return

        self._check_stats()
        self._submit_ai_analysis()
        if not self.ai_analysis:
            self.ai_analysis = {"Thinks": "Not state"}

        lang = constants.LANGUAGE
        leak_analyzer = LeakAnalyzer(self, bad_file_ext=bool(self.status and "File extension" in self.status[0]))
        analysis = leak_analyzer.compute_full_analysis()

        # --- Header: assessment + corporate committers (target first) ---
        self.status.insert(0, analysis["assessment"])
        committers = sorted(
            leak_analyzer.get_corporate_committers(),
            key=lambda c: not c.get("matches_company"),
        )
        for i, comm in enumerate(committers):
            is_target = comm.get("matches_company")
            msg_key = "corporate_committer_target" if is_target else "corporate_committer_other"
            kwargs = {"name": comm.get("commiter_name", "Unknown"), "email": comm.get("commiter_email", "")}
            if not is_target:
                kwargs["domain"] = comm.get("domain", "")
            self.status.insert(1 + i, self._get_message(msg_key, lang, **kwargs))

        # --- Credibility + context warnings ---
        cred = analysis["credibility_score"]
        if cred >= 0.7:
            cred_key = "repo_credibility_high"
        elif cred >= 0.4:
            cred_key = "repo_credibility_medium"
        else:
            cred_key = "repo_credibility_low"
        self.status.append(self._get_message(cred_key, lang, score=cred))

        for flag, msg_key in [("is_tiny", "repo_is_tiny"), ("is_personal", "repo_is_personal"), ("is_popular_oss", "repo_is_popular_oss")]:
            if analysis[flag]:
                self.status.append(self._get_message(msg_key, lang))
        if analysis["is_very_old"]:
            self.status.append(self._get_message("repo_is_very_old", lang, years=constants.REPO_AGE_VERY_OLD_YEARS))

        self.status.append(self._get_message("leak_found_in_section", lang, obj_type=self.obj_type, dork=self.dork))
        self.status.extend(self.secrets.get("status", []))

        # Unified results for downstream consumers
        if isinstance(self.secrets, (dict, constants.AutoVivification)):
            self.secrets["unified_results"] = self._get_unified_results_block()

        # --- Leak type keyword matches ---
        founded_commiters = [
            f'{c["commiter_name"]}/{c["commiter_email"]}' for c in self.stats.commits_stats_commiters_table
        ]
        commiters_str = ", ".join(founded_commiters)
        for leak_type in constants.leak_check_list:
            for text, msg_key, kw in [
                (self.author_name, "leak_in_author_name", {"author_name": self.author_name}),
                (commiters_str, "leak_in_committers", {}),
                (self.repo_name, "leak_in_repo_name", {"repo_name": self.repo_name}),
            ]:
                if leak_type in text:
                    self.status.append(self._get_message(msg_key, lang, leak_type=leak_type, **kw))

        # --- Description & topics ---
        stats_table = self.stats.repo_stats_leak_stats_table
        if isinstance(stats_table, dict):
            description_value = stats_table.get("description")
        else:
            logger.warning(f"repo_stats_leak_stats_table is not a dict: {type(stats_table)}")
            description_value = None

        if isinstance(description_value, str) and description_value.strip() not in ("", " ", "_"):
            desc = description_value[:constants.MAX_DESCRIPTION_LEN]
            if len(description_value) > constants.MAX_DESCRIPTION_LEN:
                desc += "..."
            self.status.append(self._get_message("short_description", lang, description=desc))
        else:
            self.status.append(self._get_message("no_description", lang))

        topics = stats_table["topics"]
        self.status.append(self._get_message(
            "topics", lang,
            topics=topics if topics not in ("", " ", "_") else self._get_message("no_topics", lang),
        ))

        # --- Committers display ---
        if len(founded_commiters) > constants.MAX_COMMITERS_DISPLAY:
            self.status.append(self._get_message(
                "committers_found", lang,
                committers=", ".join(founded_commiters[:constants.MAX_COMMITERS_DISPLAY]),
                remaining=len(founded_commiters) - constants.MAX_COMMITERS_DISPLAY,
            ))
        else:
            self.status.append(self._get_message("committers_all", lang, committers=commiters_str))

        # --- Scanner results ---
        grepscan = self._scanner_results("grepscan")
        if grepscan:
            try:
                first_val = next(iter(grepscan.values()))
                if isinstance(first_val, dict) and "Match" in first_val:
                    self.status.append(self._get_message("first_grepscan_line", lang, match=first_val["Match"]))
            except (StopIteration, KeyError, TypeError) as e:
                self.status.append(self._get_message("grepscan_parsing_error", lang, error=str(e)))

        sum_leaks_count = 0
        for scan_type in constants.SCANNER_TYPES:
            data = self._scanner_results(scan_type)
            if data:
                sum_leaks_count += len(data)
                self.status.append(self._get_message("leaks_found_by_scanner", lang, count=len(data), scanner=scan_type))

        self.status.append(self._get_message("total_leaks_found", lang, total_count=sum_leaks_count))
        self.status.append(self._get_message("full_report_length", lang, length=utils.count_nested_dict_len(self.secrets)))

        # --- Scoring & verdict ---
        self.profitability_scores = analysis["profitability"]
        verdict = analysis["verdict"]
        tp = analysis["unified_probability"]

        if constants.AI_ANALYSIS_ENABLED and self.ai_analysis != {"Thinks": "Not state"}:
            self._add_ai_analysis_to_status()

        self.status.append(self._get_message(
            "profitability_scores", lang,
            org_rel=self.profitability_scores["org_relevance"],
            sens_data=self.profitability_scores["sensitive_data"],
            tp=tp, fp=round(1.0 - tp, 2),
        ))

        target_result_code = verdict.get("target_result_code")
        if isinstance(target_result_code, int):
            self.res_check = target_result_code
        if verdict.get("should_close"):
            self._append_auto_close_to_brief_description(verdict.get("reason", ""))

        self.lvl = analysis["lvl"]
        self.status = "\n- ".join(dict.fromkeys(self.status))
        self.ready_to_send = True

    def _append_auto_close_to_brief_description(self, reason: str):
        """Append auto-close reason to brief description line only."""
        reason = (reason or "").strip()
        if not reason:
            return

        for idx, line in enumerate(self.status):
            if isinstance(line, str) and line.startswith(("Brief description:", "Краткое описание:")):
                self.status[idx] = f"{line} | {reason}"
                return

        self.status.append(self._get_message("short_description", constants.LANGUAGE, description=f"- | {reason}"))

    def _get_unified_results_block(self):
        """Build a block with unique results from all scanners combined."""
        all_unique_results = {}

        try:
            for scanner in constants.SCANNER_TYPES:
                if scanner in self.secrets and isinstance(self.secrets[scanner], constants.AutoVivification):
                    for key, value in self.secrets[scanner].items():
                        if key == "Info":  # Skip Info entries
                            continue
                        if isinstance(value, dict):
                            # Extract Match field for uniqueness comparison
                            match_text = str(
                                value.get("Match")
                                or value.get("Raw")
                                or value.get("RawV2")
                                or value.get("Description")
                                or ""
                            ).strip()

                            if not match_text or match_text == "...":
                                continue

                            # Use Match text as unique key (case-insensitive)
                            unique_key = match_text.lower()[:50]  # First 50 chars for uniqueness

                            if unique_key not in all_unique_results:
                                # Store the Match as value, not the full object
                                all_unique_results[unique_key] = {
                                    "scanner": scanner,
                                    "Match": match_text,  # Store Match text, not full object
                                    "File": value.get("File") or value.get("file") or "",
                                    "SecretType": value.get("Rule") or value.get("DetectorName") or "",
                                }

            return all_unique_results

        except Exception as e:
            logger.warning(f"Error building unified results block: {e}")
            return {}

    def write_obj(self):  # for write to DB
        if not self.ready_to_send:
            self._check_status()
        self.final_leak = {
            "url": self.repo_url,
            "level": self.lvl,
            "author_info": self.author_name,
            "found_at": self.found_time,
            "created_at": self.stats.created_at,
            "updated_at": self.stats.updated_at,
            "approval": 0,  # 0=not seen, 1=approved, 2=not found
            "leak_type": str(self.status[:10000]) + "..." if len(self.status) > 10000 else self.status,
            "result": int(self.res_check),  # 0=not found, 1=sent, 2=pending, 3=blocked, 4=not set, 5=rescan
            "company_id": self.company_id if isinstance(self.company_id, int) else 0,
        }
        return self.final_leak

    def _check_stats(self):
        if not self.stats.coll_stats_getted:
            self.stats.fetch_contributors_stats()
        if not self.stats.comm_stats_getted:
            self.stats.fetch_commits_stats()
        for contributor in self.stats.contributors_stats_accounts_table:
            contributor["company_id"] = self.company_id

        if "trufflehog" in self.secrets and len(self.secrets["trufflehog"]):
            commiter = {}
            missing_email_count = 0
            for leak in self.secrets["trufflehog"]:
                try:
                    if (
                        self.secrets["trufflehog"][leak]["SourceMetadata"]["Data"]["Git"]["email"].split("<")[0]
                        not in commiter.keys()
                    ):
                        commiter[
                            self.secrets["trufflehog"][leak]["SourceMetadata"]["Data"]["Git"]["email"].split("<")[0]
                        ] = self.secrets["trufflehog"][leak]["SourceMetadata"]["Data"]["Git"]["email"].split("<")[1]
                except Exception:
                    missing_email_count += 1
            if missing_email_count > 0:
                logger.warning("Not found acc_name/email in %d trufflehog results in %s repository", missing_email_count, self.repo_name)
            founded_commiters = [comm["commiter_name"] for comm in self.stats.commits_stats_commiters_table]
            for comm in commiter.keys():
                if comm not in founded_commiters:
                    self.stats.commits_stats_commiters_table.append(
                        {
                            "commiter_name": comm,
                            "commiter_email": commiter[comm],
                            "need_monitor": 0,
                            "related_account_id": 0,
                        }
                    )
                    founded_commiters.append(comm)

    def get_stats(self):
        return (
            self.stats.repo_stats_leak_stats_table,
            self.stats.contributors_stats_accounts_table,
            self.stats.commits_stats_commiters_table,
        )


class RepoObj(LeakObj):
    obj_type: str = "Repositories"

    def __init__(self, url: str, responce: dict, dork: str, company_id: int = 1):
        super().__init__(self.obj_type, url, responce, dork, company_id)
        self.author_name = self.responce["owner"]["login"]

    def __str__(self) -> str:
        return "Repositories"


class CommitObj(LeakObj):
    obj_type: str = "Commits"

    def __init__(self, url: str, responce: dict, dork: str, company_id: int = 0):
        super().__init__(self.obj_type, url, responce, dork, company_id)
        self.author_name = self.responce["commit"]["author"]["name"]
        self.author_email = self.responce["commit"]["author"]["email"]
        self.commit = self.responce["commit"]["message"]
        self.commit_date = self.responce["commit"]["author"]["date"]
        self.commit_hash = self.responce["sha"]
        self.status.append(self._get_message("commit_description", constants.LANGUAGE, commit=self.commit))

    def __str__(self) -> str:
        return "Commits"


class CodeObj(LeakObj):
    obj_type: str = "Code"

    def __init__(self, url: str, responce: dict, dork: str, company_id: int = 0):
        super().__init__(self.obj_type, url, responce, dork, company_id)
        self.author_name = self.responce["repository"]["owner"]["login"]

    def __str__(self) -> str:
        return "Code"


class GlistObj(LeakObj):
    obj_type: str = "Glist"

    def __init__(self, url: str, dork: str, company_id: int = 0):
        super().__init__(self.obj_type, url, {}, dork, company_id)
        self.author_name = url.split("github.com/")[1].split("/")[0]

    def __str__(self) -> str:
        return "Glist"
