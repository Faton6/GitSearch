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
            and any(keyword in str(scan_error).lower() for keyword in ["failed to clone", "clone"])
            and ("gist.github.com" in self.repo_url or int(self.stats.repo_stats_leak_stats_table["size"]) == 0)
        ):
            self.lvl = 0
            self.status = [self._get_message("gist_clone_error", constants.LANGUAGE)]
            return

        self._check_stats()
        lang = constants.LANGUAGE  # Assuming LANGUAGE is defined in constants.py

        # Submit AI analysis and wait for result before scoring
        if constants.AI_ANALYSIS_ENABLED and not self.ai_analysis:
            try:
                from src.AIObj import submit_ai_analysis, AITask
                import threading

                # Determine priority based on early signals
                priority = AITask.NORMAL
                # High priority if corporate committer found
                if hasattr(self, "stats") and hasattr(self.stats, "commits_stats_commiters_table"):
                    for committer in self.stats.commits_stats_commiters_table or []:
                        if committer.get("matches_company"):
                            priority = AITask.HIGH
                            break

                # Submit for async analysis and wait with timeout
                ai_done = threading.Event()
                submit_ai_analysis(self, callback=lambda *_: ai_done.set(), priority=priority)
                logger.debug(f"Submitted {self.repo_name} for async AI analysis")
                ai_timeout = getattr(constants, "AI_ANALYSIS_TIMEOUT", 60)
                if not ai_done.wait(timeout=ai_timeout):
                    logger.warning(f"AI analysis timed out for {self.repo_name}")
            except ImportError:
                # Fallback to sync if ai_worker not available
                self.run_ai_analysis_sync()
            except Exception as e:
                logger.warning(f"Failed to submit async AI analysis: {e}, using sync")
                self.run_ai_analysis_sync()

        if not self.ai_analysis:
            self.ai_analysis = {"Thinks": "Not state"}

        # Используем LeakAnalyzer для анализа
        bad_file_ext = len(self.status) > 0 and "File extension" in self.status[0]
        leak_analyzer = LeakAnalyzer(self, bad_file_ext=bad_file_ext)

        # Get final assessment from LeakAnalyzer and insert as the first line
        final_assessment = leak_analyzer.get_final_assessment()
        self.status.insert(0, final_assessment)

        # ===== CRITICAL: Highlight corporate committers (almost 100% relevance!) =====
        corporate_committers = leak_analyzer.get_corporate_committers()

        # Sort committers: Target company first, then others
        target_committers = [c for c in corporate_committers if c.get("matches_company")]
        other_committers = [c for c in corporate_committers if not c.get("matches_company")]

        # Display Target Company committers (High Priority)
        for committer in target_committers:
            self.status.insert(
                1,
                self._get_message(
                    "corporate_committer_target",
                    lang,
                    name=committer.get("commiter_name", "Unknown"),
                    email=committer.get("commiter_email", ""),
                ),
            )

        # Display Other Corporate committers (Medium Priority)
        # Insert after target messages (which are at pos 1..N) to keep them prominent but secondary
        insert_pos = 1 + len(target_committers)
        for committer in other_committers:
            self.status.insert(
                insert_pos,
                self._get_message(
                    "corporate_committer_other",
                    lang,
                    name=committer.get("commiter_name", "Unknown"),
                    email=committer.get("commiter_email", ""),
                    domain=committer.get("domain", ""),
                ),
            )
            insert_pos += 1

        # ===== Repository credibility assessment =====
        credibility_score = leak_analyzer._calculate_repo_credibility_score()
        if credibility_score >= 0.7:
            self.status.append(self._get_message("repo_credibility_high", lang, score=credibility_score))
        elif credibility_score >= 0.4:
            self.status.append(self._get_message("repo_credibility_medium", lang, score=credibility_score))
        else:
            self.status.append(self._get_message("repo_credibility_low", lang, score=credibility_score))

        # Add context warnings
        if leak_analyzer._is_tiny_repository():
            self.status.append(self._get_message("repo_is_tiny", lang))
        if leak_analyzer._is_likely_personal_project():
            self.status.append(self._get_message("repo_is_personal", lang))
        if leak_analyzer._is_very_popular_repository():
            self.status.append(self._get_message("repo_is_popular_oss", lang))
        if leak_analyzer._is_very_old_repository():
            self.status.append(
                self._get_message("repo_is_very_old", lang, years=constants.REPO_AGE_VERY_OLD_YEARS)
            )

        self.status.append(self._get_message("leak_found_in_section", lang, obj_type=self.obj_type, dork=self.dork))

        if "status" in self.secrets:
            for i in self.secrets["status"]:
                self.status.append(i)

        # Keep unified results also inside secrets for downstream consumers
        if isinstance(self.secrets, (dict, constants.AutoVivification)):
            # Always expose the key to avoid KeyError downstream
            self.secrets["unified_results"] = self._get_unified_results_block()
        founded_commiters = [
            f'{comm["commiter_name"]}/{comm["commiter_email"]}' for comm in self.stats.commits_stats_commiters_table
        ]
        for leak_type in constants.leak_check_list:
            if leak_type in self.author_name:
                self.status.append(
                    self._get_message("leak_in_author_name", lang, leak_type=leak_type, author_name=self.author_name)
                )
            if leak_type in ", ".join(founded_commiters):
                self.status.append(self._get_message("leak_in_committers", lang, leak_type=leak_type))
            if leak_type in self.repo_name:
                self.status.append(
                    self._get_message("leak_in_repo_name", lang, leak_type=leak_type, repo_name=self.repo_name)
                )

        if isinstance(self.stats.repo_stats_leak_stats_table, dict):
            description_value = self.stats.repo_stats_leak_stats_table.get("description")
        else:
            logger.warning(f"repo_stats_leak_stats_table is not a dict: {type(self.stats.repo_stats_leak_stats_table)}")
            description_value = None

        if isinstance(description_value, str) and description_value.strip() not in ["_", "", " "]:
            description = description_value
            if len(description) > constants.MAX_DESCRIPTION_LEN:
                description = description[: constants.MAX_DESCRIPTION_LEN] + "..."
            self.status.append(self._get_message("short_description", lang, description=description))
        else:
            self.status.append(self._get_message("no_description", lang))
        topics = self.stats.repo_stats_leak_stats_table["topics"]
        self.status.append(
            self._get_message(
                "topics", lang, topics=topics if topics not in ["_", "", " "] else self._get_message("no_topics", lang)
            )
        )

        if len(founded_commiters) > constants.MAX_COMMITERS_DISPLAY:
            self.status.append(
                self._get_message(
                    "committers_found",
                    lang,
                    committers=", ".join(founded_commiters[: constants.MAX_COMMITERS_DISPLAY]),
                    remaining=len(founded_commiters) - constants.MAX_COMMITERS_DISPLAY,
                )
            )
        else:
            self.status.append(self._get_message("committers_all", lang, committers=", ".join(founded_commiters)))

        scaners = list(constants.SCANNER_TYPES)
        if (
            "grepscan" in self.secrets
            and isinstance(self.secrets["grepscan"], constants.AutoVivification)
            and len(self.secrets["grepscan"])
        ):
            try:
                grepscan_values = list(self.secrets["grepscan"].values())
                if grepscan_values and isinstance(grepscan_values[0], dict) and "Match" in grepscan_values[0]:
                    first_match = grepscan_values[0]["Match"]
                    self.status.append(self._get_message("first_grepscan_line", lang, match=first_match))
            except (IndexError, KeyError, TypeError) as e:
                # Gracefully handle malformed grepscan results
                self.status.append(self._get_message("grepscan_parsing_error", lang, error=str(e)))

        sum_leaks_count = 0
        for scan_type in scaners:
            if (
                scan_type in self.secrets
                and isinstance(self.secrets[scan_type], constants.AutoVivification)
                and len(self.secrets[scan_type])
            ):
                sum_leaks_count += len(self.secrets[scan_type])
                self.status.append(
                    self._get_message(
                        "leaks_found_by_scanner", lang, count=len(self.secrets[scan_type]), scanner=scan_type
                    )
                )

        self.status.append(self._get_message("total_leaks_found", lang, total_count=sum_leaks_count))
        self.status.append(
            self._get_message("full_report_length", lang, length=utils.count_nested_dict_len(self.secrets))
        )

        # Calculate profitability scores (base: org_relevance + sensitive_data)
        self.profitability_scores = leak_analyzer.calculate_profitability()

        # Add AI analysis to status
        if constants.AI_ANALYSIS_ENABLED and self.ai_analysis != {"Thinks": "Not state"}:
            self._add_ai_analysis_to_status()

        # Unified probability: single source of truth combining all signals
        true_positive_chance = leak_analyzer.calculate_unified_probability(self.profitability_scores)

        if isinstance(self.profitability_scores, dict):
            self.profitability_scores["unified_probability"] = true_positive_chance

        verdict = leak_analyzer.evaluate_incident_verdict(
            unified_score=true_positive_chance,
            profitability=self.profitability_scores,
        )

        if isinstance(self.profitability_scores, dict):
            self.profitability_scores.update(
                {
                    "target_result_code": verdict.get("target_result_code", constants.RESULT_CODE_TO_SEND),
                    "should_close": bool(verdict.get("should_close")),
                    "should_recheck": bool(verdict.get("should_recheck")),
                    "is_high_priority": bool(verdict.get("is_high_priority", False)),
                    "verdict_reason": verdict.get("reason", ""),
                }
            )

        if self.profitability_scores:
            self.status.append(
                self._get_message(
                    "profitability_scores",
                    lang,
                    org_rel=self.profitability_scores["org_relevance"],
                    sens_data=self.profitability_scores["sensitive_data"],
                    tp=true_positive_chance,
                    fp=round(1.0 - true_positive_chance, 2),
                )
            )

        # Decisive auto-close / recheck based on unified verdict
        target_result_code = verdict.get("target_result_code")
        if isinstance(target_result_code, int):
            self.res_check = target_result_code

        if verdict.get("should_close"):
            self._append_auto_close_to_brief_description(verdict.get("reason", ""))

        if true_positive_chance < 0.2:
            self.lvl = 0  # 'Low'
        elif 0.2 <= true_positive_chance < 0.5:
            self.lvl = 1  # 'Medium'
        else:
            self.lvl = 2  # 'High' (0.5+)

        # Remove duplicates from status while preserving order
        self.status = list(dict.fromkeys(self.status))

        # Add unified results block with all unique findings from all scanners

        self.status = "\n- ".join(self.status)
        self.ready_to_send = True

    def _append_auto_close_to_brief_description(self, reason: str):
        """Append auto-close reason to brief description line only."""
        reason_text = (reason or "").strip()
        if not reason_text:
            return

        description_prefixes = ("Brief description:", "Краткое описание:")
        for idx, line in enumerate(self.status):
            if isinstance(line, str) and line.startswith(description_prefixes):
                self.status[idx] = f"{line} | {reason_text}"
                return

        fallback = self._get_message("short_description", constants.LANGUAGE, description=f"- | {reason_text}")
        self.status.append(fallback)

    def _get_unified_results_block(self):
        """Add a block with unique results from all scanners combined."""
        scanners = list(constants.SCANNER_TYPES)
        all_unique_results = {}  # key -> result mapping

        try:
            for scanner in scanners:
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
            founded_leak = str(self.status[:10000]) + "..."
        else:
            founded_leak = self.status
        # Result:
        # 0 - leaks doesn't found, add to exclude list
        # 1 - leaks found, sent request to block
        # 2 - leaks found, not yet sent request to block
        # 3 - leaks found, blocked
        # 4 - not set
        # 5 - need more scan
        self.final_leak = {
            "url": self.repo_url,
            "level": self.lvl,
            "author_info": self.author_name,
            "found_at": self.found_time,
            "created_at": self.stats.created_at,
            "updated_at": self.stats.updated_at,
            "approval": res_human_check,
            "leak_type": founded_leak,
            "result": int(self.res_check),
            # DB schema expects int; local config may use string IDs like "kbtest"
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
