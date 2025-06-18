-- Database: `Gitsearch`

START TRANSACTION;

CREATE TABLE accounts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  account TEXT NOT NULL,
  need_monitor TINYINT(1) NOT NULL,
  related_company_id INT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE commiters (
  id INT AUTO_INCREMENT PRIMARY KEY,
  leak_id INT NOT NULL,
  commiter_name TEXT NOT NULL,
  commiter_email TEXT NOT NULL,
  need_monitor TINYINT(1) NOT NULL,
  related_account_id INT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE companies (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  company_name TEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

INSERT INTO companies (id, company_name) VALUES
  (1, 'Google');

CREATE TABLE dorks (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  dork TEXT NOT NULL,
  company_id INT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

INSERT INTO dorks (id, dork, company_id) VALUES
  (1, 'R29vZ2xlLWRldiwgZGV2Lmdvb2dsZQ==', 1);

CREATE TABLE leak (
  id INT AUTO_INCREMENT PRIMARY KEY,
  url CHAR(255) NOT NULL,
  level TINYINT NOT NULL,
  author_info TEXT NOT NULL,
  found_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NULL,
  approval TINYINT NULL,
  leak_type TEXT NOT NULL,
  result TINYINT NULL,
  done_by SMALLINT DEFAULT -1,
  company_id INT UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE leak_stats (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  leak_id INT UNSIGNED NOT NULL,
  size INT UNSIGNED NOT NULL,
  stargazers_count INT UNSIGNED NOT NULL,
  has_issues TINYINT(1) NOT NULL,
  has_projects TINYINT(1) NOT NULL,
  has_downloads TINYINT(1) NOT NULL,
  has_wiki TINYINT(1) NOT NULL,
  has_pages TINYINT(1) NOT NULL,
  forks_count INT UNSIGNED NOT NULL,
  open_issues_count INT UNSIGNED NOT NULL,
  subscribers_count INT UNSIGNED NOT NULL,
  topics MEDIUMTEXT NOT NULL,
  contributors_count INT NOT NULL,
  commits_count INT NOT NULL,
  commiters_count INT NOT NULL,
  ai_result INT NOT NULL,
  description MEDIUMTEXT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE related_accounts_leaks (
  id INT AUTO_INCREMENT PRIMARY KEY,
  leak_id INT NOT NULL,
  account_id INT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE raw_report (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  leak_id INT UNSIGNED NOT NULL,
  report_name CHAR(255) NOT NULL,
  raw_data MEDIUMTEXT NOT NULL,
  ai_report MEDIUMTEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

COMMIT;
-- --------------------------------------------------------