-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 172.32.0.97:3306:3306
-- Generation Time: Jun 18, 2024 at 11:06 AM
-- Server version: 10.3.39-MariaDB-1:10.3.39+maria~ubu2004
-- PHP Version: 8.2.20

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `Gitsearch`
--

-- --------------------------------------------------------

--
-- Table structure for table `accounts`
--

CREATE TABLE `accounts` (
  `id` int(11) NOT NULL,
  `account` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `need_monitor` tinyint(1) NOT NULL,
  `related_company_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table structure for table `commiters`
--

CREATE TABLE `commiters` (
  `id` int(11) NOT NULL,
  `leak_id` int(11) NOT NULL,
  `commiter_name` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `commiter_email` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `need_monitor` tinyint(1) NOT NULL,
  `related_account_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table structure for table `companies`
--

CREATE TABLE `companies` (
  `id` int(10) UNSIGNED NOT NULL,
  `company_name` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `companies`
--

INSERT INTO `companies` (`id`, `company_name`) VALUES
(1, 'Google');

-- --------------------------------------------------------

--
-- Table structure for table `dorks`
--

CREATE TABLE `dorks` (
  `id` int(10) UNSIGNED NOT NULL,
  `dork` text NOT NULL,
  `company_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `dorks`
--

INSERT INTO `dorks` (`id`, `dork`, `company_id`) VALUES
(1, 'R29vZ2xlLWRldiwgZGV2Lmdvb2dsZQ==', 1);

-- --------------------------------------------------------

--
-- Table structure for table `leak`
--

CREATE TABLE `leak` (
  `id` int(11) NOT NULL,
  `url` char(255) NOT NULL,
  `level` tinyint(4) NOT NULL,
  `author_info` text NOT NULL,
  `found_at` datetime NOT NULL,
  `created_at` datetime NOT NULL,
  `updated_at` datetime DEFAULT NULL,
  `approval` tinyint(4) DEFAULT NULL,
  `leak_type` text NOT NULL,
  `result` tinyint(4) DEFAULT NULL,
  `done_by` smallint(6) DEFAULT -1,
  `company_id` int(10) UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `leak_stats`
--

CREATE TABLE `leak_stats` (
  `id` int(10) UNSIGNED NOT NULL,
  `leak_id` int(10) UNSIGNED NOT NULL,
  `size` int(10) UNSIGNED NOT NULL,
  `stargazers_count` int(10) UNSIGNED NOT NULL,
  `has_issues` tinyint(1) NOT NULL,
  `has_projects` tinyint(1) NOT NULL,
  `has_downloads` tinyint(1) NOT NULL,
  `has_wiki` tinyint(1) NOT NULL,
  `has_pages` tinyint(1) NOT NULL,
  `forks_count` int(10) UNSIGNED NOT NULL,
  `open_issues_count` int(10) UNSIGNED NOT NULL,
  `subscribers_count` int(10) UNSIGNED NOT NULL,
  `topics` mediumtext CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `contributors_count` int(11) NOT NULL,
  `commits_count` int(11) NOT NULL,
  `commiters_count` int(11) NOT NULL,
  `description` mediumtext CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table structure for table `related_accounts_leaks`
--

CREATE TABLE `related_accounts_leaks` (
  `id` int(11) NOT NULL,
  `leak_id` int(11) NOT NULL,
  `account_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table structure for table `row_report`
--

CREATE TABLE `row_report` (
  `id` int(10) UNSIGNED NOT NULL,
  `leak_id` int(10) UNSIGNED NOT NULL,
  `report_name` char(255) NOT NULL,
  `row_data` mediumtext NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `accounts`
--
ALTER TABLE `accounts`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `commiters`
--
ALTER TABLE `commiters`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `companies`
--
ALTER TABLE `companies`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `dorks`
--
ALTER TABLE `dorks`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `leak`
--
ALTER TABLE `leak`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `leak_stats`
--
ALTER TABLE `leak_stats`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `related_accounts_leaks`
--
ALTER TABLE `related_accounts_leaks`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `row_report`
--
ALTER TABLE `row_report`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `accounts`
--
ALTER TABLE `accounts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `commiters`
--
ALTER TABLE `commiters`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `companies`
--
ALTER TABLE `companies`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `dorks`
--
ALTER TABLE `dorks`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `leak`
--
ALTER TABLE `leak`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `leak_stats`
--
ALTER TABLE `leak_stats`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `related_accounts_leaks`
--
ALTER TABLE `related_accounts_leaks`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `row_report`
--
ALTER TABLE `row_report`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
