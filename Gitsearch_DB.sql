-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 172.32.0.97:3306:3306
-- Generation Time: May 10, 2024 at 02:50 PM
-- Server version: 10.3.39-MariaDB-1:10.3.39+maria~ubu2004
-- PHP Version: 8.2.18

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
-- Table structure for table `dorks`
--

CREATE TABLE `dorks` (
  `id` int(10) UNSIGNED NOT NULL,
  `dork` text NOT NULL,
  `company_id` int(10) UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `dorks`
--

INSERT INTO `dorks` (`id`, `dork`, `company_id`) VALUES
(1, 'b\'YWxwaGEgYmFuaywgYXBwZm94LCBhaWhvbW0sIHNreWVuZywgaGFicmFoYWJy\'', 1),
(2, 'b\'Y3JvYywgc2JlcnRlY2gsIHRpbmtvZmY=\'', 2);

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
-- Indexes for table `row_report`
--
ALTER TABLE `row_report`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `dorks`
--
ALTER TABLE `dorks`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT for table `leak`
--
ALTER TABLE `leak`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7624;

--
-- AUTO_INCREMENT for table `row_report`
--
ALTER TABLE `row_report`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7792;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
