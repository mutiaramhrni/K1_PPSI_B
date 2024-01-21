-- --------------------------------------------------------
-- Host:                         127.0.0.1
-- Server version:               8.0.30 - MySQL Community Server - GPL
-- Server OS:                    Win64
-- HeidiSQL Version:             12.1.0.6537
-- --------------------------------------------------------

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8 */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
-- Dumping structure for table ppsitb.enroll
CREATE TABLE IF NOT EXISTS `enroll` (
  `id_enroll` int NOT NULL AUTO_INCREMENT,
  `enroll_key` text,
  `id_user` varchar(50) DEFAULT NULL,
  `Created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `Updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id_enroll`),
  KEY `id_user` (`id_user`),
  CONSTRAINT `enroll_ibfk_1` FOREIGN KEY (`id_user`) REFERENCES `user` (`id_user`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Dumping data for table ppsitb.enroll: ~2 rows (approximately)
INSERT INTO `enroll` (`id_enroll`, `enroll_key`, `id_user`, `Created_at`, `Updated_at`) VALUES
	(1, 'daspro2023', '2111521006', '2023-11-13 17:49:14', '2023-11-13 17:49:14'),
	(2, 'daspro2023', '2111521007', '2023-11-13 18:20:44', '2023-11-13 18:20:44');

-- Dumping structure for table ppsitb.grades
CREATE TABLE IF NOT EXISTS `grades` (
  `grade_id` int NOT NULL AUTO_INCREMENT,
  `id_upload` int DEFAULT NULL,
  `id_user` varchar(50) DEFAULT NULL,
  `grade` decimal(5,2) DEFAULT NULL,
  `feedback` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci,
  `Created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `Updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`grade_id`),
  KEY `id_user` (`id_user`),
  KEY `id_tugas` (`id_upload`) USING BTREE,
  CONSTRAINT `FK_grades_submission` FOREIGN KEY (`id_upload`) REFERENCES `submission` (`id_upload`),
  CONSTRAINT `grades_ibfk_2` FOREIGN KEY (`id_user`) REFERENCES `user` (`id_user`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Dumping data for table ppsitb.grades: ~0 rows (approximately)

-- Dumping structure for table ppsitb.kelas
CREATE TABLE IF NOT EXISTS `kelas` (
  `id_kelas` int NOT NULL AUTO_INCREMENT,
  `title` varchar(255) DEFAULT NULL,
  `slug_kelas` varchar(255) DEFAULT NULL,
  `enroll_key` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `excerpt` varchar(50) DEFAULT NULL,
  `deadline` datetime DEFAULT NULL,
  `id_user` varchar(50) DEFAULT NULL,
  `Created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `Updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id_kelas`),
  KEY `id_user` (`id_user`),
  CONSTRAINT `kelas_ibfk_1` FOREIGN KEY (`id_user`) REFERENCES `user` (`id_user`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Dumping data for table ppsitb.kelas: ~2 rows (approximately)
INSERT INTO `kelas` (`id_kelas`, `title`, `slug_kelas`, `enroll_key`, `excerpt`, `deadline`, `id_user`, `Created_at`, `Updated_at`) VALUES
	(1, 'Dasar Dasar Pemrograman', 'dasar-dasar-pemrograman', 'daspro2023', 'Project GUI C++', NULL, '0000000000000001', '2023-11-13 17:26:39', '2023-11-13 17:26:39'),
	(2, 'Database', 'database', 'db2023', 'Website menggunakan Codeigniter 4', NULL, '0000000000000001', '2023-11-20 16:24:39', '2023-11-20 16:24:39');

-- Dumping structure for table ppsitb.submission
CREATE TABLE IF NOT EXISTS `submission` (
  `id_upload` int NOT NULL AUTO_INCREMENT,
  `id_user` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `file` varchar(50) NOT NULL,
  `created_at` timestamp(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `updated_at` timestamp(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id_upload`),
  KEY `nim` (`id_user`) USING BTREE,
  KEY `id_file` (`file`) USING BTREE,
  CONSTRAINT `FK_upload_user` FOREIGN KEY (`id_user`) REFERENCES `user` (`id_user`)
) ENGINE=InnoDB AUTO_INCREMENT=17 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Dumping data for table ppsitb.submission: ~0 rows (approximately)

-- Dumping structure for table ppsitb.user
CREATE TABLE IF NOT EXISTS `user` (
  `id_user` varchar(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `role` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `username` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `email` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `password` varchar(255) NOT NULL,
  `avatar` varchar(255) DEFAULT NULL,
  `created_at` timestamp(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `updated_at` timestamp(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id_user`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Dumping data for table ppsitb.user: ~5 rows (approximately)
INSERT INTO `user` (`id_user`, `role`, `username`, `email`, `password`, `avatar`, `created_at`, `updated_at`) VALUES
	('0000000000000001', 'dosen', NULL, 'dosen01@gmail.com', '$2b$10$LQmxS7g.c2CCWNg1GfqkfuIAk3OllN4TBZJnMz7EeFDHdNqCF8aWO', NULL, '2023-11-13 17:03:21.987496', '2023-11-13 17:03:21.987496'),
	('2111521006', 'mahasiswa', 'Mutiara', 'mhs1@gmail.com', '$2b$10$.IOVGNCMFbluNBiUP9zqDeJLZwMo2nNE0dgImkju4hVvZ/cd/eota', NULL, '2023-11-06 16:32:01.583280', '2023-11-06 16:32:01.583280'),
	('2111521007', 'mahasiswa', NULL, 'mhs2@gmail.com', '$2b$10$kg8lteUYm1D8w3KnhxszQO5R8GS67dAT2qVb1mJ6tCgeDa3auo2PO', NULL, '2023-11-13 18:20:35.057636', '2023-11-13 18:20:35.057636'),
	('2111521008', 'mahasiswa', 'Mawar', NULL, '$2b$10$v/rlW89aHCLapyNd2L/9O.74bmDlydNZtV9LpFW3hZapuWoIZ.Dbm', NULL, '2023-11-14 06:35:57.698539', '2023-11-14 06:35:57.698539'),
	('9999999999', 'admin', 'Admin', 'admin@gmail.com', '$2b$10$RC85K.J3KJLnjLC/iI2rGudq22cElPWCV.WjmWXuMLaxIN7XERSS6', NULL, '2023-11-09 06:30:57.041963', '2023-11-09 06:30:57.041963');

/*!40103 SET TIME_ZONE=IFNULL(@OLD_TIME_ZONE, 'system') */;
/*!40101 SET SQL_MODE=IFNULL(@OLD_SQL_MODE, '') */;
/*!40014 SET FOREIGN_KEY_CHECKS=IFNULL(@OLD_FOREIGN_KEY_CHECKS, 1) */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40111 SET SQL_NOTES=IFNULL(@OLD_SQL_NOTES, 1) */;
usersubmission