SET SQL_MODE = "ONLY_FULL_GROUP_BY,NO_ZERO_IN_DATE,NO_ZERO_DATE,NO_ENGINE_SUBSTITUTION,NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+08:00";

CREATE TABLE IF NOT EXISTS `title` (
    `id` tinyint(1) NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `text` varchar(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `title` (`id`, `text`) VALUES ("1", "My Message Board System");

CREATE TABLE IF NOT EXISTS `users` (
    `uid` int(11) NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `username` varchar(64) NOT NULL,
    `password` char(128) NOT NULL,
    `profile` varchar(300),
    `isadmin` boolean DEFAULT false
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `message` (
    `mid` int(11) NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `uid` int(11) NOT NULL,
    `message` varchar(1000) NOT NULL,
    `isdelete` boolean DEFAULT false,
    `attachment` varchar(300),
    FOREIGN KEY (uid) REFERENCES users(uid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;