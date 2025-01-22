create database kinerja_db;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('Pelapor', 'Verifikator', 'Admin') NOT NULL
);

CREATE TABLE tasks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    deadline DATE NOT NULL,
    reporter_id INT NOT NULL,
    verifier_id INT NOT NULL,
    FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (verifier_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    task_id INT NOT NULL,
    achievements FLOAT NOT NULL,
    notes TEXT,
    file_path VARCHAR(255),
    status VARCHAR(20) NOT NULL CHECK (status IN ('Menunggu Verifikasi', 'Diterima', 'Ditolak')),
    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
);