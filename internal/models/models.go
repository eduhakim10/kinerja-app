package models

type User struct {
    ID       int    `db:"id"`
	Name string `db:"name"`
    Username string `db:"username"`
    Password string `db:"password"`
    Role     string `db:"role"`
}

type Report struct {
    ID          int    `db:"id"`
    TaskID      int    `db:"task_id"` // ID Tugas
    Achievements float64 `db:"achievements"` // Capaian kerja
    Notes       string `db:"notes"` // Keterangan tambahan
    FilePath    string `db:"file_path"` // Path file pendukung
    Status      string `db:"status"` // Status: Menunggu Verifikasi, Diterima, Ditolak
}

type Task struct {
    ID           int    `db:"id" json:"id"`
    Title        string `db:"title" json:"title"`
    Deadline     string `db:"deadline" json:"deadline"` // Format tanggal
    ReporterID   int    `db:"reporter_id" json:"reporter_id"` // ID pengguna yang melaporkan
    VerifierID   int    `db:"verifier_id" json:"verifier_id"` // ID pengguna yang memverifikasi
    ReporterName string `db:"reporter_name" json:"reporter_name"` // Nama reporter
    VerifierName string `db:"verifier_name" json:"verifier_name"` // Nama verifier
    Status       string `db:"status" json:"status"` // Status laporan
}
