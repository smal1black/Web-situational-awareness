package sqlserve

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type IPInfo struct {
	ID int    `json:"id"`
	IP string `json:"ip"`
}

var (
	db         *sql.DB
	DBpassword string
	DBaddress  string
	DBname     string
	DBport     string
)

func DBinitialize(dbAddress string, dbPort string, dbPassword string, dbName string) {
	DBpassword = dbPassword
	DBaddress = dbAddress
	DBname = dbName
	DBport = dbPort
}

func InitDB() error {
	var err error
	dsn := fmt.Sprintf("root:%s@tcp(%s:%s)/%s", DBpassword, DBaddress, DBport, DBname)
	fmt.Println(dsn)
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		return err
	}

	err = db.Ping()
	if err != nil {
		return err
	}

	return nil
}

func CloseDB() {
	if db != nil {
		db.Close()
	}
}

func CheckIPExists(ip string) (bool, error) {
	if db == nil {
		if err := InitDB(); err != nil {
			log.Println("Failed to connect to the database:", err)
			return false, err
		}
	}

	query := "SELECT EXISTS(SELECT 1 FROM ip_info WHERE ip = ?)"
	stmt, err := db.Prepare(query)
	if err != nil {
		log.Println("Failed to prepare statement:", err)
		return false, err
	}

	var exists bool
	err = stmt.QueryRow(ip).Scan(&exists)
	if err != nil {
		log.Println("Failed to execute query:", err)
		return false, err
	}

	return exists, nil
}

func WriteIP(ip string) error {
	if db == nil {
		if err := InitDB(); err != nil {
			log.Println("Failed to connect to the database:", err)
			return err
		}
	}

	exists, err := CheckIPExists(ip)
	if err != nil {
		return err
	}

	if exists {
		log.Println("IP already exists:", ip)
		return nil
	}

	insertSQL := "INSERT INTO ip_info (ip) VALUES (?)"
	_, err = db.Exec(insertSQL, ip)
	if err != nil {
		log.Println("Failed to insert IP:", err)
		return err
	}

	return nil
}

func DeleteIP(ip string) error {
	if db == nil {
		if err := InitDB(); err != nil {
			log.Println("Failed to connect to the database:", err)
			return err
		}
	}

	exists, err := CheckIPExists(ip)
	if err != nil {
		return err
	}

	if !exists {
		log.Println("IP does not exist:", ip)
		return nil
	}

	deleteSQL := "DELETE FROM ip_info WHERE ip = ?"
	_, err = db.Exec(deleteSQL, ip)
	if err != nil {
		log.Println("Failed to delete IP:", err)
		return err
	}

	return nil
}

func createTable() error {
	createSQL := `
       CREATE TABLE IF NOT EXISTS ip_info (
          id INT AUTO_INCREMENT PRIMARY KEY,
          ip VARCHAR(50) NOT NULL
       );`

	_, err := db.Exec(createSQL)
	if err != nil {
		return err
	}

	fmt.Println("Table created successfully.")
	return nil
}

func Init() error {
	if db == nil {
		if err := InitDB(); err != nil {
			log.Fatal("Failed to connect to the database:", err)
			return err
		}
	}

	err := createTable()
	if err != nil {
		log.Fatal("Failed to create table:", err)
		return err
	}

	fmt.Println("Initialization completed successfully.")
	return nil
}
func GetAllIPs() ([]string, error) {
	if db == nil {
		if err := InitDB(); err != nil {
			return nil, err
		}
	}

	query := "SELECT ip FROM ip_info"
	rows, err := db.Query(query)
	if err != nil {
		log.Println("Failed to execute query:", err)
		return nil, err
	}
	defer rows.Close()

	var ipList []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			log.Println("Failed to scan row:", err)
			return nil, err
		}
		ipList = append(ipList, ip)
	}

	if err := rows.Err(); err != nil {
		log.Println("Error occurred while iterating through rows:", err)
		return nil, err
	}

	return ipList, nil
}

func CreateInformationTable() error {
	_, err := db.Exec(`
       CREATE TABLE IF NOT EXISTS information (
          id INT AUTO_INCREMENT PRIMARY KEY,
          time VARCHAR(19),
          method VARCHAR(10),
          ip VARCHAR(15),
          url VARCHAR(255),
          status VARCHAR(10),
          intact VARCHAR(3000)
       )
    `)
	return err
}

type Information struct {
	ID     int
	Time   string
	Method string
	IP     string
	URL    string
	Status string
	Intact string
}

func GetInformation() ([]Information, error) {
	rows, err := db.Query("SELECT id, time, method, ip, url, status, intact FROM information")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var information []Information

	for rows.Next() {
		var info Information
		err := rows.Scan(&info.ID, &info.Time, &info.Method, &info.IP, &info.URL, &info.Status, &info.Intact)
		if err != nil {
			return nil, err
		}
		information = append(information, info)
	}

	return information, nil
}

func InsertInformation(method, ip, url, status, intact string) error {
	if db == nil {
		return errors.New("database connection not initialized")
	}

	currentTime := time.Now()

	stmt, err := db.Prepare("INSERT INTO information(time, method, ip, url, status, intact) VALUES(?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(currentTime.Format("2006-01-02 15:04:05"), method, ip, url, status, intact)
	if err != nil {
		return err
	}

	return nil
}

func DeleteInformationByIPAndURL(ip, url string) error {
	if db == nil {
		return errors.New("database connection not initialized")
	}

	stmt, err := db.Prepare("DELETE FROM information WHERE ip = ? AND url = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(ip, url)
	if err != nil {
		return err
	}

	return nil
}
