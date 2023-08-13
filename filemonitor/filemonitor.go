package filemonitor

import (
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"redrock/deepscan"
	"redrock/filedelet"
	"time"
)

var (
	MaliciousFiles  = make(map[string]string)
	SuspiciousFiles = make(map[string]string)
	reports         = make(map[string]string)
)
var updates = make(chan map[string]string)
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func Filemonitor(webPath string) {

	fmt.Printf("开始监测是否有恶意文件生成")
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	dir := webPath
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Println(err)
			return nil
		}

		if info.IsDir() {
			return watcher.Add(path)
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if event.Op&fsnotify.Create == fsnotify.Create {

					fmt.Print("有新文件产生")
					isMaliciousFile(event.Name)
				}

				updates <- map[string]string{
					"newFiles":        event.Name,
					"maliciousFiles":  MaliciousFiles[event.Name],
					"suspiciousFiles": SuspiciousFiles[event.Name],
				}
			case err := <-watcher.Errors:
				log.Println("错误:", err)
			}
		}
	}()

	// 等待程序终止
	<-make(chan struct{})
}

func isMaliciousFile(filepath string) {

	filePath := filepath
	time.Sleep(30 * time.Second)
	fileData, err := os.Open(filePath)
	if err != nil {
		fmt.Print("获取文件内容出错")
		return
	}
	defer fileData.Close()

	uploadResponse, err := deepscan.UploadFile(fileData, filePath)
	if err != nil {
		return
	}

	reports[filePath] = uploadResponse.Data.Sha256
	for filePath, sha256 := range reports {
		reportResponse, err := deepscan.GetReport(sha256)
		if err != nil {
			fmt.Printf("Failed to get report for file %s: %s\n", filePath, err.Error())
			continue
		}

		threatLevel := reportResponse.Data.Summary.ThreatLevel
		if threatLevel == "" {
			fmt.Printf("文件路径: %s，报告还未生成，60秒后将再次查看\n", filePath)
			time.Sleep(60 * time.Second)

			reportResponse, err = deepscan.GetReport(sha256)
			if err != nil {
				fmt.Printf("Failed to get report for file %s: %s\n", filePath, err.Error())
				continue
			}

			threatLevel = reportResponse.Data.Summary.ThreatLevel
		}

		fmt.Printf("文件路径: %s，威胁等级: %s\n", filePath, threatLevel)

		reportURL := fmt.Sprintf("https://s.threatbook.com/report/file/%s", sha256)
		reports[filePath] = reportURL

		if threatLevel == "malicious" {
			MaliciousFiles[filePath] = reportURL
		} else if threatLevel == "suspicious" {
			SuspiciousFiles[filePath] = reportURL
		}
	}
	fmt.Println("发现恶意文件：")
	for filePath, reportURL := range MaliciousFiles {
		fmt.Printf("文件路径: %s，报告地址：%s\n", filePath, reportURL)
	}
	fmt.Println("发现可疑文件：")
	for filePath, reportURL := range SuspiciousFiles {
		fmt.Printf("文件路径: %s，报告地址：%s\n", filePath, reportURL)
	}
	fmt.Println("删除恶意文件(若有)：")
	for filePath := range MaliciousFiles {
		err := filedelet.DeleteFile(filePath)
		if err != nil {
			fmt.Printf("删除文件 %s 失败：%s\n", filePath, err.Error())
		} else {
			fmt.Printf("已删除文件 %s\n", filePath)
		}
	}
	fmt.Println("删除可疑文件：")
	for filePath := range SuspiciousFiles {
		err := filedelet.DeleteFile(filePath)
		if err != nil {
			fmt.Printf("删除文件 %s 失败：%s\n", filePath, err.Error())
		} else {
			fmt.Printf("已删除文件 %s\n", filePath)
		}

		return
	}
}
func WebSocketHandler(c *gin.Context) {

	ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Println("WebSocket连接升级失败:", err)
		return
	}

	defer ws.Close()

	for {
		select {
		case update := <-updates:

			err := ws.WriteJSON(update)
			if err != nil {
				log.Println("WebSocket消息发送失败:", err)
				return
			}

		}
	}
}
