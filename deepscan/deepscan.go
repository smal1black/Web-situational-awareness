package deepscan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

var (
	uploadAPIURL    = "https://api.threatbook.cn/v3/file/upload"
	reportAPIURL    = "https://api.threatbook.cn/v3/file/report"
	runTime         = 60
	threatbookKey   = "替换为自己的key"
	reports         = make(map[string]string)
	MaliciousFiles  = make(map[string]string)
	SuspiciousFiles = make(map[string]string)
	client          = &http.Client{Timeout: 5 * time.Second}
)

type UploadResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Sha256 string `json:"sha256"`
	} `json:"data"`
}

type ReportResponse struct {
	Code       int    `json:"code"`
	Message    string `json:"message"`
	Data       Data   `json:"data"`
	VerboseMsg string `json:"verbose_msg"`
}

type Data struct {
	Summary Summary `json:"summary"`
}

type Summary struct {
	ThreatLevel string `json:"threat_level"`
}

func Apilogin() {
	if threatbookKey == "" {
		fmt.Println("apikey自动登录失败")
		fmt.Print("ThreatBook API KEY > ")
		fmt.Scanln(&threatbookKey)
	}
}

func UploadAllFilesInDir(dirPath string) {
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			err = UploadFileAndStorePath(path)
			if err != nil {
				fmt.Printf("Failed to upload and store file %s: %s\n", info.Name(), err.Error())
			}
		}

		return nil
	})

	if err != nil {
		fmt.Println("Failed to read files in the directory:", err)
	}
}

func UploadFileAndStorePath(filePath string) error {
	fileData, err := os.Open(filePath)
	if err != nil {
		fmt.Print("获取文件内容出错")
		return err
	}
	defer fileData.Close()

	fileInfo, _ := fileData.Stat()
	if fileInfo.Size() == 0 {
		fmt.Printf("文件 %s 内容为空，不进行上传\n", filePath)
		return nil
	}

	uploadResponse, err := UploadFile(fileData, filePath)
	if err != nil {
		return err
	}

	reports[filePath] = uploadResponse.Data.Sha256

	return nil
}

func UploadFile(fileData io.Reader, filePath string) (*UploadResponse, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return nil, err
	}

	_, err = io.Copy(part, fileData)
	if err != nil {
		return nil, err
	}

	err = writer.WriteField("apikey", threatbookKey)
	if err != nil {
		return nil, err
	}

	err = writer.WriteField("run_time", fmt.Sprintf("%d", runTime))
	if err != nil {
		return nil, err
	}

	err = writer.Close()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", uploadAPIURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed with status code: %d", resp.StatusCode)
	}

	var response UploadResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, err
	}

	if response.Code != 0 {
		return nil, fmt.Errorf("API request failed with message: %s", response.Message)
	}

	return &response, nil
}

func CheckReports() {
	for filePath, sha256 := range reports {
		reportResponse, err := GetReport(sha256)
		if err != nil {
			fmt.Printf("Failed to get report for file %s: %s\n", filePath, err.Error())
			continue
		}

		threatLevel := reportResponse.Data.Summary.ThreatLevel
		if threatLevel == "" {
			fmt.Printf("文件路径: %s，报告还未生成，60秒后将再次查看\n", filePath)
			time.Sleep(60 * time.Second) // 等待60秒

			// 再次获取报告
			reportResponse, err = GetReport(sha256)
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
}

func GetReport(sha256 string) (*ReportResponse, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	err := writer.WriteField("apikey", threatbookKey)
	if err != nil {
		return nil, err
	}

	err = writer.WriteField("sha256", sha256)
	if err != nil {
		return nil, err
	}

	err = writer.Close()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", reportAPIURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed with status code: %d", resp.StatusCode)
	}

	var response ReportResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, err
	}

	if response.Code != 0 {
		return nil, fmt.Errorf("API request failed with message: %s", response.Message)
	}

	return &response, nil
}
