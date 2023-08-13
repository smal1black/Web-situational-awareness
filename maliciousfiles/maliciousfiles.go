package maliciousfiles

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func CheckMaliciousFiles(webPath string, dictionary []string) []string {
	var maliciousFiles []string

	err := filepath.Walk(webPath, func(filePath string, fileInfo os.FileInfo, err error) error {
		if err != nil {
			fmt.Println("遍历文件时出错:", err)
			return nil
		}

		if fileInfo.IsDir() {
			return nil
		}

		if isMalicious(fileInfo.Name(), dictionary) {
			fmt.Println("发现疑似恶意文件:", filePath)
			maliciousFiles = append(maliciousFiles, filePath)
		}

		return nil
	})

	if err != nil {
		fmt.Println("遍历路径时出错:", err)
	}

	return maliciousFiles
}

func isMalicious(fileName string, dictionary []string) bool {

	fileName = strings.ToLower(fileName)

	for _, word := range dictionary {
		if strings.Contains(fileName, strings.ToLower(word)) {
			return true
		}
	}

	return false
}
