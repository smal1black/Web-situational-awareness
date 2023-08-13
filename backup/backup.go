package backup

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func Backup(webPath string) {
	if webPath == "" {
		webPath = "/var/www/html"
	}
	targetPath := "/var/www/backup/backup.zip" // 备份文件的目标路径

	err := BackupToZip(webPath, targetPath)
	if err != nil {
		fmt.Println("网站源码备份出错:", err)
		panic(err)
	}
	fmt.Println("网站文件备份成功并已打包为ZIP！")
	fmt.Printf("备份文件保存在：%s\n", targetPath)

}

func BackupToZip(sourcePath string, targetPath string) error {

	err := os.MkdirAll(filepath.Dir(targetPath), os.ModePerm)
	if err != nil {
		fmt.Println("无法创建目标文件夹:", err)
		return err
	}

	zipFile, err := os.Create(targetPath)
	if err != nil {
		fmt.Println("创建ZIP文件时出错:", err)
		return err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	err = filepath.Walk(sourcePath, func(filePath string, fileInfo os.FileInfo, err error) error {
		if err != nil {
			fmt.Println("遍历网站路径时出错:", err)
			return err
		}

		header, err := zip.FileInfoHeader(fileInfo)
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(sourcePath, filePath)
		if err != nil {
			return err
		}
		header.Name = relPath

		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}

		if fileInfo.IsDir() {
			return nil
		}

		file, err := os.Open(filePath)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(writer, file)
		return err
	})

	return err
}

func BackupMaliciousFile(filePath string) error {
	backupDir := "/var/www/backup"
	err := os.MkdirAll(backupDir, 0755)
	if err != nil {
		return err
	}

	_, fileName := filepath.Split(filePath)
	backupPath := filepath.Join(backupDir, fileName)

	srcFile, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(backupPath)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}

	return nil
}
