package changeport

import (
	"log"
	"os/exec"
)

func ApacheChangePort(configPath string, aport string) {
	// 配置文件路径"/usr/local/lighthouse/softwares/apache/conf/httpd.conf"
	if aport == "" {
		aport = "80"
	}
	apacheConfig := configPath
	oldPort := aport
	// 新的端口
	newPort := "7778"

	err := exec.Command("cp", apacheConfig, apacheConfig+".bak").Run()
	if err != nil {
		log.Fatal(err)
	}

	cmd := exec.Command("sed", "-i", "s/Listen "+oldPort+"/Listen 127.0.0.1:"+newPort+"/g", apacheConfig)
	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}

	// 重新启动 Apache 服务
	err = exec.Command("service", "apache", "restart").Run()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Apache配置已更新并成功重启服务")
}
