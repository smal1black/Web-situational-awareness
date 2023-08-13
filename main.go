package main

import (
	"embed"
	"fmt"
	"github.com/dchest/captcha"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	_ "golang.org/x/net/websocket"
	"html/template"
	"log"
	"net/http"
	apache "redrock/apche"
	"redrock/backup"
	"redrock/changeport"
	"redrock/deepscan"
	"redrock/filedelet"
	"redrock/filemonitor"
	"redrock/login"
	"redrock/maliciousfiles"
	"redrock/sqlserve"
	"strconv"
)

//go:embed WebUI/*
var f embed.FS
var (
	webPath                string
	fileMonitorDone        chan struct{}
	deletedMaliciousFiles  = make([]string, 0)
	deletedSuspiciousFiles = make([]string, 0)
)

func main() {
	var (
		username        string
		password        string
		captcha1        string
		configPath      string
		aport           string
		dbAddress       string
		dbPort          string
		dbName          string
		dbPassword      string
		changedusername string
		changedpassword string
		maliciousFiles  []string
	)

	router := gin.Default()
	// 初始化会话中间件
	store := cookie.NewStore([]byte("secret"))
	router.Use(sessions.Sessions("session", store))

	router.GET("/login", func(c *gin.Context) {
		content, err := f.ReadFile("WebUI/login.html")
		if err != nil {
			c.String(http.StatusInternalServerError, "Internal Server Error")
			return
		}
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, string(content))
	})

	router.POST("/login", func(c *gin.Context) {
		username = c.PostForm("username")
		password = c.PostForm("password")
		captcha1 = c.PostForm("captcha")

		session := sessions.Default(c)
		savedCaptcha, _ := session.Get("captcha").(string)

		if captcha.VerifyString(savedCaptcha, captcha1) {
			if login.Login(username, password) {
				session.Set("username", username)
				session.Save()

				c.Redirect(http.StatusFound, "/initialize")
			} else {
				c.Set("errorMessage", "用户名或密码错误")
				c.Redirect(http.StatusFound, "/login")
			}
		} else {
			c.Set("errorMessage", "验证码错误")
			c.Redirect(http.StatusFound, "/login")
		}
	})
	router.GET("/getcaptcha", getCaptchaHandler)
	router.GET("/background-image", func(c *gin.Context) {

		content, err := f.ReadFile("WebUI/27.jpg")
		if err != nil {
			c.String(http.StatusInternalServerError, "Internal Server Error")
			return
		}

		c.Header("Content-Type", "image/jpeg")
		c.Data(http.StatusOK, "image/jpeg", content)
	})
	router.GET("/initialize", AuthMiddleware(), func(c *gin.Context) {
		content, err := f.ReadFile("WebUI/initialize.html")
		if err != nil {
			c.String(http.StatusInternalServerError, "Internal Server Error")
			return
		}
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, string(content))
	})
	router.POST("/initialize", AuthMiddleware(), func(c *gin.Context) {
		dbAddress = c.PostForm("dbAddress")
		dbPort = c.PostForm("dbPort")
		dbName = c.PostForm("dbName")
		dbPassword = c.PostForm("dbPassword")
		webPath = c.PostForm("webPath")
		configPath = c.PostForm("configPath")
		aport = c.PostForm("port")
		changedusername = c.PostForm("changedusername")
		changedpassword = c.PostForm("changedpassword")
		fmt.Print(dbAddress, dbPort, dbPassword, webPath, configPath, aport, dbName)
		backup.Backup(webPath)
		login.ChangeUsernameAndPassword(changedusername, changedpassword)
		changeport.ApacheChangePort(configPath, aport)
		// 启动服务器监听端口
		go func() {
			apache.Apache(aport)
		}()
		sqlserve.DBinitialize(dbAddress, dbPort, dbPassword, dbName)
		err := sqlserve.Init()
		if err != nil {
			log.Fatal("Failed to initialize database:", err)
		}

		c.Redirect(http.StatusFound, "/main")
	})
	router.GET("/main", AuthMiddleware(), func(c *gin.Context) {
		content, err := f.ReadFile("WebUI/main.html")
		if err != nil {
			c.String(http.StatusInternalServerError, "Internal Server Error")
			return
		}
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, string(content))

	})
	router.POST("/start-file-monitoring", AuthMiddleware(), func(c *gin.Context) {

		fileMonitorDone = make(chan struct{})
		go func() {
			filemonitor.Filemonitor(webPath)
			fileMonitorDone <- struct{}{}
		}()

		c.String(http.StatusOK, "文件监控已启动")
	})
	router.GET("/ws", AuthMiddleware(), filemonitor.WebSocketHandler)
	router.GET("/scan-files", AuthMiddleware(), func(c *gin.Context) {
		dictionary := []string{"-7.php", "cmd.asp", "cmd.aspx", "cmd.php", "1.asp", "1.asp;1.jpg", "1.aspx", "1.php", "1.php;1.jpg", "123.asp", "123.aspx", "123.php", "1d.asp", "1（中文版aspx马）.aspx", "zhongwen.apx", "2.asp", "2.aspx", "2.php", "2013110125027897.asp", "2013110125222650.aspx", "2015miansha.asp", "22.asp", "22.aspx", "22.php", "222.asp", "222.aspx", "222.php", "404.asp", "51j.aspx", "520.asp", "520.aspx", "520.php", "80sec.asa", "80sec.asp", "80sec.aspx", "80sec.php", "80sec2.asp", "90sec.asp", "90sec.aspx", "90sec.php", "aa.asp", "abcd.aspx", "about.aspx", "admin.asp", "admin.aspx", "admin.php", "ajan.asp", "ajn.asp", "asp.asp", "asp.aspx", "asp.php", "asp1.asp", "asp1.aspx", "asp1.php", "asp2.asp", "asp2.aspx", "asp2.php", "aspadmin_black.asp", "aspwebpack1.2带进度显示的打包网站用的asp程序.asp", "aspx.aspx", "aspxiaoma.asp", "aspxspy.aspx", "aspxspy2.aspx", "aspxspy2014final.aspx", "aspx一句话木马小集.aspx", "aspx下嗅探工具websniff1.0-linux.aspx", "aspx变形一句话.aspx", "aspx小马.aspx", "aspx（免杀）.aspx", "aspy.aspx", "asp站长助手.asp", "backup.asp", "bf.asp", "bf.aspx", "bf.php", "bianxing.asp", "bs.asp", "bs.aspx", "bs.php", "bypass-iisuser-p.asp", "caomeide.asp", "caomeide.aspx", "caomeide.php", "caonima.asp", "caonima.aspx", "caonima.php", "clouder 大.asp", "cmd-asp-5.1.asp", "cmdasp.asp", "cmdasp.aspx", "cmdexec.aspx", "cmdshell.aspx", "cmdwebshell.asp", "con2.asp", "con2.aspx", "cpanel.asp", "cyberspy5.asp", "d.asp", "d.aspx", "d.php", "dama.asp", "dama.aspx", "dama.php", "data.asp", "dataoutexl.aspx", "dataoutexl_方便导入库版.aspx", "devilzshell.asp", "devilzshell.aspx", "devshell.asp", "devshell.aspx", "dir.asp", "dir.aspx", "dir.php", "diy.asp", "dm.asp", "dm.aspx", "dm.php", "down.asp", "download.asp", "editor.aspx", "efso_2.asp", "evilsadness 大.asp", "expdoor.com.asp", "fake.aspx", "filesystembrowser.aspx", "fileupload.aspx", "fso.asp", "fuck.asp", "fuck.aspx", "fuck.php", "h4ck door.asp", "hack.asp", "hack.aspx", "hack.php", "hack_tianya大.asa", "hake.asp", "hake.aspx", "hake.php", "help.asp", "help.aspx", "help.php", "helps.asp", "helps.aspx", "helps.php", "hez.asp", "hkmjj.asp", "hxhack 小 密.asa", "ice.asp", "ice.aspx", "icesword.aspx", "image.asp", "image.aspx", "image.php", "images.asp", "images.aspx", "images.php", "inc.asp", "inderxer.asp", "index.asp", "jc.mp3.aspx", "jc[1].mp3.aspx", "jks 大.asa", "js.asp", "k-shell.aspx", "kather.asp", "kather终极免杀asp大马.asp", "kefuold.asp", "keio.aspx", "klasvayv.asp", "list.asp", "mdb.asp", "miansha.asp", "miansha.aspx", "miansha.php", "ms.asp", "ms.aspx", "ms.php", "mssql.asp", "mssql.aspx", "mssql控制程序.asp", "mumaasp.com.asp", "mysql.aspx", "mysql管理工具.aspx", "new_pass_waf.aspx", "newasp.asp", "ntdaddy.asp", "ok.asp", "ok.aspx", "ok.php", "p.asp", "p.aspx", "p.php", "php1.asp ", "php1.aspx   ", "php1.php    ", "php2.asp", "php2.aspx", "php2.php", "r00ts.asp", "rader.asp", "radhat.asp", "redirect.asp", "remexp.asp", "rinim.asp", "root.asp", "root.aspx", "root.php", "rootkit.asp", "rootkit.aspx", "rootkit.php", "sa.asp", "sa.aspx", "sa.php", "server variables.asp", "shell.asp", "shell.aspx", "shell_decoded.asp", "showcenter2.aspx", "simoen.aspx", "sniffer--aspx嗅探工具.aspx", "spexec.aspx", "sql.aspx", "sqlrootkitsqlrootkit.asp", "stylehh专用版小马 密.asa", "style专用版asp大马.asp", "syjh.asp", "test.asp", "test.aspx", "test.php", "tools.asp", "tools.aspx", "tools.php", "tp.asp", "tuok.aspx", "udf.asp", "udf.aspx", "udf.php", "up.asp", "up.jsp", "up_win32.jsp", "upfile.asp", "upfile.aspx", "upfile.php", "upload.asp", "upload.aspx", "upload.php", "v.asp", "v.aspx", "v.php", "web.aspx", "webadmin.aspx", "websniff1.0-linx.aspx", "wso.aspx", "wt.asp", "wt.aspx", "wt.php", "x.asp", "xiaoma.asp", "xiaoma.aspx", "xiaoma.php", "xiaoma1.asa", "xise.asp", "xise.aspx", "xise.php", "xm.asp", "xm.aspx", "xm.php", "xok.aspx", "xx.asp", "xx00.asp", "xx00.aspx", "xx00.php", "xxdoc'sxxdoc's.asp", "xxoo.asp", "xxoo.aspx", "xxoo.php", "zhuanyong.asp", "arixtony.asa", "不死僵尸.asp", "不灭之魂.asp", "专杀不死马甲精简版本.asp", "修改属性.asp", "免杀小马.asp", "免杀小马2.asp", "加密版.asp", "史上最强asp大马.asp", "喷火恐龙 小 非密.asa", "回忆专用 大.asp", "多种组件执行dos.asp", "xiaomi.asp", "小勇大马.asp", "小强免杀asp大马.asp", "小强免杀asp小马.asp", "小马.asp", "带密码的asp小马.asp", "带密码的小马dog.asp", "常用大马.asp", "必备版.asp", "旁注小助手.asp", "明文版.asp", "暗组小马.asp", "最强asp木马.asa", "某种加密一句话密码 x.asp", "海洋顶端最新免杀.asp", "海阳犬龍2006α.asp", "点点专用脱裤mssql.asp", "简洁版 大.asp", "糊涂虾小马.asp", "网络军刀xxdoc's.asp", "美化版.asp", "老兵保密.asp", "老兵免杀.asp", "老兵好修改版.asp", "萧萧asp大马超强版.asp", "虚拟机提权大马.asp", "超强版 大.asp", "超强版.asp", "转换字符的一句话a.asp", "过狗asp一句话.asp", "邪恶十进制 大.asa", "预编译出错shell.aspx", "风云专用.asp", "黑客动画吧 专用免杀版.asp", "000.jsp", "0000.jsp", "1.jsp", "102.jsp", "123.jsp", "12302.jsp", "2.jsp", "201.jsp", "2011ok.php", "3.jsp", "400.jsp", "403.jsp", "404.jsp", "404.php", "404页面小马.php", "520.jsp", "action.jsp", "adminer-3.3.3.php", "adminer-4.2.1-en.php", "adminer-4.2.1-mysql.php", "adminer-4.2.1.php", "asd.jsp", "aspadmin_a.asp", "aspadmin_white.asp", "browser.jsp", "c5.jsp", "caidao.php", "cat.jsp", "cmd.jsp", "cmd_win32.jsp", "cmdjsp.jsp", "cms.php", "cofigrue.jsp", "config.inc.php", "config.jsp", "customize.jsp", "data.jsp", "data.php", "data02.jsp", "db_mysql.class.php", "db_mysql_error.inc.php", "devilzshell.jsp", "devilzshell.php", "devshell.jsp", "devshell.php", "down.php", "down2.php", "dumporacle.jsp", "dumporacle2.jsp", "edit_ot.jsp", "gb2321.php", "guige.jsp", "guige02.jsp", "guo.php", "hackk8minupload.jsp", "helper6.asp", "hsxa.jsp", "hsxa1.jsp", "ice.jsp", "ice.php", "icesword.jsp", "in.jsp", "inback3.jsp", "index.php", "index_bak1.jsp", "index_sys.jsp", "indexop.jsp.上传.jsp", "info.jsp", "injection.php", "ixrbe.jsp", "ixrbe02.jsp", "java shell.jsp", "jdbc.jsp", "jfolder.jsp", "jfolder01.jsp", "job.jsp", "jshell.jsp", "jsp.jsp", "jspspy.jsp", "jspspyjdk5.jsp", "jspspyweb.jsp", "jspwebshell 1.2.jsp", "jsp菜刀一句话木马.jsp", "k81.jsp", "k8cmd.jsp", "leo.jsp", "list.jsp", "list.php", "list1.jsp", "long19961029.php", "luci.jsp.spy2009.jsp", "ma (1).jsp", "ma.jsp", "ma1.jsp", "ma2.jsp", "ma3.jsp", "ma4.jsp", "maint.jsp", "mg.jsp", "minupload.jsp", "mssql加mysql拖库脚本.php", "mssql加mysql拖库脚本2.php", "mysq.php", "mysql tuoku.php", "mysql数据库脱单个表.jsp", "mysql脱库.php", "myxx.jsp", "myxx1.jsp", "new_pass_waf.php", "no.jsp", "one8.jsp", "oracle.jsp", "oracle脱裤脚本.jsp", "pass--免杀.php", "php-backdoor.php", "phpfile.php", "phpmm.php", "phpshell.php", "phpspy-中文版.php", "phpwebbackup.php", "php小马.php", "php小马up.php", "php整站打包.php", "postgresql.php", "pyth.jsp", "querydong.jsp", "rootmdm  utf8.php", "roottows.jsp", "shell.jsp", "silic webshell.jsp", "silic.jsp", "simple-backdoor.php", "spjspshell.jsp", "spyjsp2010.jsp", "style.jsp", "suiyue.jsp", "sys3.jsp", "system.jsp", "system1.jsp.上传.jsp", "t.jsp", "t00ls.jsp", "terms.jsp", "toby57解析加密一句话木马.php", "tree.jsp", "udf1.php", "unzipfile.php", "up.php", "utils.jsp", "ver007.jsp", "ver008.jsp", "warn.jsp", "web.jsp", "web02.jsp", "webshell-nc.jsp", "win32up_win32.jsp", "x0rg.php", "xall.php", "xall.php-批量查询插入一句话.php", "xia.jsp", "xm.jsp", "xx.jsp", "xx.php", "xxxttt.php", "yjy.jsp", "zend.jsp", "zhongwen .jsp", "zip.func.php", "zipfile.php", "zval.jsp", "zx.jsp", "zw.aspx", "去后门.asp", "执行cmd函数比较多点的php大马.php", "新型jsp小马支持上传任意格式文件.jsp", "脱mysql数据库.jsp", "脱库工具.php", "菜刀jsp修改.jsp", "菜刀jsp脚本文明版.jsp", "菜刀jsp脚本无压缩版.jsp", "菜刀jsp脚本更新版.jsp"}

		maliciousFiles = []string{}
		maliciousFiles = maliciousfiles.CheckMaliciousFiles(webPath, dictionary)
		DepthScanHandler(c)
		c.JSON(http.StatusOK, gin.H{
			"发现疑似恶意文件": maliciousFiles,
			"已删除恶意文件":  deletedMaliciousFiles,
			"已删除可疑文件":  deletedSuspiciousFiles,
		})

	})
	router.GET("/ip", AuthMiddleware(), func(c *gin.Context) {
		content, err := f.ReadFile("WebUI/ip.html")
		if err != nil {
			c.String(http.StatusInternalServerError, "Internal Server Error")
			return
		}
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, string(content))

	})
	router.POST("/insertIP", AuthMiddleware(), handleInsertIP)
	router.POST("/deleteIP", AuthMiddleware(), handleDeleteIP)
	router.GET("/getIPList", AuthMiddleware(), handleGetIPList)
	router.GET("/information", AuthMiddleware(), func(c *gin.Context) {
		err := sqlserve.CreateInformationTable()
		if err != nil {
			log.Fatal(err)
		}

		informationData, err := sqlserve.GetInformation()
		if err != nil {
			c.HTML(http.StatusInternalServerError, "Error.html", gin.H{"error": err.Error()})
			return
		}
		id := c.Query("id")
		var selectedData sqlserve.Information
		for _, d := range informationData {
			if strconv.Itoa(d.ID) == id {
				selectedData = d
				break
			}
		}

		tmplContent, err := f.ReadFile("WebUI/information.html")
		if err != nil {
			c.HTML(http.StatusInternalServerError, "Error.html", gin.H{"error": err.Error()})
			return
		}

		tmpl, err := template.New("information").Parse(string(tmplContent))
		if err != nil {
			c.HTML(http.StatusInternalServerError, "Error.html", gin.H{"error": err.Error()})
			return
		}

		data := gin.H{
			"Information":  informationData,
			"SelectedData": selectedData,
		}
		err = tmpl.Execute(c.Writer, data)
		if err != nil {
			c.HTML(http.StatusInternalServerError, "Error.html", gin.H{"error": err.Error()})
			return
		}
	})

	go func() {
		router.Run(":7777")
	}()

	// 阻塞主goroutine
	done := make(chan bool)
	<-done
	// 等待文件监控完成信号
	<-fileMonitorDone

	fmt.Println("程序结束")
}

func DepthScanHandler(c *gin.Context) {
	deletedMaliciousFiles = make([]string, 0)
	deletedSuspiciousFiles = make([]string, 0)
	deepscan.Apilogin()
	deepscan.UploadAllFilesInDir(webPath)
	deepscan.CheckReports()

	fmt.Println("发现恶意文件：")
	for filePath, reportURL := range deepscan.MaliciousFiles {
		fmt.Printf("文件路径: %s，报告地址：%s\n", filePath, reportURL)

		err := backup.BackupMaliciousFile(filePath)
		if err != nil {
			fmt.Printf("备份文件 %s 失败：%s\n", filePath, err.Error())
		} else {
			fmt.Printf("已备份文件 %s 到 /var/www/backup\n", filePath)
		}
	}

	fmt.Println("发现可疑文件：")
	for filePath, reportURL := range deepscan.SuspiciousFiles {
		fmt.Printf("文件路径: %s，报告地址：%s\n", filePath, reportURL)
		err := backup.BackupMaliciousFile(filePath)
		if err != nil {
			fmt.Printf("备份文件 %s 失败：%s\n", filePath, err.Error())
		} else {
			fmt.Printf("已备份文件 %s 到 /var/www/backup\n", filePath)
		}
	}

	fmt.Println("删除恶意文件：")
	for filePath := range deepscan.MaliciousFiles {
		err := filedelet.DeleteFile(filePath)
		if err != nil {
			fmt.Printf("删除文件 %s 失败：%s\n", filePath, err.Error())
		} else {
			fmt.Printf("已删除文件 %s\n", filePath)
			deletedMaliciousFiles = append(deletedMaliciousFiles, filePath)
		}
	}
	deepscan.MaliciousFiles = make(map[string]string)

	fmt.Println("删除可疑文件：")
	for filePath := range deepscan.SuspiciousFiles {
		err := filedelet.DeleteFile(filePath)
		if err != nil {
			fmt.Printf("删除文件 %s 失败：%s\n", filePath, err.Error())
		} else {
			fmt.Printf("已删除文件 %s\n", filePath)
			deletedSuspiciousFiles = append(deletedSuspiciousFiles, filePath)
		}
	}
	deepscan.SuspiciousFiles = make(map[string]string)
}
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		username := session.Get("username")
		fmt.Println("当前会话的用户名:", username)

		if username == nil {

			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		c.Next()
	}
}
func handleInsertIP(c *gin.Context) {

	var data struct {
		IP string `json:"ip"`
	}
	err := c.BindJSON(&data)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to decode request body"})
		return
	}

	exists, err := sqlserve.CheckIPExists(data.IP)
	if err != nil {
		log.Println("Failed to check IP:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check IP"})
		return
	}

	if exists {
		log.Println("IP already exists:", data.IP)
		c.JSON(http.StatusBadRequest, gin.H{"error": "IP already exists"})
		return
	}

	err = sqlserve.WriteIP(data.IP)
	if err != nil {
		log.Println("Failed to write IP:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to write IP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

func handleDeleteIP(c *gin.Context) {

	var data struct {
		IP string `json:"ip"`
	}
	err := c.BindJSON(&data)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to decode request body"})
		return
	}

	exists, err := sqlserve.CheckIPExists(data.IP)
	if err != nil {
		log.Println("Failed to check IP:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check IP"})
		return
	}

	if !exists {
		log.Println("IP does not exist:", data.IP)
		c.JSON(http.StatusBadRequest, gin.H{"error": "IP does not exist"})
		return
	}

	err = sqlserve.DeleteIP(data.IP)
	if err != nil {
		log.Println("Failed to delete IP:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete IP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

func handleGetIPList(c *gin.Context) {

	ipList, err := sqlserve.GetAllIPs()
	if err != nil {
		log.Println("Failed to get IP list:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get IP list"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "ipList": ipList})
}
func getCaptchaHandler(c *gin.Context) {
	captchaDigits := captcha.NewLen(6)
	session := sessions.Default(c)
	session.Set("captcha", captchaDigits)
	session.Save()

	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")
	captcha.WriteImage(c.Writer, captchaDigits, 200, 100)
}
