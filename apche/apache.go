package apache

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"redrock/checkrequest"
	"redrock/ddosprotection"
	"redrock/sqlserve"
	"strconv"
)

var (
	localPort  = ":80"            // 监听服务器的开放端口80
	apacheHost = "127.0.0.1:7778" // Apache的地址和端口
)

func Apache(aport string) {
	localPort = ":" + aport

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	counter := ddosprotection.NewIPCounter()

	router.Any("/*path", forwardToApache(counter))

	log.Println("监听80端口...")
	err1 := http.ListenAndServe(localPort, router)
	if err1 != nil {
		log.Fatal("监听80端口出错: ", err1)
	}
}
func forwardToApache(counter *ddosprotection.IPCounter) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestIP := c.ClientIP()
		fmt.Println("请求IP地址", requestIP)
		requestDump, err := httputil.DumpRequest(c.Request, true)
		if err != nil {
			log.Println("Failed to dump request:", err)
			return
		} else {
			fmt.Println(string(requestDump))
		}

		c.Set("requestDump", requestDump)

		if checkRequestCondition(c, requestIP) {

			c.AbortWithStatus(http.StatusNotFound)
			method := c.Request.Method
			url := c.Request.URL.String()
			status := 404
			intact := string(requestDump)

			err = sqlserve.CreateInformationTable()
			if err != nil {
				log.Fatal(err)
			}

			err2 := sqlserve.InsertInformation(method, requestIP, url, strconv.Itoa(status), intact)
			if err2 != nil {
				log.Println("Failed to write to database:", err2)
			}
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(&url.URL{
			Scheme: "http",
			Host:   apacheHost,
		})

		c.Request.Host = apacheHost

		c.Request.Header.Set("X-Forwarded-Host", c.Request.Host)

		proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proxy.ServeHTTP(w, r)
		})

		// 添加DDoS保护中间件
		ddosMiddleware := ddosprotection.DosProtectionMiddleware(proxyHandler, counter, requestIP)
		ddosMiddleware.ServeHTTP(c.Writer, c.Request)

		method := c.Request.Method
		url := c.Request.URL.String()
		status := c.Writer.Status()
		intact := string(requestDump)

		err = sqlserve.CreateInformationTable()
		if err != nil {
			log.Fatal(err)
		}

		err2 := sqlserve.InsertInformation(method, requestIP, url, strconv.Itoa(status), intact)
		if err2 != nil {
			log.Println("Failed to write to database:", err2)
		}
	}
}

func checkRequestCondition(c *gin.Context, requestIP string) bool {
	requestDump, ok := c.Get("requestDump")
	if !ok {
		log.Println("Failed to get requestDump from context")
		return false
	}

	requestData, ok := requestDump.([]byte)
	if !ok {
		log.Println("Failed to convert requestDump to []byte")
		return false
	}

	isAttack := checkrequest.CheckURLforSecurityAttacks(string(requestData), requestIP)

	return isAttack
}
