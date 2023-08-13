package checkrequest

import (
	"embed"
	"encoding/xml"
	"fmt"
	"github.com/dlclark/regexp2"
	"log"
	"redrock/filedelet"
	"redrock/sqlserve"
	"strings"
)

//go:embed xml/*
var x embed.FS

type Filter struct {
	ID          int      `xml:"id"`
	Rule        string   `xml:"rule"`
	Description string   `xml:"description"`
	Tags        []string `xml:"tags>tag"`
}

type Filters struct {
	Filters []Filter `xml:"filter"`
}

func CheckURLforSecurityAttacks(requestDump string, clientIP string) bool {

	parsedURL := requestDump
	if filter(parsedURL) {
		return true
	}
	requestDumpS := strings.ToLower(requestDump)

	requestDumpS = string(filedelet.RemoveSpaces([]byte(requestDumpS)))

	authorized, err := sqlserve.CheckIPExists(clientIP)
	if err != nil {
		log.Println("Failed to check IP authorization:", err)

		return false
	}

	if authorized {
		return true
	}

	if CheckForProtocolAttack(requestDumpS) {
		return true
	}

	if CheckForPathAttack(requestDumpS) {
		return true
	}

	if CheckForParameterAttack(requestDumpS) {
		return true
	}

	if CheckForUrlAttack(requestDumpS) {
		return true
	}

	if CheckForXssAttack(requestDumpS) {
		return true
	}

	if CheckForSqlAttack(requestDumpS) {
		return true
	}

	return false
}

func CheckForProtocolAttack(requestDump string) bool {

	dangerousProtocols := []string{"file://", "gopher://", "dict://"}
	for _, protocol := range dangerousProtocols {
		if strings.Contains(requestDump, protocol) {
			return true
		}
	}

	return false
}

func CheckForPathAttack(requestDump string) bool {

	dangerousPaths := []string{"/etc", "/proc", "/apache", "/apache2", "/httpd", "/log", "/usr", "/var", "/logs", "/www", "/bin", "/init", "/opt", "/local"}
	for _, dangerousPath := range dangerousPaths {
		if strings.Contains(requestDump, dangerousPath) {
			return true
		}
	}

	return false
}

func CheckForParameterAttack(requestDump string) bool {

	specialStrings := []string{"../", "%2e%2e/", ".ini", ".log", ".conf"}
	for _, specialString := range specialStrings {
		if strings.Contains(requestDump, specialString) {
			return true
		}
	}

	return false
}

func CheckForUrlAttack(requestDump string) bool {

	specialStrings := []string{"192.168.0.1", "127.0.0.1", "10.0.0.1"}
	for _, specialString := range specialStrings {
		if strings.Contains(requestDump, specialString) {
			return true
		}
	}

	return false
}
func CheckForXssAttack(requestDump string) bool {

	specialStrings := []string{"[a", "<javascript", "<&#x", "[test]", "[clickme]", "<1>", "<char", "(javascript:", "[ ]", "[XSS]", "<script", "</SCRIPT>", "</script>", "<INPUT", "<IMG", "<META", "<DIV", "<FRAMESET", "<BASE", "<DIV", "<BODY", "\"><", "('xss')", "</object>", "('XSS')", "</table>", "<svg", "<marquee", "src", "<x", "<brute", "<form", "<a href", "<p>", "<ul>", "<iframe>", "<label>", "<textarea>", "<select>", "<td>", "<tr>", "<li>", "<ol>", "<ul>", "<div>", "<span>", "<p>", "<h1>", "<h2>", "<h3>", "<h4>", "<h5>", "<h6>", "<body", "<style", "<html", "<svg", "--><!--"}
	for _, specialString := range specialStrings {
		if strings.Contains(requestDump, specialString) {
			return true
		}
	}

	return false
}
func CheckForSqlAttack(requestDump string) bool {

	specialStrings := []string{
		"%u", "--+", "/**/", "select", "limit", "colum", "reverse", "database", "ascii", "group by", "union", "group_concat", "updatexml", "extractvalue", "geometrycollection", "%0", "%1", "%2", "%3", "%4", "%5", "%6", "%7", "%8", "%9", "0x", "multipoint", "polygon", "multilinestring", "multipolygon", "linestring", "infromation_schema", "schema_name", "table_schema", "table_name", "table_schema", "column_name",
	}
	for _, specialString := range specialStrings {
		if strings.Contains(requestDump, specialString) {
			return true
		}
	}

	return false
}
func filter(requestDump string) bool {

	//xmlData, err := ioutil.ReadFile("default_filter.xml")
	xmlData, err := x.ReadFile("xml/default_filter.xml")
	if err != nil {
		fmt.Println("无法读取 XML 文件:", err)
	}

	var filters Filters
	err = xml.Unmarshal(xmlData, &filters)
	if err != nil {
		fmt.Println("无法解析 XML 数据:", err)
	}

	text := requestDump

	for _, filter := range filters.Filters {
		rule := filter.Rule
		description := filter.Description

		re := regexp2.MustCompile(rule, 0)

		match, err := re.MatchString(text)
		if err != nil {
			fmt.Println("正则表达式匹配错误:", err)
		}

		if match {
			fmt.Println("匹配成功，描述:", description)
			return true
		}
	}
	return false
}
