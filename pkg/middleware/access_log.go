package middleware

import (
	"bytes"
	"encoding/json"
	"golang_project_layout/pkg/global"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type OperationRecord struct {
	UserID    int    `json:"user_id"`
	Ip        string `json:"ip"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status_code"`
	Code      int    `json:"code"`
	Agent     string `json:"agent"`
	Body      string `json:"request_body"`
	Message   string `json:"message"`
	BeginTime string `json:"begin_time"`
	EndTime   string `json:"end_time"`
}

type ResponseMessage struct {
	// 自定义的响应码
	Code int
	// 附加消息
	Message string
}

type AccessLogWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *AccessLogWriter) Write(p []byte) (int, error) {
	if n, err := w.body.Write(p); err != nil {
		return n, err
	}
	return w.ResponseWriter.Write(p)
}

func AccessLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		var body []byte
		if c.Request.Method != http.MethodGet {
			var err error
			body, err = io.ReadAll(c.Request.Body)
			if err != nil {
				global.GVA_LOG.Error("read body from request error:", zap.Error(err))
			} else {
				c.Request.Body = io.NopCloser(bytes.NewBuffer(body))
			}
		} else {
			query := c.Request.URL.RawQuery
			query, _ = url.QueryUnescape(query)
			split := strings.Split(query, "&")
			m := make(map[string]string)
			for _, v := range split {
				kv := strings.Split(v, "=")
				if len(kv) == 2 {
					m[kv[0]] = kv[1]
				}
			}
			body, _ = json.Marshal(&m)
		}

		bodyWriter := &AccessLogWriter{
			body:           bytes.NewBufferString(""),
			ResponseWriter: c.Writer,
		}
		c.Writer = bodyWriter

		beginTime := time.Now().Local().Format("2006-01-02 15:04:05")
		c.Next()
		endTime := time.Now().Local().Format("2006-01-02 15:04:05")

		resp := ResponseMessage{}

		json.Unmarshal(bodyWriter.body.Bytes(), &resp)

		record, _ := json.Marshal(&OperationRecord{
			Ip:        c.ClientIP(),
			Method:    c.Request.Method,
			Status:    bodyWriter.Status(),
			Code:      resp.Code,
			Path:      c.Request.URL.Path,
			Agent:     c.Request.UserAgent(),
			Body:      string(body),
			Message:   resp.Message,
			BeginTime: beginTime,
			EndTime:   endTime,
		})

		global.GVA_LOG.Info(string(record))
	}
}
