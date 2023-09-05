package response

import (
	"fmt"
	"golang_project_layout/pkg/global"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/marmotedu/errors"
)

const SUCCESS = 100000

// ErrResponse defines the return messages when an error occurred.
// Reference will be omitted if it does not exist.
// swagger:model
type ErrResponse struct {
	// Code defines the business error code.
	Code int `json:"code"`

	// Message contains the detail of this message.
	// This message is suitable to be exposed to external
	Message string `json:"message"`

	// Reference returns the reference document which maybe useful to solve this error.
	Reference string `json:"reference,omitempty"`
}

type Response struct {
	Code    int         `json:"code"`
	Data    interface{} `json:"data"`
	Message string      `json:"message"`
}

// WriteResponse write an error or the response data into http response body.
// It use errors.ParseCoder to parse any error into errors.Coder
// errors.Coder contains error code, user-safe error message and http status code.
func WriteResponse(c *gin.Context, err error, data interface{}, msg ...string) {
	if err != nil {
		global.GVA_LOG.Error(fmt.Errorf("%-v", err).Error())
		coder := errors.ParseCoder(err)

		c.JSON(http.StatusOK, ErrResponse{
			Code:      coder.Code(),
			Message:   coder.String(),
			Reference: coder.Reference(),
		})

		return
	}

	if len(msg) > 0 {
		c.JSON(http.StatusOK, Response{SUCCESS, data, msg[0]})
	} else {
		c.JSON(http.StatusOK, Response{Code: SUCCESS, Data: data})
	}
}
