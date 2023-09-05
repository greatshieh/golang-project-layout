package errcode

func init() {
	register(ErrUserNotFound, 404, "用户不存在")
	register(ErrUserAlreadyExist, 400, "用户已存在")
	register(ErrUserForbidden, 400, "用户被禁止登录")
	register(ErrReachMaxCount, 400, "Secret reach the max count")
	register(ErrSecretNotFound, 404, "Secret not found")
	register(ErrSuccess, 200, "OK")
	register(ErrUnknown, 500, "内部服务器错误")
	register(ErrBind, 400, "Error occurred while binding the request body to the struct")
	register(ErrValidation, 400, "验证失败")
	register(ErrErrTokenInvalid, 401, "Token 不可用")
	register(ErrInternalServer, 500, "内部服务器异常")
	register(ErrDatabase, 500, "数据库错误")
	register(ErrEncrypt, 401, "Error occurred while encrypting the user password")
	register(ErrSignatureInvalid, 401, "Signature is invalid")
	register(ErrExpired, 401, "Token expired")
	register(ErrInvalidAuthHeader, 401, "Invalid authorization header")
	register(ErrMissingHeader, 401, "The `Authorization` header was empty")
	register(ErrorExpired, 401, "Token 已过期")
	register(ErrPasswordIncorrect, 401, "密码错误")
	register(ErrPermissionDenied, 403, "Permission denied")
	register(ErrEncodingFailed, 500, "Encoding failed due to an error with the data")
	register(ErrDecodingFailed, 500, "Decoding failed due to an error with the data")
	register(ErrInvalidJSON, 500, "Data is not valid JSON")
	register(ErrEncodingJSON, 500, "JSON data could not be encoded")
	register(ErrDecodingJSON, 500, "JSON data could not be decoded")
	register(ErrInvalidYaml, 500, "Data is not valid Yaml")
	register(ErrEncodingYaml, 500, "Yaml data could not be encoded")
	register(ErrDecodingYaml, 500, "Yaml data could not be decoded")
	register(ErrEmailSend, 500, "邮件发送失败, 请联系管理员")
	register(ErrLimitedIP, 500, "请求频繁")
	register(ErrTooManyRequests, 401, "服务器繁忙, 请等待")
}
