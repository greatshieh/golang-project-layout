// 错误码定义
package errcode

// 通用: 基本错误
// Code must start with 1xxxxx
const (
	// ErrSuccess - 200: OK.
	ErrSuccess int = iota + 100001

	// ErrUnknown - 500: Internal server error.
	ErrUnknown

	// ErrBind - 400: Error occurred while binding the request body to the struct.
	ErrBind

	// ErrValidation - 400: Validation failed.
	ErrValidation

	// ErrErrTokenInvalid - 401: Token invalid.
	ErrErrTokenInvalid

	// ErrInternalServer - 500: Server Exception.
	ErrInternalServer

	// ErrTooManyRequests - 429: Too many requests
	ErrTooManyRequests
)

// 通用：数据库类错误
const (
	// ErrDatabase - 500: Database error.
	ErrDatabase int = iota + 100101
)

// 通用：认证授权类错误
const (
	// ErrEncrypt - 401: Error occurred while encrypting the user password.
	ErrEncrypt int = iota + 100201

	// ErrSignatureInvalid - 401: Signature is invalid.
	ErrSignatureInvalid

	// ErrExpired - 401: Token expired.
	ErrExpired

	// ErrInvalidAuthHeader - 401: Invalid authorization header.
	ErrInvalidAuthHeader

	// ErrMissingHeader - 401: The `Authorization` header was empty.
	ErrMissingHeader

	// ErrorExpired - 401: Token expired.
	ErrorExpired

	// ErrPasswordIncorrect - 401: Password was incorrect.
	ErrPasswordIncorrect

	// PermissionDenied - 403: Permission denied.
	ErrPermissionDenied

	// ErrCasbinUpdate - 403: Permission denied.
	ErrCasbinUpdate
)

// 通用：编解码类错误
const (
	// ErrEncodingFailed - 500: Encoding failed due to an error with the data.
	ErrEncodingFailed int = iota + 100301

	// ErrDecodingFailed - 500: Decoding failed due to an error with the data.
	ErrDecodingFailed

	// ErrInvalidJSON - 500: Data is not valid JSON.
	ErrInvalidJSON

	// ErrEncodingJSON - 500: JSON data could not be encoded.
	ErrEncodingJSON

	// ErrDecodingJSON - 500: JSON data could not be decoded.
	ErrDecodingJSON

	// ErrInvalidYaml - 500: Data is not valid Yaml.
	ErrInvalidYaml

	// ErrEncodingYaml - 500: Yaml data could not be encoded.
	ErrEncodingYaml

	// ErrDecodingYaml - 500: Yaml data could not be decoded.
	ErrDecodingYaml
)

// User(用户)相关错误
const (
	// ErrUserNotFound - 404: User not found
	ErrUserNotFound = iota + 110001
	// ErrUserAlreadyExist - 400: User already exist
	ErrUserAlreadyExist
	// ErrUserForbidden - 400: User is forbidden
	ErrUserForbidden
)

// 密钥相关错误
const (
	// ErrReachMaxCount - 400: Secret reach the max count
	ErrReachMaxCount = iota + 110101
	// ErrSecretNotFound - 404: Secret not found
	ErrSecretNotFound
)

// 插件相关错误
const (
	// ErrEmailSend - 500: Email Failed
	ErrEmailSend = iota + 110201
	// ErrLimitedIP - 500: Limited IP
	ErrLimitedIP
)
