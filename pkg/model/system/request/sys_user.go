package request

import "golang_project_layout/pkg/model/system"

// Register User register structure
type Register struct {
	Username     string `json:"userName" example:"用户名"`
	Password     string `json:"passWord" example:"密码"`
	NickName     string `json:"nickName" example:"昵称"`
	Avatar       string `json:"avatar" example:"头像链接"`
	AuthorityId  uint   `json:"authorityId" swaggertype:"string" example:"int 角色id"`
	IsActive     bool   `json:"isActive" swaggertype:"string" example:"bool 是否启用"`
	AuthorityIds []uint `json:"authorityIds" swaggertype:"string" example:"[]uint 角色id"`
	Phone        string `json:"phone" example:"电话号码"`
	Email        string `json:"email" example:"电子邮箱"`
}

// User login structure
type Login struct {
	Username string `json:"username"` // 用户名
	Password string `json:"password"` // 密码
}

// Modify password structure
type ChangePasswordReq struct {
	ID          uint   `json:"-"`           // 从 JWT 中提取 user id，避免越权
	Password    string `json:"password"`    // 密码
	NewPassword string `json:"newPassword"` // 新密码
}

// Modify  user's auth structure
type SetUserAuth struct {
	AuthorityId uint `json:"authorityId"` // 角色ID
}

// Modify  user's auth structure
type SetUserAuthorities struct {
	ID           uint
	AuthorityIds []uint `json:"authorityIds"` // 角色ID
}

type ChangeUserInfo struct {
	ID           uint                  `gorm:"primarykey"`                                                                                             // 主键ID
	NickName     string                `json:"nickName" gorm:"default:系统用户;comment:用户昵称"`                                                              // 用户昵称
	Phone        string                `json:"phone"  gorm:"comment:用户手机号"`                                                                            // 用户手机号
	AuthorityIds []uint                `json:"authorityIds" gorm:"-"`                                                                                  // 角色ID
	Email        string                `json:"email"  gorm:"comment:用户邮箱"`                                                                             // 用户邮箱
	Avatar       string                `json:"avatar" gorm:"default:https://wpimg.wallstcn.com/f778738c-e4f8-4870-b634-56703b4acafe.gif;comment:用户头像"` // 用户头像
	IsActive     bool                  `json:"isActive" gorm:"comment:冻结用户"`                                                                           //冻结用户
	Authorities  []system.SysAuthority `json:"-" gorm:"many2many:sys_user_authority;"`
}
