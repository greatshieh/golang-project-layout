package system

import (
	"database/sql/driver"
	"fmt"
	"golang_project_layout/pkg/global"
	"time"

	uuid "github.com/satori/go.uuid"
)

type SysUser struct {
	global.GVA_MODEL
	UUID         uuid.UUID      `json:"uuid" gorm:"index;comment:用户UUID"`
	Username     string         `json:"userName" gorm:"index;comment:用户登录名"`
	Password     string         `json:"-"  gorm:"comment:用户登录密码"`
	NickName     string         `json:"nickName" gorm:"default:普通用户;comment:用户昵称"`
	Avatar       string         `json:"avatar" gorm:"default:https://wpimg.wallstcn.com/f778738c-e4f8-4870-b634-56703b4acafe.gif;comment:用户头像"`
	Introduction string         `json:"introduction" gorm:"comment:自我介绍"`
	AuthorityId  uint           `json:"authorityId" gorm:"default:200;comment:用户角色ID"`
	Authority    SysAuthority   `json:"authority" gorm:"foreignKey:AuthorityId;references:AuthorityId;comment:用户角色"`
	Authorities  []SysAuthority `json:"authorities" gorm:"many2many:sys_user_authority;"`
	Phone        string         `json:"phone"  gorm:"comment:用户手机号"`
	Email        string         `json:"email"  gorm:"comment:用户邮箱"`
	IsStaff      bool           `json:"isStaff" grom:"default:false;comment:是否员工"` // 员工可以访问admin站点
	IsActive     bool           `json:"isActive" gorm:"default:true;comment:是否可用"`
	IsSuperUser  bool           `json:"isSuperuser" gorm:"default:false;comment:是否超级管理员"`
	LastLogin    *LoginTime     `json:"lastLogin" gorm:"comment:最后登录时间"`
}

func (SysUser) TableName() string {
	return "sys_users"
}

type LoginTime time.Time

func (l *LoginTime) MarshalJSON() ([]byte, error) {
	tTime := time.Time(*l)
	return []byte(fmt.Sprintf("\"%v\"", tTime.Format("2006-01-02 15:04:05"))), nil
}

// 在存储时调⽤，将该⽅法的返回值进⾏存储，该⽅法可以实现数据存储前对数据进⾏相关操作。
func (l LoginTime) Value() (driver.Value, error) {
	var zeroTime time.Time
	tlt := time.Time(l)
	//判断给定时间是否和默认零时间的时间戳相同
	if tlt.UnixNano() == zeroTime.UnixNano() {
		return nil, nil
	}
	return tlt.Format("2006-01-02 15:04:05"), nil
}

// 实现在数据查询出来之前对数据进⾏相关操作
func (l *LoginTime) Scan(v interface{}) error {
	if value, ok := v.(time.Time); ok {
		*l = LoginTime(value)
		return nil
	}
	return fmt.Errorf("can not convert %v to timestamp", v)
}
