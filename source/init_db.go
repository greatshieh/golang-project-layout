package main

import (
	"fmt"
	"golang_project_layout/pkg/app"
	"golang_project_layout/pkg/db"
	"golang_project_layout/pkg/global"
	"golang_project_layout/pkg/model/system"
	"golang_project_layout/pkg/utils"

	uuid "github.com/satori/go.uuid"
	"go.uber.org/zap"
)

func main() {
	global.GVA_VP = app.Viper() // 初始化Viper
	global.GVA_LOG = app.Zap()  // 初始化zap日志库
	zap.ReplaceGlobals(global.GVA_LOG)
	global.GVA_DB = db.NewGorm() // gorm连接数据库

	if global.GVA_DB != nil {
		tables := []interface{}{system.SysUser{}, system.JwtBlacklist{}, system.SysUserAuthority{}, system.SysAuthority{}}

		// 删除表格
		db.NewGorm().Migrator().DropTable(tables...)
		// 初始化表
		db.RegisterTables(tables...)
		// 程序结束前关闭数据库链接
		db, _ := global.GVA_DB.DB()
		defer db.Close()
	}

	initSysAuthority()
	initUser()

	user := system.SysUser{}
	global.GVA_DB.Preload("Authorities").First(&user)
	fmt.Printf("%#+v\n", user)
}

// 初始化系统权限表
// admin 管理员, 权限ID: 100, 父权限ID: 0(无)
// staff 员工, 权限ID: 1001, 父权限ID: 100
// admin 用户, 权限ID: 200, 父权限ID: 0(无)
func initSysAuthority() {
	entities := []system.SysAuthority{
		{AuthorityId: 100, AuthorityName: "admin", ParentId: utils.Pointer[uint](0)},
		{AuthorityId: 1001, AuthorityName: "staff", ParentId: utils.Pointer[uint](100)},
		{AuthorityId: 200, AuthorityName: "user", ParentId: utils.Pointer[uint](0)},
	}

	// 创建权限表
	global.GVA_DB.Create(&entities)

	// admin具有所有的数据操作权限
	if err := global.GVA_DB.Model(&entities[0]).Association("DataAuthorityId").Replace([]*system.SysAuthority{{AuthorityId: 100}, {AuthorityId: 1001}, {AuthorityId: 200}}); err != nil {
		fmt.Printf("替换 AuthorityId: %d 关联错误, %s\n", entities[0].AuthorityId, err.Error())
	}

	// staff具有staff和User的数据操作权限
	if err := global.GVA_DB.Model(&entities[1]).Association("DataAuthorityId").Replace([]*system.SysAuthority{{AuthorityId: 1001}, {AuthorityId: 200}}); err != nil {
		fmt.Printf("替换 AuthorityId: %d 关联错误, %s\n", entities[1].AuthorityId, err.Error())
	}

	// user具有User的数据操作权限
	if err := global.GVA_DB.Model(&entities[2]).Association("DataAuthorityId").Replace([]*system.SysAuthority{{AuthorityId: 200}}); err != nil {
		fmt.Printf("替换 AuthorityId: %d 关联错误, %s\n", entities[2].AuthorityId, err.Error())
	}
}

// 初始化系统用户表
func initUser() {
	// 创建sys_user
	users := []system.SysUser{
		{UUID: uuid.NewV4(), Username: "superadmin", Password: utils.BcryptHash("123456"), NickName: "超级管理员", AuthorityId: 100, Phone: "18900000000", Email: "ivan.xiewei@foxmail.com", IsStaff: true, IsActive: true, IsSuperUser: true},
		{UUID: uuid.NewV4(), Username: "staff", Password: utils.BcryptHash("123456"), NickName: "普通员工", AuthorityId: 1001, Phone: "13600000000", Email: "xxx@qq.com", IsStaff: true, IsSuperUser: false, IsActive: true},
		{UUID: uuid.NewV4(), Username: "passive", Password: utils.BcryptHash("123456"), NickName: "冻结员工", AuthorityId: 1001, Phone: "13600000001", Email: "xxx@qq.com", IsStaff: true, IsSuperUser: false, IsActive: false},
		{UUID: uuid.NewV4(), Username: "user", Password: utils.BcryptHash("123456"), NickName: "普通用户", AuthorityId: 200, Phone: "13600000001", Email: "xxx@qq.com", IsStaff: false, IsSuperUser: false, IsActive: true},
	}

	if err := global.GVA_DB.Create(&users).Error; err != nil {
		panic("创建sys_user失败")
	}

	entities := []system.SysAuthority{
		{AuthorityId: 100, AuthorityName: "admin", ParentId: utils.Pointer[uint](0)},
		{AuthorityId: 1001, AuthorityName: "staff", ParentId: utils.Pointer[uint](100)},
		{AuthorityId: 200, AuthorityName: "user", ParentId: utils.Pointer[uint](0)},
	}

	if err := global.GVA_DB.Model(&users[0]).Association("Authorities").Replace(entities); err != nil {
		fmt.Println(err.Error())
	}

	if err := global.GVA_DB.Model(&users[1]).Association("Authorities").Replace(entities[1:3]); err != nil {
		fmt.Println(err.Error())
	}

	if err := global.GVA_DB.Model(&users[2]).Association("Authorities").Replace(entities[1:3]); err != nil {
		fmt.Println(err.Error())
	}

	if err := global.GVA_DB.Model(&users[3]).Association("Authorities").Replace(entities[2:3]); err != nil {
		fmt.Println(err.Error())
	}
}
