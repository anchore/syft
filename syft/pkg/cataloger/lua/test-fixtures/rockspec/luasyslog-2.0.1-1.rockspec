local package_name = "luasyslog"
local package_version = "2.0.1"
local rockspec_revision = "1"
local github_account_name = "lunarmodules"
local github_repo_name = package_name


package = package_name
version = package_version.."-"..rockspec_revision
source = {
   url = "git://github.com/"..github_account_name.."/"..github_repo_name..".git",
   branch = (package_version == "dev") and "main" or nil,
   tag = (package_version ~= "dev") and package_version or nil,
}
description = {
   summary = "Syslog logging for Lua",
   detailed = [[
     Addon for LuaLogging to log to the system log on unix systems.
     Can also be used without LuaLogging to directly write to syslog.
   ]],
   license = "MIT/X11",
   homepage = "https://github.com/"..github_account_name.."/"..github_repo_name,
}
dependencies = {
   "lua >= 5.1",
   "lualogging >= 1.4.0, < 2.0.0",
}
build = {
   type = "builtin",
   modules = {
      lsyslog = {
         sources = "lsyslog.c",
      },
      ["logging.syslog"] = "syslog.lua",
   }
}
