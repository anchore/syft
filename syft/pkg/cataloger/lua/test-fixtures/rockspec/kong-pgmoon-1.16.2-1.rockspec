package = "kong-pgmoon"
version = "1.16.2-1"

source = {
  url = "git+https://github.com/kong/pgmoon.git",
  tag = "v1.16.2"
}

description = {
  summary = "Postgres driver for OpenResty and Lua",
  detailed = [[PostgreSQL driver written in pure Lua for use with OpenResty's cosocket API. Can also be used in regular Lua with LuaSocket and LuaCrypto.]],
  homepage = "https://github.com/Kong/pgmoon",
  maintainer = "Kong Inc",
  license = "MIT"
}

dependencies = {
  "lua >= 5.1",
  "lpeg",

  -- "luasocket",
  -- "luasec",
  --
  -- "cqueues",
  -- "luaossl"
  --
  -- "lua-resty-openssl",
}

build = {
  type = "builtin",
  modules = {
    ["pgmoon"] = "pgmoon/init.lua",
    ["pgmoon.arrays"] = "pgmoon/arrays.lua",
    ["pgmoon.bit"] = "pgmoon/bit.lua",
    ["pgmoon.cqueues"] = "pgmoon/cqueues.lua",
    ["pgmoon.crypto"] = "pgmoon/crypto.lua",
    ["pgmoon.hstore"] = "pgmoon/hstore.lua",
    ["pgmoon.json"] = "pgmoon/json.lua",
    ["pgmoon.socket"] = "pgmoon/socket.lua",
    ["pgmoon.util"] = "pgmoon/util.lua",
  },
}

