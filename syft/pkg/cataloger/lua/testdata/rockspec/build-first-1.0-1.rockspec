build = {
   type = "builtin",
   modules = {
      foo = "src/foo.lua"
   }
}
package = "foo"
version = "1.0-1"
source = {
   url = "git+https://github.com/example/foo.git"
}
description = {
   summary = "an example rock",
   homepage = "https://github.com/example/foo",
   license = "MIT"
}
dependencies = {
   "lua >= 5.1"
}
