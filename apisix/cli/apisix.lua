--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--


local pkg_cpath_org = package.cpath
local pkg_path_org = package.path

local _, find_pos_end = string.find(pkg_path_org, ";", -1, true)
if not find_pos_end then
    pkg_path_org = pkg_path_org .. ";"
end

local apisix_home = "/usr/local/apisix"
local pkg_cpath = apisix_home .. "/deps/lib64/lua/5.1/?.so;"
                  .. apisix_home .. "/deps/lib/lua/5.1/?.so;"
local pkg_path_deps = apisix_home .. "/deps/share/lua/5.1/?.lua;"
local pkg_path_env = apisix_home .. "/?.lua;"

-- 设置cpath和path
-- modify the load path to load our dependencies
package.cpath = pkg_cpath .. pkg_cpath_org
package.path  = pkg_path_deps .. pkg_path_org .. pkg_path_env

-- pass path to construct the final result
local env = require("apisix.cli.env")(apisix_home, pkg_cpath_org, pkg_path_org)
-- 实现了apisix的相关命令
local ops = require("apisix.cli.ops")

-- Usage: apisix [action] <argument>
--help:       print the apisix cli help message
--init:       initialize the local nginx.conf
--init_etcd:  initialize the data of etcd
--start:      start the apisix server
--stop:       stop the apisix server
--quit:       stop the apisix server gracefully
--restart:    restart the apisix server
--reload:     reload the apisix server
--test:       test the generated nginx.conf
--version:    print the version of apisix
ops.execute(env, arg)
