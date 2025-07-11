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
local core = require("apisix.core")
local ext = require("apisix.plugins.ext-plugin.init")


local name = "ext-plugin-post-req"
-- https://apisix.apache.org/zh/docs/apisix/plugins/ext-plugin-post-req/
-- 内置 Lua 插件执行之后且在请求到达上游之前工作。 执行于access阶段
local _M = {
    version = 0.1,
    priority = -3000,       -- 一个比较小的优先级
    name = name,
    schema = ext.schema,
}


function _M.check_schema(conf)
    return core.schema.check(_M.schema, conf)
end


function _M.access(conf, ctx)
    return ext.communicate(conf, ctx, name)
end


return _M
