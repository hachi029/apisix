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
local fetch_secrets = require("apisix.secret").fetch_secrets
local limit_count = require("apisix.plugins.limit-count.init")
local workflow = require("apisix.plugins.workflow")

-- 使用固定窗口算法，通过给定时间间隔内的请求数量来限制请求速率。超过配置配额的请求将被拒绝
-- https://apisix.apache.org/zh/docs/apisix/plugins/limit-count
local plugin_name = "limit-count"
local _M = {
    version = 0.5,
    priority = 1002,
    name = plugin_name,
    schema = limit_count.schema,
    metadata_schema = limit_count.metadata_schema,
}


function _M.check_schema(conf, schema_type)
    return limit_count.check_schema(conf, schema_type)
end


function _M.access(conf, ctx)
    -- 将conf中value以$开头的，解析为对应变量值
    conf = fetch_secrets(conf, true)
    return limit_count.rate_limit(conf, ctx, plugin_name, 1)
end

-- plugin初始化时调用。配合workflow插件
function _M.workflow_handler()
    workflow.register(plugin_name,
    function (conf)
        return limit_count.check_schema(conf)
    end,
    function (conf, ctx)
        return limit_count.rate_limit(conf, ctx, plugin_name, 1)
    end)
end

return _M
