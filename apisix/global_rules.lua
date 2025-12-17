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

local core    = require("apisix.core")
local plugin_checker = require("apisix.plugin").plugin_checker
local error = error


local _M = {}

-- 为 core.config.new("/global_rules",opts)
local global_rules

function _M.init_worker()
    local err
    global_rules, err = core.config.new("/global_rules", {
        automatic = true,
        item_schema = core.schema.global_rule,
        -- checker, global_rules本质就是plugin
        checker = plugin_checker,
    })
    if not global_rules then
        error("failed to create etcd instance for fetching /global_rules : "
            .. err)
    end
end


-- 获取当前配置的全局策略, 返回值为 "/global_rules"配置目录下的 配置值 和 配置版本
function _M.global_rules()
    if not global_rules then
        return nil, nil
    end
    -- conf_version 初始为0， 配置每变化一次，conf_version+1
    return global_rules.values, global_rules.conf_version
end


function _M.get_pre_index()
    if not global_rules then
        return nil
    end
    return global_rules.prev_index
end

return _M
