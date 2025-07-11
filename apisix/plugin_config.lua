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
local plugin_checker = require("apisix.plugin").plugin_checker
local pairs = pairs
local error = error


local plugin_configs


local _M = {
}


function _M.init_worker()
    local err
    plugin_configs, err = core.config.new("/plugin_configs", {
        automatic = true,
        item_schema = core.schema.plugin_config,
        checker = plugin_checker,
    })
    if not plugin_configs then
        error("failed to sync /plugin_configs: " .. err)
    end
end


function _M.plugin_configs()
    if not plugin_configs then
        return nil, nil
    end
    return plugin_configs.values, plugin_configs.conf_version
end


function _M.get(id)
    return plugin_configs:get(id)
end

-- 路由插件和plugin_config合并
-- plugin_config不会覆盖route_conf，只是作为route_conf的补充
-- Plugin Config 属于一组通用插件配置的抽象, 包含多个插件配置 {"plugins":{"key-auth":{...}, "rate-limit":{...}}}
-- return route_conf
function _M.merge(route_conf, plugin_config)
    if route_conf.prev_plugin_config_ver == plugin_config.modifiedIndex then
        return route_conf
    end

    if not route_conf.value.plugins then
        route_conf.value.plugins = {}
    end

    if route_conf.orig_plugins then
        -- recover
        route_conf.value.plugins = route_conf.orig_plugins
    else
        -- backup in the first time
        route_conf.orig_plugins = route_conf.value.plugins
    end

    route_conf.value.plugins = core.table.clone(route_conf.value.plugins)

    -- 合并配置，plugin_config不会覆盖route_conf，只是作为route_conf的补充
    for name, value in pairs(plugin_config.value.plugins) do
        if not route_conf.value.plugins[name] then  -- 如果route上没配置这个插件，则合并到route上
            route_conf.value.plugins[name] = value
        end
    end

    route_conf.modifiedIndex = route_conf.orig_modifiedIndex .. "#" .. plugin_config.modifiedIndex
    route_conf.prev_plugin_config_ver = plugin_config.modifiedIndex

    return route_conf
end


return _M
