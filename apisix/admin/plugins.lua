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
local require   = require
local core = require("apisix.core")
local check_schema = require("apisix.plugin").check_schema
local ipairs    = ipairs
local table_sort = table.sort
local table_insert = table.insert
local get_uri_args = ngx.req.get_uri_args
local plugin_get_all = require("apisix.plugin").get_all
local plugin_get_http = require("apisix.plugin").get
local plugin_get_stream = require("apisix.plugin").get_stream
local encrypt_conf = require("apisix.plugin").encrypt_conf
local pairs = pairs

local _M = {}


function _M.check_schema(plugins_conf, schema_type)
    local ok, err = check_schema(plugins_conf, schema_type, false)
    if ok then
        for name, conf in pairs(plugins_conf) do
            encrypt_conf(name, conf, schema_type)
        end
    end
    return ok, err
end


function _M.get(name)
    local arg = get_uri_args()
    -- If subsystem is passed inside args then it should be oneOf: http / stream.
    local subsystem = arg["subsystem"] or "http"
    if subsystem ~= "http" and subsystem ~= "stream" then
        return 400, {error_msg = "unsupported subsystem: "..subsystem}
    end

    -- arg all to be deprecated
    if (arg and arg["all"] == "true") then
        core.log.warn("query parameter \"all\" will be deprecated soon.")
        local http_plugins, stream_plugins = plugin_get_all({
            version = true,
            priority = true,
            schema = true,
            metadata_schema = true,
            consumer_schema = true,
            type = true,
            scope = true,
        })

        if arg["subsystem"] == "stream" then
            return 200, stream_plugins
        end

        return 200, http_plugins
    end

    local plugin

    if subsystem == "http"  then
        plugin = plugin_get_http(name)
    else
        plugin = plugin_get_stream(name)
    end

    if not plugin then
        local err = "plugin not found in subsystem " .. subsystem
        core.log.warn(err)
        return 404, {error_msg = err}
    end

    local json_schema = plugin.schema
    if arg and arg["schema_type"] == "consumer" then
        json_schema = plugin.consumer_schema
    end

    if not json_schema then
        return 400, {error_msg = "not found schema"}
    end

    return 200, json_schema
end

-- 获取插件名称列表，列表根据插件的优先级进行了排序
function _M.get_plugins_list(subsystem)
    local http_plugins
    local stream_plugins
    if subsystem == "http" then
        http_plugins = core.config.local_conf().plugins
    else
        stream_plugins = core.config.local_conf().stream_plugins
    end

    local priorities = {}
    local success = {}
    if http_plugins then
        for i, name in ipairs(http_plugins) do
            local plugin = plugin_get_http(name)
            if plugin and plugin.priority then
                priorities[name] = plugin.priority
                table_insert(success, name)
            end
        end
    end

    if stream_plugins then
        for i, name in ipairs(stream_plugins) do
            local plugin = plugin_get_stream(name)
            if plugin and plugin.priority then
                priorities[name] = plugin.priority
                table_insert(success, name)
            end
        end
    end

    local function cmp(x, y)
        return priorities[x] > priorities[y]
    end

    table_sort(success, cmp)
    return success
end


return _M
