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

local memory_handler = require("apisix.plugins.proxy-cache.memory_handler")
local disk_handler = require("apisix.plugins.proxy-cache.disk_handler")
local util = require("apisix.plugins.proxy-cache.util")
local core = require("apisix.core")
local ipairs = ipairs

local plugin_name = "proxy-cache"

local STRATEGY_DISK = "disk"
local STRATEGY_MEMORY = "memory"
local DEFAULT_CACHE_ZONE = "disk_cache_one"

local schema = {
    type = "object",
    properties = {
        cache_zone = {
            type = "string",
            minLength = 1,
            maxLength = 100,
            default = DEFAULT_CACHE_ZONE,
        },
        cache_strategy = {
            type = "string",
            enum = {STRATEGY_DISK, STRATEGY_MEMORY},
            default = STRATEGY_DISK,
        },
        cache_key = {
            type = "array",
            minItems = 1,
            items = {
                description = "a key for caching",
                type = "string",
                pattern = [[(^[^\$].+$|^\$[0-9a-zA-Z_]+$)]],
            },
            default = {"$host", "$request_uri"}
        },
        cache_http_status = {
            type = "array",
            minItems = 1,
            items = {
                description = "http response status",
                type = "integer",
                minimum = 200,
                maximum = 599,
            },
            uniqueItems = true,
            default = {200, 301, 404},
        },
        cache_method = {
            type = "array",
            minItems = 1,
            items = {
                description = "supported http method",
                type = "string",
                enum = {"GET", "POST", "HEAD"},
            },
            uniqueItems = true,
            default = {"GET", "HEAD"},
        },
        hide_cache_headers = {
            type = "boolean",
            default = false,
        },
        cache_control = {
            type = "boolean",
            default = false,
        },
        cache_bypass = {
            type = "array",
            minItems = 1,
            items = {
                type = "string",
                pattern = [[(^[^\$].+$|^\$[0-9a-zA-Z_]+$)]]
            },
        },
        no_cache = {
            type = "array",
            minItems = 1,
            items = {
                type = "string",
                pattern = [[(^[^\$].+$|^\$[0-9a-zA-Z_]+$)]]
            },
        },
        cache_ttl = {
            type = "integer",
            minimum = 1,
            default = 300,
        },
    },
}

--https://apisix.apache.org/zh/docs/apisix/plugins/proxy-cache/
-- 支持基于磁盘和内存的缓存。提供了根据缓存键缓存响应的功能
-- 基于磁盘，是利用Nginx原生能力
-- 基于内存，使用的是 shdict
local _M = {
    version = 0.2,
    priority = 1085,
    name = plugin_name,
    schema = schema,
}


-- 插件配置conf的格式校验
function _M.check_schema(conf)
    -- schema校验
    local ok, err = core.schema.check(schema, conf)
    if not ok then
        return false, err
    end

    --conf.cache_key 用于缓存的键。支持NGINX 变量和值中的常量字符串。变量应该以 $ 符号为前缀
    for _, key in ipairs(conf.cache_key) do
        -- 不能仅仅使用请求方法
        if key == "$request_method" then
            return false, "cache_key variable " .. key .. " unsupported"
        end
    end

    local found = false
    local local_conf = core.config.local_conf()
    -- 校验conf/config.yaml中关于proxy_cache的配置
    if local_conf.apisix.proxy_cache then
        local err = "cache_zone " .. conf.cache_zone .. " not found"
        -- 遍历所有的zones, 查找插件配置conf里的cache_zone是否已经在conf/config.yaml中预先配置了
        for _, cache in ipairs(local_conf.apisix.proxy_cache.zones) do
            -- cache_zone passed in plugin config matched one of the proxy_cache zones
            -- 找到了
            if cache.name == conf.cache_zone then
                -- check for the mismatch between cache_strategy and corresponding cache zone
                if (conf.cache_strategy == STRATEGY_MEMORY and cache.disk_path) or
                (conf.cache_strategy == STRATEGY_DISK and not cache.disk_path) then
                    err =  "invalid or empty cache_zone for cache_strategy: "..conf.cache_strategy
                else
                    found = true
                end
                break
            end
        end

        if found == false then
            return false, err
        end
    end

    return true
end


function _M.access(conf, ctx)
    core.log.info("proxy-cache plugin access phase, conf: ", core.json.delay_encode(conf))

    -- 生成cache_key array[string]. 如["$host", "$request_uri"]
    local value = util.generate_complex_value(conf.cache_key, ctx) --解析变量
    -- 设置变量 upstream_cache_key
    ctx.var.upstream_cache_key = value
    core.log.info("proxy-cache cache key value:", value)

    local handler
    if conf.cache_strategy == STRATEGY_MEMORY then
        handler = memory_handler
    else
        handler = disk_handler
    end

    return handler.access(conf, ctx)
end


function _M.header_filter(conf, ctx)
    core.log.info("proxy-cache plugin header filter phase, conf: ", core.json.delay_encode(conf))

    local handler
    if conf.cache_strategy == STRATEGY_MEMORY then
        handler = memory_handler
    else
        handler = disk_handler
    end

    handler.header_filter(conf, ctx)
end


function _M.body_filter(conf, ctx)
    core.log.info("proxy-cache plugin body filter phase, conf: ", core.json.delay_encode(conf))

    if conf.cache_strategy == STRATEGY_MEMORY then
        memory_handler.body_filter(conf, ctx)
    end
end


return _M
