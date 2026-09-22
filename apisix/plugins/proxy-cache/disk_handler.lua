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

local os = os
local ngx_re = require("ngx.re")
local core = require("apisix.core")
local util = require("apisix.plugins.proxy-cache.util")

local _M = {}

-- 基于磁盘的缓存，本质还是使用nginx本身的cache能力，这个插件只是增加了动态配置的能力

-- 清空整个磁盘缓存文件
local function disk_cache_purge(conf, ctx)
    -- map $upstream_cache_zone $upstream_cache_zone_info {
    --    disk_cache_one /tmp/disk_cache_one,1:2;
    --}
    -- 变量upstream_cache_zone_info 由变量$upstream_cache_zone映射而来。
    local cache_zone_info = ngx_re.split(ctx.var.upstream_cache_zone_info, ",")

    -- 找到upstream_cache_key对于的磁盘缓存文件
    local filename = util.generate_cache_filename(cache_zone_info[1], cache_zone_info[2],
        ctx.var.upstream_cache_key)

    -- 如果缓存文件存在，则将其删除
    if util.file_exists(filename) then
        os.remove(filename)
        return nil
    end

    return "Not found"
end


function _M.access(conf, ctx)
    -- 设置变量值 upstream_cache_zone
    ctx.var.upstream_cache_zone = conf.cache_zone

    -- 如果是PURGE, 则清空整个磁盘缓存文件
    if ctx.var.request_method == "PURGE" then
        local err = disk_cache_purge(conf, ctx)
        if err ~= nil then
            return 404
        end

        return 200
    end

    -- 一个或多个用于解析值的参数，如果任何值不为空且不等于 0，则不会从缓存中检索响应
    if conf.cache_bypass ~= nil then
        local value = util.generate_complex_value(conf.cache_bypass, ctx)
        -- https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_bypass
        ctx.var.upstream_cache_bypass = value
        core.log.info("proxy-cache cache bypass value:", value)
    end

    -- 应缓存响应的请求方法。
    if not util.match_method(conf, ctx) then
        ctx.var.upstream_cache_bypass = "1"
        core.log.info("proxy-cache cache bypass method: ", ctx.var.request_method)
    end
end


function _M.header_filter(conf, ctx)
    local no_cache = "1"

    if util.match_method(conf, ctx) and util.match_status(conf, ctx) then
        no_cache = "0"
    end

    -- conf.no_cache 用于解析值的一个或多个参数，如果任何值不为空且不等于 0，则不会缓存响应
    if conf.no_cache ~= nil then
        local value = util.generate_complex_value(conf.no_cache, ctx)
        core.log.info("proxy-cache no-cache value:", value)

        if value ~= nil and value ~= "" and value ~= "0" then
            no_cache = "1"
        end
    end

    local upstream_hdr_cache_control
    local upstream_hdr_expires

    -- 如果为 true，则隐藏 Expires 和 Cache-Control 响应标头。
    if conf.hide_cache_headers == true then
        upstream_hdr_cache_control = ""
        upstream_hdr_expires = ""
    else
        upstream_hdr_cache_control = ctx.var.upstream_http_cache_control
        upstream_hdr_expires = ctx.var.upstream_http_expires
    end

    core.response.set_header("Cache-Control", upstream_hdr_cache_control,
        "Expires", upstream_hdr_expires,
        "Apisix-Cache-Status", ctx.var.upstream_cache_status)

    -- 设置no_cache值 https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_no_cache
    -- Defines conditions under which the response will not be saved to a cache。
    -- If at least one value of the string parameters is not empty and is not equal to “0” then the response will not be saved
    ctx.var.upstream_no_cache = no_cache
    core.log.info("proxy-cache no cache:", no_cache)
end


return _M
