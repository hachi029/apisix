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

--- Get or set the information of the client request.
--
-- @module core.request

local lfs = require("lfs")
local log = require("apisix.core.log")
local json = require("apisix.core.json")
local io = require("apisix.core.io")
local req_add_header
if ngx.config.subsystem == "http" then
    local ngx_req = require "ngx.req"
    req_add_header = ngx_req.add_header
end
-- https://github.com/api7/apisix-nginx-module/blob/main/lib/resty/apisix/request.lua
local is_apisix_or, a6_request = pcall(require, "resty.apisix.request")
local ngx = ngx
local get_headers = ngx.req.get_headers
local clear_header = ngx.req.clear_header
local tonumber  = tonumber
local error     = error
local type      = type
local str_fmt   = string.format
local str_lower = string.lower
local req_read_body = ngx.req.read_body
local req_get_body_data = ngx.req.get_body_data
local req_get_body_file = ngx.req.get_body_file
local req_get_post_args = ngx.req.get_post_args
local req_get_uri_args = ngx.req.get_uri_args
local req_set_uri_args = ngx.req.set_uri_args
local table_insert = table.insert
local req_set_header = ngx.req.set_header


local _M = {}


local function _headers(ctx)
    if not ctx then
        ctx = ngx.ctx.api_ctx
    end

    if not is_apisix_or then
        -- ngx.req.get_headers
        return get_headers()
    end

    -- https://github.com/api7/apisix-nginx-module/blob/main/lib/resty/apisix/request.lua#L22
    if a6_request.is_request_header_set() then
        a6_request.clear_request_header()
        ctx.headers = get_headers()
    end

    local headers = ctx.headers
    if not headers then
        headers = get_headers()
        ctx.headers = headers
    end

    return headers
end

-- 校验header key，必须是一个string
local function _validate_header_name(name)
    local tname = type(name)
    if tname ~= "string" then
        return nil, str_fmt("invalid header name %q: got %s, " ..
                "expected string", name, tname)
    end

    return name
end

---
-- Returns all headers of the current request.
-- The name and value of the header in return table is in lower case.
--
-- @function core.request.headers
-- @tparam table ctx The context of the current request.
-- @treturn table all headers
-- @usage
-- local headers = core.request.headers(ctx)
_M.headers = _headers

---
-- Returns the value of the header with the specified name.
--
-- @function core.request.header
-- @tparam table ctx The context of the current request.
-- @tparam string name The header name, example: "Content-Type".
-- @treturn string|nil the value of the header, or nil if not found.
-- @usage
-- -- You can use upper case for header "Content-Type" here to get the value.
-- local content_type = core.request.header(ctx, "Content-Type") -- "application/json"
function _M.header(ctx, name)
    if not ctx then
        ctx = ngx.ctx.api_ctx
    end

    local value = _headers(ctx)[name]
    return type(value) == "table" and value[1] or value
end

-- override: add_header false; set_header: true
local function modify_header(ctx, header_name, header_value, override)
    if type(ctx) == "string" then
        -- It would be simpler to keep compatibility if we put 'ctx'
        -- after 'header_value', but the style is too ugly!
        header_value = header_name
        header_name = ctx
        ctx = nil

        if override then
            log.warn("DEPRECATED: use set_header(ctx, header_name, header_value) instead")
        else
            log.warn("DEPRECATED: use add_header(ctx, header_name, header_value) instead")
        end
    end

    local err
    -- 校验header key，必须是一个string
    header_name, err = _validate_header_name(header_name)
    if err then
        error(err)
    end

    local changed = false
    if is_apisix_or then
        changed = a6_request.is_request_header_set()
    end

    if override then
        -- ngx.req.set_header
        req_set_header(header_name, header_value)
    else
        -- ngx_req.add_header
        req_add_header(header_name, header_value)
    end

    -- 重置缓存
    if ctx and ctx.var then
        -- when the header is updated, clear cache of ctx.var
        ctx.var["http_" .. str_lower(header_name)] = nil
    end

    if is_apisix_or and not changed then
        -- if the headers are not changed before,
        -- we can only update part of the cache instead of invalidating the whole
        a6_request.clear_request_header()
        if ctx and ctx.headers then
            -- set header
            if override or not ctx.headers[header_name] then
                ctx.headers[header_name] = header_value
            else
                -- add header
                local values = ctx.headers[header_name]
                if type(values) == "table" then
                    table_insert(values, header_value)
                else
                    ctx.headers[header_name] = {values, header_value}
                end
            end
        end
    end
end

function _M.set_header(ctx, header_name, header_value)
    modify_header(ctx, header_name, header_value, true)
end

function _M.add_header(ctx, header_name, header_value)
    modify_header(ctx, header_name, header_value, false)
end

-- return the remote address of client which directly connecting to APISIX.
-- so if there is a load balancer between downstream client and APISIX,
-- this function will return the ip of load balancer.
function _M.get_ip(ctx)
    if not ctx then
        ctx = ngx.ctx.api_ctx
    end
    return ctx.var.realip_remote_addr or ctx.var.remote_addr or ''
end


-- get remote address of downstream client,
-- in cases there is a load balancer between downstream client and APISIX.
function _M.get_remote_client_ip(ctx)
    if not ctx then
        ctx = ngx.ctx.api_ctx
    end
    return ctx.var.remote_addr or ''
end


function _M.get_remote_client_port(ctx)
    if not ctx then
        ctx = ngx.ctx.api_ctx
    end
    return tonumber(ctx.var.remote_port)
end


-- 获取uri查询参数
function _M.get_uri_args(ctx)
    if not ctx then
        ctx = ngx.ctx.api_ctx
    end

    if not ctx.req_uri_args then
        -- use 0 to avoid truncated result and keep the behavior as the
        -- same as other platforms
        -- ngx.req.get_uri_args
        local args = req_get_uri_args(0)
        ctx.req_uri_args = args
    end

    return ctx.req_uri_args
end


-- 设置uri查询参数
function _M.set_uri_args(ctx, args)
    if not ctx then
        ctx = ngx.ctx.api_ctx
    end

    ctx.req_uri_args = nil
    -- ngx.req.set_uri_args
    return req_set_uri_args(args)
end


-- 获取post_args
function _M.get_post_args(ctx)
    if not ctx then
        ctx = ngx.ctx.api_ctx
    end

    if not ctx.req_post_args then
        -- ngx.req.read_body
        req_read_body()

        -- use 0 to avoid truncated result and keep the behavior as the
        -- same as other platforms
        -- ngx.req.get_post_args
        local args, err = req_get_post_args(0)
        if not args then
            -- do we need a way to handle huge post forms?
            log.error("the post form is too large: ", err)
            args = {}
        end
        ctx.req_post_args = args
    end

    return ctx.req_post_args
end


local function check_size(size, max_size)
    if max_size and size > max_size then
        return nil, "request size " .. size .. " is greater than the "
                    .. "maximum size " .. max_size .. " allowed"
    end

    return true
end


local function test_expect(var)
    local expect = var.http_expect
    return expect and str_lower(expect) == "100-continue"
end


-- 读取请求体，如果请求体大小超过了max_size, 则返回错误
function _M.get_body(max_size, ctx)
    if max_size then
        local var = ctx and ctx.var or ngx.var
        local content_length = tonumber(var.http_content_length)
        if content_length then
            -- make sure content_length <= max_size
            local ok, err = check_size(content_length, max_size)
            if not ok then
                -- When client_max_body_size is exceeded, Nginx will set r->expect_tested = 1 to
                -- avoid sending the 100 CONTINUE.
                -- We use trick below to imitate this behavior.
                if test_expect(var) then
                    clear_header("expect")
                end

                return nil, err
            end
        end
    end

    -- check content-length header for http2/http3
    do
        local var = ctx and ctx.var or ngx.var
        local content_length = tonumber(var.http_content_length)
        if (var.server_protocol == "HTTP/2.0" or var.server_protocol == "HTTP/3.0")
            and not content_length then
            return nil, "HTTP2/HTTP3 request without a Content-Length header"
        end
    end
    req_read_body()

    -- 读取请求体
    local req_body = req_get_body_data()
    if req_body then
        local ok, err = check_size(#req_body, max_size)
        if not ok then
            return nil, err
        end

        return req_body
    end

    -- 请求体被缓存到了文件中
    local file_name = req_get_body_file()
    if not file_name then
        return nil
    end

    log.info("attempt to read body from file: ", file_name)

    if max_size then
        -- 检查请求体缓存文件大小
        local size, err = lfs.attributes (file_name, "size")
        if not size then
            return nil, err
        end

        -- 如果文件大小超过max_size，则返回
        local ok, err = check_size(size, max_size)
        if not ok then
            return nil, err
        end
    end

    -- 调用lua原生接口，此处是一个阻塞操作
    local req_body, err = io.get_file(file_name)
    return req_body, err
end


function _M.get_json_request_body_table()
    -- 读取请求体
    local body, err = _M.get_body()
    if not body then
        return nil, { message = "could not get body: " .. (err or "request body is empty") }
    end

    -- json decode
    local body_tab, err = json.decode(body)
    if not body_tab then
        return nil, { message = "could not get parse JSON request body: " .. err }
    end

    return body_tab
end


function _M.get_scheme(ctx)
    if not ctx then
        ctx = ngx.ctx.api_ctx
    end
    return ctx.var.scheme or ''
end


function _M.get_host(ctx)
    if not ctx then
        ctx = ngx.ctx.api_ctx
    end
    return ctx.var.host or ''
end


function _M.get_port(ctx)
    if not ctx then
        ctx = ngx.ctx.api_ctx
    end
    return tonumber(ctx.var.server_port)
end


_M.get_http_version = ngx.req.http_version


_M.get_method = ngx.req.get_method

return _M
