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
local pairs       = pairs
local type        = type
local ngx         = ngx


local schema = {
    type = "object",
    properties = {
        before_body = {
            description = "body before the filter phase.",
            type = "string"
        },
        body = {
            description = "body to replace upstream response.",
            type = "string"
        },
        after_body = {
            description = "body after the modification of filter phase.",
            type = "string"
        },
        headers = {
            description = "new headers for response",
            type = "object",
            minProperties = 1,
        },
    },
    anyOf = {
        {required = {"before_body"}},
        {required = {"body"}},
        {required = {"after_body"}}
    },
    minProperties = 1,
}

local plugin_name = "echo"
-- https://apisix.apache.org/zh/docs/apisix/plugins/echo/  插件开发的demo
local _M = {
    version = 0.1,
    priority = 412,
    name = plugin_name,
    schema = schema,
}


function _M.check_schema(conf)
    local ok, err = core.schema.check(schema, conf)
    if not ok then
        return false, err
    end

    return true
end

-- before_body: 在 body 属性之前添加的内容
-- body: 覆盖上游返回的响应 body
-- after_body: 在 body 属性之后添加的内容
function _M.body_filter(conf, ctx)
    if conf.body then
        ngx.arg[1] = conf.body
        ngx.arg[2] = true
    end

    if conf.before_body and not ctx.plugin_echo_body_set then
        ngx.arg[1] = conf.before_body ..  ngx.arg[1]
        ctx.plugin_echo_body_set = true
    end

-- ngx.arg[2] 标识是否是最后一个chunk
    if ngx.arg[2] and conf.after_body then
        ngx.arg[1] = ngx.arg[1] .. conf.after_body
    end
end


function _M.header_filter(conf, ctx)
    if conf.body or conf.before_body or conf.after_body then
        core.response.clear_header_as_body_modified()   -- 清除响应头 content_length content_encoding
    end

    if not conf.headers then
        return
    end

    if not conf.headers_arr then
        conf.headers_arr = {}

        for field, value in pairs(conf.headers) do      -- 添加返回的响应头
            if type(field) == 'string'
                    and (type(value) == 'string' or type(value) == 'number') then
                if #field == 0 then
                    return false, 'invalid field length in header'
                end
                core.table.insert(conf.headers_arr, field)
                core.table.insert(conf.headers_arr, value)
            else
                return false, 'invalid type as header value'
            end
        end
    end

    local field_cnt = #conf.headers_arr
    for i = 1, field_cnt, 2 do
        ngx.header[conf.headers_arr[i]] = conf.headers_arr[i+1]
    end
end

return _M
