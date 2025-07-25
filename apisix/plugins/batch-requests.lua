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
local core      = require("apisix.core")
local http      = require("resty.http")
local plugin    = require("apisix.plugin")
local ngx       = ngx
local ipairs    = ipairs
local pairs     = pairs
local str_find  = core.string.find
local str_lower = string.lower

-- https://apisix.apache.org/zh/docs/apisix/plugins/batch-requests/
-- 将多个请求请求参数(request_line/headers/body)放到请求体中，多个请求的响应(status_line/headers/body)也会被放到响应体中
local plugin_name = "batch-requests"

local default_uri = "/apisix/batch-requests"

local attr_schema = {
    type = "object",
    properties = {
        uri = {
            type = "string",
            description = "uri for batch-requests",
            default = default_uri
        }
    },
}

local schema = {
    type = "object",
}

local default_max_body_size = 1024 * 1024 -- 1MiB
local metadata_schema = {
    type = "object",
    properties = {
        max_body_size = {
            description = "max pipeline body size in bytes",
            type = "integer",
            exclusiveMinimum = 0,
            default = default_max_body_size,
        },
    },
}

local method_schema = core.table.clone(core.schema.method_schema)
method_schema.default = "GET"

local req_schema = {
    type = "object",
    properties = {
        query = {
            description = "pipeline query string",
            type = "object"
        },
        headers = {
            description = "pipeline header",
            type = "object"
        },
        timeout = {
            description = "pipeline timeout(ms)",
            type = "integer",
            default = 30000,
        },
        pipeline = {
            type = "array",
            minItems = 1,
            items = {
                type = "object",
                properties = {
                    version = {
                        description = "HTTP version",
                        type = "number",
                        enum = {1.0, 1.1},
                        default = 1.1,
                    },
                    method = method_schema,
                    path = {
                        type = "string",
                        minLength = 1,
                    },
                    query = {
                        description = "request header",
                        type = "object",
                    },
                    headers = {
                        description = "request query string",
                        type = "object",
                    },
                    ssl_verify = {
                        type = "boolean",
                        default = false
                    },
                }
            }
        }
    },
    anyOf = {
        {required = {"pipeline"}},
    },
}

local _M = {
    version = 0.1,
    priority = 4010,
    name = plugin_name,
    schema = schema,
    metadata_schema = metadata_schema,
    attr_schema = attr_schema,
    scope = "global",
}


function _M.check_schema(conf, schema_type)
    if schema_type == core.schema.TYPE_METADATA then
        return core.schema.check(metadata_schema, conf)
    end
    return core.schema.check(schema, conf)
end


local function check_input(data)
    local ok, err = core.schema.check(req_schema, data)
    if not ok then
        return 400, {error_msg = "bad request body: " .. err}
    end
end

local function lowercase_key_or_init(obj)
    if not obj then
        return {}
    end

    local lowercase_key_obj = {}
    for k, v in pairs(obj) do
        lowercase_key_obj[str_lower(k)] = v
    end

    return lowercase_key_obj
end

local function ensure_header_lowercase(data)
    data.headers = lowercase_key_or_init(data.headers)

    for i,req in ipairs(data.pipeline) do
        req.headers = lowercase_key_or_init(req.headers)
    end
end


local function set_common_header(data)
    local local_conf = core.config.local_conf()
    local real_ip_hdr = core.table.try_read_attr(local_conf, "nginx_config", "http",
                                                 "real_ip_header")
    -- we don't need to handle '_' to '-' as Nginx won't treat 'X_REAL_IP' as 'X-Real-IP'
    real_ip_hdr = str_lower(real_ip_hdr)

    local outer_headers = core.request.headers(nil)
    for i,req in ipairs(data.pipeline) do
        for k, v in pairs(data.headers) do
            if not req.headers[k] then
                req.headers[k] = v
            end
        end

        if outer_headers then
            for k, v in pairs(outer_headers) do
                local is_content_header = str_find(k, "content-") == 1
                -- skip header start with "content-"
                if not req.headers[k] and not is_content_header then
                    req.headers[k] = v
                end
            end
        end

        req.headers[real_ip_hdr] = core.request.get_remote_client_ip()
    end
end


local function set_common_query(data)
    if not data.query then
        return
    end

    for i,req in ipairs(data.pipeline) do
        if not req.query then
            req.query = data.query
        else
            for k, v in pairs(data.query) do
                if not req.query[k] then
                    req.query[k] = v
                end
            end
        end
    end
end

---'request {
--    "headers": {
--        "Content-Type": "application/json",
--        "admin-jwt":"xxxx"
--    },
--    "timeout": 500,
--    "pipeline": [
--        {
--            "method": "POST",
--            "path": "/community.GiftSrv/GetGifts",
--            "body": "test"
--        },
--        {
--            "method": "POST",
--            "path": "/community.GiftSrv/GetGifts",
--            "body": "test2"
--        }
--    ]
--}'
--- response: [
--  {
--    "status": 200,
--    "reason": "OK",
--    "body": "{\"ret\":500,\"msg\":\"error\",\"game_info\":null,\"gift\":[],\"to_gets\":0,\"get_all_msg\":\"\"}",
--    "headers": {
--      "Connection": "keep-alive",
--      "Date": "Sat, 11 Apr 2020 17:53:20 GMT",
--      "Content-Type": "application/json",
--      "Content-Length": "81",
--      "Server": "APISIX web server"
--    }
--  },
--  {
--    "status": 200,
--    "reason": "OK",
--    "body": "{\"ret\":500,\"msg\":\"error\",\"game_info\":null,\"gift\":[],\"to_gets\":0,\"get_all_msg\":\"\"}",
--    "headers": {
--      "Connection": "keep-alive",
--      "Date": "Sat, 11 Apr 2020 17:53:20 GMT",
--      "Content-Type": "application/json",
--      "Content-Length": "81",
--      "Server": "APISIX web server"
--    }
--  }
--]
local function batch_requests(ctx)
    local metadata = plugin.plugin_metadata(plugin_name)
    core.log.info("metadata: ", core.json.delay_encode(metadata))

    local max_body_size
    if metadata then
        max_body_size = metadata.value.max_body_size
    else
        max_body_size = default_max_body_size
    end

    local req_body, err = core.request.get_body(max_body_size, ctx)
    if err then
        -- Nginx doesn't support 417: https://trac.nginx.org/nginx/ticket/2062
        -- So always return 413 instead
        return 413, { error_msg = err }
    end
    if not req_body then
        return 400, {
            error_msg = "no request body, you should give at least one pipeline setting"
        }
    end

    local data, err = core.json.decode(req_body)
    if not data then
        return 400, {
            error_msg = "invalid request body: " .. req_body .. ", err: " .. err
        }
    end

    local code, body = check_input(data)
    if code then
        return code, body
    end

    local httpc = http.new()
    httpc:set_timeout(data.timeout)
    local ok, err = httpc:connect("127.0.0.1", ngx.var.server_port) --重新向自己发起请求
    if not ok then
        return 500, {error_msg = "connect to apisix failed: " .. err}
    end

    ensure_header_lowercase(data)
    set_common_header(data)
    set_common_query(data)
    -- https://github.com/ledgetech/lua-resty-http?tab=readme-ov-file#request_pipeline
    local responses, err = httpc:request_pipeline(data.pipeline)
    if not responses then
        return 400, {error_msg = "request failed: " .. err}
    end

    local aggregated_resp = {}
    for _, resp in ipairs(responses) do
        if not resp.status then
            core.table.insert(aggregated_resp, {
                status = 504,
                reason = "upstream timeout"
            })
        end
        local sub_resp = {
            status  = resp.status,
            reason  = resp.reason,
            headers = resp.headers,
        }
        if resp.has_body then
            local err
            sub_resp.body, err = resp:read_body()
            if err then
                sub_resp.read_body_err = err
                core.log.error("read pipeline response body failed: ", err)
            else
                resp:read_trailers()
            end
        end
        core.table.insert(aggregated_resp, sub_resp)
    end
    return 200, aggregated_resp
end

-- 对外暴露api /apisix/batch-requests
function _M.api()
    local uri = default_uri
    local attr = plugin.plugin_attr(plugin_name)
    if attr then
        uri = attr.uri or default_uri
    end
    return {
        {
            methods = {"POST"},
            uri = uri,
            handler = batch_requests,
        }
    }
end


return _M
