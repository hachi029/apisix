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

--- Wrapped `ngx.log`.
--
-- @module core.log

local ngx = ngx
local ngx_log  = ngx.log
local require  = require
local select = select
local setmetatable = setmetatable
local tostring = tostring
local unpack = unpack
-- avoid loading other module since core.log is the most foundational one
local tab_clear = require("table.clear")
local ngx_errlog = require("ngx.errlog")
local ngx_get_phase = ngx.get_phase


local _M = {version = 0.4}


local log_levels = {
    stderr = ngx.STDERR,
    emerg  = ngx.EMERG,
    alert  = ngx.ALERT,
    crit   = ngx.CRIT,
    error  = ngx.ERR,
    warn   = ngx.WARN,
    notice = ngx.NOTICE,
    info   = ngx.INFO,
    debug  = ngx.DEBUG,
}


local cur_level

local do_nothing = function() end


local function update_log_level()
    -- Nginx use `notice` level in init phase instead of error_log directive config
    -- Ref to src/core/ngx_log.c's ngx_log_init
    if ngx_get_phase() ~= "init" then
        -- get_sys_filter_level 获取当前nginx.conf里配置的日志级别
        -- https://github.com/openresty/lua-resty-core/blob/master/lib/ngx/errlog.md#get_sys_filter_level
        cur_level = ngx.config.subsystem == "http" and ngx_errlog.get_sys_filter_level()
    end
end


function _M.new(prefix)
    local m = {version = _M.version}
    setmetatable(m, {__index = function(self, cmd)
        local log_level = log_levels[cmd]
        local method
        update_log_level()

        if cur_level and (log_level > cur_level)
        then
            method = do_nothing
        else
            method = function(...)
                return ngx_log(log_level, prefix, ...)
            end
        end

        -- cache the lazily generated method in our
        -- module table
        if ngx_get_phase() ~= "init" then
            self[cmd] = method
        end

        return method
    end})

    return m
end

-- cmd: debug info notice warn ...
setmetatable(_M, {__index = function(self, cmd)
    local log_level = log_levels[cmd]
    local method
    update_log_level()

    -- 日志级别越低，值越大
    if cur_level and (log_level > cur_level) -- debug > notice, cur_level 是配置的日志级别
    then
        method = do_nothing
    else
        method = function(...)
            return ngx_log(log_level, ...)
        end
    end

    -- cache the lazily generated method in our
    -- module table
    if ngx_get_phase() ~= "init" then
        self[cmd] = method
    end

    return method
end})


local delay_tab = setmetatable({
    func = function() end,
    args = {},
    res = nil,
    }, {
    __tostring = function(self)
        -- the `__tostring` will be called twice, the first to get the length and
        -- the second to get the data
        if self.res then
            local res = self.res
            -- avoid unexpected reference
            self.res = nil
            return res
        end

        local res, err = self.func(unpack(self.args))
        if err then
            ngx.log(ngx.WARN, "failed to exec: ", err)
        end

        -- avoid unexpected reference
        tab_clear(self.args)
        self.res = tostring(res)
        return self.res
    end
})


---
-- Delayed execute log printing.
-- It works well with log.$level, eg: log.info(..., log.delay_exec(func, ...))
-- Should not use it elsewhere.
--
-- @function core.log.delay_exec
-- @tparam function func Functions that need to be delayed during log printing.
-- @treturn table The table with the res attribute overridden.
-- @usage
-- local function delay_func(param1, param2)
--     return param1 .. " " .. param2
-- end
-- core.log.info("delay log print: ", core.log.delay_exec(delay_func, "hello", "world))
-- -- then the log will be: "delay log print: hello world"
function _M.delay_exec(func, ...)
    delay_tab.func = func

    tab_clear(delay_tab.args)
    for i = 1, select('#', ...) do
        delay_tab.args[i] = select(i, ...)
    end

    delay_tab.res = nil
    return delay_tab
end


return _M
