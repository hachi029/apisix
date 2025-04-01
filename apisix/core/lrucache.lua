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

--- LRU Caching Implementation.
--
-- @module core.lrucache
-- https://github.com/openresty/lua-resty-lrucache
local lru_new = require("resty.lrucache").new
local resty_lock = require("resty.lock")
local log = require("apisix.core.log")
local tostring = tostring
local ngx = ngx
local get_phase = ngx.get_phase


local lock_shdict_name = "lrucache-lock"
if ngx.config.subsystem == "stream" then
    lock_shdict_name = lock_shdict_name .. "-" .. ngx.config.subsystem
end


local can_yield_phases = {
    ssl_session_fetch = true,
    ssl_session_store = true,
    rewrite = true,
    access = true,
    content = true,
    timer = true
}

local GLOBAL_ITEMS_COUNT = 1024
local GLOBAL_TTL         = 60 * 60          -- 60 min
local PLUGIN_TTL         = 5 * 60           -- 5 min
local PLUGIN_ITEMS_COUNT = 8
local global_lru_fun

-- lru_obj: resty.lrucache(item_count)
-- invalid_stale: 过期对象是否无效，如果否，过期的对象会被重新设置ttl并返回
-- item_ttl: 对象的ttl
-- item_release: item从缓存中释放的回调 （几乎没有场景传这个参数）
-- key: lru key,
-- version: obj附加字段version. 如果指定了version, 只有version一致，才会返回key对应的对象
local function fetch_valid_cache(lru_obj, invalid_stale, item_ttl,
                                 item_release, key, version)
    local obj, stale_obj = lru_obj:get(key)     -- stale_obj, 过期的obj
    if obj and obj.ver == version then  --版本一致
        return obj
    end

    -- 如果允许返回过期对象
    if not invalid_stale and stale_obj and stale_obj.ver == version then
        lru_obj:set(key, stale_obj, item_ttl)
        return stale_obj
    end

    if item_release and obj then   -- 对象未过期但版本不一致，调用释放方法对obj进行释放
        item_release(obj.val)
    end

    return nil
end

-- opts = { count=200,
-- item_ttl=123,
-- type='plugin',
-- item_release = function item从缓存中释放的回调 （几乎没有场景传这个参数）
-- invalid_stale = true 是否允许返回过期的对象，如果允许，过期的对象会被重新设置ttl
-- serial_creating = true  是否同步创建
--}
local function new_lru_fun(opts)
    local item_count, item_ttl
    if opts and opts.type == 'plugin' then
        item_count = opts.count or PLUGIN_ITEMS_COUNT   -- 8
        item_ttl = opts.ttl or PLUGIN_TTL   -- 5min
    else
        item_count = opts and opts.count or GLOBAL_ITEMS_COUNT  --1024
        item_ttl = opts and opts.ttl or GLOBAL_TTL  --60 min
    end

    local item_release = opts and opts.release
    local invalid_stale = opts and opts.invalid_stale
    local serial_creating = opts and opts.serial_creating
    local lru_obj = lru_new(item_count)

    -- key: 缓存key; version: 缓存版本; create_obj_fun: 如果缓存不存在，创建方法; ... create_obj_fun参数
    return function (key, version, create_obj_fun, ...)     --缓存获取元素的方法
        if not serial_creating or not can_yield_phases[get_phase()] then --允许并发创建且执行过程不能被阻塞
            local cache_obj = fetch_valid_cache(lru_obj, invalid_stale,
                                item_ttl, item_release, key, version)
            if cache_obj then
                return cache_obj.val
            end

            local obj, err = create_obj_fun(...)    --缓存里没找到，创建对象
            if obj ~= nil then
                lru_obj:set(key, {val = obj, ver = version}, item_ttl)
            end

            return obj, err
        end

        -- 执行过程允许阻塞且不允许并发创建对象
        local cache_obj = fetch_valid_cache(lru_obj, invalid_stale, item_ttl,
                            item_release, key, version)
        if cache_obj then
            return cache_obj.val
        end

        local lock, err = resty_lock:new(lock_shdict_name)  --控制并发
        if not lock then
            return nil, "failed to create lock: " .. err
        end

        local key_s = tostring(key)
        log.info("try to lock with key ", key_s)

        local elapsed, err = lock:lock(key_s)
        if not elapsed then
            return nil, "failed to acquire the lock: " .. err
        end

        cache_obj = fetch_valid_cache(lru_obj, invalid_stale, item_ttl,
                        nil, key, version)
        if cache_obj then   --说明有其他协程已经创建了obj
            lock:unlock()
            log.info("unlock with key ", key_s)
            return cache_obj.val
        end

        local obj, err = create_obj_fun(...)
        if obj ~= nil then
            lru_obj:set(key, {val = obj, ver = version}, item_ttl)
        end
        lock:unlock()
        log.info("unlock with key ", key_s)

        return obj, err
    end
end


global_lru_fun = new_lru_fun()


local function plugin_ctx_key_and_ver(api_ctx, extra_key)
    local key = api_ctx.conf_type .. "#" .. api_ctx.conf_id

    if extra_key then
        key = key .. "#" .. extra_key
    end

    return key, api_ctx.conf_version
end

---
--  Cache some objects for plugins to avoid duplicate resources creation.
--
-- @function core.lrucache.plugin_ctx
-- @tparam table lrucache LRUCache object instance.
-- @tparam table api_ctx The request context.
-- @tparam string extra_key Additional parameters for generating the lrucache identification key.
-- @tparam function create_obj_func Functions for creating cache objects.
-- If the object does not exist in the lrucache, this function is
-- called to create it and cache it in the lrucache.
-- @treturn table The object cached in lrucache.
-- @usage
-- local function create_obj() {
-- --   create the object
-- --   return the object
-- }
-- local obj, err = core.lrucache.plugin_ctx(lrucache, ctx, nil, create_obj)
-- -- obj is the object cached in lrucache
local function plugin_ctx(lrucache, api_ctx, extra_key, create_obj_func, ...)
    local key, ver = plugin_ctx_key_and_ver(api_ctx, extra_key)
    return lrucache(key, ver, create_obj_func, ...)
end

local function plugin_ctx_id(api_ctx, extra_key)
    local key, ver = plugin_ctx_key_and_ver(api_ctx, extra_key)
    return key .. "#" .. ver
end


local _M = {
    version = 0.1,
    new = new_lru_fun,
    global = global_lru_fun,
    plugin_ctx = plugin_ctx,
    plugin_ctx_id = plugin_ctx_id,
}


return _M
