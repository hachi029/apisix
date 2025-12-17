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
local pairs = pairs
local pcall = pcall
local unpack = unpack
local tostring = tostring
local ngx = ngx
local get_phase = ngx.get_phase
local timer_every = ngx.timer.every
local exiting = ngx.worker.exiting


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

local stale_obj_pool = {}

local GLOBAL_ITEMS_COUNT = 1024
local GLOBAL_TTL         = 60 * 60          -- 60 min
local PLUGIN_TTL         = 5 * 60           -- 5 min
local PLUGIN_ITEMS_COUNT = 8
local global_lru_fun


-- lru_obj: 缓存对象，为resty.lrucache(item_count)
-- invalid_stale: 过期对象是否无效，如果否，过期的对象会被重新设置ttl并返回
-- refresh_stale: 如果true, 当缓存过期时，会提交一个刷新缓存的异步任务
-- item_ttl: 对象的ttl
-- item_release: item从缓存中释放的回调 （几乎没有场景传这个参数）
-- key: lru key,
-- version: obj附加字段version. 如果指定了version, 只有version一致，才会返回key对应的对象
-- create_obj_fun： 创建对象方法
local function fetch_valid_cache(lru_obj, invalid_stale, refresh_stale, item_ttl,
                                 key, version, create_obj_fun, ...)

    -- https://github.com/openresty/lua-resty-lrucache/tree/master?tab=readme-ov-file#get
    -- the stale data is also returned as the second return value if available
    local obj, stale_obj = lru_obj:get(key)
    -- 对象未过期且版本也相同
    if obj and obj.ver == version then
        return obj
    end

    -- 对象已过期，版本有效
    if stale_obj and stale_obj.ver == version then
        if not invalid_stale then
            lru_obj:set(key, stale_obj, item_ttl)
            return stale_obj
        end

        -- 如果要刷新已过期对象，则提交一个刷新任务
        if refresh_stale then
            -- 提交异步任务，在 refresh_stale_objs()被中执行
            stale_obj_pool[lru_obj][key] = {
                fn = create_obj_fun,
                args = {...},
                ver = version,
                ttl = item_ttl,
            }
            return stale_obj
        end
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
        -- opts为nil则表示全局lru_cache
        item_count = opts and opts.count or GLOBAL_ITEMS_COUNT  --1024
        item_ttl = opts and opts.ttl or GLOBAL_TTL  --60 min
    end

    local invalid_stale = opts and opts.invalid_stale
    -- 如果为true,且缓存对象已过期， 则提交一个异步刷新任务
    local refresh_stale = opts and opts.refresh_stale
    local serial_creating = opts and opts.serial_creating
    -- 创建lua_cache对象 require("resty.lrucache").new
    local lru_obj = lru_new(item_count)

    -- 在neg_lru_obj中的key, 始终返回nil。neg_lru_obj缓存的是无效的key和version
    local neg_lru_obj
    if opts and opts.neg_ttl and opts.neg_count then
        neg_lru_obj = lru_new(opts.neg_count)
    end

    -- stale_obj_pool 存放着需要被异步刷新缓存的任务，参考 refresh_stale_objs() 方法
    stale_obj_pool[lru_obj] = {}
    -- key: 缓存key; version: 缓存版本; create_obj_fun: 如果缓存不存在，创建方法; ... create_obj_fun参数
    return function (key, version, create_obj_fun, ...)      --缓存获取元素的方法
        -- check negative cache first
        -- 在neg_lru_obj中的key, 始终返回nil
        if neg_lru_obj then
            local neg_obj = neg_lru_obj:get(key)
            if neg_obj and neg_obj.ver == version then
                return nil, neg_obj.err
            end
        end

        -- 如果 允许并发创建对象(not serial_creating) 或 当前上下文不允许阻塞(即无法使用锁)
        if not serial_creating or not can_yield_phases[get_phase()] then
            -- 获取缓存对象
            local cache_obj = fetch_valid_cache(lru_obj, invalid_stale, refresh_stale,
                                item_ttl, key, version, create_obj_fun, ...)
            if cache_obj then
                return cache_obj.val
            end

            local obj, err = create_obj_fun(...)    --缓存里没找到，创建对象
            if obj ~= nil then
                -- 重新设置到lur_obj中
                lru_obj:set(key, {val = obj, ver = version}, item_ttl)
            elseif neg_lru_obj then
                -- cache the failure in negative cache
                neg_lru_obj:set(key, {err = err, ver = version}, opts.neg_ttl)
            end

            return obj, err
        end

        -- 此处说明执行过程允许阻塞(可以使用锁)且不允许并发创建对象
        local cache_obj = fetch_valid_cache(lru_obj, invalid_stale, refresh_stale, item_ttl,
                            key, version, create_obj_fun, ...)
        -- 如果获取到了对象，直接返回
        if cache_obj then
            return cache_obj.val
        end

        local lock, err = resty_lock:new(lock_shdict_name)  --控制并发
        if not lock then
            return nil, "failed to create lock: " .. err
        end

        local key_s = tostring(key)
        log.info("try to lock with key ", key_s)

        -- 锁定
        local elapsed, err = lock:lock(key_s)
        if not elapsed then
            return nil, "failed to acquire the lock: " .. err
        end

        -- 再次检查
        cache_obj = fetch_valid_cache(lru_obj, invalid_stale, refresh_stale, item_ttl,
                        key, version, create_obj_fun, ...)
        --说明有其他协程已经创建了obj
        if cache_obj then
            lock:unlock()
            log.info("unlock with key ", key_s)
            return cache_obj.val
        end

        -- 加载
        local obj, err = create_obj_fun(...)
        if obj ~= nil then
            lru_obj:set(key, {val = obj, ver = version}, item_ttl)
        elseif neg_lru_obj then
            -- cache the failure in negative cache
            neg_lru_obj:set(key, {err = err, ver = version}, opts.neg_ttl)
        end
        -- 释放锁
        lock:unlock()
        log.info("unlock with key ", key_s)

        return obj, err
    end
end


-- 创建全局lru_cache
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


-- apisix.http_init_worker() -> init_worker -> .
-- 每秒执行一次。执行 存放在 stale_obj_pool 中需要被异步加载缓存的任务
local function refresh_stale_objs()
    -- 遍历每个lrucache
    for lru_obj, keys in pairs(stale_obj_pool) do
        -- 执行lrucache中的每个需要刷新缓存的key。 参考fetch_valid_cache()方法
        for key, new_obj in pairs(keys) do
            local obj, err = new_obj.fn(unpack(new_obj.args))
            if obj ~= nil then
                lru_obj:set(key, {val = obj, ver = new_obj.ver}, new_obj.ttl)
                keys[key] = nil
                log.info("successfully refresh stale obj for key ",
                            tostring(key), " to ver ", new_obj.ver)
            else
                log.error("failed to refresh stale obj for key ", key, ": ", err)
            end
        end
    end
end


-- apisix.http_init_worker() -> .
local function init_worker()
    local running = false
    -- 每秒执行一次.refresh_stale_objs 中执行 存放在stale_obj_pool中需要被异步加载缓存的任务
    timer_every(1, function ()
        if not exiting() then
            if running then
                log.info("timer_refresh_stale is already running, skipping this iteration")
                return
            end
            running = true
            local ok, err = pcall(refresh_stale_objs)
            if not ok then
                log.error("failed to run timer_refresh_stale: ", err)
            end
            running = false
        end
    end)
end


local _M = {
    version = 0.1,
    init_worker = init_worker,
    -- return function (key, version, create_obj_fun, ...)
    new = new_lru_fun,
    global = global_lru_fun,
    plugin_ctx = plugin_ctx,
    plugin_ctx_id = plugin_ctx_id,
}


return _M
