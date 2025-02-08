local core = require('apisix.core')
local luv = require('luv')
local json = require('dkjson') -- 需要安装 dkjson 库 

-- 创建标准输出流 
local stdout = luv.newStream()
stdout:open(luv.constants.STDOUT_FILENO, 'w')

-- 定义日志级别 
local LOG_LEVELS = {
    DEBUG = 1,
    INFO = 2,
    WARNING = 3,
    ERROR = 4
}

-- 当前日志级别 
local current_level = LOG_LEVELS.INFO

-- 日志缓存和队列 
local log_cache = {}
local cache_size = 1000 -- 缓存大小 
local log_queue = {}
local queue_mutex = { locked = false }

-- 队列操作函数 
local function enqueue(message)
    while queue_mutex.locked do
        coroutine.yield()
    end
    queue_mutex.locked = true
    table.insert(log_queue, message)
    queue_mutex.locked = false
end

local function dequeue()
    while queue_mutex.locked do
        coroutine.yield()
    end
    queue_mutex.locked = true
    local message = table.remove(log_queue, 1)
    queue_mutex.locked = false
    return message
end

-- 监听流的关闭事件 
stdout:addEventListener('close', function()
    print("Standard output stream closed. Attempting to reopen...")
    -- 尝试重新打开标准输出流 
    stdout:close()
    stdout = luv.newStream()
    stdout:open(luv.constants.STDOUT_FILENO, 'w')
end)

-- 定义异步写入协程 
local writer_co = coroutine.create(function()
    while true do
        local message = dequeue()
        if message then
            -- 尝试写入标准输出 
            local success, err = pcall(function()
                stdout:write(message .. "\n")
            end)
            if not success then
                -- 如果写入失败，尝试重新打开流并重试 
                print("Error writing to stdout:", err)
                stdout:close()
                stdout = luv.newStream()
                stdout:open(luv.constants.STDOUT_FILENO, 'w')
                -- 重新尝试写入 
                stdout:write(message .. "\n")
            end
        end
        coroutine.yield()
    end
end)

-- 启动写入协程 
coroutine.resume(writer_co)

-- 格式化日志函数 
local function format_log(level, message)
    local log_entry = {
        timestamp = os.time(),
        level = level,
        message = message
    }
    return json.encode(log_entry)
end

-- 写入日志函数 
local function write_log(level, message)
    if level >= current_level then
        local formatted_log = format_log(level, message)
        enqueue(formatted_log)
    end
end

-- APISIX插件示例 
local plugin = {
    version = 0.1,
    priority = 1000,
    name = "coroutine-log-support",

    -- 插件初始化函数 
    init = function(conf)
        -- 初始化配置 
        current_level = conf.level or current_level
        return plugin
    end,

    -- 请求处理函数 
    access = function(conf, ctx)
        -- 示例：在访问阶段记录日志 
        write_log(LOG_LEVELS.INFO, "Access phase log message.")
    end,

    -- 日志处理函数 
    log = function(conf, ctx)
        -- 示例：在日志阶段记录日志 
        write_log(LOG_LEVELS.INFO, "Log phase log message.")
    end,
}

-- 注册插件 
core.register_plugin(plugin.name, plugin)

-- 使用示例 
core.add_route({
    methods = {"GET"},
    uri = "/test",
    plugins = {
        [plugin.name] = {
            level = LOG_LEVELS.INFO -- 设置日志级别 
        }
    },
    handler = function(ctx)
        -- 示例：在路由处理中记录日志 
        write_log(LOG_LEVELS.INFO, "Route handler log message.")
        return core.response.send(200, { message = "Test" })
    end
})

-- 等待所有消息写入完成 
while #log_queue > 0 do
    coroutine.resume(writer_co)
end

-- 关闭写入协程 
coroutine.close(writer_co)

-- 关闭标准输出流 
stdout:close()local core = require('apisix.core')
local luv = require('luv')
local json = require('dkjson') -- 需要安装 dkjson 库

-- 创建标准输出流
local stdout = luv.newStream()
stdout:open(luv.constants.STDOUT_FILENO, 'w')

-- 定义日志级别
local LOG_LEVELS = {
    DEBUG = 1,
    INFO = 2,
    WARNING = 3,
    ERROR = 4
}

-- 当前日志级别
local current_level = LOG_LEVELS.INFO

-- 日志缓存和队列
local log_cache = {}
local cache_size = 1000 -- 缓存大小
local log_queue = {}
local queue_mutex = { locked = false }

-- 队列操作函数
local function enqueue(message)
    while queue_mutex.locked do
        coroutine.yield()
    end
    queue_mutex.locked = true
    table.insert(log_queue, message)
    queue_mutex.locked = false
end

local function dequeue()
    while queue_mutex.locked do
        coroutine.yield()
    end
    queue_mutex.locked = true
    local message = table.remove(log_queue, 1)
    queue_mutex.locked = false
    return message
end

-- 监听流的关闭事件
stdout:addEventListener('close', function()
    print("Standard output stream closed. Attempting to reopen...")
    -- 尝试重新打开标准输出流
    stdout:close()
    stdout = luv.newStream()
    stdout:open(luv.constants.STDOUT_FILENO, 'w')
end)

-- 定义异步写入协程
local writer_co = coroutine.create(function()
    while true do
        local message = dequeue()
        if message then
            -- 尝试写入标准输出
            local success, err = pcall(function()
                stdout:write(message .. "\n")
            end)
            if not success then
                -- 如果写入失败，尝试重新打开流并重试
                print("Error writing to stdout:", err)
                stdout:close()
                stdout = luv.newStream()
                stdout:open(luv.constants.STDOUT_FILENO, 'w')
                -- 重新尝试写入
                stdout:write(message .. "\n")
            end
        end
        coroutine.yield()
    end
end)

-- 启动写入协程
coroutine.resume(writer_co)

-- 格式化日志函数
local function format_log(level, message)
    local log_entry = {
        timestamp = os.time(),
        level = level,
        message = message
    }
    return json.encode(log_entry)
end

-- 写入日志函数
local function write_log(level, message)
    if level >= current_level then
        local formatted_log = format_log(level, message)
        enqueue(formatted_log)
    end
end

-- APISIX插件示例
local plugin = {
    version = 0.1,
    priority = 1000,
    name = "coroutine-log-support",

    -- 插件初始化函数
    init = function(conf)
        -- 初始化配置
        current_level = conf.level or current_level
        return plugin
    end,

    -- 请求处理函数
    access = function(conf, ctx)
        -- 示例：在访问阶段记录日志
        write_log(LOG_LEVELS.INFO, "Access phase log message.")
    end,

    -- 日志处理函数
    log = function(conf, ctx)
        -- 示例：在日志阶段记录日志
        write_log(LOG_LEVELS.INFO, "Log phase log message.")
    end,
}

-- 注册插件
core.register_plugin(plugin.name, plugin)

-- 使用示例
core.add_route({
    methods = {"GET"},
    uri = "/test",
    plugins = {
        [plugin.name] = {
            level = LOG_LEVELS.INFO -- 设置日志级别
        }
    },
    handler = function(ctx)
        -- 示例：在路由处理中记录日志
        write_log(LOG_LEVELS.INFO, "Route handler log message.")
        return core.response.send(200, { message = "Test" })
    end
})

-- 等待所有消息写入完成
while #log_queue > 0 do
    coroutine.resume(writer_co)
end

-- 关闭写入协程
coroutine.close(writer_co)

-- 关闭标准输出流
stdout:close()