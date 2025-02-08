-- 导入Lua模块 
local log_module = require('add_log_message')

-- 初始化内存池 
local memory_pool = log_module.init_memory_pool(1024, 100)

-- 初始化无锁环形队列 
local log_queue = log_module.init_lock_free_log_queue()

-- 初始化线程池 
local thread_pool = log_module.create_thread_pool(log_queue, 4)

-- 注册全局变量 
log_module.register_globals(memory_pool, log_queue, thread_pool)

-- 示例：添加日志消息 
for i=1,10 do
    log_module.add_log_message(string.format('Log message %d', i))
end 