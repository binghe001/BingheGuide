---
--- Created by binghe.
---
local ffi = require("ffi")
local MutexLock = require("MutexLock")

-- 创建一个互斥锁实例
local mutex = MutexLock.new()

-- 定义线程安全的任务
local function thread_task(id)
    local timeout = 2 -- 超时时间（秒）

    print("Thread " .. id .. " attempting to acquire lock...")
    if mutex:lock(timeout) then
        print("Thread " .. id .. " acquired the lock.")
        -- 模拟工作
        os.execute("sleep 1")
        mutex:unlock()
        print("Thread " .. id .. " released the lock.")
    else
        print("Thread " .. id .. " failed to acquire the lock (timeout).")
    end
end

-- 创建线程
local threads = {}
for i = 1, 5 do
    threads[i] = coroutine.create(thread_task)
end

-- 启动线程
for i = 1, 5 do
    coroutine.resume(threads[i], i)
end

-- 销毁互斥锁
mutex:destroy()
