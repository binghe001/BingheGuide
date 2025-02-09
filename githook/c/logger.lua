local logger = require("logger")
local log = logger.new()

-- 定期检查写入线程状态
local function checkThreadStatus()
    log:checkWriterThread()
    print("Current thread status:", log.thread_status)
end

-- 记录日志消息
for i = 1, 10 do
    log:record("Log message #" .. i)
    os.execute("sleep 1") -- 模拟长时间运行
end

-- 销毁日志记录器
log:destroy()