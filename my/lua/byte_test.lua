-- 首先定义一个字符串
local str = "012abcd"
print("str = "..str)

-- 使用常规方式
print("\nafter string.byte(str,1,4)")
print(string.byte(str,1,4))             -- 48      49      50      97

local a,b,c,d = string.byte(str,1,4)
print(a,b,c,d)                                -- 48      49      50      97

print(type(string.byte(str,1,4)))       -- name

-- 使用负数索引
print("\nafter str:byte(-2,-1)")
print(str:byte(-2,-1))                  -- 99      100

-- 当参数i大于j时
print("\nafter str:byte(2,1)")
print(str:byte(2, 1))

-- 当索引无效时
print("\nafter str:byte(2000,1000000)")
print(str:byte(2000,1000000))
