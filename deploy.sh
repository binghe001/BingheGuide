#!/usr/bin/env sh

# 确保脚本抛出遇到的错误
set -e

### 更新文章
git config --global http.sslVerify "false"
git add .
git commit -m '更新文章'
git push

## 生成静态文件
npm install
npm run build

# 进入生成的文件夹
cd .site

# 如果是发布到自定义域名
# echo 'www.example.com' > CNAME

git init
git config --global http.sslVerify "false"
git add -A
git commit -m 'deploy'

# 如果发布到 https://<USERNAME>.github.io
git push -f https://binghe001@github.com/binghe001/binghe001.github.io.git master
# 如果发布到 https://<USERNAME>.github.io/<REPO>
# git push -f git@github.com:<USERNAME>/<REPO>.git master:gh-pages

cd -