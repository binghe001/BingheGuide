<template>
    <div class="redirect-read-more-wrap"
         style="display: none; position: absolute; bottom: 0px; z-index: 9999; width: 100%; margin-top: -100px; font-family: PingFangSC-Regular, sans-serif;">
        <div id="redirect-read-more-mask"
             style="position: relative; height: 200px; background: -webkit-gradient(linear, 0 0%, 0 100%, from(rgba(255, 255, 255, 0)), to(rgb(255, 255, 255)));"></div>
        <a id="redirect-read-more-btn" target="_blank"
           style="position: absolute; left: 50%; top: 70%; bottom: 30px; transform: translate(-50%, -50%); width: 160px; height: 36px; line-height: 36px; font-size: 15px; text-align: center; border: 1px solid rgb(222, 104, 109); color: rgb(222, 104, 109); background: rgb(255, 255, 255); cursor: pointer; border-radius: 6px;">跳转链接</a>
    </div>
</template>

<script>
    export default {
        name: 'RedirectArticle',
        data() {
            return {}
        },
        mounted: function () {

            // 延迟执行
            setTimeout(() => {
                if (this.isRedirect()) {
                    let $article = this.articleObj();
                    this._detect($article, this);
                }
            }, 150);

            // 定时任务
            let interval = setInterval(() => {
                if (this.isRedirect()) {
                    let $article = this.articleObj();
                    // if ($article && $article.article.hasClass("lock-redirect")){
                    //     clearInterval(interval);
                    // }
                    this._detect($article, this);
                }
            }, 1000);
        },
        methods: {
          isRedirect() {
                return this.$page.frontmatter.redirectUrl;
            },
            articleObj: function () {
                let $article = $('.theme-default-content');
                if ($article.length <= 0) return null;

                // 文章的实际高度
                let height = $article[0].clientHeight;

                return {
                    article: $article,
                    height: height
                }
            },
            _detect: function (articleObj, t) {
                if (null == articleObj) return;

                let $article = articleObj.article;
                let height = articleObj.height;
                if ($article.length <= 0) return;

                // 文章隐藏后的高度
                let halfHeight = height * 0.9;

                // 判断是否已加锁
                if ($article.hasClass("lock-redirect")) {
                    return;
                }

                // 设置文章可显示高度
                $article.css({"height": halfHeight + 'px'});
                $article.addClass('lock-redirect');

                // 删除原有标签
                $article.remove("#redirect-read-more-wrap");

                // 添加加锁标签
                let clone = $('.redirect-read-more-wrap').clone();
                clone.attr('id', 'redirect-read-more-wrap');
                clone.css('display', 'block');

                // 按钮跳转付费
                clone.find("#redirect-read-more-btn").attr("href", this.$page.frontmatter.redirectUrl);

                $article.append(clone);
            }
        }
    }
</script>

<style lang="stylus">
    #redirect-read-more-btn {
        border: none !important;
        text-decoration: none;
        background: #3eaf7c !important;
    }

    #redirect-read-more-btn {
        color: #fff !important;
        transition: all .5s ease;
    }

    #redirect-read-more-btn:hover {
        background: #de3636 !important;
    }

    .lock-redirect {
        position: relative;
        overflow: hidden;
        padding-bottom: 30px;
    }
</style>