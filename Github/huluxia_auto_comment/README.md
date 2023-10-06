# huluxia_auto_comment

通过python实现葫芦侠自动刷评论

### 使用方法

首先通过抓包等方式获取账号当前包含了**key**和**设备码**的评论链接，一般为评论数据包的post链接，格式是这个样子：

> http://floor.huluxia.com/comment/create/ANDROID/2.0?platform=2&gkey=000000&app_version=4.1.1.4&versioncode=324&market_id=tool_web&_key=6862A43A7126C3C5D7AB0BFE61BAE16FA5852495DFCFB4DCD5D1D34F3B9678F18C11DF30A4EAC58ED693FD5A1E4E7DCA522FA2837AB0F714&device_code=%5Bd%5Dd113ce76-27bb-469a-a8b5-0d704ea275a7&phone_brand_type=MI

把这个链接设置在第9行的**comment_url**变量内

接着修改第200行的**range()**函数内的参数，这个是决定刷评论的次数

第202行的**time.sleep()**函数内的参数是评论的间隔，推荐在5秒以上，否则会检测频繁评论，需要验证码