document.write("<script language=javascript src='http://res2.wx.qq.com/open/js/jweixin-1.6.0.js'></script>");
//var timestamp = 'timestamp';
//var appId = 'appId';
//var nonceStr = 'nonceStr';
//var signature = 'signature';
//var title = 'title';
//var desc = 'desc';
//var pageUrl = 'Html.Raw(pageUrl)';
//var imgUrl = 'Html.Raw(imgUrl)';
function wechatshare(timestamp, appId, nonceStr, signature, title, desc, pageUrl, imgUrl) {
    wx.config({
        debug: false, // 开启调试模式,调用的所有api的返回值会在客户端alert出来，若要查看传入的参数，可以在pc端打开，参数信息会通过log打出，仅在pc端时才会打印。
        appId: appId, // 必填，公众号的唯一标识
        timestamp: timestamp, // 必填，生成签名的时间戳
        nonceStr: nonceStr, // 必填，生成签名的随机串
        signature: signature,// 必填，签名
        jsApiList: [
            'updateAppMessageShareData',
            'updateTimelineShareData',
            'onMenuShareAppMessage',  //旧的接口，即将废弃
            'onMenuShareTimeline' //旧的接口，即将废弃
        ] // 必填，需要使用的JS接口列表
    });
    wx.ready(function () {   //需在用户可能点击分享按钮前就先调用
        //分享给朋友-新
        //wx.updateAppMessageShareData({
        //    title: title, // 分享标题
        //    desc: desc, // 分享描述
        //    link: pageUrl, // 分享链接，该链接域名或路径必须与当前页面对应的公众号JS安全域名一致
        //    imgUrl: imgUrl, // 分享图标
        //    success: function () {
        //        // 设置成功
        //        alert('有分享');
        //    }
        //})
        //分享给朋友 - 旧
        wx.onMenuShareAppMessage({
            title: title, // 分享标题
            desc: desc, // 分享描述
            link: pageUrl, // 分享链接，该链接域名或路径必须与当前页面对应的公众号JS安全域名一致
            imgUrl: imgUrl, // 分享图标
            success: function () {
                alert('分享好友成功！');
            }
        });
        //分享到朋友圈-新
        //wx.updateTimelineShareData({
        //    title: '荣誉', // 分享标题
        //    link: '@pageUrl', // 分享链接，该链接域名或路径必须与当前页面对应的公众号JS安全域名一致
        //    imgUrl: '@imgUrl', // 分享图标
        //    success: function () {
        //        // 设置成功
        //        alert("success-02");
        //    }
        //})
        //分享到朋友圈-旧
        wx.onMenuShareTimeline({
            title: title, // 分享标题
            link: pageUrl, // 分享链接，该链接域名或路径必须与当前页面对应的公众号JS安全域名一致
            imgUrl: imgUrl, // 分享图标
            success: function (res) {
                // 用户点击了分享后执行的回调函数
                alert('分享朋友圈成功！');
            }
        })
    });
}