window.qq = window.qq || {};
qq.maps = qq.maps || {};
window.soso || (window.soso = qq);
soso.maps || (soso.maps = qq.maps);
(function () {
    function getScript(src) {
        document.write('<' + 'script src="' + src + '"' +' type="text/javascript"><' + '/script>');
    }
    qq.maps.__load = function (apiLoad) {
        delete qq.maps.__load;
        apiLoad([["2.3.21","",0],["http://open.map.qq.com/","apifiles/2/3/21/mods/","http://open.map.qq.com/apifiles/2/3/21/theme/",true],[1,18,34.519469,104.461761,4],[1462274576867,"http://pr.map.qq.com/pingd","http://pr.map.qq.com/pingd"],["http://apis.map.qq.com/jsapi","http://apikey.map.qq.com/mkey/index.php/mkey/check","http://sv.map.qq.com/xf","http://sv.map.qq.com/boundinfo","http://sv.map.qq.com/rarp","http://search.map.qq.com/","http://routes.map.qq.com/"],[[null,["http://p0.map.gtimg.com/maptilesv3","http://p1.map.gtimg.com/maptilesv3","http://p2.map.gtimg.com/maptilesv3","http://p3.map.gtimg.com/maptilesv3"],"png",[256,256],1,19,"",true,false],[null,["http://m0.map.gtimg.com/hwap","http://m1.map.gtimg.com/hwap","http://m2.map.gtimg.com/hwap","http://m3.map.gtimg.com/hwap"],"png",[128,128],4,18,"107",false,false],[null,["http://p0.map.gtimg.com/sateTiles","http://p1.map.gtimg.com/sateTiles","http://p2.map.gtimg.com/sateTiles","http://p3.map.gtimg.com/sateTiles"],"jpg",[256,256],1,19,"",false,false],[null,["http://p0.map.gtimg.com/sateTranTilesv3","http://p1.map.gtimg.com/sateTranTilesv3","http://p2.map.gtimg.com/sateTranTilesv3","http://p3.map.gtimg.com/sateTranTilesv3"],"png",[256,256],1,19,"",false,false],[null,["http://sv0.map.qq.com/road/","http://sv1.map.qq.com/road/","http://sv2.map.qq.com/road/","http://sv3.map.qq.com/road/"],"png",[256,256],1,19,"",false,false],[null,["http://rtt2a.map.qq.com/live/","http://rtt2b.map.qq.com/live/","http://rtt2c.map.qq.com/live/"],"png",[256,256],1,19,"",false,false],null,null,null],["http://s.map.qq.com/TPano/v1.1.1/TPano.js","http://map.qq.com/",""]],loadScriptTime);
    };
    var loadScriptTime = (new Date).getTime();
    getScript("http://open.map.qq.com/apifiles/2/3/21/main.js");
})();