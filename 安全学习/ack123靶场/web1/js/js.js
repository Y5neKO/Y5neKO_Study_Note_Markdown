/**
*后台左导航显示关闭控制函数
*/
function HdhToHref(a) {
    location.href = a;
}
function doClick(id) {
    var classElements = [];
    allElements = document.getElementsByTagName('div');
    for (var i = 0; i < allElements.length; i++) {
        if (allElements[i].className == "xm") {
            allElements[i].style.display = "none";
        }
    }
    if (document.getElementById("xm" + id).style.display == "block") {
        document.getElementById("xm" + id).style.display = "none";
    } else {
        document.getElementById("xm" + id).style.display = "block";
    }
}
function checkclick(msg) { if (confirm(msg)) { event.returnValue = true; } else { event.returnValue = false; } }
function DonforCheckDoAll(xzk) {
    for (var j = 1; j <= xzk; j++) {
        box = eval('document.checkboxform.DonforDoRecord' + j);
        if (box.checked == false) box.checked = true;
    }
}
function UnDonforCheckDoAll(xzk) {
    for (var j = 1; j <= xzk; j++) {
        box = eval('document.checkboxform.DonforDoRecord' + j);
        if (box.checked == true) box.checked = false;
    }
}
function DonforSwitchAll(xzk) {
    for (var j = 1; j <= xzk; j++) {
        box = eval('document.checkboxform.DonforDoRecord' + j);
        box.checked = !box.checked;
    }
}
function HdhToHref(lj) { window.location.href = lj; }
function HdhToTopLj(lj) { top.location.href = lj; }
function HdhToRight(lj) {
    parent.hdhright.location.href = lj;
    var hztzid = parent.document.getElementById("hdhtckall").value;
    if (hztzid.split("||").length > 0) {
        for (var x = 0; x < hztzid.split("||").length; x++) {
            hdhztl = hztzid.split("||")[x].replace("|", "");
            hdhztl = hdhztl.replace("|", "");
            if (hdhztl.length > 0) {
                parent.document.getElementById(hdhztl).style.display = "none";
                parent.document.getElementById("ztl" + hdhztl).className = "wx";
            }
        }
    }

}//后台左框架
function HdhToLeft(lj) { parent.hdhleft.location.href = lj; }//后台右框架
function HdhClickMove(msg, lj) { if (confirm(msg)) { window.location.href = lj; } else { event.returnValue = false; } }
function HdhOpenDiv(d) {
    if (document.getElementById(d).style.display == "block" || document.getElementById(d).style.display == "") {
        document.getElementById(d).style.display = "none"
    } else {
        document.getElementById(d).style.display = "block";
    }
}
function WxgOpenDiv(d) {
    if (document.getElementById(d).style.display == "none") {
        document.getElementById(d).style.display = ""
    } else {
        document.getElementById(d).style.display = "none";
    }
}
function HdhXdQxDo(id, blm, blz) {
    var hdhyz = document.getElementById(blm).value;
    var newyz = "";
    if (document.getElementById(id).className == "HdhDxDxd") {
        document.getElementById(id).className = "HdhDxYxd";
        if (hdhyz.length == 0) {
            hdhyz = blz;
        } else {
            hdhyz += "," + blz;
        }
        document.getElementById(blm).value = hdhyz;
    }
    else {
        document.getElementById(id).className = "HdhDxDxd";
        if (hdhyz.length > 0) {
            if (hdhyz.indexOf(",") >= 0) {
                for (var i = 0; i < hdhyz.split(",").length; i++) {
                    if (hdhyz.split(",")[i] != blz) {
                        if (newyz.length == 0) { newyz = hdhyz.split(",")[i]; }
                        else { newyz += "," + hdhyz.split(",")[i]; }
                    }
                }
                hdhyz = newyz;
            } else {
                hdhyz = "";
            }
            document.getElementById(blm).value = hdhyz;
        }
    }
}


//打开QQ地图控件
function DrvHdhFunOpen(hi) {
    if (hi != null) {
        hiIfr = "DrvHdhIframe_" + hi;
    } else {
        hiIfr = "DrvHdhIframe";
    }
    document.getElementById(hiIfr).style.display = "block";

}
//获取QQ地图坐标数据
function DrvHdhGetContent(hi) {
    var DrvHdhObj;
    var hiPos = "";
    var hiPos = "";
    var hiAdr = "";
    var hiIfr = "";
    if (hi != null) {
        hiPos = "DrvHdhGetPos_" + hi;
        hiAdr = "DrvHdhGetAdr_" + hi;
        hiIfr = "DrvHdhIframe_" + hi;
        HiIfrOne = "DrvHdhGetIframe_" + hi;
    } else {
        hiPos = "DrvHdhGetPos";
        hiAdr = "DrvHdhGetAdr";
        hiIfr = "DrvHdhIframe";
        HiIfrOne = "DrvHdhGetIframe";
    }
    if (document.all) {
        DrvHdhObj = document.frames[HiIfrOne].document;
    } else {
        DrvHdhObj = document.getElementById(HiIfrOne).contentDocument;
    }
    document.getElementById(hiPos).value = DrvHdhObj.getElementById("poi_cur").value;
    document.getElementById(hiAdr).value = DrvHdhObj.getElementById("addr_cur").value;
    document.getElementById(hiIfr).style.display = "none";
}
function DrvHdhCloContent() {
    var DrvHdhObj;
    if (document.all) {
        DrvHdhObj = document.frames["DrvHdhGetIframe"].document;
    } else {
        DrvHdhObj = document.getElementById("DrvHdhGetIframe").contentDocument;
    }
    document.getElementById("DrvHdhIframe").style.display = "none";
}

//内嵌IFRAME带隐形背景弹出框
//bt：弹出框的标题
//width：弹出框宽度
//height：弹出框高度
//url：URL地址
//divin：弹出框嵌入的DIV的ID号
//调用此JS需要在调用页面插入一个ID为“divin”的层
function OpenIframe(bt, width, height, url, divin) {
    backchar = "<div class='hdhtck' id='hdhtck'>";
    backchar += "<div class='tcxsk' style='width:" + width + "px;height:" + height + "px;left:50%;right:auto;margin-left:-" + width / 2 + "px;top:50%;margin-top:-" + height / 2 + "px;'>";
    backchar += " <div class='tcbtk'>";
    backchar += "<b>" + bt + "</b><a onclick=\"document.getElementById('hdhtck').style.display='none';\">X</a>";
    backchar += " </div>";
    backchar += "<iframe id='hdhiframe' style='border:0px;width:" + width + "px;height:" + (height - 26) + "px;' src=\"" + url + "\"></iframe";
    backchar += "</div>";
    backchar += "</div>";
    document.getElementById(divin).innerHTML = backchar;
    return backchar;
}
//内嵌IFRAME弹出框每次更新URL
//bt：弹出框的标题
//width：弹出框宽度
//height：弹出框距离顶部的高度
//url：URL地址
//divin：弹出框嵌入的DIV的ID号
//调用此JS需要在调用页面插入一个ID为“divin”的层
function OpenIframeReplaceUrl(bt, width, height, url, divin, idname) {
    var hdhtck;
    var backchar;
    var wkjHeight = height;
    if (idname == "undefined") { idname = "hdhtcka"; }
    var divexit = document.getElementById(idname);
    if (divexit) {
        document.getElementById(idname).style.display = "block";
        document.getElementById("hdhiframe" + idname).src = url;
        document.getElementById("hdhtitle" + idname).innerHTML = bt;
    } else {
        hdhtck = "<div class='hdhtck'  style='width:" + width + "px;height:" + (document.documentElement.clientHeight - wkjHeight) + "px;right:10px;top:" + height + "px;' id='" + idname + "'>";
        hdhtck += "<div class='tcxsk' style='top:0px;left:left;height:" + (document.documentElement.clientHeight - (wkjHeight + 10)) + "px;right:0px;'>";
        hdhtck += " <div class='tcbtk'>";
        hdhtck += "<b id='hdhtitle" + idname + "'>" + bt + "</b><a onclick=\"document.getElementById('" + idname + "').style.display='none';\" title='关闭'>X</a>";
        hdhtck += " </div>";
        hdhtck += "<iframe id='hdhiframe" + idname + "' style='border:0px;width:100%;height:" + (document.documentElement.clientHeight - (wkjHeight + 50)) + "px;' src=\"" + url + "\"></iframe";
        hdhtck += "</div>";
        hdhtck += "</div>";
        document.getElementById(divin).innerHTML += hdhtck;
    }
    return backchar;
}


//内嵌IFRAME带不带背景弹出框
//bt：弹出框的标题
//width：弹出框宽度
//height：弹出框高度
//url：URL地址
//divin：弹出框嵌入的DIV的ID号,调用此JS需要在调用页面插入一个ID为“divin”的层
//idname:DIV弹出框的ID
function OpenIframeNo(bt, width, height, url, divin, idname) {
    var hdhtck;
    var hdhztlid = "ztl" + idname;
    var wkjHeight = 120;
    if (idname == "undefined") { idname = "hdhtck"; }
    var divexit = document.getElementById(idname);
    if (divexit) {
        document.getElementById("hdhiframe"+ idname).src="";
        document.getElementById("hdhiframe"+ idname).src=url;
        document.getElementById(idname).style.display = "block";
    } else {
        hdhtck = "<div class='hdhtck'  style='width:" + width + "px;height:" + (document.documentElement.clientHeight - wkjHeight) + "px;right:10px;top:60px;' id='" + idname + "'>";
        hdhtck += "<div class='tcxsk' style='top:0px;left:left;height:" + (document.documentElement.clientHeight - (wkjHeight + 10)) + "px;right:0px;'>";
        hdhtck += " <div class='tcbtk'>";
        hdhtck += "<b>" + bt + "</b><a onclick=\"document.getElementById('" + idname + "').style.display='none';\" title='关闭'>X</a>";
        hdhtck += " </div>";
        hdhtck += "<iframe id='hdhiframe" + idname + "' style='border:0px;width:100%;height:" + (document.documentElement.clientHeight - (wkjHeight + 26)) + "px;' src=\"" + url + "\"></iframe";
        hdhtck += "</div>";
        hdhtck += "</div>";
        document.getElementById(divin).innerHTML += hdhtck;
    }
    return hdhtck;
}


//主框架弹出框状态栏目显示
//bt：弹出框的标题
//width：弹出框宽度
//height：弹出框高度
//url：URL地址
//divin：弹出框嵌入的DIV的ID号,调用此JS需要在调用页面插入一个ID为“divin”的层
//idname:DIV弹出框的ID
//ztlid：显示最小框的状态栏ID
//ztzid：隐藏框保存状态值的弹出框ID号
//topsize：隔顶部的间隔，不调用或设置此参数用默认的“60”值，设置为20表示隔顶部20px
function hdhCmsOpenIframes(bt, width, height, url, divin, idname, ztlid, ztzid,topsize) {
    var hdhtck;
    var hdhztl;
    var hdhztlid = "ztl" + idname; //状态最小化ID
    var wkjHeight = 104;
    var hdhtckall = "";
    if (idname == "undefined") { idname = "hdhtck"; }
    var topstr = " top:60px;";
    if (topsize != undefined)
    {
        topstr = " top:" + topsize + "px;";
    } else {
        topsize = 60;
    }
    var heightWin =60-parseInt(topsize);
    var hztzid = document.getElementById(ztzid).value;
    if (hztzid.split("||").length > 0) {
        for (var x = 0; x < hztzid.split("||").length; x++) {
            hdhztl = hztzid.split("||")[x].replace("|", "");
            hdhztl = hdhztl.replace("|", "");
            if (hdhztl.length > 0) {
                document.getElementById(hdhztl).style.display = "none";
                document.getElementById("ztl" + hdhztl).className = "wx";
            }
        }
    }
    var divexit = document.getElementById(idname);
    if (divexit) {
        document.getElementById(hdhztlid).className = "xz";
        document.getElementById(idname).style.display = "block";
    } else {
        hdhztl = "<span class='xz' id='" + hdhztlid + "'><a onclick=\"hdhCmsClosedIframes('" + divin + "','" + ztlid + "','" + idname + "','" + ztzid + "');\" title='关闭'>X</a><span onclick=\"hdhCmsListIframes('" + ztzid + "','" + ztlid + "','" + idname + "')\">" + bt + "</span></span>";
        hdhtckall += "|" + idname + "|";
        //hdhtck = "<div class='hdhtck'  style='width:" + width + "px;height:" + (document.documentElement.clientHeight - wkjHeight) + "px;right:0px;top:60px;' id='" + idname + "'>";
        hdhtck = "<div class='tcxsk' style='position:fixed;width:" + width + "px;height:" + ((document.documentElement.clientHeight - wkjHeight) + heightWin) + "px;right:0px;" + topstr + "' id='" + idname + "'>";
        hdhtck += " <div class='tcbtk'>";
        hdhtck += "<b>" + bt + "</b>";
        hdhtck += "<a onclick=\"hdhCmsClosedIframes('" + divin + "','" + ztlid + "','" + idname + "','" + ztzid + "');\" title='关闭'>X</a>";
        hdhtck += "<a onclick=\"hdhCmsListIframes('" + ztzid + "','" + ztlid + "','" + idname + "')\" title='最小化'>—</a>";
        hdhtck += " </div>";
        hdhtck += "<iframe name='hdhiframe" + idname + "' id='hdhiframe" + idname + "' style='border:0px;width:100%;height:" + (document.documentElement.clientHeight - (wkjHeight + 38)) + "px;' src=\"" + url + "\"></iframe>";
        hdhtck += "</div>";



       //hdhtck += "</div>";
        var hdhParentDiv = document.getElementById(divin);
        var hdhParentDom = hdhParentDiv.parentNode;
        var div = document.createElement("div");
        div.innerHTML += hdhtck;
        hdhParentDom.appendChild(div);
        document.getElementById(ztlid).innerHTML += hdhztl;
        document.getElementById(ztzid).value += hdhtckall;
    }
    return hdhtck;
}
//关闭全局弹出框
//divin:要移除弹出框的外框架ID
//ztlid：要移除的最小化状态栏ID
//idname：要移除的弹出框ID
function hdhCmsClosedIframes(divin, ztlid, idname, ztzid) {
    var hdhztlid = "ztl" + idname; //状态最小化ID
    var divexit = document.getElementById(idname);
    if (divexit) {
        //存在则移除
        var hdhParentDiv = document.getElementById(idname);
        var hdhParentDom = hdhParentDiv.parentNode;
        hdhParentDom.removeChild(hdhParentDiv);
        document.getElementById(ztlid).removeChild(document.getElementById(hdhztlid));
        document.getElementById(ztzid).value = document.getElementById(ztzid).value.replace("|" + idname + "|", "");
    }

}
//显示全局弹出框
//ztzid:要移除弹出框的外框架ID
//ztlid：要移除的最小化状态栏ID
//idname：要移除的弹出框ID
function hdhCmsListIframes(ztzid, ztlid, idname) {
    var hdhztlid = "ztl" + idname; //状态最小化ID
    if (document.getElementById(hdhztlid).className == "xz") {
        document.getElementById(hdhztlid).className = "wx";
        document.getElementById(idname).style.display = "none";
    } else {
        var divexit = document.getElementById(idname);
        var hdhztl;//状态栏动态ID
        if (divexit) {
            //存在则移除
            var hztzid = document.getElementById(ztzid).value;
            if (hztzid.split("||").length > 0) {
                for (var x = 0; x < hztzid.split("||").length; x++) {
                    hdhztl = hztzid.split("||")[x].replace("|", "");
                    hdhztl = hdhztl.replace("|", "");
                    if (hdhztl.length > 0) {
                        document.getElementById(hdhztl).style.display = "none";
                        document.getElementById("ztl" + hdhztl).className = "wx";
                    }
                }
                document.getElementById(hdhztlid).className = "xz";
                document.getElementById(idname).style.display = "block";
            }
        }
    }

}

//内嵌IFRAME带不带背景弹出框
//bt：弹出框的标题
//width：弹出框宽度
//height：弹出框高度
//url：URL地址
//divin：弹出框嵌入的DIV的ID号
//bt:弹出框标题
//tskstyle:显示区域的样式
//调用此JS需要在调用页面插入一个ID为“divin”的层
function OpenIframeNoTitle(openstyle, iframestyle, url, divin, bt, tskstyle) {
    if (tskstyle.length < 5) { tskstyle = openstyle; }
    backchar = "<div class='hdhtck'  style='left:auto;" + openstyle + ";' id='hdhtck'>";
    backchar += "<div class='tcxsk' style='top:0px;left:auto;right:0px;" + tskstyle + "'>";
    if (bt.length > 1) {
        backchar += " <div class='tcbtk'>";
        backchar += "<b>" + bt + "</b><a onclick=\"document.getElementById('hdhtck').style.display='none';\">X</a>";
        backchar += " </div>";
    } else {
        backchar += "<a class='tckclose' onclick=\"document.getElementById('hdhtck').style.display='none';\">X</a>";
    }
    backchar += "<iframe id='hdhiframe' style='border:0px;" + iframestyle + ";' src=\"" + url + "\"></iframe";
    backchar += "</div>";
    backchar += "</div>";
    document.getElementById(divin).innerHTML = backchar;
    return backchar;
}

//获取flie图片路径加载到img中
function change(img, flie) {
    var vId = img.replace("ImgPic", "").replace("1", "");
    var pic = null;
    var file = null;
    var ext = null;
    var ImgUrl = null;

    if (!!window.ActiveXObject || "ActiveXObject" in window) { // IE
        pic = document.getElementById(img);//图片
        file = $("#" + flie);      //选择框
        ImgUrl = file.val();
        ext = file.val().substring(file.val().lastIndexOf(".") + 1).toLowerCase();
    }
    else
        if (navigator.userAgent.indexOf("Firefox") > 0) { // Firefox
            pic = document.getElementById(img);  //图片
            file = document.getElementById(flie);      //选择框
            ImgUrl = file.value;
            ext = file.value.substring(file.value.lastIndexOf(".") + 1).toLowerCase();
        }
        else
            if (navigator.userAgent.indexOf("Chrome") > 0) { // Chrome
                pic = document.getElementById(img);   //图片
                file = document.getElementById(flie);        //选择框
                ImgUrl = file.value;
                ext = file.value.substring(file.value.lastIndexOf(".") + 1).toLowerCase();
            }

    // gif在IE浏览器暂时无法显示
    if (ext != 'png' && ext != 'jpg' && ext != 'jpeg') {
        alert("图片的格式必须为png或者jpg或者jpeg格式！");
    }

    var isIE = !!window.ActiveXObject || "ActiveXObject" in window,
        isIE6 = navigator.userAgent.match(/MSIE 6.0/) != null;
    if (isIE) {
        file.select();
        var reallocalpath = document.selection.createRange().text;
        file.blur();
        //IE6浏览器设置img的src为本地路径可以直接显示图片
        if (isIE6) {
            pic.src = reallocalpath;
        } else {
            // 非IE6版本的IE由于安全问题直接设置img的src无法显示本地图片，但是可以通过滤镜来实现
            pic.style.filter = "progid:DXImageTransform.Microsoft.AlphaImageLoader(sizingMethod='scale',src=\"" + ImgUrl + "\")";
            // 设置img的src为base64编码的透明图片 取消显示浏览器默认图片
            pic.src = 'data:image/gif;base64,R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==';
        }
    }
    else {
        html5Reader(file, pic);
        ReaderBase64(file, vId);
    }
}
//html加载
function ReaderBase64(file, MyId) {
    var file = file.files[0];
    var reader = new FileReader();
    reader.readAsDataURL(file);
    reader.onload = function (e) {
        document.getElementById(MyId).value = this.result;
    }
}
//取得图片文件对象的BASE64代码，并填写到对应的PIC对象中
function html5Reader(file, pic) {
    var file = file.files[0];
    var reader = new FileReader();
    reader.readAsDataURL(file);
    reader.onload = function (e) {
        pic.src = this.result;
    }
}
//活动切换
function XZAmMost(Id) {
    if (Id == "0") {
        $("#txt_AmMost").hide();
        $("#AmMostB").attr("checked", "");
        $("#AmMostA").attr("checked", "checked");
    }
    else
        if (Id = "1") {
            $("#txt_AmMost").show();
            $("#AmMostA").attr("checked", "");
            $("#AmMostB").attr("checked", "checked");
        }

}

/**
 * 判断是否是IE
 * @returns boolean
 */
function isIE() {
    if (!!window.ActiveXobject || "ActiveXObject" in window) {
        return true;
    } else {
        return false;
    }
}
/**
 * 判断是否是IE11
 * @returns boolean
 */
function isIE11() {
    if ((/Trident\/7\./).test(navigator.userAgent)) {
        return true;
    } else {
        return false;
    }
}

///新增资料时批量上传影集-------------开始
//结合  HdhGetFun.cs中的 HdhCmsPhones 方法使用
function HdhCmsPhonesSelectFile(b) {
    var oFile = document.getElementById(b).files[0];
    // 过滤图片文件的类型
    var rFilter = /^(image\/bmp|image\/gif|image\/jpeg|image\/png|image\/tiff)$/i;
    if (!rFilter.test(oFile.type)) {
        alert('非图片类型不可上传！');
        return;
    }
    // 建立 HTML5 FileReader 对象
    var oReader = new FileReader();
    oReader.onload = function (e) {
        //新增影集  开始
        var HdhPhotosCount = document.getElementById("HdhPhotosCount").value;
        HdhPhotosCount++;
        var strBack = "";
        strBack = "<div class='hdhyjtpk' id='hdhyjtpk" + HdhPhotosCount + "'>";
        strBack += "<img id='HdhPhones" + HdhPhotosCount + "' class='tp' src='" + e.target.result + "'>";
        strBack += "<input type='text' class='ms' ploceholder='输入描述' id='HdhPhones" + HdhPhotosCount + "m' name='HdhPhones" + HdhPhotosCount + "m' value='" + HdhPhotosCount + "'/>"; //描述
        strBack += "<a class='a' onclick='HdhCmsPhonesDeleteFile(" + HdhPhotosCount + ");'>删除图片</a>";
        strBack += "<input type='hidden' id='HdhPhones" + HdhPhotosCount + "t' name='HdhPhones" + HdhPhotosCount + "t' value='" + e.target.result + "'/>";
        strBack += "</div>";
        document.getElementById("HdhPhotosCount").value = HdhPhotosCount;
        document.getElementById("HdhPhotosList").innerHTML += strBack;
        //新增影集  结束
    };
    // 读取所选文件的数据
    oReader.readAsDataURL(oFile);
}
function HdhCmsPhonesDeleteFile(a) {
    var id = "hdhyjtpk" + a;
    if (isIE() || isIE11()) {
        document.getElementById(id).removeNode(true);
    } else {
        document.getElementById(id).remove();
    }
}
///新增资料时批量上传影集-------------结束

//取图片保存BASE64编码
//HdhCmsGetFileId=文件选取的标签ID号
//HdhCmsTpId=用户显示图片的ID
//HdhCmsTpWidth=显示的图片的宽度
//HdhCmsTpHeight=显示的图片的高度
//SaveImgId=保存BASE64控件的ID值
function HdhCmsGetBase64(HdhCmsGetFileId, HdhCmsTpId, HdhCmsTpWidth, HdhCmsTpHeight, SaveImgId) {
    var oFile = document.getElementById(HdhCmsGetFileId).files[0];
    var a = document.getElementById(HdhCmsGetFileId).files.length;
    if (a > 0) {
        // 过滤图片文件的类型
        var rFilter = /^(image\/bmp|image\/gif|image\/jpeg|image\/png|image\/tiff)$/i;
        if (!rFilter.test(oFile.type)) {
            alert('非图片类型不可上传！');
            return;
        }
        // 建立 HTML5 FileReader 对象
        var oReader = new FileReader();
        oReader.onload = function (e) {
            //新增影集  开始
            var strBack = "";
            strBack += "<img width='" + HdhCmsTpWidth + "' height='" + HdhCmsTpHeight + "' class='tp' src='" + e.target.result + "'>";
            document.getElementById(SaveImgId).value = e.target.result;
            document.getElementById(HdhCmsTpId).innerHTML = strBack;
            //新增影集  结束
        };
        // 读取所选文件的数据
        oReader.readAsDataURL(oFile);
    } else {
        alert('未选择文件！');
    }
}


//新增资料切换功能
function NewsJsOpen(a, b, c) {
    var c1 = c.split('|')[0];
    var c2 = c.split('|')[1];
    for (i = 1; i <= b; i++) {
        if (i == a) {
            document.getElementById("title" + i).className = c1;
            document.getElementById("news" + i).style.display = "";
        } else {
            document.getElementById("title" + i).className = c2;
            document.getElementById("news" + i).style.display = "none";
        }
    }
}
//性能参数增加与移除，配置hdhNews中新增修改性能参数时使用
function XncsAdd(idInner) {
    var iCount = document.getElementById("iCount").value;
    var idInner = "lrZzx";
    iCount++;
    var a = "<div class='Lrxncs' id='Lrxncs" + iCount + "'><input type='hidden' value='0' id='DonforId" + iCount + "' name='DonforId" + iCount + "'><span class='xm'><input type='text' required value='' name='xmm" + iCount + "'></span><span class='xm'><input type='text' required value='' name='xmz" + iCount + "'></span><span class='xm'><input type='text' required value='1' name='plz" + iCount + "'></span><span class='xm'><a onclick='XncsDel(" + iCount + ")' class='fa fa-trash' title='移除当前参数'></a></span>";
    var hdhParentDiv = document.getElementById(idInner);
    //var hdhParentDom = hdhParentDiv.parentNode;
    var div = document.createElement("div");
    div.innerHTML += a;
    hdhParentDiv.appendChild(div);
    //document.getElementById(idInner).innerHTML += a;
    document.getElementById("iCount").value = iCount;
}
function XncsDel(i) {
    if (confirm("确定移除当前性能参数项？移除后提交才能彻底删除参数。")) {
        var DonforId = document.getElementById("DonforId" + i).value;
        if (DonforId > 0) {
            document.getElementById("xnDelId").value += "," + DonforId;
        }
        document.getElementById("lrZzx").removeChild(document.getElementById("Lrxncs" + i).parentNode);
    }
}
//移动框 弹出开始
var Dragging = function (validateHandler) { //参数为验证点击区域是否为可移动区域，如果是返回欲移动元素，负责返回null
    var draggingObj = null; //dragging Dialog
    var diffX = 0;
    var diffY = 0;

    function mouseHandler(e) {
        switch (e.type) {
            case 'mousedown':
                draggingObj = validateHandler(e);//验证是否为可点击移动区域
                if (draggingObj != null) {
                    diffX = e.clientX - draggingObj.offsetLeft;
                    diffY = e.clientY - draggingObj.offsetTop;
                }
                break;

            case 'mousemove':
                if (draggingObj) {
                    draggingObj.style.left = (e.clientX - diffX) + 'px';
                    draggingObj.style.top = (e.clientY - diffY) + 'px';
                }
                break;

            case 'mouseup':
                draggingObj = null;
                diffX = 0;
                diffY = 0;
                break;
        }
    };
    return {
        enable: function () {
            document.addEventListener('mousedown', mouseHandler);
            document.addEventListener('mousemove', mouseHandler);
            document.addEventListener('mouseup', mouseHandler);
        },
        disable: function () {
            document.removeEventListener('mousedown', mouseHandler);
            document.removeEventListener('mousemove', mouseHandler);
            document.removeEventListener('mouseup', mouseHandler);
        }
    }
}
function getDraggingDialog(e) {

    var target = e.target;
    while (target && target.className.indexOf('tcbtk') == -1) {
        target = target.offsetParent;
    }
    if (target != null) {
        return target.offsetParent;
    } else {
        return null;
    }
}
Dragging(getDraggingDialog).enable();
//移动框 弹出结束


