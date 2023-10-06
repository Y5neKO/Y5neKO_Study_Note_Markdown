// JavaScript Document JS裁减图片生成BASE64编码
//
var hdhcmscantox = document.getElementById("hdhcmscantox");
var hdhcmscliptox = document.getElementById("hdhcmscliptox");
var hdhcmsbtnclip = document.getElementById("hdhcmsbtnclip");
var hdhcmsoldcanvas = document.getElementById("hdhcmsoldcanvas");
var hdhcmsnowcanvas = document.getElementById("hdhcmsnowcanvas");
var hdhcmsoldcontext = hdhcmsoldcanvas.getContext('2d');
var hdhcmsnowcontext = hdhcmsnowcanvas.getContext('2d');
var img = new Image();
img.src = "";
window.onload = function () {
    hdhcmsoldcontext.drawImage(img, 0, 0, hdhcmsoldcanvas.width, hdhcmsoldcanvas.height);
}
var startPoint;
var endPoint;
var w;
var h;
var flag = false;
hdhcmscantox.onmousedown = function (e) {
    flag = true;
    hdhcmscliptox.style.display = 'block';
    startPoint = windowToCanvas(hdhcmsoldcanvas, e.clientX, e.clientY);
    hdhcmscliptox.style.left = startPoint.x + 'px';
    hdhcmscliptox.style.top = startPoint.y + 'px';
}
hdhcmscantox.onmousemove = function (e) {
    if (flag) {
        hdhcmscliptox.style.background = 'rgba(0,0,0,0.5)';
        endPoint = windowToCanvas(hdhcmsoldcanvas, e.clientX, e.clientY);
        w = endPoint.x - startPoint.x;
        //h = endPoint.y - startPoint.y;
        //h = (w / 3) * 2;
        h = w;
        hdhcmscliptox.style.width = w + 'px';
        hdhcmscliptox.style.height = h + 'px';
    }
}
hdhcmscantox.onmouseup = function (e) {
    flag = false;
}
hdhcmsbtnclip.onclick = function () {
    var strx = startPoint.x, stry = startPoint.y;
    /////////////////////
    imgw = img.width, imgh = img.height;
    iw = img.width, ih = img.height;
    cw = hdhcmsoldcanvas.width, ch = hdhcmsoldcanvas.height;
    now = iw, noh = ih;
    tempi = 0;
    if (iw > ih) {
        if (iw > cw) {
            tempi = iw / cw;
            now = cw;
            noh = ih / tempi;
            strx = strx * tempi;
            stry = stry * tempi;
            w = w * tempi;
            h = h * tempi;
        }
    }
    else {
        if (ih > ch) {
            tempi = ih / ch;
            noh = ch;
            now = iw / tempi;
            strx = strx * tempi;
            stry = stry * tempi;
            w = w * tempi;
            h = h * tempi;
        }
    }
    imgCut(hdhcmsnowcontext, img, imgw, imgh, strx, stry, w, h);
    var base64Img = document.getElementById("hdhcmsnowcanvas").toDataURL();
    document.getElementById("hdhtp").value = base64Img;
}
function imgCut(context, image, imgElementW, imgElementH, sx, sy, w, h) {
    context.clearRect(0, 0, imgElementW, imgElementH);
    var ratioW = image.width / imgElementW;
    var ratioH = image.height / imgElementH;
    //context.drawImage(image, ratioW * sx, ratioH * sy, ratioW * w, ratioH * h, 0, 0, w, h);
    context.drawImage(image, ratioW * sx, ratioH * sy, ratioW * w, ratioH * h, 0, 0, 300, 300);
}

function windowToCanvas(element, x, y) {
    var box = element.getBoundingClientRect();
    var bx = x - box.left;
    var by = y - box.top;
    return {
        x: bx,
        y: by
    };
}
function Hdhhtml5Reader(afile, pic) {
    afile = document.getElementById(afile);
    var file = afile.files[0];
    var reader = new FileReader();
    reader.readAsDataURL(file);
    reader.onload = function (e) {
        var hdhimg = this.result;
        img.src = hdhimg;
        var iw = img.width, ih = img.height;
        img.onload = function (argument) {
            iw = this.width;
            ih = this.height;
            var cw = hdhcmsoldcanvas.width, ch = hdhcmsoldcanvas.height;
            var now = iw, noh = ih;
            var tempi = 0;
            if (iw > ih) {
                if (iw > cw) {
                    tempi = iw / cw;
                    now = cw;
                    noh = ih / tempi;
                }
            } else {
                if (ih > ch) {
                    tempi = ih / ch;
                    noh = ch;
                    now = iw / tempi;
                }
            }
            hdhcmsoldcontext.drawImage(img, 0, 0, now, noh);
        }
    }
}