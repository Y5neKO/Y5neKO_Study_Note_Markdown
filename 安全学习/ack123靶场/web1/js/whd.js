var GoOn;
var MyMinute = 30;//间隔时间
function hdhStar(aDim) {
    var HdhAmId = $("#HdhAmId").val();
    var HdhCjdqjx = $("#HdhCjdqjx").val();
    var HdhLx = $("#HdhLx").val();
    if (HdhCjdqjx < 1) {
        alert("请选择抽奖奖项！");
    } else {
        $.ajax({
            type: 'get',
            url: '?',
            data: { "AmId": HdhAmId, "HdhCjdqjx": HdhCjdqjx, "HdhLx": HdhLx, "HdhCj": 1 },
            success: function (msg) {
                var x = msg.split('||hdhcj||');
                if (x[0] == "0") {
                    alert(x[1]);
                } else {
                    document.getElementById("HdhCjlr").innerHTML += x[1];
                    document.getElementById("HdhCjsm").innerHTML += x[2];
                    setTimeout(setImg(aDim), MyMinute)
                }
            }
        });
    }
}
//进入抽奖计时器，并进入图片轮替状态
function setImg(aDim) {
    document.getElementById("HdhCjkscj").style.display = "none";
    document.getElementById("HdhCjxydz").style.display = "block";
    var HdhListId = document.getElementById("HdhListId").value;
    var HdhListNo = document.getElementById("HdhListNo").value;
    var HdhListCount = document.getElementById("HdhListCount").value;
    var aDimLen = aDim.length;
    var aListId = Math.floor(Math.random() * aDimLen);
    document.getElementById('tpk' + HdhListId).innerHTML = "<img src='" + aDim[aListId][1] + "' width=290 height=290>";
    HdhListId++;
    if (HdhListId == 4) { HdhListId = 1; }
    document.getElementById("HdhListId").value = HdhListId;
    var x = HdhListNo * MyMinute;
    HdhListNo++;
    GoOn = setTimeout(function () { setImg(aDim); }, x);
}
//清除抽奖计时器，并展现所中奖项
function setOver() {
    var aWz = ['中', '了', '么'];
    for (var i = 1; i <= 3; i++) {
        document.getElementById("tpk" + i).innerHTML = aWz[i - 1];
    }
    clearTimeout(GoOn);
    document.getElementById("HdhCjkscj").style.display = "block";
    document.getElementById("HdhCjxydz").style.display = "none";
    HdhOpenDiv("HdhCjjg");
}
//设置所抽奖项
function setItem(id) {
    document.getElementById('h1title').innerHTML = document.getElementById('Jx' + id).innerHTML;
    document.getElementById('HdhCjdqjx').value = id;
}
//中奖处理JS，包括AJAX发送与处理
function getLottery() {

}