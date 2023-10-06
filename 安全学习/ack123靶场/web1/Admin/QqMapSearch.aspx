<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="QqMapSearch.aspx.cs" Inherits="HdhCms_QqMapSearch" MasterPageFile="" ValidateRequest="false"%>
<!DOCTYPE html>
<%
    %>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>腾讯地图开放API - 轻快小巧,简单易用!</title>
    <script charset="utf-8" src="../js/jquery-1.9.1.min.js"></script>
    <script charset="utf-8" src="../js/jsQqMap.js"></script>
       <style type="text/css">
           html, body {
               width:100%;height:100%;
           }
            html, body, a, p, b ,div{
               font-size:12px;
           }
           p {
               height:auto;margin:2px 0px;padding:1px;
           }
       #main {
            height: 90%;
            width: 100%;
            margin: 0px auto;
            border: 0px solid #5688CB;
            border-top: 0px;
            overflow: hidden;
        }

        #tooles {
            height: 23px;
            width:200px;
            background: #5688CB;
            position: relative;
            z-index: 100;
            color: white;
        }

        #cur_city, #no_value {
            height: 20px;
            position: absolute;
            top: 3px;
            left: 10px;
        }

        #level {
            margin-left: 20px;
        }


        .poi {
            width: 800px;
            height: 41px;
            padding-top: 12px;
            float: left;
            position: relative;
        }


        .poi_note {
            width: auto;
            line-height: 32px;
            float: left;
            text-align: right;
            font-size: 12px;
        }


        #poi_cur {
            width: 120px;
            height: 22px;
            margin-right: 10px;
            margin-top: 3px;
            line-height: 26px;
            float: left;
            text-align: center;
        }


        #addr_cur {
            width: 140px;
            height: 22px;
            margin-right: 5px;
            margin-top: 3px;
            line-height: 26px;
            float: left;
            text-align: center;
        }



        .logo_img {
            width: 172px;
            height: 23px;
        }



        #city .close {
            width: 20px;
            height: 20px;
            display: inline-block;
            float: right;
            font-size: 20px;
            font-weight: normal;
            cursor: pointer;
        }


        #city .city_name {
            line-height: 20px;
            margin-left: 5px;
            color: #2F82C4;
            cursor: pointer;
            display: inline-block;
            font-size: 12px;
        }


        #curCity {
            margin-right: 5px;
        }


        .hide {
            display: none;
        }

        #bside_left {
    max-width: 240px;
    height: 320px;
    padding: 5px 0px 5px 5px;
    float: left;
    overflow: auto;
        }

        #txt_pannel {
            height: 320px;
            font-size: 12px;
        }

        .search_t {
            width: 120px;
            height: 18px;
            padding: 3px;
            margin-top: 3px;
            line-height: 20px;
        }

        #bside_rgiht {
width: auto;
    height: 100%;
    margin-left: 0px;
    border-BOTTOM: 0px solid #5688CB;
    font-size: 12px;
    overflow: hidden;
    margin-top: 20px;
        }


        #container {
            width: 100%;
            height: 320px;
            border: 0px solid #fff;
        }

        .info_list {
            margin-bottom: 5px;
            clear: both;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div style="width: auto; height: auto; position: relative; margin: 0px auto;">
        <div style="height: 53px;">

            <div class="poi">
                <input type="text" class="search_t ui-autocomplete-input" onkeypress="if(event.keyCode==13) {btnSearch.click();return false;}" autocomplete="off">
                <input type="button" value="搜索" id="btn_search" style="width: auto; padding-left: 2px; padding-right: 2px; height: 25px; margin-top: 3px;" />
                <input type="button" value="自选坐标" style="width: auto; padding-left: 2px; padding-right: 2px; height: 25px; margin-top: 3px;" onclick="location.reload();" />
                <div class="poi_note">
                    当前坐标：
                </div>
                <input type="text" id="poi_cur" name="poi_cur" />
                <div class="poi_note">
                    当前地址：
                </div>
                <input type="text" id="addr_cur">

            </div>

        </div>
        <div id="main">
            <div id="tooles">
                <div id="cur_city"><span id="level">当前缩放等级：10</span></div>
            </div>

            <div id="bside_left">
                <%--                
                    <div id="txt_pannel">
                    <h3>功能简介：</h3>

                    <p>1、支持地址 精确/模糊 查询；</p>

                    <p>2、支持POI点坐标显示；</p>

                    <p>3、坐标鼠标跟随显示；</p>

                    <h3>使用说明：</h3>

                    <p>在搜索框搜索关键词后，地图上会显示相应poi点，同时左侧显示对应该点的信息，点击某点或某信息，右上角会显示相应该点的坐标和地址。</p>
                </div>
                --%>
            </div>

            <div id="bside_rgiht">
                <div id="container" style="position: relative; overflow: hidden; transform: translateZ(0px); background-color: rgb(229, 227, 223);">
                </div>
            </div>
        </div>
    </div>

    <script type="text/javascript">
        var container = document.getElementById("container");
        var map = new qq.maps.Map(container, {
            //center: new qq.maps.LatLng(23.02067, 113.75179),
            center: new qq.maps.LatLng(<%=x%>, <%=y%>),
            zoom: 14
        }),
            label = new qq.maps.Label({
                map: map,
                offset: new qq.maps.Size(15, -12),
                draggable: false,
                clickable: false
            }),
            markerArray = [],
            curCity = document.getElementById("cur_city"),
            btnSearch = document.getElementById("btn_search"),
            bside = document.getElementById("bside_left"),
            url, query_city,
            cityservice = new qq.maps.CityService({
                complete: function (result) {
                    curCity.children[0].innerHTML = result.detail.name;
                    map.setCenter(result.detail.latLng);
                }
            });
        map.setOptions({
            draggableCursor: "crosshair"
        });
        $(container).mouseenter(function () {
            label.setMap(map);
        });
        $(container).mouseleave(function () {
            label.setMap(null);
        });
        qq.maps.event.addListener(map, "mousemove", function (e) {
            var latlng = e.latLng;
            label.setPosition(latlng);
            label.setContent(latlng.getLat().toFixed(6) + "," + latlng.getLng().toFixed(6));
        });
        var url3;
        qq.maps.event.addListener(map, "click", function (e) {
            document.getElementById("poi_cur").value = e.latLng.getLat().toFixed(6) + "," + e.latLng.getLng().toFixed(6);
            url3 = encodeURI("http://apis.map.qq.com/ws/geocoder/v1/?location=" + e.latLng.getLat() + "," + e.latLng.getLng() + "&key=<%=QqMapApi%>&output=jsonp&&callback=?");
            $.getJSON(url3, function (result) {
                if (result.result != undefined) {
                    document.getElementById("addr_cur").value = result.result.address;
                } else {
                    document.getElementById("addr_cur").value = "";
                }

            })
        });

        qq.maps.event.addListener(map, "zoom_changed", function () {
            document.getElementById("level").innerHTML = "当前缩放等级：" + map.getZoom();
        });

        ///============== 2018-05-25 地图搜索Begin ===========================================

        var listener_arr = [];
        var isNoValue = false;
        qq.maps.event.addDomListener(btnSearch, 'click', function () {
            var value = this.parentNode.getElementsByTagName("input")[0].value;
            var latlngBounds = new qq.maps.LatLngBounds();
            for (var i = 0, l = listener_arr.length; i < l; i++) {
                qq.maps.event.removeListener(listener_arr[i]);
            }

            listener_arr.length = 0;
            query_city = '<%=cityName%>';
            url = encodeURI("http://apis.map.qq.com/ws/place/v1/search?keyword=" + value + "&boundary=region(" + query_city + ",0)&page_size=9&page_index=1&key=<%=QqMapApi%>&output=jsonp&&callback=?");
            $.getJSON(url, function (result) {

                if (result.count) {
                    isNoValue = false;
                    bside.innerHTML = "";
                    each(markerArray, function (n, ele) {
                        ele.setMap(null);
                    });
                    markerArray.length = 0;
                    each(result.data, function (n, ele) {
                        var latlng = new qq.maps.LatLng(ele.location.lat, ele.location.lng);
                        latlngBounds.extend(latlng);
                        var left = n * 27;
                        var marker = new qq.maps.Marker({
                            map: map,
                            position: latlng,
                            zIndex: 10
                        });
                        marker.index = n;
                        marker.isClicked = false;
                        setAnchor(marker, true);
                        markerArray.push(marker);
                        var listener1 = qq.maps.event.addDomListener(marker, "mouseover", function () {
                            var n = this.index;
                            setCurrent(markerArray, n, false);
                            setCurrent(markerArray, n, true);
                            label.setContent(this.position.getLat().toFixed(6) + "," + this.position.getLng().toFixed(6));
                            label.setPosition(this.position);
                            label.setOptions({
                                offset: new qq.maps.Size(15, -20)
                            })

                        });
                        listener_arr.push(listener1);
                        var listener2 = qq.maps.event.addDomListener(marker, "mouseout", function () {
                            var n = this.index;
                            setCurrent(markerArray, n, false);
                            setCurrent(markerArray, n, true);
                            label.setOptions({
                                offset: new qq.maps.Size(15, -12)
                            })
                        });
                        listener_arr.push(listener2);
                        var listener3 = qq.maps.event.addDomListener(marker, "click", function () {
                            var n = this.index;
                            setFlagClicked(markerArray, n);
                            setCurrent(markerArray, n, false);
                            setCurrent(markerArray, n, true);
                            document.getElementById("addr_cur").value = bside.childNodes[n].childNodes[1].childNodes[1].innerHTML.substring(3);
                        });
                        listener_arr.push(listener3);
                        map.fitBounds(latlngBounds);
                        var div = document.createElement("div");
                        div.className = "info_list";
                        var order = document.createElement("div");
                        var leftn = -54 - 17 * n;
                        order.style.cssText = "width:0px;height:17px;margin:3px 3px 0px 0px;float:left;";
                        div.appendChild(order);
                        var pannel = document.createElement("div");
                        pannel.style.cssText = "width:160px;float:left;";
                        div.appendChild(pannel);
                        var name = document.createElement("p");
                        name.style.cssText = "margin:0px;color:#0000CC";
                        name.innerHTML = ele.title;
                        pannel.appendChild(name);
                        var address = document.createElement("p");
                        address.style.cssText = "margin:0px;";
                        address.innerHTML = "地址：" + ele.address;
                        pannel.appendChild(address);
                        if (ele.tel != undefined) {
                            var phone = document.createElement("p");
                            phone.style.cssText = "margin:0px;";
                            phone.innerHTML = "电话：" + ele.tel;
                            pannel.appendChild(phone);
                        }
                        var position = document.createElement("p");
                        position.style.cssText = "margin:0px;";
                        position.innerHTML = "坐标：" + ele.location.lat.toFixed(6) + "，" + ele.location.lng.toFixed(6);
                        pannel.appendChild(position);
                        bside.appendChild(div);
                        console.log("pannel.offsetHeight", pannel.offsetHeight)
                        div.style.height = pannel.offsetHeight + "px";
                        div.isClicked = false;
                        div.index = n;
                        marker.div = div;
                        div.marker = marker;
                    });
                    $("#bside_left").delegate(".info_list", "mouseover", function (e) {

                        var n = this.index;

                        setCurrent(markerArray, n, false);
                        setCurrent(markerArray, n, true);
                    });
                    $("#bside_left").delegate(".info_list", "mouseout", function () {
                        each(markerArray, function (n, ele) {
                            if (!ele.isClicked) {
                                setAnchor(ele, true);
                                ele.div.style.background = "#fff";
                            }
                        })
                    });
                    $("#bside_left").delegate(".info_list", "click", function (e) {
                        var n = this.index;
                        setFlagClicked(markerArray, n);
                        setCurrent(markerArray, n, false);
                        setCurrent(markerArray, n, true);
                        map.setCenter(markerArray[n].position);
                        document.getElementById("addr_cur").value = this.childNodes[1].childNodes[1].innerHTML.substring(3);

                        Position(markerArray[n].position);  //点击查找出来的具体结果


                    });
                } else {

                    bside.innerHTML = "";
                    each(markerArray, function (n, ele) {
                        ele.setMap(null);
                    });
                    markerArray.length = 0;
                    var novalue = document.createElement('div');
                    novalue.id = "bside_left";
                    novalue.innerHTML = "对不起，没有搜索到您要找的结果!";
                    bside.appendChild(novalue);
                    isNoValue = true;
                }
            });
        });



        btnSearch.onmousedown = function () {
            this.className = "btn_active";
        };
        btnSearch.onmouseup = function () {
            this.className = "btn";
        };
        function setAnchor(marker, flag) {
            var left = marker.index * 27;
            if (flag == true) {
                var anchor = new qq.maps.Point(10, 30),
                        origin = new qq.maps.Point(left, 0),
                        size = new qq.maps.Size(27, 33),
                        icon = new qq.maps.MarkerImage("images/Yzok.jpg", size, origin, anchor);
                marker.setIcon(icon);
            } else {
                var anchor = new qq.maps.Point(10, 30),
                        origin = new qq.maps.Point(left, 35),
                        size = new qq.maps.Size(27, 33),
                        icon = new qq.maps.MarkerImage("images/Yzok.jpg", size, origin, anchor);
                marker.setIcon(icon);
            }
        }
        function setCurrent(arr, index, isMarker) {
            if (isMarker) {
                each(markerArray, function (n, ele) {
                    if (n == index) {
                        setAnchor(ele, false);
                        ele.setZIndex(10);
                    } else {
                        if (!ele.isClicked) {
                            setAnchor(ele, true);
                            ele.setZIndex(9);
                        }
                    }
                });
            } else {
                each(markerArray, function (n, ele) {
                    if (n == index) {
                        ele.div.style.background = "#DBE4F2";
                    } else {
                        if (!ele.div.isClicked) {
                            ele.div.style.background = "#fff";
                        }
                    }
                });
            }
        }
        function setFlagClicked(arr, index) {
            each(markerArray, function (n, ele) {
                if (n == index) {
                    ele.isClicked = true;
                    ele.div.isClicked = true;
                    var str = '<div style="width:250px;">' + ele.div.children[1].innerHTML.toString() + '</div>';
                    var latLng = ele.getPosition();
                    document.getElementById("poi_cur").value = latLng.getLat().toFixed(6) + "," + latLng.getLng().toFixed(6);
                } else {
                    ele.isClicked = false;
                    ele.div.isClicked = false;
                }
            });
        }
        var city = document.getElementById("city");

        curCity.onclick = function (e) {
            var e = e || window.event,
                    target = e.target || e.srcElement;
            if (target.innerHTML == "更换城市") {
                city.style.display = "block";
                if (isNoValue) {
                    bside.innerHTML = "";
                    each(markerArray, function (n, ele) {
                        ele.setMap(null);
                    });
                    markerArray.length = 0;
                }

            }
        };

<%--        var url2;
        city.onclick = function (e) {
            var e = e || window.event,
                    target = e.target || e.srcElement;
            if (target.className == "close") {
                city.style.display = "none";
            }
            if (target.className == "city_name") {

                curCity.children[0].innerHTML = target.innerHTML;

                url2 = encodeURI("http://apis.map.qq.com/ws/geocoder/v1/?region=" + curCity.children[0].innerHTML + "&address=" + curCity.children[0].innerHTML + "&key=<%=QqMapApi%>&output=jsonp&&callback=?");
                $.getJSON(url2, function (result) {
                    map.setCenter(new qq.maps.LatLng(result.result.location.lat, result.result.location.lng));
                    map.setZoom(10);
                });
                city.style.display = "none";
            }
        };
        var url4;
        $(".search_t").autocomplete({
            source: function (request, response) {
                url4 = encodeURI("http://apis.map.qq.com/ws/place/v1/suggestion/?keyword=" + request.term + "&region=" + curCity.children[0].innerHTML + "&key=<%=QqMapApi%>&output=jsonp&&callback=?");
                $.getJSON(url4, function (result) {

                    response($.map(result.data, function (item) {
                        return ({
                            label: item.title

                        })
                    }));
                });
            }
        });--%>


        function Position(zuobiao) {
            var x = zuobiao.toString().split(",")[0];
            var y = zuobiao.toString().split(",")[1];
            var center = new qq.maps.LatLng(x, y);
            var map = new qq.maps.Map(document.getElementById('container'), {
                center: center,
                zoom: 13
            });
            var marker = new qq.maps.Marker({
                position: center,
                map: map
            });

        }

        ///==================2018-05-25 地图搜索End ===================================
        function each(obj, fn) {
            for (var n = 0, l = obj.length; n < l; n++) {
                fn.call(obj[n], n, obj[n]);
            }
        }
    </script>
    <ul class="ui-autocomplete ui-front ui-menu ui-widget ui-widget-content ui-corner-all" id="ui-id-1" tabindex="0" style="display: none;"></ul>

</body>
</html>
