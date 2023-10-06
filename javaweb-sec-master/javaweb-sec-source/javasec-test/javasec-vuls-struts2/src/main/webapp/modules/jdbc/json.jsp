<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.sql.Connection" %>
<%@ page import="java.sql.DriverManager" %>
<%@ page import="java.sql.ResultSet" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="java.util.Map" %>
<%@ page import="com.alibaba.fastjson.JSON" %>
<%@ page import="org.apache.commons.io.IOUtils" %>
<%@ page import="com.alibaba.fastjson.JSONObject" %>

<%
    //    MYSQL sys_user示例表，测试时请先创建对应的数据库和表
//
//    CREATE TABLE `sys_user` (
//        `id` int(9) unsigned NOT NULL AUTO_INCREMENT COMMENT '用户ID',
//        `username` varchar(16) NOT NULL COMMENT '用户名',
//        `password` varchar(32) NOT NULL COMMENT '用户密码',
//        `user_avatar` varchar(255) DEFAULT NULL COMMENT '用户头像',
//        `register_time` datetime DEFAULT NULL COMMENT '注册时间',
//        PRIMARY KEY (`id`),
//        UNIQUE KEY `idx_sys_user_username` (`username`) USING BTREE
//    ) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8 COMMENT='系统用户表'
//
//    INSERT INTO `sys_user` VALUES ('1', 'admin', '123456', '/res/images/avatar/default.png', '2020-05-05 17:21:27'), ('2', 'test', '123456', '/res/images/avatar/default.png', '2020-05-06 18:27:10'), ('3', 'root', '123456', '/res/images/avatar/default.png', '2020-05-06 18:28:27'), ('4', 'user', '123456', '/res/images/avatar/default.png', '2020-05-06 18:31:34'), ('5', 'rasp', '123456', '/res/images/avatar/default.png', '2020-05-06 18:32:08');
%>

<%
    String contentType = request.getContentType();

    // 只接受JSON请求
    if (contentType != null && contentType.toLowerCase().contains("application/json")) {
        String     content  = IOUtils.toString(request.getInputStream());
        JSONObject json     = JSON.parseObject(content);
        String     username = json.getString("username");
        String     password = json.getString("password");

        // 处理用户登陆逻辑
        if (username != null && password != null) {
            ResultSet           rs         = null;
            Connection          connection = null;
            Map<String, Object> userInfo   = new HashMap<String, Object>();

            try {
                Class.forName("com.mysql.jdbc.Driver");
                connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/javaweb-bbs", "root", "root");

                String sql = "select * from sys_user where username = '" + username + "' and password = '" + password + "'";
                System.out.println(sql);

                rs = connection.prepareStatement(sql).executeQuery();

                while (rs.next()) {
                    userInfo.put("id", rs.getString("id"));
                    userInfo.put("username", rs.getString("username"));
                    userInfo.put("password", rs.getString("password"));
                    userInfo.put("user_avatar", rs.getString("user_avatar"));
                    userInfo.put("register_time", rs.getDate("register_time"));
                }

                // 检查是否登陆成功
                if (userInfo.size() > 0) {
                    // 设置用户登陆信息
                    out.println(JSON.toJSONString(userInfo));
                } else {
                    out.println("<script>alert('登陆失败，账号或密码错误!');history.back(-1)</script>");
                }
            } catch (Exception e) {
            	e.printStackTrace();
                out.println("<script>alert('登陆失败，服务器异常!');history.back(-1)</script>");
            } finally {
                // 关闭数据库连接
                if (rs != null)
                    rs.close();

                if (connection != null)
                    connection.close();
            }
        }
    }
%>