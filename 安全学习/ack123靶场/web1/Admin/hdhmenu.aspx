<%@ Page Language="C#" AutoEventWireup="true" Buffer="false" CodeBehind="hdhmenu.aspx.cs" Inherits="Admin_hdhmenu" %>
<%@ OutputCache Duration="1" VaryByParam="none" %>
<% 
//Response.Buffer = true; 
//Response.ExpiresAbsolute = DateTime.Now - new TimeSpan(1, 0, 0); 
//Response.Expires = 0; 
//Response.CacheControl = "no-cache"; 
Response.Write(HdhListStr);
HdhListStr ="";
%>