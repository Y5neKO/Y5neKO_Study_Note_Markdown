<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="hdhzbb.aspx.cs" Inherits="HdhCms.Admin.hdhzbb" MasterPageFile="~/Admin/MasterPage.master" %>
<asp:Content ContentPlaceHolderID="ContentPlaceHolderR" ID="right" runat="server">
<%
    Response.Write(HdhListStr);
    HdhListStr = "";
%>
</asp:Content>