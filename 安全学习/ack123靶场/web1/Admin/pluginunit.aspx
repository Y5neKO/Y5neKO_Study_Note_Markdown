<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="pluginunit.aspx.cs" Inherits="HdhCms.Admin.pluginunit" MasterPageFile="~/Admin/MasterPage.master" ValidateRequest="false" %>
<asp:Content ContentPlaceHolderID="ContentPlaceHolderR" ID="right" runat="server">
<%
    Response.Write(HdhListStr);
    HdhListStr = "";
%>
</asp:Content>