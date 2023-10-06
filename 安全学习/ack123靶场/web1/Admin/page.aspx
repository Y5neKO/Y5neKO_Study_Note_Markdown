<%@ Page Language="C#" AutoEventWireup="true"  CodeBehind="page.aspx.cs" Inherits="Admin_page" ValidateRequest="false" MasterPageFile="~/Admin/MasterPage.master" %>
<asp:Content ContentPlaceHolderID="ContentPlaceHolderR" ID="right" runat="server">
<%
    Response.Write(HdhListStr);
    HdhListStr = "";
%>
</asp:Content>
