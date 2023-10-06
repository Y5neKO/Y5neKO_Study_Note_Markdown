<%@ Page Language="C#" AutoEventWireup="true"  CodeBehind="module.aspx.cs" Inherits="Admin_module" ValidateRequest="false" MasterPageFile="~/Admin/MasterPage.master" %>
<asp:Content ContentPlaceHolderID="ContentPlaceHolderR" ID="right" runat="server">
<%
    Response.Write(HdhListStr);
    HdhListStr = "";
%>
</asp:Content>
