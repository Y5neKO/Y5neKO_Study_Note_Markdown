<%@ Page Language="C#"  AutoEventWireup="true" ValidateRequest="false" MasterPageFile="~/admin/MasterPage.master" CodeBehind="ToHtml.aspx.cs" Inherits="Admin_ToHtml" %>
<asp:Content ContentPlaceHolderID="ContentPlaceHolderR" ID="right" runat="server">
<%
    Response.Write(HdhListStr);
%>
</asp:Content>
