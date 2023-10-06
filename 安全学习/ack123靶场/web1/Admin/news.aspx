<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="news.aspx.cs" Inherits="Admin_news" ValidateRequest="false" MasterPageFile="~/Admin/MasterPage.master" %>
<asp:Content ContentPlaceHolderID="ContentPlaceHolderR" ID="right" runat="server">
<%Response.Write(HdhListStr); HdhListStr = "";%>
</asp:Content>
