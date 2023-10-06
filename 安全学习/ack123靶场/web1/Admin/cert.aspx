<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="cert.aspx.cs" Inherits="Admin_cert" MasterPageFile="~/Admin/MasterPage.master" ValidateRequest="false" %>
<asp:Content ContentPlaceHolderID="ContentPlaceHolderR" ID="right" runat="server">
<%
    Response.Write(HdhListStr);
    HdhListStr = "";
%>
</asp:Content>