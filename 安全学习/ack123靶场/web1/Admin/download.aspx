<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="download.aspx.cs" Inherits="Admin_download"  MasterPageFile="~/Admin/MasterPage.master" ValidateRequest="false" %>
<asp:Content ContentPlaceHolderID="ContentPlaceHolderR" ID="right" runat="server">
<%
    Response.Write(HdhListStr);
    HdhListStr = "";
%>
</asp:Content>
