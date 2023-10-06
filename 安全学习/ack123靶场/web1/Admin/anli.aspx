<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="anli.aspx.cs" Inherits="HdhCms.Admin.anli" MasterPageFile="~/Admin/MasterPage.master" ValidateRequest="false"  %>
<asp:Content ContentPlaceHolderID="ContentPlaceHolderR" ID="right" runat="server">
<%
    Response.Write(HdhListStr);
    HdhListStr = "";
%>
</asp:Content>
