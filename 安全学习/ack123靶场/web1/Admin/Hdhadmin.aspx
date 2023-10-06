<%@ Page Language="C#" AutoEventWireup="true" ValidateRequest="false" Debug="true" MasterPageFile="~/admin/MasterPage.master" CodeBehind="Hdhadmin.aspx.cs" Inherits="Admin_Hdhadmin" %>
<asp:Content ContentPlaceHolderID="ContentPlaceHolderR" ID="right" runat="server">
<%
    Response.Write(HdhListStr);
    HdhListStr ="";
%>
</asp:Content>
