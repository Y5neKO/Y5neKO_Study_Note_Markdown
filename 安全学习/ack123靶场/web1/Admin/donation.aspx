<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="donation.aspx.cs" Inherits="Admin_product" ValidateRequest="false" MasterPageFile="~/Admin/MasterPage.master" %>
<asp:Content ContentPlaceHolderID="ContentPlaceHolderR" ID="right" runat="server">
<%
    Response.Write(HdhListStr);
    HdhListStr = "";
%>
</asp:Content>
