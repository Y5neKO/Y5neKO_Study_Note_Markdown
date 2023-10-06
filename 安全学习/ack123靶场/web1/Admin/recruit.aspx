<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="recruit.aspx.cs" Inherits="Admin_recruit"  ValidateRequest="false" MasterPageFile="~/Admin/MasterPage.master" %>
<asp:Content ContentPlaceHolderID="ContentPlaceHolderR" ID="right" runat="server">
<%
    Response.Write(HdhListStr);
    HdhListStr = "";
%>
</asp:Content>
