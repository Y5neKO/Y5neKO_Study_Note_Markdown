using HdhCmsDll.HdhEntity;
using HdhCmsDll.HdhPublic;
using HdhCmsMan.Public;
using HdhCmsMode.HdhShare;

public static class ParseHtml
{
    /// <summary>
    /// 模板解析变量，可以参考二次开发
    /// </summary>
    /// <param name="DonforLr">模板内容</param>
    /// <param name="Dyj">一级栏目</param>
    /// <param name="Dej">二级栏目</param>
    /// <param name="Dsj">三级栏目</param>
    /// <param name="Did">文章或内容ID</param>
    /// <param name="Dym">页码</param>
    /// <param name="Dzj">章节</param>
    /// <param name="Dlr"></param>
    /// <param name="HdhGjc">搜索关键词</param>
    /// <param name="Space">会员名</param>
    /// <returns></returns>
    public static string Parsing(string DonforLr, HdhEnGlobalRequset Hegr,GetHdh Gh)
    {
        DonforLr = HdhParseHtml.Parsing(DonforLr, Hegr, Gh);
        //HdhToLabel HdhToLabel = new HdhToLabel();
        //HdhMemLabel HdhMemLabel = new HdhMemLabel();
        //HdhLabelSpecial HdhLabelSpecial = new HdhLabelSpecial();
        //DonforLr = HdhToLabel.HeDongHuaTemplateWj(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaModuel(DonforLr,Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaDoChangeAll(DonforLr, Hegr,Gh);
        //DonforLr = HdhToLabel.HeDongHuafixedif(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaAdvert(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaPosition(DonforLr, Hegr,Gh);
        //DonforLr = HdhToLabel.HeDongHuaSiteTitle(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaMainMenu(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaMenuList(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaAdvertBt(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaTextAds(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaSmallTitle(DonforLr, Hegr,Gh);
        //DonforLr = HdhToLabel.HeDongHuaBigTitle(DonforLr, Hegr,Gh);
        //DonforLr = HdhToLabel.HeDongHuaContentTitle(DonforLr, Hegr,Gh);
        //DonforLr = HdhToLabel.HeDongHuaOrderCount(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaCataLog(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaSingleMenu(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaPageNoOne(DonforLr, Hegr,Gh);
        //DonforLr = HdhToLabel.HeDongHuaContent(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaDisplay(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaProGoodsNorms(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaPhotoAlbum(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaBigVideo(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaMoreVideo(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaListVideo(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaKeyWord(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaProdetail(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaComment(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaLength(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaLeftStr(DonforLr, Hegr, Gh);
        //DonforLr = HdhMemLabel.HeDongHuaMemList(DonforLr, Hegr, Gh);
        //DonforLr = HdhMemLabel.HeDongHuaMemPage(DonforLr, Hegr, Gh);
        //DonforLr = HdhMemLabel.HeDongHuaSendEmail(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaTagList(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaParameter(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaParameterCount(DonforLr, Hegr, Gh);
        //DonforLr = HdhLabelSpecial.HdhCmsSpecialCategory(DonforLr, Hegr, Gh);
        //DonforLr = HdhLabelSpecial.HdhCmsSpecialcontent(DonforLr, Hegr, Gh);
        //DonforLr = HdhLabelSpecial.HdhCmsSpecialdisplay(DonforLr, Hegr, Gh);
        //DonforLr = HdhLabelSpecial.HdhCmsSpecialattribute(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HdhPubPublicPage(DonforLr, Hegr, Gh);

        //DonforLr = HdhToLabel.HeDongHuaAppShare(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaFor(DonforLr, Hegr, Gh);
        //DonforLr = HdhToLabel.HeDongHuaif(DonforLr, Hegr, Gh);
        return DonforLr;
    }
}
