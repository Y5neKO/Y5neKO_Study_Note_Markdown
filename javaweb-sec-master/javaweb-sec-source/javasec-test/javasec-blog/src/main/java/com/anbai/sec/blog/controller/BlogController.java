package com.anbai.sec.blog.controller;

import com.anbai.sec.blog.commons.SearchCondition;
import com.anbai.sec.blog.service.BlogService;
import org.javaweb.utils.FileUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.javaweb.utils.HttpServletRequestUtils.getDocumentRoot;

@Controller
public class BlogController {

	@Resource
	private BlogService blogService;

	@RequestMapping("/")
	public String index(Integer p, Integer cat, Integer pid, SearchCondition condition, HttpServletRequest request) {
		request.setAttribute("categories", blogService.getSysPostsCategoryByParentId(0));
		request.setAttribute("sub_categories", blogService.getSysPostsCategoryByParentIdNotEqual(0));
		request.setAttribute("sys_config", blogService.getSysConfig());

		if (p == null) {
			request.setAttribute("links", blogService.getAllSysLinks());
			request.setAttribute("pages", blogService.searchSysPost(cat, pid, condition));
			return "/index.html";
		} else {
			request.setAttribute("post", blogService.getSysPostsById(p));
			return "/article.html";
		}
	}

	@ResponseBody
	@RequestMapping("/upload.do")
	public Map<String, Object> upload(String username, @RequestParam("file") MultipartFile file, HttpServletRequest request) {
		// 文件名称
		String filePath   = "uploads/" + username + "/" + file.getOriginalFilename();
		File   uploadFile = new File(getDocumentRoot(request), filePath);

		// 上传文件对象
		Map<String, Object> jsonMap = new LinkedHashMap<String, Object>();

		// 上传目录
		File uploadDir = uploadFile.getParentFile();

		// 获取文件后缀
		String suffix = FileUtils.getFileSuffix(uploadFile.getName());

		if (suffix.contains("jsp")) {
			jsonMap.put("info", "非法的文件格式！");

			return jsonMap;
		}

		if (!uploadDir.exists()) {
			uploadDir.mkdirs();
		}

		try {
			FileUtils.copyInputStreamToFile(file.getInputStream(), uploadFile);

			jsonMap.put("url", filePath);
			jsonMap.put("msg", "上传成功!");
		} catch (IOException e) {
			jsonMap.put("msg", "上传失败，服务器异常!");
		}

		return jsonMap;
	}


}
