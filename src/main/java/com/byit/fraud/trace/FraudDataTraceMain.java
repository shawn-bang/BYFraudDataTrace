package com.byit.fraud.trace;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.CoreConnectionPNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 解决问题: 反欺诈系统规则结果数据丢失, 导致数据不一致
 * 单线程下追数据
 * 逻辑: 收集数据丢失的当天日志文件, 程序扫描指定路径解析日志文件, 拿到所有的请求报文
 *      按照AF1001, AF1002的优先级调用反欺诈系统服务接口;
 * @author shawn
 */
public class FraudDataTraceMain {
	private static final Logger logger = LoggerFactory.getLogger(FraudDataTraceMain.class);
	private static String logFilesPath = "";
	private static String serviceUrl = "";
	private static Map<String, String> AF1001 = null;
	private static Map<String, String> AF1002 = null;
	private static int totalCount = 0, successCount = 0, failCount = 0;

	/**
	 * 解析单个日志文件
	 * @param fileName
	 * @param content
	 */
	private static void traceSingleLogFile(String fileName, String content){
		// 使用正则表达式按日志记录时间顺序提取请求json报文
		List<String> inputJsons = regexMatcher(content, "(getInputJson\\:)(\\{(.*?)\\}\\})\n");
		logger.info("log file & request count:{}:{}", fileName, inputJsons.size());

		// According to fromflowpoint to slice
		for (String inputJson : inputJsons) {
			JSONObject whole = JSON.parseObject(inputJson);
			String appId = whole.getJSONArray("applicants").getJSONObject(0).getJSONObject("applicantinfo").getString("app_id");
			String point = whole.getJSONObject("requestdesc").getString("fromflowpoint");
			if (point.equals(AppReqNumEnum.AF1001.name())) {
				AF1001.put(appId, inputJson);
			}else if (point.equals(AppReqNumEnum.AF1002.name())){
				AF1002.put(appId, inputJson);
			}else {
				logger.info("Can't found fromflowpoint:{}", point);
			}
		}
	}

	/**
	 * 读取指定路径下的日志文件
	 */
	private static void readLogFiles(){
		// 循环读取所有日志文件
		File directory = new File(logFilesPath);
		if (!directory.exists()){
			logger.warn("The directory is not exists.");
		}
		File[] files = directory.listFiles();
		logger.info("The directory contains {} files", files.length);

		if (files.length == 0) return;

		for (File file : files) {
			try {
				if (file.isDirectory()) continue;
				String fileName = file.getName();
				logger.info("read log file start:{}", fileName);
				BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file)));
				StringBuilder content = new StringBuilder("");
				while (reader.ready()) {
					content.append(reader.readLine()).append("\n");
				}

				traceSingleLogFile(fileName, content.toString());
				logger.info("read log file end:{}", fileName);
			} catch (Exception e) {
				logger.error("read log file error", e);
			}
		}

		// send http message to target web server url: priority first AF1001, second AF1002
		doRequestService(AF1001);
		doRequestService(AF1002);
		logger.info("Total request count:{}", totalCount);
		logger.info("Success request count:{}", successCount);
		logger.info("Fail request count:{}", failCount);
	}

	/**
	 * request target service and count
	 * @param map
	 */
	private static void doRequestService(Map<String, String> map) {
		for (Map.Entry<String, String> entry : map.entrySet()) {
			totalCount++;
			String appId = entry.getKey();
			String json = entry.getValue();
			if (httpPostWithJson(json, appId)) {
				successCount++;
			}else {
				failCount++;
			}
		}
	}

	/**
	 * Entrance main
	 * @param args
	 * @throws IOException
	 */
	public static void main(String args[]) throws IOException {
		logger.info("Jar running start.");
		Properties properties = new Properties();
		properties.load(FraudDataTraceMain.class.getClassLoader().getResourceAsStream("config.properties"));
		logFilesPath = (String) properties.get("logFilesPath");
		serviceUrl = (String) properties.get("serviceUrl");
		logger.info("Config File loading:logFilesPath:{}", logFilesPath);
		readLogFiles();
		logger.info("Jar running end.");
	}

	/**
	 * 正则匹配方法
	 *
	 * @param input：待匹配的字符串
	 * @param regex：正则表达式
	 * @return
	 */
	private static List<String> regexMatcher(String input, String regex) {
		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(input);
		List<String> list = new ArrayList<>();
		while (matcher.find()) {
			// must be group 2
			list.add(matcher.group(2));
		}
		return list;
	}

	private static boolean httpPostWithJson(String json, String appId){
		boolean flag;
		HttpPost post = null;
		try {
			HttpClient httpClient = new DefaultHttpClient();

			// set timeout
			httpClient.getParams().setParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, 1000);
			httpClient.getParams().setParameter(CoreConnectionPNames.SO_TIMEOUT, 1000);

			post = new HttpPost(serviceUrl);
			// construct message headers
			post.setHeader("Content-type", "application/json; charset=utf-8");
			post.setHeader("Connection", "close");
			// construct message entity
			StringEntity entity = new StringEntity(json, Charset.forName("UTF-8"));
			entity.setContentEncoding("UTF-8");
			// set content type
			entity.setContentType("application/json");
			post.setEntity(entity);

			HttpResponse response = httpClient.execute(post);

			// check response result status:1-success, 0-fail
			int statusCode = response.getStatusLine().getStatusCode();
			if(statusCode != HttpStatus.SC_OK){
				logger.warn("response status exception:{}:{}", appId, statusCode);
				flag = false;
			}else {
				String responseJson = response.getEntity().toString();
				String status = JSON.parseObject(responseJson).getJSONObject("response").getString("status");
				if (!status.equals("1")) {
					logger.warn("response result status exception:{}:{}", appId, responseJson);
					flag = false;
				} else {
					flag = true;
				}
			}
		} catch (Exception e) {
			logger.error("request error:{}", appId);
			logger.error("request error", e);
			flag = false;
		}finally{
			if(post != null){
				try {
					post.releaseConnection();
					Thread.sleep(100);
				} catch (InterruptedException e) {
					logger.error("request error:{}", appId);
					logger.error("request error", e);
				}
			}
		}

		return flag;
	}

}
