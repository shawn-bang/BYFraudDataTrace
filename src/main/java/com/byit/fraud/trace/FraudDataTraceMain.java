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
import java.util.*;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
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
	private static Executor executor = Executors.newFixedThreadPool(2 * Runtime.getRuntime().availableProcessors());

	/**
	 * 解析单个日志文件
	 * @param fileName
	 * @param content
	 */
	private static void traceSingleLogFile(String fileName, String content){
		// 使用正则表达式按日志记录时间顺序提取请求json报文
		List<String> inputJsons = regexMatcher(content, "(getInputJson\\:)(\\{(.*?)\\}\\})\n");
		logger.info("{}:request count:{}:{}", fileName, inputJsons.size());

		// init map:just once
		if (AF1001 == null) AF1001 = new HashMap<>();
		if (AF1002 == null) AF1002 = new HashMap<>();

		// According to fromflowpoint to slice
		int count1001 = 0, count1002 = 0;
		for (String inputJson : inputJsons) {
			JSONObject whole = JSON.parseObject(inputJson);
			String appId = whole.getJSONArray("applicants").getJSONObject(0).getJSONObject("applicantinfo").getString("app_id");
			String point = whole.getJSONObject("requestdesc").getString("fromflowpoint");
			if (point.equals(AppReqNumEnum.AF1001.name())) {
				AF1001.put(appId, inputJson);
				count1001++;
			}else if (point.equals(AppReqNumEnum.AF1002.name())){
				AF1002.put(appId, inputJson);
				count1002++;
			}else {
				logger.info("{}:Can't found fromflowpoint:{}", fileName, point);
			}
		}

		logger.info("{}:Count AF1001:{}", fileName, count1001);
		logger.info("{}:Count AF1002:{}", fileName, count1002);
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
				logger.info("Read log file end:{}", fileName);
			} catch (Exception e) {
				logger.error("Read log file error", e);
			}
		}

		// send http message to target web server url: priority first AF1001, second AF1002
		logger.info("AF1001 run start");
		long startTime1001 = System.currentTimeMillis();
		doRequestService(AF1001);
		long endTime1001 = System.currentTimeMillis();
		logger.info("AF1001 run end:{}", (endTime1001 - startTime1001) + "");
		logger.info("AF1002 run start");
		long startTime1002 = System.currentTimeMillis();
		doRequestService(AF1002);
		long endTime1002 = System.currentTimeMillis();
		logger.info("AF1002 run end:{}", (endTime1002 - startTime1002) + "");
		logger.info("Total request count:{}", totalCount);
		logger.info("Success request count:{}", successCount);
		logger.info("Fail request count:{}", failCount);
	}

	/**
	 * request target service and count
	 * @param map
	 */
	private static void doRequestService(Map<String, String> map) {
		int threadNum;
		if (map.size() % 5 == 0) {
			threadNum = map.size() / 5;
		}else {
			threadNum = map.size() / 5 + 1;
		}
		ThreadListener listener = new ThreadListener(threadNum);//线程监视器

		List<Map<String, String>> l = splitMap(map);
		for (int i = 0; i < threadNum; i++) {
			executor.execute(new DoPostServiceThread(l.get(i), listener));
		}

		//等待所有线程执行完毕，返回对象
		logger.info("等待所有线程都结束================================");
		if (listener.isAllThreadsFinished()) {

		} else {
			throw new RuntimeException("有线程没有正常结束");
		}
	}

	private static List<Map<String, String>> splitMap(Map<String, String> map) {
		if (null == map || map.size() == 0) return null;
		int count = 0;
		List<Map<String, String>> l = new ArrayList<>();
		Map<String, String> divMap = null;
		for (Map.Entry<String, String> entry : map.entrySet()) {
			count++;
			if (divMap == null) divMap = new HashMap<>();
			divMap.put(entry.getKey(), entry.getValue());
			if (count % 5 == 0 && count != map.size()) {
				l.add(divMap);
				divMap = new HashMap<>();
			}
			if (count == map.size()) {
				l.add(divMap);
			}
		}

		return l;
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

	static class DoPostServiceThread implements Runnable {

		private Map<String, String> map;
		private ThreadListener listener;

		public DoPostServiceThread(Map<String, String> map, ThreadListener listener) {
			this.map = map;
			this.listener = listener;
		}

		@Override
		public void run() {
			logger.info("开启一个新的线程：" + Thread.currentThread().getName());
			long start_time = System.currentTimeMillis();

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

			logger.debug("====线程结束：" + Thread.currentThread().getName());
			long end_time = System.currentTimeMillis();
			logger.debug("耗时：" + (end_time - start_time) / 1000 + " 秒");
			//监听线程之用
			try {
				listener.getQueue().put(Thread.currentThread().getName());
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}

		private boolean httpPostWithJson(String json, String appId){
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
					logger.warn("Response status exception:{}:{}", appId, statusCode);
					flag = false;
				}else {
					String responseJson = response.getEntity().toString();
					String status = JSON.parseObject(responseJson).getJSONObject("response").getString("status");
					if (!status.equals("1")) {
						logger.warn("Response result status exception:{}:{}", appId, responseJson);
						flag = false;
					} else {
						flag = true;
					}
				}
			} catch (Exception e) {
				logger.error("Request error:{}", appId);
				logger.error("Request error", e);
				flag = false;
			}finally{
				if(post != null){
					try {
						post.releaseConnection();
						Thread.sleep(100);
					} catch (InterruptedException e) {
						logger.error("Request error:{}", appId);
						logger.error("Request error", e);
					}
				}
			}

			return flag;
		}
	}

	static class ThreadListener {
		private LinkedBlockingQueue<String> queue = new LinkedBlockingQueue<>();//利用阻塞队列实现所有线程结束的监听
		private int threadNum;//线程数目

		ThreadListener(int threadNum) {
			this.threadNum = threadNum;
		}

		LinkedBlockingQueue<String> getQueue() {
			return queue;
		}

		/**
		 * 判断是否所有线程都程结束
		 *
		 * @return
		 */
		boolean isAllThreadsFinished() {
			for (int i = 0; i < threadNum; i++) {
				try {
					String threadName = queue.take();
					logger.info(threadName + " 线程结束");
				} catch (InterruptedException e) {
					e.printStackTrace();
					return false;
				}
			}
			return true;
		}

	}

}
