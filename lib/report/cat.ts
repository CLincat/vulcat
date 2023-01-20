// ! 0. 漏洞标题和内容
interface Vul {
	id: number;
	target: string;
	fullUrl: string;
	ftype: string;	// * Framework + Type
	vulnid: string;
	time: string;
	requests: string[];
}

var vulnTitle = [
	{
		"id": "ID",
		"target": "Target",
		"ftype": "Framework/Type",
		"vulnid": "VulnID",
		"time": "Time"
	}
]

var vulnContent: Vul[] = [
	{
		"id": 1,
		"target": "http://cn.bing.com/",
		"fullUrl": "http://cn.bing.com/asdsadsadsa",
		"ftype": "ThinkPHP/RCE",
		"vulnid": "CVE-2022-0202",
		"time": "2023-1-5 11:18:02",
		"requests": [`GET /bluecms/uploads/user.php?user_name=qweasd%df*&timestamp=1664163010594&act=check_user_name HTTP/1.1
Host: cntj8003.ia.aqlab.cn
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Cookie: detail=1; PHPSESSID=27p9v03t6ifkp7c8pvhde74p02; BLUE[user_id]=20; BLUE[user_name]=qweasd; BLUE[user_pwd]=e9dbeb4e29f78852363f933689af2670
Upgrade-Insecure-Requests: 1

a=123`,
`GET /index.php?&act=check_user_name HTTP/1.1
Host: abc.ia.aqlab.cn
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Cookie: detail=1; PHPSESSID=27p9v03t6ifkp7c8pvhde74p02; BLUE[user_id]=20; BLUE[user_name]=qweasd; BLUE[user_pwd]=e9dbeb4e29f78852363f933689af2670
Upgrade-Insecure-Requests: 1

a=456`]
	},
	{
		"id": 2,
		"target": "http://www.baidu.com/",
		"fullUrl": "http://www.baidu.com/qwewqewqewqe",
		"ftype": "Apache/RCE",
		"vulnid": "CNVD-2000-3000",
		"time": "2023-1-4 21:52:42",
		"requests": ["1"],
	},
	{
		"id": 3,
		"target": "http://www.baidu.com/",
		"fullUrl": "http://www.baidu.com/zxcxzc/asd//wqe",
		"ftype": "Apache/SSRF",
		"vulnid": "CNVD-2000-4000",
		"time": "2023-1-4 21:53:46",
		"requests": ["1"],
	},
	{
		"id": 4,
		"target": "http://www.abc.com/",
		"fullUrl": "http://www.abc.com/?asd=1",
		"ftype": "Spring/SSRF",
		"vulnid": "CNVD-2000-2323",
		"time": "2023-1-4 21:58:42",
		"requests": [`GET /bluecms/uploads/user.php?user_name=qweasd%df*&amp;timestamp=1664163010594&act=check_user_name HTTP/1.1
Host: cntj8003.ia.aqlab.cn
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Cookie: detail=1; PHPSESSID=27p9v03t6ifkp7c8pvhde74p02; BLUE[user_id]=20; BLUE[user_name]=qweasd; BLUE[user_pwd]=e9dbeb4e29f78852363f933689af2670
Upgrade-Insecure-Requests: 1

a=123&lt;/code&gt;&lt;/td>&lt;/tr>&lt;/tbody>&lt;/table>&lt;/li>&lt;script>alert(1)&lt;/script>//`],
	},
	{
		"id": 5,
		"target": "http://www.example.com/",
		"fullUrl": "http://www.example.com/zxcxzsad/asd/index.qwe?id=123",
		"ftype": "Grafana/FileRead",
		"vulnid": "CNVD-2021-1000",
		"time": "2023-1-3 13:58:42",
		"requests": ["1"],
	}
]

// ! 0.1 预定义通用函数

// todo 批量添加一个点击事件
function add_click_each(eLements, tEvent) {
	/*
	 * params: eLements: 元素数组
	 * params: tEvent: 要添加的事件函数
	*/

	eLements.forEach(function (item, index) {
		item.addEventListener("click", tEvent)
	})
}

// ? ------------------------------------------------------------
// ? ------------------------------------------------------------
// ? ------------------------------------------------------------
// ? ------------------------------------------------------------
// ? ------------------------------------------------------------

// ! 1. 记录初始样式 / 定义页面样式
var initHtmlStyle = document.querySelector("style").innerHTML

var HtmlStyle = {
	"default": {},
	"cerculean": {
		"backgroundColor": "#ffffff",
		"a": "#4bb1ea",
		"ul_li_hover": "#a9b3be",
		"ul_li_hover_fontColor": "white",
		"header": "#84b251",
		"a_hover": "#225384",
		"border": "#a1b5ca",
		"fontColor": "#2fa4e7",
		"style_ul": "#cf3c40",
		"style_ul_li": "#e16e25",
		"nav": "#a3d7f4",
		"main_ul": "#ffffff"
	},
	"morph": {
		"backgroundColor": "#d9e3f1",
		"a": "#378dfc",
		"ul_li_hover": "#aaaaaa",
		"ul_li_hover_fontColor": "white",
		"header": "#43cc29",
		"a_hover": "#5a61f4",
		"border": "#8189f1",
		"fontColor": "#7e8db9",
		"style_ul": "#e52527",
		"style_ul_li": "#ffc107",
		"nav": "#003f92",
		"main_ul": "#f0f5fa"
	},
	"darkly": {
		"backgroundColor": "#222222",
		"a": "#375a7f",
		"ul_li_hover": "#444444",
		"ul_li_hover_fontColor": "#ffffff",
		"header": "#00bc8c",
		"a_hover": "#3498db",
		"border": "#2d72a1",
		"fontColor": "#ffffff",
		"style_ul": "#e74c3c",
		"style_ul_li": "#f39c12",
		"nav": "#375a7f",
		"main_ul": "#2f2f2f"
	},
	"superhero": {
		"backgroundColor": "#2b3e50",
		"a": "#4c9be8",
		"ul_li_hover": "#4e5d6c",
		"ul_li_hover_fontColor": "#ffffff",
		"header": "#5cb85c",
		"a_hover": "#5bc0de",
		"border": "#4b97b2",
		"fontColor": "#ffffff",
		"style_ul": "#d9534f",
		"style_ul_li": "#f0ad4e",
		"nav": "#4c9be8",
		"main_ul": "#32465a"
	}
}

// !! 1.1 建立选择Style的标签
var classTop = document.querySelector(".top")
var classTopHtml = "<ul>Style"
for (const [key, val] of Object.entries(HtmlStyle)) {
	classTopHtml += "<li>" + key + "</li>"
}
classTopHtml += "</ul>"
classTop.innerHTML = classTopHtml

// !! 1.2 给标签绑定 切换样式的事件
function select_style(event) {
	var styleName = event.target.textContent			// * 获取样式名称
	var labelStyle = document.querySelector("style")	// * 获取style标签
	var style = HtmlStyle[styleName]					// * 根据样式名称 获取定义好的样式
	labelStyle.innerHTML = initHtmlStyle				// * 初始化样式

	if (styleName == "default") {
		return						// * 如果样式名称是default, 则退出, 不需要使用新样式
	}
	
	// todo 页面背景色
	labelStyle.innerHTML += `html {
		background-color: ` + style["backgroundColor"] + ";}\n"
	
	// todo 超链接 和 Copy的文字颜色
	labelStyle.innerHTML += `a,
	.right .main .requests table tbody tr td span {
		color: ` + style["a"] + ";}\n"
	
	// todo 当鼠标移动到ul和li时 的背景色
	labelStyle.innerHTML += `.left ul:hover,
	.left ul li:hover,
	.right .main ul:hover,
	.right nav ul li:hover {
		background-color: ` + style["ul_li_hover"] + ";}\n"
	
	labelStyle.innerHTML += `.left ul:hover strong,
	.left ul li:hover,
	.right .main ul:hover li:not(:last-child),
	.right nav ul li:hover {
		color: ` + style["ul_li_hover_fontColor"] + ";}\n"

	// todo 顶部背颜色
	labelStyle.innerHTML += `header {
		background-color: ` + style["header"] + ";}\n"
	
	// todo 当鼠标移动到 超链接 和 Copy 时的文字颜色
	labelStyle.innerHTML += `a:hover,
	.right .main .requests table tbody tr td span:hover {
		color: ` + style["a_hover"] + ";}\n"
	
	// todo 边框颜色
	labelStyle.innerHTML += `header .top ul li,
	.right .main,
	.right .main .icon,
	.right .main ul,
	.right .main .requests table tbody tr td,
	.left>ul,
	.left>ul:not(:first-child),
	.left>ul>strong {
		border-color: ` + style["border"] + ";}\n"
	
	// todo 文字颜色
	labelStyle.innerHTML += `.left, .right {
		color: ` + style["fontColor"] + ";}\n"
	
	// todo 切换样式ul的背景色
	labelStyle.innerHTML += `header .top ul {
		background-color: ` + style["style_ul"] + ";}\n"
	
	// todo 切换样式ul li的背景色
	labelStyle.innerHTML += `header .top ul li {
		background-color: ` + style["style_ul_li"] + ";}\n"
	
	// todo 导航栏颜色
	labelStyle.innerHTML += `.right nav ul {
		background-color: ` + style["nav"] + ";}\n"
	
	// todo 内容区背景颜色
	labelStyle.innerHTML += `.right main ul {
		background-color: ` + style["main_ul"] + ";}\n"
}

var classTopUlLi = document.querySelectorAll(".top ul li")
add_click_each(classTopUlLi, select_style)

// ! 1.3 这是左上角的logo
var a = `
                  ___                   _____
  _    _  _   _   | |     ____   ____  [_____]
 | \\  / /| | | |  | |    / ___) / _  ]   | |
  \\ \\/ / | (_/ |  | |__ ( (___ ( [_] |   | |
   \\__/  (____ ]/[_____] \\____) \\____]/  [_]
`
var logo = document.querySelector(".logo")
logo.innerHTML = "<a href=\"\"><pre>" + a + "</pre></a>"

// ? ------------------------------------------------------------
// ? ------------------------------------------------------------
// ? ------------------------------------------------------------
// ? ------------------------------------------------------------
// ? ------------------------------------------------------------

// ! 2. 排序
var bool = true // * 计数器, true升序, false降序
var noShowList: string[] = []  // * 列显示 黑名单
var noShowTrList = { // * 行显示 黑名单
	"target": [],
	"vulnid": [],
	"ftype": [],
	"time": []
}

// ! 2.1 数组排序函数
function sort(arr, dataLeven, bool) {
	/* 获取数组元素内需要比较的值
	 * params: arr: 需要排序的数组
	 * params: dataLeven: 数组内的需要比较的元素属性
	 * params: bool: 布尔值, true-升序, false-降序
	*/
	function getValue (option) { // 参数： option 数组元素
	  if (!dataLeven) return option

	  var data = option
	  dataLeven.split('.').filter(function (item) {
	    data = data[item]
	  })

	  return data + ''
	}

	arr.sort(function (item1, item2) {
		if (bool) {
			return getValue(item1).localeCompare(getValue(item2));
		}

	  	return getValue(item2).localeCompare(getValue(item1));
	})
}

// ! 2.2 排序漏洞数组的内容, 并在页面上重新显示
function show_sort(event) {
	/*
	 * 获取用户点击的类名
	 * 对bool取反, 升序与降序切换
	 * 根据类名排序数组
	 * 重新显示漏洞信息
	*/

	var className = event.target.className
	bool = !bool
	sort(vulnContent, className, bool)
	show()
}

// ! 2.3 显示漏洞信息内容

var classNav = document.querySelector(".nav")		// * 获取漏洞标题
var classMain = document.querySelector(".main")		// * 获取漏洞内容

function show(noShow=noShowList, noShowTr=noShowTrList) {
	/*
	 * params: noShow: 列黑名单
	 * params: noShowTr: 行黑名单
	*/

	var len = Object.keys(vulnTitle[0]).length		// * 获取标题个数
	var width = "width:" + (96 / len) + "%;"		// * 根据个数计算平均宽度, 100-X=96, X为预留宽度

	var classNavHtml = "<ul>"							// * 标题 起始ul
	var classMainHtml = ""								// * 内容 起始
	
	// todo 遍历漏洞标题, 判断是否在黑名单noShow中, 使用<ul><li>生成HTML结构
	vulnTitle.forEach(function (item, index) {
		classNavHtml += "<li class=\"icon\"></li>"
		for (const [key, val] of Object.entries(item)) {
			if (noShow.includes(key)) {
				continue
			}
			classNavHtml += "<li class=\"" + key  + "\">" + val + "</li>"
		}
		classNavHtml += "</ul>"							// * 标题 结束ul
	})

	// todo 遍历漏洞内容, 判断是否在黑名单noShowTr中, 使用<ul><li>生成HTML结构
	vulnContent.forEach(function (content_item, content_index) {
		var i = -1		// * 默认不在黑名单中

		for (const [key, val] of Object.entries(noShowTr)) {
			val.forEach(function (val_item, val_index) {
				if (!(i+1)) {	// * indexOf在黑名单中查找, 直到找到 (行 黑名单)
					i = content_item[key].indexOf(val_item)
				}
			})
		}

		if (i+1) {
			// todo 如果在黑名单中, 则不生成该行内容 (行 黑名单)
		} else {
			classMainHtml += "<ul>"
	
			// todo 查找行中的 某列内容, 是否在黑名单中, 在的话不生成该列 (列 黑名单)
			var fullUrl = ''
			for (const [key, val] of Object.entries(content_item)) {
				if (noShow.includes(key)) {
					continue
				}
	
				if (key == "id") {
					classMainHtml += "<li class=\"icon\">+</li>"
					classMainHtml += "<li class=\"" + key + "\">"
					classMainHtml += val
					classMainHtml += "</li>"
				} else if (key == "fullUrl") {
					fullUrl = val
				} else if (key == "requests") {
					classMainHtml += "<li class=\"" + key + "\">"
					classMainHtml += "<table>"
					classMainHtml += "<tbody>"
	
					classMainHtml += "<tr><td><a href=\"" + fullUrl + "\" target=_blank>" + fullUrl + "</a></td></tr>"
	
					val.forEach(function (reqValItem, reqValIndex) {
						classMainHtml += "<tr><td><strong>Request-" + (reqValIndex + 1) + "</strong><span>Copy</span></td></tr>"
						classMainHtml += "<tr><td><code>" + reqValItem + "</code></td></tr>"
					})
					
					classMainHtml += "</tbody>"
					classMainHtml += "</table>"
					classMainHtml += "</li>"
				} else {
					classMainHtml += "<li class=\"" + key  + "\">" + val + "</li>"
				}
			}
			classMainHtml += "</ul>"						// * 内容 结束
		}
	})
	
	classNav.innerHTML = classNavHtml					// * 标题 应用
	classMain.innerHTML = classMainHtml					// * 内容 应用

	// todo 宽度 应用, 获取标题和内容中的所有<li>, 应用宽度
	var classNavLis = document.querySelectorAll(".nav ul li:not(:first-child)")
	var classMainLis = document.querySelectorAll(".main ul li:not(:last-child):not(:first-child)")
	var lis = [...classNavLis, ...classMainLis]

	lis.forEach(function (item, index) {
		item.setAttribute("style", width)
	})

	// todo 获取标题中的所有<li>, 添加点击事件show_sort, 用于内容的 升序和降序
	var classNavLis_2 = document.querySelectorAll(".nav ul li")
	add_click_each(classNavLis_2, show_sort)

	// todo 获取内容中的所有<li>, 通过 hide_each 批量绑定和解绑相关事件
	var classMainLis_2 = document.querySelectorAll(".main ul li:not(:last-child)")
	hide_each(classMainLis)

	// todo 获取内容中的Requests显示栏, 为其中的 Copy 添加点击事件, 用于复制Requests的数据包
	var requestsCopys = document.querySelectorAll(".right .main .requests table tbody tr td span")
	add_click_each(requestsCopys, requests_copy)
}

// todo 复制Requests请求数据包
function requests_copy(event) {
	var content_txt = event.target.parentNode.parentNode.nextSibling.textContent	// * 获取文本内容

	const selBox = document.createElement('textarea')
    selBox.value = content_txt
    document.body.appendChild(selBox)	// * 添加一个临时元素
    // selBox.focus()
    selBox.select()						// * 选中临时元素
    document.execCommand('copy')		// * 调用copy
    document.body.removeChild(selBox)	// * 移除临时元素

	var copy_success=document.createElement("div")
    copy_success.id="copy_success"

	// * 当找不到id为lunbo的控件时
	if (document.getElementById("copy_success") == null) {
		// todo 弹窗, 显示“复制成功”, 2000毫秒后删除该弹窗

		document.body.appendChild(copy_success)

		copy_success.innerHTML="<strong>复制成功</strong>"
		setTimeout("document.body.removeChild(copy_success)", 2000)
	}
}

// ! 打开文件时, 先对标题 id 进行升序, 然后显示漏洞内容
sort(vulnContent, 'id', bool)
show()

// ! 2.4 显示 或 隐藏Requests
function show_or_hide_requests(event, show=true) {
	var parent = event.target.parentNode	// * 获取父元素

	var requests_li = parent.lastChild		// * 获取Requests
	var icon_span = parent.firstChild		// * 获取图标
	var main_li = parent.childNodes			// * 获取所有子元素
	
	if (show) {
		// todo 显示Requests, 将图标改为 - , 使用show_each()批量绑定和解绑相关事件

		requests_li.setAttribute("style", "display:block;")
		icon_span.innerText = "-"

		show_each(main_li)
	} else {
		// todo 隐藏Requests, 将图标改为 + , 使用hide_each()批量绑定和解绑相关事件
		
		requests_li.setAttribute("style", "display:none;")
		icon_span.innerText = "+"

		hide_each(main_li)
	}

	// todo Requests不应该有 显示和隐藏 的相关事件, 移除.requests的show和hide
	var req_li = document.querySelectorAll(".requests")
	req_li.forEach(function (item, index) {
		item.removeEventListener("click", show_requests)
		item.removeEventListener("click", hide_requests)
	})
}

function show_each(main) {
	/* 
	 * 移除show_requests, 添加hide_requests
	 * 点击 main li 之后, 其下的Requests显示, 移除 li 的显示事件, 同时为 li 添加隐藏事件
	*/

	main.forEach(function (item, index) {
		item.removeEventListener("click", show_requests)
	})

	add_click_each(main, hide_requests)
}

function hide_each(main) {
	/* 
	 * 移除hide_requests, 添加show_requests
	 * 点击 main li 之后, 其下的Requests隐藏, 移除 li 的隐藏事件, 同时为 li 添加显示事件
	*/

	main.forEach(function (item, index) {
		item.removeEventListener("click", hide_requests)
	})

	add_click_each(main, show_requests)
}

// todo 以下函数用于中转, 默认传递true显示Requests, 隐藏则是传递false
function show_requests(event) {
	show_or_hide_requests(event)
}

function hide_requests(event) {
	show_or_hide_requests(event, false)
}

// ? ------------------------------------------------------------
// ? ------------------------------------------------------------
// ? ------------------------------------------------------------
// ? ------------------------------------------------------------
// ? ------------------------------------------------------------

// ! 3. 侧边栏

// todo 增/删 黑名单

function filter_show(className) {
	/*
	 * 根据对应的className 添加/移除 黑名单中的元素
	 * 然后重新显示页面内容
	*/

	var noShowTr = className.split("_")				// * 获取<input>的类名, 以下划线分割为数组
	var noShows = noShowTrList[noShowTr[0]]			// * 获取对应的黑名单数组
	var no = noShowTr[1]							// * 黑名单内容

	if (noShows.includes(no)) {
		// * 如果在黑名单数组中 找到了对应的内容, 则删除 (移出黑名单)

		var i = noShows.indexOf(no)
		if (i+1) {
			noShows.splice(i, 1)
		}
	} else {
		// * 如果在黑名单数组中 没有找到对应的内容, 则添加 (加入黑名单)

		noShows.push(no)
	}

	show()	// * 重新显示页面内容
}

// todo 生成过滤器
function create_filter(vulnArr, noCreate) {
	/*
	 * params: vulnArr: 对哪个数组生成过滤器
	 * params: noCreate: 忽略数组中的某个字段
	*/

	var filter = []

	vulnArr.forEach(function (item, index) {
		filter[index] = {}
	
		for (const [key, val] of Object.entries(item)) {
			if (!noCreate.includes(key)) {
				filter[index][key] = val
				
				if (key == "ftype") {
					var f_type = val.split("/")
					filter[index]["framework"] = f_type[0]
					filter[index]["type"] = f_type[1]
				}
			}
		}
	})

	return filter
}

var vulnTitleFilter = create_filter(vulnTitle, ["id"])					// * 标题过滤器
var vulnContentFilter = create_filter(vulnContent, ["id", "requests"])	// * 内容过滤器

// ! 3.1 侧边栏HTML结构, 每个<ul>对应一个标题的过滤器, <ul><li>是内容的过滤器
var leftHtml = ""

vulnTitleFilter.forEach(function (item, index) {
	var itemKeyList = []

	for (const [key, val] of Object.entries(item)) {
		leftHtml += "<ul class=\"" + key  + "\">"
		if (!["framework", "type"].includes(key)) {
			leftHtml += "<input type=checkbox " + "class=\"" + key + "\" checked>"
		}
		leftHtml += "<strong>" + val + "</strong><i><span class=\"arrow " + key + "\"></span></i>"
		
		// * 一次性 全选/反选 <li>
		leftHtml += "<li class=\"all left_" + key + "\">"
		leftHtml += "<input type=\"checkbox\" class=\"all_" + key + "\" checked>"
		leftHtml += "<span>All</span></li>"

		// todo 生成<ul><li>内容过滤部分
		vulnContentFilter.forEach(function (item, index) {

			// * 时间只取 年月日, 舍弃 时分秒
			var itemKeyValue
			if (key == "time") {
				itemKeyValue = item[key].split(" ")[0]
			} else {
				itemKeyValue = item[key]
			}

			// * 用一个数组+if去重
			if (!(itemKeyList.includes(itemKeyValue))) {
				leftHtml += "<li class=left_" + key + ">"
				
				if (["framework", "type"].includes(key)) {
					var noShowKey = "ftype"
				} else {
					var noShowKey = key
				}

				leftHtml += "<input type=\"checkbox\" class=\"" + noShowKey + "_" + itemKeyValue + "\" checked>"
				leftHtml += "<span>" + itemKeyValue + "</span></li>"

				itemKeyList.push(itemKeyValue)		// * 往去重数组里添加一个元素
			}
		})

		leftHtml += "</ul>"		// * 侧边栏 结束
	}
})

var left = document.querySelector(".left")
left.innerHTML = leftHtml	// * 获取侧边栏, 应用HTML内容

// ! 3.2 侧边栏 "列"过滤功能

// todo 获取left ul中的 第1和第2个元素, 为它们绑定点击事件filter_current_title
var classLeftUlLi_1 = document.querySelectorAll(".left>ul :nth-child(1)")
var classLeftUlLi_2 = document.querySelectorAll(".left>ul :nth-child(2)")
add_click_each(classLeftUlLi_1, filter_current_title)
add_click_each(classLeftUlLi_2, filter_current_title)

// todo 标题过滤
function filter_current_title(event) {
	var parent = event.target.parentNode	// * 获取父元素
	var checkbox = parent.firstChild		// * 获取复选框

	if (event.target.nodeName != "INPUT") {
		// * 如果鼠标点击的不是<input>, 则需要手动设置相反的值, 以更改<input>选中状态
		checkbox.checked = !checkbox.checked
	}

	if (checkbox.checked) {
		// * 如果选中当前标题, 则删除黑名单中的对应值, 让其在内容中 显示

		var i = noShowList.indexOf(checkbox.className)
		if (i+1) {
			noShowList.splice(i, 1)
		}
	} else {
		// * 如果取消选中当前标题, 将其加入黑名单中, 让其在内容中 隐藏

		noShowList.push(checkbox.className)
	}

	show()
}

// ! 3.3 侧边栏 "行"过滤功能
function filter_current_main(event) {
	// * 获取.left ul li里的<input>标签
	if (event.target.nodeName == "INPUT") {
		var target = event.target
	} else {
		var target = event.target.previousSibling
	}
	
	filter_show(target.className)
}

// todo 获取下拉<li>, 为其添加点击事件filter_current_main
var classLeftUlLis_1 = document.querySelectorAll(".left>ul li:not(.all)>input")
var classLeftUlLis_2 = document.querySelectorAll(".left>ul li:not(.all)>span")
add_click_each(classLeftUlLis_1, filter_current_main)
add_click_each(classLeftUlLis_2, filter_current_main)

// todo 为每个.all添加事件, 用于一次性 选中/反选 其下所有<li>
function select_current_all_li(event) {
	// * 获取父级
	var parent = event.target.parentNode
	var allInput = parent.firstChild		// * 获取.all input

	var className = parent.className.replace("all ", ".")	// * 获取<input>的类名
	var current_lis = document.querySelectorAll(className + ":not(.all)")

	// todo 更改所在ul的所有<li>选中状态, 并将其 添加/移出 黑名单
	current_lis.forEach(function (item, index) {
		var itemInput = item.firstChild

		if (allInput.checked != itemInput.checked) {
			filter_show(itemInput.className)
			itemInput.checked = !itemInput.checked
		}
	})
}

var classleftAll_1 = document.querySelectorAll(".left ul .all>input")
var classleftAll_2 = document.querySelectorAll(".left ul .all>span")
add_click_each(classleftAll_1, select_current_all_li)
add_click_each(classleftAll_2, select_current_all_li)

// ! 3.4 侧边栏 <ul><li>的 上卷/下拉 功能
function show_current_li(event) {
	// * 获取箭头
	if (event.target.nodeName == "SPAN") {
		var target = event.target
	} else {
		var target = event.target.firstChild
	}


	var className = target.className.replace("arrow ", ".left_")	// * 获取箭头的类名
	var current_lis = document.querySelectorAll(className)			// * 根据获取的className, 获取当前ul下面的所有li

	// todo 更改<li>显示, 并修改箭头样式
	current_lis.forEach(function (item, index) {
		if (item.style.display == "block") {
			// * 如果现在是显示状态, 则改为隐藏

			item.style.display = "none"
			target.style.borderColor = "transparent transparent black transparent"
		} else {
			// * 如果现在是隐藏状态, 则改为显示

			item.style.display = "block"
			target.style.borderColor = "black transparent transparent transparent"
		}
	})
}

// todo 获取left中的箭头, 添加点击事件show_current_li
var leftArrow = document.querySelectorAll(".left>ul>i")
add_click_each(leftArrow, show_current_li)
