function hexoChangeBanner() {
  var url = document.location.pathname;
  var folderName = url.substr(1, url.length - 2);
  console.log(folderName);

  var listPostUrl = [
    "/" + folderName + "/" + "post-banner.png",
    "/" + folderName + "/" + "post-banner.jpg",
  ];

  var nSuccessCount = 0;
  var nResponceCount = 0;
  function OnHttpResponse(bSuccess, strUrl) {
    console.log("OnHttpResponse: " + bSuccess + ", " + strUrl);
    nResponceCount++;
    if (nSuccessCount > 0) {
      return;
    }
    if (bSuccess) {
      nSuccessCount++;
      document.getElementById("id-post-top").style.backgroundImage =
        "url(" + strUrl + ")";
    }
    if (nResponceCount >= listPostUrl.length && nSuccessCount <= 0) {
      // 使用默认图
      document.getElementById("id-post-top").style.backgroundImage =
        "url(/images/head-background.jpg)";
    }
  }

  function changeBanner(strPostUrl, nIndex) {
    console.log("try to load" + strPostUrl);
    var xmlhttp;
    if (window.XMLHttpRequest) {
      //  IE7+, Firefox, Chrome, Opera, Safari 浏览器执行代码
      xmlhttp = new XMLHttpRequest();
    } else {
      // IE6, IE5 浏览器执行代码
      xmlhttp = new ActiveXObject("Microsoft.XMLHTTP");
    }
    xmlhttp.onreadystatechange = function () {
      if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
        OnHttpResponse(true, strPostUrl);
      } else {
        OnHttpResponse(false, strPostUrl);
      }
    };
    xmlhttp.open("HEAD", strPostUrl, true);
    xmlhttp.send();
  }

  listPostUrl.forEach(changeBanner);
}
