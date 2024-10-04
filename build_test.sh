rm -rf images
mkdir images
cat > http3.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>HTTP/3 DEMO</title>
</head>
<script>
        function imageLoadTime() {
                var lapsed = Date.now() - pageStart;
                document.getElementById("loadTime").innerHTML = ((lapsed) / 1000).toFixed(2)
        }
        var pageStart = Date.now();
</script>
<body>
<div id="main" >
<div>Load time: <span id="loadTime">0</span>s.</div>
</div>
EOF

i=0
while [ $i -lt 25 ]
do
  echo "<div id=\"row$i\" >" >> http2.html
  j=0
  while [ $j -lt 45 ]
  do 
    cp -p tomcat.png images/$i$j.png
    echo "<img height=\"20\" width=\"20\" onload='imageLoadTime()' src=\"images/$i$j.png\" />" >> http2.html
    j=`expr $j + 1`
  done
  echo "</div>" >> http2.html
  i=`expr $i + 1`
done

cat >> http2.html << EOF
</body>
</html>
EOF
