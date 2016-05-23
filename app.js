//var express = require('express');
//var path = require('path');
//var favicon = require('serve-favicon');
//var logger = require('morgan');
//var cookieParser = require('cookie-parser');
//var bodyParser = require('body-parser');
//
//var routes = require('./routes/index');
//var users = require('./routes/users');
//
//var app = express();
//
//// view engine setup
//app.set('views', path.join(__dirname, 'views'));
//app.set('view engine', 'jade');
//
//// uncomment after placing your favicon in /public
////app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
//app.use(logger('dev'));
//app.use(bodyParser.json());
//app.use(bodyParser.urlencoded({ extended: false }));
//app.use(cookieParser());
//app.use(express.static(path.join(__dirname, 'public')));
//
//app.use('/', routes);
//app.use('/users', users);
//
//// catch 404 and forward to error handler
//app.use(function(req, res, next) {
//  var err = new Error('Not Found');
//  err.status = 404;
//  next(err);
//});
//
//// error handlers
//
//// development error handler
//// will print stacktrace
//if (app.get('env') === 'development') {
//  app.use(function(err, req, res, next) {
//    res.status(err.status || 500);
//    res.render('error', {
//      message: err.message,
//      error: err
//    });
//  });
//}
//
//// production error handler
//// no stacktraces leaked to user
//app.use(function(err, req, res, next) {
//  res.status(err.status || 500);
//  res.render('error', {
//    message: err.message,
//    error: {}
//  });
//});
//
//
//module.exports = app;
////1.
//var express = require('express');
//var app = express();
//app.get('/about',function(request,response) {
//  response.send('hello,world');
//});
//
//app.get('*',function(request,response) {
//  response.send('404 error! -- liaozhongru');//*号是通配图，如果上面的get请求，没有被其他人处理，由于这里的是*号通配符，他就可以处理任何请求
//});
//
//app.listen(3000);

////2.
//var express = require('express');
//var app = express();
////use的作用是加载中间件，所以，中间件里面的function都会按照顺序执行一遍。不过前提是，要记得写上next，才可以按照顺序执行，不然没有next的话，那么下一个use
////就没法用了。
//app.use(function(request,response,next) {
//  console.log("method:" + request.method + "====" + "url:" + request.url);
//  next();
//});
//
//app.use(function(request,response) {
//  response.writeHead(200,{"Content-Type":"text/html;charset=utf-8"});
//  response.end('示例：连续调用两个中间件');
//});
//
//
//app.listen(3000);

////3.
//var express = require('express');
//var app = express();
////use不仅可以用来加载中间件，还可以根据网络请求，返回不同的网页内容。
//app.use(function(request,response,next) {
//  if(request.url == '/') {
//    response.send('welcome to homepage');
//  }else {
//    next();
//  }
//});
//
//app.use(function(request,response,next) {
//  if(request.url == '/about') {
//    response.send('welcom to aboutpage');
//  }else {
//    next();
//  }
//});
//
//app.use(function(request,response) {
//  response.send('404 -- error!');
//})
//
//app.listen(3000);

////4.request
////Express回调函数有两个参数，分别是request(简称req)和response(简称res)，request代表客户端发来的HTTP请求
////，response代表发向客户端的HTTP回应，这两个参数都是对象。
//
//var express = require('express');
//var app = express();
//app.get('*',function(request,response) {
//  console.log(request.path);
//  console.log(request.query);//这里可以把http://localhost:3000/?name=hello&&age=14提取出来，成为{ name: 'hello', age: '14' }
//  console.log(request.param("name"));//也可以通过这个方式来取出这个结果来，结果是hello
//  response.send("req.host 获取主机名，req.path获取请求路径名");
//
//});
//app.listen(3000);

////response的send函数
//var express = require('express');
//var app = express();
//app.get('/',function(request,response) {
//  //response.send('hello,world');//如果参数是字符串，那么默认的Content-Type就是text/html
//  //response.send([1,2,3]);
//  response.send({'name':'Tim','age':'14'});//如果参数是Array，或者字典，那么，返回的就是JSON
//});
//
//app.listen(3000);

////5.设定模板引擎
//var express = require('express');
//var app = express();
//
//app.set('view engine','ejs');//我们通过控制台到untitled1目录，然后npm install ejs，然后，就可以把ejs这个包下载到node_modules下了。
////这么写，那么，express，就支持渲染ejs文件，如果，我们想用html的形式去书写，那么，我们就去修改模板引擎好了。
//
//
////app.set('view engine','html');
////app.engine('.html',require('ejs').__express);//可以通过这种方式来使用html的形式。
//
//app.listen(3000);

//现在在慢慢摸到前端后端的门道了。
////6.渲染视图
//var express = require('express');
//var app = express();
//var path = require('path');
//app.set('views',__dirname+'/views');///其实__dirname就是我们工程的路径：Users/xuexibao/WebstormProjects/untitled1，但是我们的视图
////是放在untitled1的views文件夹里面的。所以，我们要拼接字符串，拼接成__dirname+'/views'
//上面设定的是视图文件所在路径
//app.set('view engine','html');//这里设置的是渲染引擎用什么
//app.engine('.html',require('ejs').__express);//html的引擎，要从ejs从获取。
//app.get('/',function(request,response) {
//    response.render('home'); //render函数可以渲染视图文件，并发送回去。
//});
//app.listen(3000);

////7.使用redirect来做重定向。
//var express = require('express');
//var app = express();
//app.get('/',function(request,response) {
//    response.redirect('http:baidu.com');//这里给一个地址即可重定向到那里去。所以，最终显示的内容就是这个baidu.com的内容。
//    //response.redirect('login');//当然，我们也可以重定向到我们指定的某一个视图上
//});
//app.listen(3000);


////8.访问视图--我们可以通过设定所渲染的视图路径，设定路由，然后即可渲染，并返回指定的视图
//var express = require('express');
//var app = express();
//var path = require('path');
//app.set('views',__dirname+'/views');
//app.set('view engine','html');
//app.engine('.html',require('ejs').__express);
//app.get('/',function(request,response) {
//    //response.render('')
//    response.send('hello,world');
//});
//app.get('/login',function(request,response) {
//    response.render('login');
//});
//app.get('/home',function(request,response) {
//    response.render('home');
//});
//app.listen(3000);


////这段代码是错的，但是不知道为啥错了。。
//var express = require('express');
//var app = express();
//var bodyParser = require('body-parser');
//var multer = require('multer');
//app.set('views',__dirname+'/views');
//app.set('view engine','html');
//app.engine('.html',require('ejs').__express);
//app.use(bodyParser.json());
//app.use(bodyParser.urlencoded({extended:true}));
//app.use(multer());
//app.get('/',function(request,response) {
//    response.render('login');
//});
//app.post('/login',function(request,response) {
//   console.log("用户名称为："+request.body.username);
//});
//
//app.listen(3000);


//我们可以用post请求，但是，我们在浏览器里面无法模拟post请求，所以，我们可以通过控制台的curl来模拟post请求
//curl -d "param1=value1&param2=value2" http://localhost:3000/login
//var express = require('express');
//var app = express();
//app.post('/login',function(request,response) {
//   console.log('hello,world');
//    response.send('post hello,world');
//});

//
//app.listen(3000);

//var express = require('express');
//var app = express();
////var bodyParser = require('body-parser');
////var multer = require('multer');
////app.use(bodyParser.json());
////app.use(bodyParser.urlencoded({extented:true}));
////app.use(multer());
//app.set('views',__dirname+'/views');
//app.set('view engine','html');
//app.engine('.html',require('ejs').__express);
//
//app.get('/login',function(request,response) {
//   response.render('login');
//});
//app.listen(3000);

////一个完整的post请求
//var express = require('express');
//var app = express();
//var bodyParser = require('body-parser');
//var multer = require('multer');//安装别的版本会出错，就只能安装这个版本：到项目目录下去安装。npm install multer@0.1.6
//app.set('views',__dirname + '/views');
//app.set('view engine','html');
//app.engine('.html',require('ejs').__express);
//app.use(bodyParser.json());
//app.use(bodyParser.urlencoded({extended:true}));
//app.use(multer());
//app.get('/',function(request,response) {
//    console.log('get hello,world');
//   response.render('login');
//});
//app.post('/login',function(request,response) {
//    console.log('用户名为：' + request.body.username);//通过这个方式可以拿到某一个数据
//    // curl -d "username=liaozhongru&age=12" http://localhost:3000/login
//});
//app.listen(3000);

//var express = require('express');
//var app = express();
//var bodyParser = require('body-parser');
//var multer = require('multer');
//app.set('views',__dirname + '/views');
//app.set('view engine','html');
//app.engine('.html',require('ejs').__express);
//app.use(bodyParser.json());
//app.use(bodyParser.urlencoded({extended:true}));
//app.use(multer());
//app.get('/',function(request,response) {
//    response.render('home');
//});
//app.get('/home',function(request,response) {
//    response.render('home');
//});
//
//app.get('/login',function(request,response) {
//    response.render('login');
//});
//app.post('/login',function(request,response) {
//    var user = {
//        username:'admin',
//        password:'admin'
//    };
//    if(request.body.username == user.username && request.body.password == user.password) {
//        console.log('');
//        response.send(200);
//    }
//    else {
//        response.send(404);
//    }
//});
//app.listen(3000);

//var session = require('express-session');
//app.use

////JSPatch的项目实现1------实现简单的post网络请求
//var express = require('express');
//var app = express();
////必须要body-parser，不然无法解析request的body参数
//var bodyParser = require('body-parser');
//app.use(bodyParser.json());
//app.use(bodyParser.urlencoded({extended:true}));
//
//app.post('/patch/updinfo',function(request,response) {
//   console.log('app_ver ==' + request.body.app_ver);
//    console.log('bundle_id ==' + request.body.bundle_id);
//    response.send({'name':'liaozhongru','corp':'xuexibao'})
//});
//app.listen(8080);


//数据库的使用
////首先，我们要启动数据库：mongod —config /usr/local/etc/mongod.conf
////然后，我们要连接数据库，我们通过下面的代码，就可以连接上数据库了。
//var mongoose = require('mongoose');
//var db = mongoose.connect("mongodb://127.0.0.1:27017/test");
//db.connection.on('error',function(error) {
//   console.log('连接数据库失败：' + error);
//});
//
//db.connection.on('open',function() {
//    console.log('----连接数据库成功-----');
//});



////概念：集合==表、文档：一行数据
//var mongoose = require("mongoose");
//
////Schema是文件形式的数据库模型骨架，他定义了一个集合，也就是表的骨架。
//这个在zhihui网上有问题
//var tschema= new mongoose.Schema({
//    name  : { type:String },
//    age   : { type:Number, default:18 },
//    gender: { type: Boolean, default: true }
//});
//
////model是由schema生产的模型。它具有对数据库进行操作的行为。
//var mongoose = require('mongoose');
//var schema = new mongoose.Schema({
//    name : {type:String},
//    age : {type:Number,default:18}
//});
//var db = mongoose.connect('mongodb://localhost:27017/test');
//db.connection.on('error',function(error) {
//    console.log('连接数据库失败');
//});
//db.connection.on('open',function() {
//    console.log('连接数据库成功');
//})
//
//var model = db.model("Test1",schema);


//文件读取成功
//var fs = require('fs');
//fs.readFile('hello.txt','utf-8',function(error,data) {
//   if(error) {
//       console.log(error);
//   } else {
//       console.log(data);
//   }
//});

//JSPatch的项目实现2-- 压缩文件的发送
//var express = require('express');
//var app = express();
//app.get('/',function(request,response) {
//    //response.sendfile('hello.txt');//以前，用这个就可以发送文件，现在已经被废弃，现在要用下面复杂的写法
//    //options要规定好文件的根目录的路径__dirname是项目根目录
//    //options 输入什么见http://www.expressjs.com.cn/4x/api.html#res
//    var options = {
//        root:__dirname + '/source',
//        dotfiles:'deny',
//        headers:{
//            'x-timestamp':Date.now(),
//            'x-sent':true
//        }
//    };
//    response.sendFile('xuexibao_v3.4_script.zip',options,function(err) {
//        if(err) {
//            console.log(err);
//        } else {
//            console.log('Sent:',request.params.name);
//        }
//    });
//})
//app.listen(8080);




//const crypto = require('crypto');
//const secret = 'hello,world';
//const hash = crypto.createHmac('md5',secret)
//    .update('I love cupcakes')
//    .digest('hex');
//console.log(hash.length);


////异步加密做法
//var crypto = require('crypto');
//var fs = require('fs');
//var jsFile = fs.readFile('hello.txt','utf-8',function(err,data) {
//    if(err) {
//        console.log(err);
//    } else {
//        console.log(data);
//        //var key = data.toString('ascii');
//        //生成文件md5摘要
//        var MD5 = crypto.createHmac('md5',data);
//        //console.log(MD5.update('foo'));//我们还可以添加新的字符串来更新摘要。
//
//        //接口说明：https://nodejs.org/dist/latest-v4.x/docs/api/crypto.html#crypto_hmac_update_data_input_encoding
//        //https://nodejs.org/dist/latest-v4.x/docs/api/crypto.html#crypto_hmac_digest_encoding
//        //var
//        var md5Digest = MD5.digest('hex');//只能调用一次
//        console.log(md5Digest);
//
//
//    }
//});
//


////同步加密做法
////先把js文件转化为md5摘要
//var crypto = require('crypto');
//var fs = require('fs');
//var jsFile = fs.readFileSync('hello.txt');
////var jsData = jsFile.toString('ascii');
//var fileMD5 = crypto.createHmac('md5',jsFile);
//var fileMD5Digest = fileMD5.digest('hex');
//console.log(fileMD5Digest);
//
//
////再把私钥以上文的md5摘要作为形参update出一个新的Digest
//var pemFile = fs.readFileSync('ssl/private.pem','utf-8');
////console.log(pemFile);
//var pemMD5 = crypto.createHmac('md5',pemFile);
//pemMD5.update(fileMD5Digest);
//var finalDigest = pemMD5.digest('hex');
//console.log(finalDigest);
//
//
////rsacert.crt
//var publicKeyFile = fs.readFileSync('ssl/rsacert.der','utf-8');
//var publicKeyMD5 = crypto.createHmac('md5',publicKeyFile);
//publicKeyMD5.update(fileMD5Digest);
//var finalDigest2 = publicKeyMD5.digest('hex');
//console.log(finalDigest2);

////对文件做签名
//const crypto = require('crypto');
//const sign = crypto.createSign('RSA-SHA256');
////write和end组合和update函数效果是一样的。
////sign.write('some data to sign');
////sign.end();
//sign.update('some data to sign');
//var fs = require('fs');
//var private_key = fs.readFileSync('ssl/private.pem','utf-8');
//var signature = sign.sign(private_key,'hex');
//console.log(signature);
////3e93c47e16af20f2350d3ae312434d9173c114....
//
////对签名文件做校验
//
//const verify = crypto.createVerify('RSA-SHA256');
////verify.write('some data to sign');
////verify.end();
//verify.update('some data to sign');
//const public_key = fs.readFileSync('ssl/rsacert.crt','utf-8');
////console.log(sign.verify(public_key,signature));
//
//console.log(verify.verify(public_key,signature));


//crypto.privateDecrypt()
//var private_key =

////JSPatch的项目实现3--生成脚本文件的MD5的加密MD5
//
////私钥加密
//var fs = require('fs');
//var private_key = fs.readFileSync('ssl/rsa_private_key.pem','utf-8');
//console.log('private_key = ',private_key);
//
//var crypto = require('crypto');
//var str = 'hello,world';
//console.log('str = ',str);
//var buffer = crypto._toBuf(str);//这是原始的buffer：<Buffer 68 65 6c 6c 6f 2c 77 6f 72 6c 64>
//console.log('buffer = ',buffer);
//var cryptBuffer =crypto.privateEncrypt(private_key,buffer);//这是生成的加密buffer
////<Buffer 2f ad 98 8c f1 2f ee ee 38 2a 07 d0 6c f2 4e 67 77 c2 3d 3c 0d 96 fa b......
//console.log('cryptBuffer = ',cryptBuffer);
//
//fs.writeFileSync('source/key',cryptBuffer);
//
//fs.writeFileSync('source/key',cryptBuffer);
//
//
////文件的压缩
//var archiver = require('archiver');
//var archive = archiver('zip');
//var output = fs.createWriteStream('source/xuexibao_v3.4_script.zip');
////output.on('close',function() {
////        //console.log(arhive.pointer() + 'total bytes');
////        // console.log('archiver has been finalized and the output file description');
////});
////output.on('error',function(err) {
////    console.log(err);
////});
//archive.pipe(output);
//var file1 = __dirname + '/source/script.zip';
//var file2 = __dirname + '/source/key';
//archive
//    .append(fs.createReadStream(file1),{name:'script.zip'})
//    .append(fs.createReadStream(file2),{name:'key'})
//    .finalize();
//
//
//
//
//
//
////文件发送
//var express = require('express');
//var app = express();
//app.post('/patch/updinfo',function(request,response) {
//    //response.sendfile('hello.txt');//以前，用这个就可以发送文件，现在已经被废弃，现在要用下面复杂的写法
//    //options要规定好文件的根目录的路径__dirname是项目根目录
//    //options 输入什么见http://www.expressjs.com.cn/4x/api.html#res
//    var options = {
//        root:__dirname + '/source',
//        dotfiles:'deny',
//        headers:{
//            'x-timestamp':Date.now(),
//            'x-sent':true
//        }
//    };
//    response.sendFile('xuexibao_v3.4_script.zip',options,function(err) {
//        if(err) {
//            console.log(err);
//        } else {
//            console.log('Sent:',request.params.name);
//        }
//    });
//})
//app.listen(8080);
//
//
//
////公钥解密
//
//var public_key = fs.readFileSync('ssl/rsa_public_key.pem','utf-8');
//console.log('------------------');
//console.log(public_key);
//console.log('-------------------');
//var result = crypto.publicDecrypt(public_key,cryptBuffer);//这是解密的buffer：<Buffer 68 65 6c 6c 6f 2c 77 6f 72 6c 64>
////可以看出来，原始的buf和最终的buffer结果是一样的。
//console.log(result);
//var resultStr = result.toString();
//console.log('resutlt = ',resultStr);


////JSPatch的项目实现4--文件目录的读取,目前，就实现了读取单层目录，多层目录逻辑等下在做。
//var util = require('./Util/MDUtil');
//var mp = util.allDir('./source');
//console.log(mp);


//////JSPatch的项目实现5---启用redis服务，记得前提是是到控制台里面启动redis：redis-server /usr/local/etc/redis.conf
//var redis = require('redis');
//var client = redis.createClient('6379','127.0.0.1');
//client.on('error',function(err) {
//    console.log(err);
//});

//client.select('15',function(error) { //这
// 是打开名字为15的表
//    if(error) {
//        console.log(error);
//    } else {
        //设定键值对
        //这是set方法
        //client.set('str_key_0','0',function(error,res) {
        //    if(error) {
        //        console.log(error);
        //    } else {
        //        console.log(res);
        //    }
        //   // client.end();
        //})
        //////这是get方法
        //client.get('str_key_0',function(error,res) {
        //    if(error) {
        //        console.log(error);
        //    } else {
        //        console.log(res);
        //    }
        //});



        //var info = {};
        //info.baidu = 'www.baidu.com';
        //info.sina = 'www.sina.com';
        //info.qq = 'www.qq.com';
        //client.hmset('site',info,function(error,res) {
        //    if(error) {
        //        console.log(error);
        //    } else {
        //        console.log(res);
        //    }
        //});
        //
        //client.hmget('site','baidu',function(error,res) {
        //    if(error) {
        //        console.log(error);
        //    } else {
        //        console.log(res);
        //    }
        //});
        //
        //client.hgetall('site',function(error,res) {
        //    if(error) {
        //        console.log(error);
        //    } else {
        //        console.log(res);
        //    }
        //})
    //}
//})



////JSPatch的项目实现6---实现https的网络请求,目前实现了get请求。
////postman不能验证https请求，请查看postman返回的原因，找着要求，到chrome里面修改了，postman就可以用https的网络请求了。
//
//var fs = require('fs');
//var express = require('express');
//var app = express();
//app.listen(8080);
//var bodyParser = require('body-parser');
//app.use(bodyParser.json());
//app.use(bodyParser.urlencoded({extended:true}));
//
//var redis = require('redis');
//var client = redis.createClient('6379','127.0.0.1');
//client.on('error',function(error) {
//    console.log(error);
//});
//
//
//var https = require('https');
//var options = {
//    key:fs.readFileSync(__dirname + '/ssl/meadowlark.pem'),
//    cert:fs.readFileSync(__dirname + '/ssl/meadowlark.crt')
//};
//
//
//https.createServer(options,app).listen(8081);
//app.post('/patch/updinfo',function(request,response) {
//    console.log('hello,world');
//
//    if(request.secure) {
//        var bundle_id = request.body.bundle_id;
//        var app_ver = request.body.app_ver;
//        var script_url = request.body.script_url;
//        var script_md5 = request.body.script_md5;
//        console.log(bundle_id,app_ver,script_url,script_md5);
//        if(bundle_id && app_ver) {//1.客户端指明了app包名、版本号
//            console.log('we can get all value');
//            client.select('15',function(error) { //调出数据库
//                if(error) {
//                    console.log(error);
//                } else {
//                    //var info = {};
//                    //info.script_url = script_url;
//                    //info.script_md5 = script_md5;
//                    //info.error_count = '1';
//                    //client.hmset(bundle_id+'->'+app_ver,info,function(error,result) {
//                    //    //console.log()
//                    //    if(error) {
//                    //        console.log(error);
//                    //    } else {
//                    //        //console.log(result);
//                    //        //result.error_count = result.error_count + 1;
//                    //        //console.log('haha' + result.error_count);
//                    //        var count = parseInt(result.error_count);
//                    //        //console.log(result.bundle_id);
//                    //
//                    //    }
//                    //})
//
//                    client.hgetall(bundle_id+'->'+app_ver,function(error,result) { //根据bundle_id+app_ver作为key，拿到数据库的所有数据，数据库的数据存储是key-value。key 是 bundle_id,value是一个对象，里面有ver，url，md5
//                        if(error || !result) {
//                            console.log(error);
//                            response.send('error');
//                        } else {
//                            console.log('result ==',result);
//                            if(script_url && script_md5) { //1.客户端指明了压缩包和MD5
//
//                                console.log(result.script_url,result.script_md5);
//                                //var isContain = (result.app_ver == app_ver) && (result.script_url == script_url);
//                                if(result.script_url == script_url) { //1.1
//                                    if(result.script_md5 == script_md5) {//1.1.1
//                                        console.log(!request.body.is_js_ok);
//
//                                        if(request.body.is_js_ok == 'false') { //这个要实验一下，让对方返回bool类型和字符串类型，看看效果。
//                                            //result.errorCount = result.errorCount + 1;
//                                            //console.log('count', ++result.error_count);
//
//                                            //var count = parseInt(result.error_count);
//                                            ++result.error_count;
//                                            console.log('count ==',result.error_count);
//                                            client.hmset(bundle_id+'->'+app_ver,result,function(error,result) {
//                                                console.log('data save success');
//                                                if(error) {
//                                                    console.log(error);
//                                                } else {
//                                                    console.log('save error = '+ result);
//                                                }
//                                            });
//                                        }
//                                        response.send({'has_update' : false,'need_clean' : false,'script_md5' :script_md5,'script_url':script_url});
//                                        //if(request.body.is_js_ok) {//1.1.1.1 //这个联调的时候，要检查一下，看客户端传递的bool值在这里变成什么了
//                                        //    response.send({'has_update' : false,'need_clean' : false});
//                                        //} else {//1.1.1.2
//                                        //    response.send({'has_update' : false,'need_clean' : true});
//                                        //}
//                                    } else {//1.1.2
//                                        response.send({'has_update' : true,'need_clean' : true,'script_md5' : result.script_md5,'script_url' : script_url});
//                                    }
//                                } else {//1.2
//                                    response.send({'has_update' : false,'need_clean' : true,'script_md5' : result.script_md5,'script_url' :result.script_url});
//                                }
//
//                            } else {
//                                response.send({'has_update' : true,'need_clean' : true,'script_md5' : result.script_md5,'script_url' : result.script_url});
//                            }
//                        }
//                    })
//                }
//            });
//
//
//        } else {//2.客户端连app包名和版本号都没指明清楚
//
//            console.log('we did not get value');
//            response.send('error');
//        }
//        //response.send('secure');
//    }
//    else {
//        response.send('not secure');
//    }
//});
//
//
//
//app.post('/patch/upload',function(request,response) {
//    if(request.secure) {
//        console.log('走的是https');
//    } else {
//        console.log('走的是http');
//    }
//})
//
//app.post('/patch/download',function(request,response) {
//    if(request.secure) {
//        var bundle_id = request.body.bundle_id;
//        var app_ver = request.body.app_ver;
//        var script_url = request.body.script_url;
//        client.select('15',function(error) {
//            if(error) {
//                response.send(error);
//            }
//            client.hgetall(bundle_id+'->'+app_ver,function(error,result) {
//                console.log('result',result);
//                if(error || !result) {
//                    console.log(error);
//                    response.send('找不到指定的文件夹');
//                } else {
//                    if(script_url == result.script_url) {
//                        console.log('找到文件了');
//                        var options = {
//                            root : __dirname + '/source/' + bundle_id + '/' + app_ver,
//                            dotfiles:'deny',
//                            headers:{
//                                'x-timestamp' : Date.now(),
//                                'x-sent' : true
//                            }
//                        }
//                        response.sendFile(script_url+'.zip',options,function(error) {
//                            if(error) {
//                                console.log(error);
//                            } else {
//                                console.log('ok');
//                            }
//                        })
//                    } else {
//                        console.log('找不到文件');
//                        response.send('找不到指定的文件');
//                    }
//                }
//            });
//        })
//    }
//});

////JSPatch的项目实现7--实现数据的上传
//var formidable = require('formidable');
//var express = require('express');
//var app = express();
//var fs = require('fs');
//app.post('/',function(request,response) {
//    //console.log('hello,world');
//    var form = new formidable.IncomingForm();
//    form.encoding = 'utf-8';
//    form.uploadDir = 'source';
//    //console.log('form == ',form);
//    form.parse(request,function(err,fields,files) {
//        if(err) {
//            return res.redirect(303,'/error');
//        }
//        //post请求的请求体，都在fields里面呢
//        var bundle_id = fields.bundle_id;
//        var app_ver = fields.app_ver;
//        var script_url = files.files.name;
//        console.log(bundle_id,app_ver,script_url);
//        console.log(fields);
//        //一切东西都在files.files里面，如果想想查看，或者获取，console.log一下files.files就行了。
//        console.log(files.files);
//        fs.rename(files.files.path,form.uploadDir +'/'+ files.files.name);
//        //response.redirect(303,'/thank-you');
//        response.send('hello,world');
//    })
//})
//app.listen(8080);


////JSPatch的项目实现8----实现完整的前端页面渲染，后端上传逻辑。
//
//var express = require('express');
//var app = express();
//var bodyParser = require('body-parser');
//app.use(bodyParser.json());
//app.use(bodyParser.urlencoded({extended:true}));
//
//var path = require('path');
//app.set('views',__dirname+'/views');
//app.set('view engine','html');
//app.engine('.html',require('ejs').__express);
//app.get('/patch/upload',function(request,response) {
//    response.render('iOSHotPatch1');
//});
//app.listen(8080);
//
//var formidable = require('formidable');
//var fs = require('fs');
//
//var redis = require('redis');
//var client = redis.createClient('6379','127.0.0.1');
//
//var util = require('./Util/util');


//app.post('/patch/upload',function(request,response) {
//    console.log('hello,world');
//    var form = new formidable.IncomingForm();
//    form.encoding = 'utf-8';
//    form.uploadDir = 'source';
//    console.log('body = ',request.body);
//
//    //1.通过request的post请求体的bundle_id,app_ver来决定是否要上传数据。来决定上传数据的位置。
//    form.parse(request,function(err,fields,files) {
//
//        if(err) {
//            console.log('error0 == ',err);
//            return response.redirect(303,'/error');
//        }
//        var bundle_id = fields.bundle_id;
//        var app_ver = fields.app_ver;
//        var is_release = fields.is_release;
//        var script_url = files.files.name;
//        console.log('bunld_id == ',bundle_id,app_ver,script_url,is_release);
//
//        if(bundle_id && app_ver) {
//            client.select('15',function(error) {
//                if(error) {
//                    console.log('error1 == ',error);
//                } else {
//                    client.get(bundle_id,function(error,appDirExist) {
//                        if(error) {
//                            console.log('error2 == ',error);
//                        } else {
//                            console.log('result ==== ',appDirExist);
//                            var appPath = __dirname + '/source/' + bundle_id;
//                            if(!appDirExist) {
//
//                                fs.mkdir(appPath,0777,function(error) {
//                                    if(error) {
//                                        console.log('error3 == ',error);
//                                    } else {
//                                        client.set(bundle_id,'yes');
//                                        var verPath = appPath + '/' + app_ver;
//                                        fs.mkdir(verPath,0777,function(error) {
//                                            if(error) {
//                                                console.log('error4 == ',error);
//                                            } else {
//                                                //最后把文件写在这里。
//                                                console.log('最后把文件移动到这里，并重命名');
//                                                var filePath = verPath + '/' + files.files.name;
//                                                console.log('ori fileMD5 ===',files.files.path);
//                                                fs.rename(files.files.path,filePath,function(error) {
//                                                    if(error) {
//                                                        console.log('error4.1',error);
//                                                    } else {
//                                                        var fileMD5 = util.md5Digest(filePath);
//                                                        util.cryptStr(fileMD5,verPath);
//                                                        util.archiveData(verPath,'key',files.files.name);
//
//
//                                                    }
//                                                });
//
//
//
//
//                                            }
//                                        })
//                                    }
//                                })
//                            } else {
//                                var isAppVerDirExist = util.isDirExist('./source/'+bundle_id,app_ver);
//                                var verPath = appPath + '/' + app_ver;
//                                if(isAppVerDirExist) {
//                                    var filePath = verPath + '/' +files.files.name;
//                                    fs.rename(files.files.path,filePath);
//                                } else {
//                                    fs.mkdir(verPath,0777,function(error) {
//                                        if(error) {
//                                            console.log('error5 == ',error);
//                                        } else {
//                                            console.log('最后把文件移动到这里，并重命名');
//                                            var filePath = verPath + '/' + files.files.name;
//                                            fs.rename(files.files.path,filePath);
//                                        }
//                                    })
//                                }
//                            }
//                        }
//                    })
//                }
//            });
//            console.log(bundle_id,app_ver,script_url);
//        } else {
//            //如果bundle_id和app_ver都不存在，那么，就删除这个文件，并告知用户，找不到对应的目录，上传失败。
//            console.log('找不到上传目录');
//            fs.unlink(files.files.path);
//            response.send('找不到上传目录');
//        }
//    });
//})



////JSPatch的项目实现8.1----实现完整的前端页面渲染，后端上传逻辑。
//
//var express = require('express');
//var app = express();
//var bodyParser = require('body-parser');
//app.use(bodyParser.json());
//app.use(bodyParser.urlencoded({extended:true}));
//
//var path = require('path');
//app.set('views',__dirname+'/views');
//app.set('view engine','html');
//app.engine('.html',require('ejs').__express);
//app.get('/patch/upload',function(request,response) {
//    response.render('iOSHotPatch1');
//});
//app.listen(8080);
//
//var formidable = require('formidable');
//var fs = require('fs');
//var redis = require('redis');
//var client = redis.createClient('6379','127.0.0.1');
//var util = require('./Util/util');
//app.post('/patch/upload',function(request,response) {
//    //console.log('hello,world');
//    var form = new formidable.IncomingForm();
//    form.encoding = 'utf-8';
//    form.uploadDir = 'source';
//    console.log('body = ',request.body);
////1.通过request的post请求体的bundle_id,app_ver来决定是否要上传数据。来决定上传数据的位置。
//form.parse(request,function(err,fields,files) {
//    if(err) {
//        console.log('error0 == ',err);
//        return response.redirect(303,'/error');
//    }
//    var bundle_id = fields.bundle_id;
//    var app_ver = fields.app_ver;
//
//    var appPath = __dirname + '/source/' + bundle_id;
//    var verPath = appPath + '/' + app_ver;
//    var filePath = verPath + '/' + files.files.name;
//    fs.rename(files.files.path,filePath,function(error) {
//        if(error) {
//            console.log('error4.1',error);
//            console.log('找不到上传目录');
//            fs.unlink(files.files.path);
//            response.send('找不到上传目录');
//        } else {
//            var fileMD5 = util.md5Digest(filePath);
//            util.cryptStr(fileMD5,verPath);
//            util.archiveData(verPath,'key',files.files.name);
//        }
//    });
//});
//})
////JSPatch的项目实现9 --- 设置发布接口
//app.post('/patch/release',function(request,response) {
//    if(request.secure) {
//        var bundle_id = request.body.bundle_id;
//        var app_ver = request.body.app_ver;
//        //var script_url = request.body.script_url;
//        var is_release = request.body.is_release;
//        if(bundle_id && app_ver &&  is_release) {
//            client.hgetall(bundle_id+'->'+app_ver,function(error,result) {
//                if(error || !result) {
//                    console.log('error6 == ',error);
//                    response.send('error');
//                } else {
//                    result.is_release = is_release;
//                    client.hmset(bundle_id+'->'+app_ver,result,function(error,result) {
//                        if(error) {
//                            console.log('error7 == ',error);
//                        } else {
//                            response.send('ok');
//                        }
//                    })
//                }
//            })
//        } else {
//            response.send('给的参数不全');
//        }
//    } else {
//        response.send('请用https请求');
//    }
//});



//
//JSPatch的项目实现9 --- 初始化所有信息
var express = require('express');
var app = express();
//app.use(express.limit('4M'));
app.listen(8080);
//必须要body-parser，不然无法解析request的body参数
var bodyParser = require('body-parser');
app.use(bodyParser.json());
//app.use(express.bodyp)
//现在暂时用x-www-form-urlencoded的表单形式，这个在postman里面对应的是post的body的x-www-form-urlencoded
app.use(bodyParser.urlencoded({extended:true}));
var fs = require('fs');
var https = require('https');
var options = {
   // key:fs.readFileSync(__dirname + '/ssl/meadowlark.pem'),
   // cert:fs.readFileSync(__dirname + '/ssl/meadowlark.crt')
	key:fs.readFileSync(__dirname + '/ssl/key3/server_nopwd.key'),
	cert:fs.readFileSync(__dirname + '/ssl/key3/server.crt')
};


https.createServer(options,app).listen(8081);
//https.createServer(options,app);

var redis = require('redis');
var client = redis.createClient('6379','127.0.0.1');
//监听错误
client.on('error',function(err) {
    console.log(err);
});
app.get('/',function(request,response) {
    response.send({'what' : '这是根目录'});
})

//JSPatch的项目实现10 --- 创建用户目录
app.post('/patch/addUserDirName',function(request,response) {
    if(!request.secure) {
        response.send('请使用https');
        return;
    }

    var userDirName = request.body.user_dir_name;
    console.log('dirname = ',userDirName);
    if(userDirName) {
        var userDirPath = __dirname + '/source/' + userDirName;
        fs.mkdir(userDirPath,0777,function(error) {
            if(error) {
                response.send('创建用户目录失败,或者用户目录已经存在');
            } else {
                response.send('用户目录创建成功');
            }
        })
    } else {
        response.send('user_dir_name为空，不能创建用户目录');
    }
});



//JSPatch的项目实现11 --- 添加App名字
app.post('/patch/addAppDirName',function(request,response) {
    if(!request.secure) {
        response.send('请使用https');
        return;
    }

    var userDirName = request.body.user_dir_name;
    var appDirName = request.body.bundle_id;
    console.log(userDirName,appDirName);
    if(userDirName && appDirName) {
        var appDirPath = __dirname + '/source/' + userDirName + '/' + appDirName;
        fs.mkdir(appDirPath,0777,function(error) {
            if(error) {
                response.send('创建用户目录失败，或者用户目录已经存在');
            } else {
                response.send('创建用户目录成功');
            }
        })
    } else {
        response.send('缺少user_dir_name，或者缺少bundle_id');
    }

});
//JSPatch的项目实现12 --- 添加App版本号
app.post('/patch/addVerDirName',function(request,response) {
    if(!request.secure) {
        response.send('请使用https');
        return;
    }
    var userDirName = request.body.user_dir_name;
    var appDirName = request.body.bundle_id;
    var verDirName = request.body.app_ver;
    console.log(userDirName,appDirName,verDirName);
    if(userDirName && appDirName && verDirName) {
        var verDirPath = __dirname + '/source/' + userDirName + '/' + appDirName + '/' + verDirName;
        fs.mkdir(verDirPath,0777,function(error) {
            if(error) {
                console.log(error);
                response.send('创建用户目录失败，或者用户目录已经存在');
            } else {

                var verTempDirName = verDirPath + '_tmp';
                fs.mkdir(verTempDirName,0777,function(error) {
                    if(error) {
                        console.log(error);
                        response.send('创建用户目录失败，或者用户目录已经存在1');
                    } else {
                        response.send('创建用户目录成功');
                    }
                });
            }
        })
    } else {
        response.send('缺少user_dir_name或者bundle_id或者app_ver');
    }
})

//JSPatch的项目实现13 -- 文件上传
app.set('views',__dirname+'/views');
app.set('view engine','html');
app.engine('.html',require('ejs').__express);
//先通过get请求，我们把html发到浏览器
//http://localhost:8080/patch/upload
//然后让浏览器发起post的https请求
app.get('/installCA',function(request,response) {
    if(!request.secure) {
        console.log('请使用https');
        response.send('请使用https');
        return;
    }

    response.send({'key' : 'value'});
})
app.get('/patch/upload',function(request,response) {
    console.log('hello,world');
    response.render('iOSHotPatch1');
});

var formidable = require('formidable');
var util = require('./Util/util');
app.post('/patch/upload',function(request,response) {
    if(!request.secure) {
        response.send('请使用https');
        return;
    }



    console.log('hello,wrold');
    var form = new formidable.IncomingForm();
    form.encoding = 'utf-8';
    form.uploadDir = 'source';
    form.maxFieldsSize = 1 * 1024 * 1024;
    //form.size
    //form.file.size = 1024 *1024;


    form.parse(request,function(error,fields,files) {
        if(error || !files.files) {

            //response.writeHead(200,{'content-type' : 'text/plain'});
            //response.end();
            response.send('数据太大了，不要了');
            response.end();
            form.error = true;
            return;

            //response.end(util2.inspect{msg:error});

            //response.send('上传数据失败');
        } else {
            var userDirName = fields.user_dir_name;
            var appDirName = fields.bundle_id;
            var verDirName = fields.app_ver;
            console.log('message == ',userDirName,appDirName,verDirName,files.files.name);

            //var isRelease = fields.isRelease;
            if(userDirName && appDirName && verDirName) {
                var verDirPath = __dirname + '/source/' + userDirName + '/' + appDirName + '/' + verDirName;
                var verTempDirPath = verDirPath + '_tmp';
                var fileName = Date.now() + '_' + userDirName + '_' + appDirName + '_' + verDirName + '_' + files.files.name;
                var newFilePath = verTempDirPath + '/' + fileName;


                    //files.files.name;
                fs.rename(files.files.path,newFilePath,function(error) {
                    if(error) {
                        fs.unlink(files.files.path);
                        response.send('找不到上传目录');
                    } else {
                        var fileMD5 = util.md5Digest(newFilePath);
                        var key = userDirName + '/' + appDirName + '/' + verDirName;
                        client.hgetall(key,function(error,result) {
                            console.log('error and result',error,result);
                            var keyFilePath = verDirPath + '/key';
                            if(error || !result) {

                                util.cryptStr(fileMD5,keyFilePath);
                                //util.archiveData(verDirPath,'key',files.files.name);
                                util.archiveData(verDirPath+'/patch.zip',newFilePath,keyFilePath,files.files.name,'key');

                                var info = {};
                                info.md5 = fileMD5;
                                info.errorCount = '0';
                                info.updateCount = '0';
                                info.updateTime = Date.now();
                                info.patchRelease = 'no';//先默认是yes
                                info.scriptName = 'patch.zip';
                                client.hmset(key,info,function(error,result) {
                                    if(error) {
                                        console.log('文件信息保存在redis失败');
                                    } else {
                                        console.log('文件信息成功保存在redis上');
                                    }
                                })
                                response.send('首次上传到指定的目录');
                            } else {
                                if(result.md5 !== fileMD5) {
                                    util.cryptStr(fileMD5,keyFilePath);
                                    //util.archiveData(verDirPath,'key',files.files.name);
                                    util.archiveData(verDirPath+'/patch.zip',newFilePath,keyFilePath,files.files.name,'key');
                                    result.md5 = fileMD5;
                                    result.errorCount = '0';
                                    ++result.updateCount;
                                    result.updateTime = Date.now();
                                    result.patchRelease = 'no';//先默认是yes
                                    result.scriptName = 'patch.zip';
                                    console.log('result ==',result);

                                    console.log('2目录下有',util.file(verTempDirPath));

                                    var fileArray = util.file(verTempDirPath);
                                    if(fileArray.length > 30) {

                                        var earlierFile = util.earlierFile(fileArray);
                                        console.log('earlierFile = ',earlierFile);
                                        var earlierFilePath = verTempDirPath + '/' + earlierFile;
                                        console.log('准备删除文件2');
                                        fs.unlink(earlierFilePath,function(error) {
                                            if(error) {
                                                console.log('删除早期文件错误');
                                            }
                                        })
                                    }

                                    client.hmset(key,result,function(error,result) {
                                        if(error) {
                                            console.log('文件保存在redis失败');
                                        } else {
                                            console.log('文件信息成功保存在redis上');
                                        }
                                    })
                                    response.send('再次上传文件到指定的目录');
                                } else {
                                    fs.unlink(newFilePath,function(error) {
                                        if(error) {
                                            console.log('error ==',error);
                                        }
                                    });
                                    response.send('redis错误了，或者不要上传一样的数据');
                                }
                            }
                        });

                    }
                })
            } else {
                response.send('user_dir_name，bundle_id，app_ver给的参数不全');
            }
        }
    })




    //var i = 0;
    form.on('progress',function(received,expected) {
        console.log(received,expected);
        if(received>1024 * 1024) {
            //response.end();
            console.log('数据超出一兆了，不要这些数据了');
            form.emit('error','file is too large');
            //return;
        }
    })

    form.on('error',function(error) {
        console.log('出错了，错误是 ',error);
    })

    form.on('aborted',function() {
        console.log('aborted ====== ');
    })
    form.on('end',function() {
        console.log('end =======');
    })


})

//JSPatch的项目实现14 -- 发布补丁
app.post('/patch/release',function(request,response) {
    console.log('html的信息发过来了');
    if(!request.secure) {
        response.send('请使用https');
        return;
    }
    //console.log('hello,world');

    var userDirName = request.body.user_dir_name;
    var appDirName = request.body.bundle_id;
    var verDirName = request.body.app_ver;
    var patchRelease = request.body.patch_release;
    console.log(userDirName,appDirName,verDirName,patchRelease);
    if(userDirName && appDirName && verDirName && patchRelease) {
        var key = userDirName + '/' + appDirName + '/' + verDirName;
        client.hgetall(key,function(error,result) {
            if(error || !result) {
                response.send('给的路径不对，或者redis中没有这个信息');
            } else {
                console.log(result);
                result.patchRelease = patchRelease;
                console.log(result);
                client.hmset(key,result,function(error,result) {
                    if(error) {
                        response.send('发布补丁失败');
                    } else {
                        response.send('发布补丁成功');
                    }
                })
            }
        })
    } else {
        response.send('user_dir_name&& bundle_id && app_ver && patch_release 有没给全的');
    }
})

//JSPatch的项目实现15 -- 删除补丁

app.post('/patch/delete',function(request,response) {
    console.log('delete');
    if(!request.secure) {
        response.send('请使用https');
        return;
    }
    var userDirName = request.body.user_dir_name;
    var appDirName = request.body.bundle_id;
    var verDirName = request.body.app_ver;
    var scriptName = request.body.script_url;
    console.log(userDirName,appDirName,verDirName,scriptName);
    if(userDirName && appDirName && verDirName) {
        //var verDirPath = __dirname
        var verDirPath = __dirname + '/source/' + userDirName + '/' + appDirName + '/' + verDirName;
        fs.unlink(verDirPath+'/'+'patch.zip',function(error) {
            if(error) {
                console.log('删除失败');
                response.send('路径不对，删除失败');
            } else {
                console.log('删除成功');
                var key = userDirName + '/' + appDirName + '/' + verDirName ;
                client.hgetall(key,function(error,result) {
                    if(error) {
                        console.log('redis错误 ：',error);
                    } else {
                        if(result) {
                            console.log('已经删除这些数据：',result);
                            client.del(key);
                        } else {
                            console.log('没有数据');
                        }
                    }
                });
                response.send('删除成功');
            }
        })


    } else {
        response.send('user_dir_name,bundle_id,app_ver信息没给全');
    }
})

//JSPatch的项目实现16 -- 和客户端同步
app.post('/patch/updinfo',function(request,response) {

    console.log('updinfo');
    if(!request.secure) {
        response.send('请使用https');
        return;
    }

    var userDirName = request.body.user_dir_name;
    var appDirName = request.body.bundle_id;
    var verDirName = request.body.app_ver;
    var scriptName = request.body.script_url;
    var scriptMD5 = request.body.script_md5;
    var is_js_ok = request.body.is_js_ok;


    console.log(userDirName,appDirName,verDirName,scriptName,scriptMD5,is_js_ok);
    if(userDirName && appDirName && verDirName) {
        var key = userDirName + '/' + appDirName + '/' + verDirName;
        client.hgetall(key,function(error,result) {
            if(error) {
                response.send('redis数据库出错了');
            } else {
                if(result) {
                    console.log('result = ',result);
                    if (result.patchRelease === 'no') {
                        console.log(('has_update = false,need_clean = false'));
                        response.send({'has_update' : false,'need_clean' : true,'script_md5' : scriptMD5,'script_url' : scriptName});
                        return;
                    } else if(result.patchRelease === 'yes') {
                        if(scriptName && scriptMD5) {
                            if(result.md5 === scriptMD5) {
                                if(is_js_ok === 'no') { //这里要看一下
                                    ++result.errorCount;
                                    console.log(result.errorCount);
                                    client.hmset(key,result,function(error,result) {
                                        if(error) {
                                            console.log('统计错误次数失败');
                                        } else {
                                            console.log('统计错误次数成功');
                                        }
                                    });
                                }
                                response.send({'has_update' : false,'need_clean' : false,'script_md5' : scriptMD5,'script_url' : scriptName});
                            } else {
                                response.send({'has_update' : true,'need_clean' : true,'script_md5' :result.md5,'script_url' : result.scriptName});
                            }
                        } else {
                            response.send({'has_update' : true,'need_clean' : true,'script_md5' : result.md5,'script_url' : result.scriptName});
                        }
                    }

                } else {
                    response.send({'has_update' : false,'need_clean' : true,'script_md5' : '','script_url' : ''});
                }
            }
        })
    } else {
        response.send('user_dir_name && bundle_id && app_ver && script_url && script_md5信息没给全');
    }
})

app.get('/patch/download_app_js',function(request,response) {
    console.log('download_app_js');
    if(!request.secure) {
	response.send('请使用https');
	return;
    }
    var options = {
    	root:__dirname,
	dotfiles:'deny',
	headers:{
	   'x-timestamp' : Date.now(),
  	   'x-sent' : true
	}
    };
    response.sendFile('app.js',options,function(error) {
	if(error) {
	   console.log(error);	
	}
    });
});

app.get('/patch/download_server_file',function(request,response) {
    console.log('download_server_file');
    if(!request.secure) {
        response.send('请使用https');
        return;
    }
    var options = {
        root : '/etc/nginx',
        dotfiles:'deny',
        headers:{
            'x-timestamp' : Date.now(),
            'x-sent' : true
        }
    };
    response.sendFile('server.crt',options,function(error) {
        if(error) {
            console.log(error);
        }
    })
})

app.get('/patch/download_server_file1',function(request,response) {
    console.log('download_server_file');
    if(!request.secure) {
        response.send('请使用https');
        return;
    }
    var options = {
        root : '/etc/nginx',
        dotfiles:'deny',
        headers:{
            'x-timestamp' : Date.now(),
            'x-sent' : true
        }
    };
    response.sendFile('server_nopwd.key',options,function(error) {
        if(error) {
            console.log(error);
        }
    })
})

//JSPatch的项目实现17 -- 下载补丁
app.post('/patch/download',function(request,response) {
    console.log('download');

    if(!request.secure) {
        response.send('请使用https');
        return;
    }

    var userDirName = request.body.user_dir_name;
    var appDirName = request.body.bundle_id;
    var verDirName = request.body.app_ver;
    var scriptName = request.body.script_url;
    console.log(userDirName,appDirName,verDirName,scriptName);
    //var userDirName = 'liaozhongru';
    //var appDirName = 'xuexibao';
    //var verDirName = 'v3.4';
    //var scriptName = 'patch.zip';
    var key = userDirName + '/' + appDirName + '/' + verDirName;
    client.hgetall(key,function(error,result) {
        if(error || !result) {
            response.send('找不到指定的文件');
        } else {
            //console.log(result.scriptName);
            console.log(result);
            if(result.scriptName === scriptName) {
                var options = {
                    root : __dirname + '/source/' + userDirName + '/' + appDirName + '/' + verDirName,
                    dotfiles:'deny',
                    headers:{
                        'x-timestamp' : Date.now(),
                        'x-sent' : true
                    }
                };
                response.sendFile(scriptName,options,function(error) {
                    if(error) {
                        console.log(error);
                    }
                    console.log('发送文件成功');
                })
            } else {
                response.send('没有找到指定的文件');
            }
        }
    })
})
