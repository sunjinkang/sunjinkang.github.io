// console(控制台)
// const fs = require('fs');
// const { Console } = require('console');
// const output = fs.createWriteStream('./stdout.log');
// const errorOutput = fs.createWriteStream('./stderr.log');
// // 自定义的简单记录器
// const logger = new Console(output, errorOutput);
// // 像 console 一样使用
// // const count = 5;
// // logger.log('count: %d', count);
// // // stdout.log 中打印: count 5
// // logger.error(new Error(`error: ${count}`));
// // logger.warn('test warn');

// console.assert(true, 'does nothing');
// // 通过
// console.assert(false, 'Whoops %s', "didn't work");
// Assertion failed: Whoops didn't work

// const crypto = require('crypto');

// const secret = 'abcdefg';
// const hash = crypto
//   .createHmac('sha256', secret)
//   .update('I love cupcakes')
//   .digest('hex');
// console.log(hash);
// c0fa1bc00531bd78ef38c628449c5102aeabd49b5dc3a2a516ea6ea959d6658e

// const cert = require('crypto').Certificate();
// const spkac = getSpkacSomehow();
// const challenge = cert.exportChallenge(spkac);
// console.log(challenge.toString('utf8'));

// const crypto = require('crypto');
// const cipher = crypto.createCipher('aes192', 'a password');

// let encrypted = '';
// cipher.on('readable', () => {
//   const data = cipher.read();
//   if (data) encrypted += data.toString('hex');
// });
// cipher.on('end', () => {
//   console.log(encrypted);
//   // Prints: ca981be48e90867604588e75d04feabb63cc007a8f8ad89b10616ed84d815504
// });

// cipher.write('some clear text data');
// cipher.end();

// const crypto = require('crypto');
// const fs = require('fs');
// const cipher = crypto.createCipher('aes192', 'a password');

// const input = fs.createReadStream('test.js');
// const output = fs.createWriteStream('test.enc');

// input.pipe(cipher).pipe(output);

// const crypto = require('crypto');
// const cipher = crypto.createCipher('aes192', 'a password');

// let encrypted = cipher.update('some clear text data', 'utf8', 'hex');
// encrypted += cipher.final('hex');
// console.log(encrypted);
// Prints: ca981be48e90867604588e75d04feabb63cc007a8f8ad89b10616ed84d815504

// Decipher
// 使用Decipher对象作为流
// const crypto = require('crypto');
// const decipher = crypto.createDecipher('aes192', 'a password');

// let decrypted = '';
// decipher.on('readable', () => {
//   const data = decipher.read();
//   if (data) decrypted += data.toString('utf8');
// });
// decipher.on('end', () => {
//   console.log(decrypted);
//   // Prints: some clear text data
// });

// const encrypted =
//   'ca981be48e90867604588e75d04feabb63cc007a8f8ad89b10616ed84d815504';
// decipher.write(encrypted, 'hex');
// decipher.end();

// 使用Decipher和管道流
// const crypto = require('crypto');
// const fs = require('fs');
// const decipher = crypto.createDecipher('aes192', 'a password');

// const input = fs.createReadStream('test.enc');
// const output = fs.createWriteStream('test.js');

// input.pipe(decipher).pipe(output);

// 使用decipher.update()和decipher.final()方法
// const crypto = require('crypto');
// const decipher = crypto.createDecipher('aes192', 'a password');

// const encrypted =
//   'ca981be48e90867604588e75d04feabb63cc007a8f8ad89b10616ed84d815504';
// let decrypted = decipher.update(encrypted, 'hex', 'utf8');
// decrypted += decipher.final('utf8');
// console.log(decrypted);
// Prints: some clear text data

// DiffieHellman
// const crypto = require('crypto');
// const assert = require('assert');

// // Generate Alice's keys...
// const alice = crypto.createDiffieHellman(2048);
// const aliceKey = alice.generateKeys();

// // Generate Bob's keys...
// const bob = crypto.createDiffieHellman(alice.getPrime(), alice.getGenerator());
// const bobKey = bob.generateKeys();

// // Exchange and generate the secret...
// const aliceSecret = alice.computeSecret(bobKey);
// const bobSecret = bob.computeSecret(aliceKey);

// // OK
// assert.strictEqual(aliceSecret.toString('hex'), bobSecret.toString('hex'));

// ECDH
// const crypto = require('crypto');
// const assert = require('assert');

// // Generate Alice's keys...
// const alice = crypto.createECDH('secp521r1');
// const aliceKey = alice.generateKeys();

// // Generate Bob's keys...
// const bob = crypto.createECDH('secp521r1');
// const bobKey = bob.generateKeys();

// // Exchange and generate the secret...
// const aliceSecret = alice.computeSecret(bobKey);
// const bobSecret = bob.computeSecret(aliceKey);

// assert.strictEqual(aliceSecret.toString('hex'), bobSecret.toString('hex'));
// // OK

// 使用hash对象作为流
// const crypto = require('crypto');
// const hash = crypto.createHash('sha256');
// hash.on('readable', () => {
//   const data = hash.read();
//   if (data) {
//     console.log(data.toString('hex'));
//     // Prints:
//     //   6a2da20943931e9834fc12cfe5bb47bbd9ae43489a30726962b576f4e3993e50
//   }
// });
// hash.write('some data to hash');
// hash.end();

// 使用 Hash 和管道流
// const crypto = require('crypto');
// const fs = require('fs');
// const hash = crypto.createHash('sha256');
// const input = fs.createReadStream('test.js');
// input.pipe(hash).pipe(process.stdout);

// 使用hash.update()和hash.digest()
// const crypto = require('crypto');
// const hash = crypto.createHash('sha256');
// hash.update('some data to hash');
// console.log(hash.digest('hex'));
// Prints:
//   6a2da20943931e9834fc12cfe5bb47bbd9ae43489a30726962b576f4e3993e50

// 使用Hmac对象作为流:
// const crypto = require('crypto');
// const hmac = crypto.createHmac('sha256', 'a secret');
// hmac.on('readable', () => {
//   const data = hmac.read();
//   if (data) {
//     console.log(data.toString('hex'));
//     // Prints:
//     //   7fd04df92f636fd450bc841c9418e5825c17f33ad9c87c518115a45971f7f77e
//   }
// });
// hmac.write('some data to hash');
// hmac.end();

// 使用hmac.update()和hmac.digest()方法
// const crypto = require('crypto');
// const hmac = crypto.createHmac('sha256', 'a secret');
// hmac.update('some data to hash');
// console.log(hmac.digest('hex'));

// 使用“符号”对象作为流:
// const crypto = require('crypto');
// const sign = crypto.createSign('SHA256');
// sign.write('some data to sign');
// sign.end();
// const privateKey = getPrivateKeySomehow();
// console.log(sign.sign(privateKey, 'hex'));

// console.log(crypto.getHashes());
// [
//  'RSA-MD5',
//  'RSA-RIPEMD160',
//  'RSA-SHA1',
//  'RSA-SHA1-2',
//  'RSA-SHA224',
//  'RSA-SHA256',
//  'RSA-SHA3-224',
//  'RSA-SHA3-256',
//  'RSA-SHA3-384',
//  'RSA-SHA3-512',
//  'RSA-SHA384',
//  'RSA-SHA512',
//  'RSA-SHA512/224',
//  'RSA-SHA512/256',
//  'RSA-SM3',
//  'blake2b512',
//  'blake2s256',
//  'id-rsassa-pkcs1-v1_5-with-sha3-224',
//  'id-rsassa-pkcs1-v1_5-with-sha3-256',
//  'id-rsassa-pkcs1-v1_5-with-sha3-384',
//  'id-rsassa-pkcs1-v1_5-with-sha3-512',
//  'md5',
//  'md5-sha1',
//  'md5WithRSAEncryption',
//  'ripemd',
//  'ripemd160',
//  'ripemd160WithRSA',
//  'rmd160',
//  'sha1',
//  'sha1WithRSAEncryption',
//  'sha224',
//  'sha224WithRSAEncryption',
//  'sha256',
//  'sha256WithRSAEncryption',
//  'sha3-224',
//  'sha3-256',
//  'sha3-384',
//  'sha3-512',
//  'sha384',
//  'sha384WithRSAEncryption',
//  'sha512',
//  'sha512-224',
//  'sha512-224WithRSAEncryption',
//  'sha512-256',
//  'sha512-256WithRSAEncryption',
//  'sha512WithRSAEncryption',
//  'shake128',
//  'shake256',
//  'sm3',
//  'sm3WithRSAEncryption',
//  'ssl3-md5',
//  'ssl3-sha1'
// ]

// crypto.pbkdf2
// const crypto = require('crypto');
// crypto.pbkdf2('secret', 'salt', 100000, 64, 'sha512', (err, derivedKey) => {
//   if (err) throw err;
//   console.log(derivedKey.toString('hex'));
//   // 3745e482c6e0ade35da10139e797157f4a5da669dad7d5da88ef87e47471cc47ed941c7ad618e827304f083f8707f12b7cfdd5f489b782f10cc269e3c08d59ae
// });
// randomBytes Asynchronous
// const crypto = require('crypto');
// crypto.randomBytes(256, (err, buf) => {
//   if (err) throw err;
//   console.log(`${buf.length} bytes of random data: ${buf.toString('hex')}`);
//   //   256 bytes of random data: 25f6d5add831f01b3ede1995de62dcdaf30a282a1b3a4b9e4a40ab
//   // 3ae25d68565f7f2c233c5fea5e59eaaf45e42213fa97913070b1bc79f2530b49b7396ad0e3b91e44
//   // 7ebe833b9bee2239a5b099e87c3584384ebe695083765504362a64de09eb65db12c5afd997781c83
//   // de41ab2bbe37a6a7188e495c09cd47acbaf1e30ce156a0dbae1a4bb8c6dda4edf993dd896c9ac76d
//   // e08784833c0afaa8e89f509d149e82427af478a867d0a96c68c193b9c98323b0fa96bb61b0205b19
//   // 9b6df148e92df066d06e0f8691950054c55e0788c3feb69d6c976e3ebe3c6cdc474732c4017504fc
//   // aef9b740b786d5eb9834f5e5dadc7e00c5cf8b865a6087610bfdc8aeb6
// });

// Synchronous
// const buf = crypto.randomBytes(256);
// console.log(`${buf.length} bytes of random data: ${buf.toString('hex')}`);

// randomFillSync
// const crypto = require('crypto');
// const buf = Buffer.alloc(10);
// console.log(crypto.randomFillSync(buf).toString('hex'));
// // 44c968af68492ff63978

// crypto.randomFillSync(buf, 5);
// console.log(buf.toString('hex'));
// // 44c968af68fd74439eb2

// // The above is equivalent to the following:
// crypto.randomFillSync(buf, 5, 5);
// console.log(buf.toString('hex'));
// // 44c968af685a9c630117

// randomFill
// const crypto = require('crypto');
// const buf = Buffer.alloc(10);
// crypto.randomFill(buf, (err, buf) => {
//   if (err) throw err;
//   console.log(buf.toString('hex'));
//   // 83a3fce8f37ea24bd7e8
// });

// crypto.randomFill(buf, 5, (err, buf) => {
//   if (err) throw err;
//   console.log(buf.toString('hex'));
//   // 83a3fce8f37ea24bd7e8
// });

// // The above is equivalent to the following:
// crypto.randomFill(buf, 5, 5, (err, buf) => {
//   if (err) throw err;
//   console.log(buf.toString('hex'));
//   // 83a3fce8f37ea24bd7e8
// });

// DNS
// const dns = require('dns');

// dns.lookup('nodejs.org', (err, address, family) => {
//   console.log('IP 地址: %j 地址族: IPv%s', address, family);
// });

// const dns = require('dns');

// dns.resolve4('iana.org', (err, addresses) => {
//   if (err) throw err;

//   console.log(`IP 地址: ${JSON.stringify(addresses)}`);

//   addresses.forEach((a) => {
//     dns.reverse(a, (err, hostnames) => {
//       if (err) {
//         throw err;
//       }
//       console.log(`IP 地址 ${a} 逆向解析到域名: ${JSON.stringify(hostnames)}`);
//     });
//   });
// });

// const dns = require('dns');
// const resolver = new dns.Resolver();
// resolver.setServers(['4.4.4.4']);
// // This request will use the server at 4.4.4.4, independent of global settings.
// resolver.resolve4('iana.org', (err, addresses) => {
//   // ...
// });
// resolver.cancel();
// console.log(dns.CANCELLED);
// // ECANCELLED
// console.log(dns.getServers());
// // [ '192.168.238.1' ]

// const dns = require('dns');
// const options = {
//   family: 6,
//   hints: dns.ADDRCONFIG | dns.V4MAPPED,
// };
// dns.lookup('example.com', options, (err, address, family) =>
//   console.log('address: %j family: IPv%s', address, family)
// );
// // address: "::ffff:93.184.216.34" family: IPv6

// // When options.all is true, the result will be an Array.
// options.all = true;
// dns.lookup('example.com', options, (err, addresses) =>
//   console.log('addresses: %j', addresses)
// );
// // addresses: [{"address":"::ffff:93.184.216.34","family":6}]

// lookupService
// const dns = require('dns');
// dns.lookupService('127.0.0.1', 22, (err, hostname, service) => {
//   console.log(hostname, service);
//   // DESKTOP-894BKU0 ssh
// });

// dns.resolveCname('www.baidu.com', (err, hostname) => {
//   console.log(hostname);
//   // [ 'www.a.shifen.com' ]
// });
// dns.resolveMx('google.com', (err, hostname) => {
//   console.log(hostname);
//   // [ { exchange: 'smtp.google.com', priority: 10 } ]
// });
// dns.resolveNaptr('google.com', (err, hostname) => {
//   console.log(hostname);
//   // undefined
// });
// dns.resolveSoa('google.com', (err, hostname) => {
//   console.log(hostname);
//   // {
//   //   nsname: 'ns1.google.com',
//   //   hostmaster: 'dns-admin.google.com',
//   //   serial: 500503917,
//   //   refresh: 900,
//   //   retry: 900,
//   //   expire: 1800,
//   //   minttl: 60
//   // }
// });
// dns.resolveSrv('google.com', (err, hostname) => {
//   console.log(err);
//   // code: 'ENODATA',
//   console.log(hostname);
//   // undefined
// });
// dns.resolveTxt('google.com', (err, hostname) => {
//   console.log(hostname);
// [
//   [ 'v=spf1 include:_spf.google.com ~all' ],
//   [
//     'google-site-verification=wD8N7i1JTNTkezJ49swvWW48f8_9xveREV4oB-0Hf5o'
//   ],
//   [ 'docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e' ],
//   [ 'facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95' ],
//   [ 'onetrust-domain-verification=de01ed21f2fa4d8781cbc3ffb89cf4ef' ],
//   [
//     'webexdomainverification.8YX6G=6e6922db-e3e6-4a36-904e-a805c28087fa'
//   ],
//   [
//     'atlassian-domain-verification=5YjTmWmjI92ewqkx2oXmBaD60Td9zWon9r6eakvHX6B77zzkFQto8PQ9QsKnbf4I'
//   ],
//   [ 'apple-domain-verification=30afIBcvSuDV2PLX' ],
//   [ 'MS=E4A68B9AB2BB9670BCE15412F62916164C0B20BB' ],
//   [
//     'globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8='
//   ],
//   [
//     'google-site-verification=TV9-DBe4R80X4v0M4U_bd_J9cpOJM0nikft0jAgjmsQ'
//   ],
//   [ 'docusign=1b0a6754-49b1-4db5-8540-d2c12664b289' ]
// ]
// });

// dns.resolveAny('google.com', (err, hostname) => {
//   console.log(hostname);
//   // [
//   //   { address: '142.251.43.14', ttl: 526, type: 'A' },
//   //   { value: 'ns2.google.com', type: 'NS' },
//   //   { value: 'ns1.google.com', type: 'NS' },
//   //   { value: 'ns4.google.com', type: 'NS' },
//   //   { value: 'ns3.google.com', type: 'NS' },
//   //   {
//   //     entries: [
//   //       'google-site-verification=wD8N7i1JTNTkezJ49swvWW48f8_9xveREV4oB-0Hf5o'
//   //     ],
//   //     type: 'TXT'
//   //   },
//   //   {
//   //     entries: [ 'docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e' ],
//   //     type: 'TXT'
//   //   },
//   //   {
//   //     entries: [ 'facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95' ],
//   //     type: 'TXT'
//   //   },
//   //   {
//   //     entries: [ 'onetrust-domain-verification=de01ed21f2fa4d8781cbc3ffb89cf4ef' ]
//   // ,
//   //     type: 'TXT'
//   //   },
//   //   {
//   //     entries: [
//   //       'webexdomainverification.8YX6G=6e6922db-e3e6-4a36-904e-a805c28087fa'
//   //     ],
//   //     type: 'TXT'
//   //   },
//   //   {
//   //     entries: [
//   //       'atlassian-domain-verification=5YjTmWmjI92ewqkx2oXmBaD60Td9zWon9r6eakvHX6B77zzkFQto8PQ9QsKnbf4I'
//   //     ],
//   //     type: 'TXT'
//   //   },
//   //   {
//   //     entries: [ 'apple-domain-verification=30afIBcvSuDV2PLX' ],
//   //     type: 'TXT'
//   //   },
//   //   {
//   //     entries: [ 'MS=E4A68B9AB2BB9670BCE15412F62916164C0B20BB' ],
//   //     type: 'TXT'
//   //   },
//   //   {
//   //     entries: [
//   //       'globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8='
//   //     ],
//   //     type: 'TXT'
//   //   },
//   //   {
//   //     entries: [
//   //       'google-site-verification=TV9-DBe4R80X4v0M4U_bd_J9cpOJM0nikft0jAgjmsQ'
//   //     ],
//   //     type: 'TXT'
//   //   },
//   //   {
//   //     entries: [ 'docusign=1b0a6754-49b1-4db5-8540-d2c12664b289' ],
//   //     type: 'TXT'
//   //   },
//   //   { entries: [ 'v=spf1 include:_spf.google.com ~all' ], type: 'TXT' }
//   // ]
// });

// dns.reverse('58.221.60.236', (err, hostname) => {
//   console.log(err);
//   //  code: 'ENOTFOUND'
//   console.log(hostname);
//   // undefined
// });

// function MyError() {
//   Error.stackTraceLimit = 2;
//   // Error.captureStackTrace(this);
//   Error.captureStackTrace(this, MyError);
// }

// console.log(new MyError().stack);
// const process = require('process');
// var EventEmitter = require('events').EventEmitter;
// var life = new EventEmitter();
// function water(who) {
//   console.log('给 ' + who + ' 倒水');
// }
// life.on('Miss', water);
// life.on('Miss', function (who) {
//   // setImmediate(() => {
//   //   console.log('给 ' + who + ' 按摩');
//   // });
//   process.nextTick(() => {
//     console.log('给 ' + who + ' 按摩');
//   });
// });
// life.on('Miss', function (who) {
//   console.log('给 ' + who + ' 聊天');
// });
// life.removeListener('Miss', water);
// life.emit('Miss', '汉子');
// console.log(life.listeners('Miss').length);

// var EventEmitter = require('events').EventEmitter;
// var myEmitter = new EventEmitter();
// // let m = 0;
// // myEmitter.on('event', () => {
// //   console.log(++m);
// // });
// // myEmitter.emit('event');
// // // 打印: 1
// // myEmitter.emit('event');
// // // 打印: 2

// let m = 0;
// myEmitter.once('event', () => {
//   console.log(++m);
// });
// myEmitter.emit('event');
// // 打印: 1
// myEmitter.emit('event');
// // 忽略

// var EventEmitter = require('events').EventEmitter;
// var myEmitter = new EventEmitter();
// // 只处理一次，所以不会无限循环
// myEmitter.once('newListener', (event, listener) => {
//   if (event === 'event') {
//     // 在开头插入一个新的监听器
//     myEmitter.on('event', () => {
//       console.log('B');
//     });
//   }
// });
// myEmitter.on('event', () => {
//   console.log('A');
// });
// myEmitter.emit('event');
// // 打印:
// //   B
// //   A

// const EventEmitter = require('events');
// const myEE = new EventEmitter();
// myEE.on('foo', () => {});
// myEE.on('bar', () => {});

// const sym = Symbol('symbol');
// myEE.on(sym, () => {});

// console.log(myEE.eventNames());
// // [ 'foo', 'bar', Symbol(symbol) ]

// const myEE = new EventEmitter();
// myEE.on('foo', () => console.log('a'));
// myEE.prependListener('foo', () => console.log('b'));
// myEE.emit('foo');
// b
// a

// const myEE = new EventEmitter();
// myEE.once('foo', () => console.log('a'));
// myEE.prependOnceListener('foo', () => console.log('b'));
// myEE.emit('foo');
// myEE.emit('foo');
// b
// a

// const fs = require('fs');
// // fs.appendFile('message.txt', 'data to append', 'utf8', (err) => {
// //   if (err) throw err;
// //   console.log('The "data to append" was appended to file!');
// // });

// try {
//   fs.appendFileSync(
//     'message.txt',
//     '/n data to append wfqefqfqfwqefwqf',
//     'utf8'
//   );
//   console.log('The "data to append" was appended to file!');
// } catch (err) {
//   /* Handle the error */
// }

// const http = require('http');
// const options = {
//   host: 'nodejs.cn',
// };
// const req = http.get(options);
// req.end();
// req.once('response', (res) => {
//   const ip = req.socket.localAddress;
//   const port = req.socket.localPort;
//   console.log(`你的IP地址是 ${ip}，你的源端口是 ${port}。`);
//   // consume response object
// });

// console.log(http.METHODS);
// [
//   'ACL',         'BIND',       'CHECKOUT',
//   'CONNECT',     'COPY',       'DELETE',
//   'GET',         'HEAD',       'LINK',
//   'LOCK',        'M-SEARCH',   'MERGE',
//   'MKACTIVITY',  'MKCALENDAR', 'MKCOL',
//   'MOVE',        'NOTIFY',     'OPTIONS',
//   'PATCH',       'POST',       'PROPFIND',
//   'PROPPATCH',   'PURGE',      'PUT',
//   'REBIND',      'REPORT',     'SEARCH',
//   'SOURCE',      'SUBSCRIBE',  'TRACE',
//   'UNBIND',      'UNLINK',     'UNLOCK',
//   'UNSUBSCRIBE'
// ]

// console.log(http.STATUS_CODES);
// {
//   '100': 'Continue',
//   '101': 'Switching Protocols',
//   '102': 'Processing',
//   '103': 'Early Hints',
//   '200': 'OK',
//   '201': 'Created',
//   '202': 'Accepted',
//   '203': 'Non-Authoritative Information',
//   '204': 'No Content',
//   '205': 'Reset Content',
//   '206': 'Partial Content',
//   '207': 'Multi-Status',
//   '208': 'Already Reported',
//   '226': 'IM Used',
//   '300': 'Multiple Choices',
//   '301': 'Moved Permanently',
//   '302': 'Found',
//   '303': 'See Other',
//   '304': 'Not Modified',
//   '305': 'Use Proxy',
//   '307': 'Temporary Redirect',
//   '308': 'Permanent Redirect',
//   '400': 'Bad Request',
//   '401': 'Unauthorized',
//   '402': 'Payment Required',
//   '403': 'Forbidden',
//   '404': 'Not Found',
//   '405': 'Method Not Allowed',
//   '406': 'Not Acceptable',
//   '407': 'Proxy Authentication Required',
//   '408': 'Request Timeout',
//   '409': 'Conflict',
//   '410': 'Gone',
//   '411': 'Length Required',
//   '412': 'Precondition Failed',
//   '413': 'Payload Too Large',
//   '414': 'URI Too Long',
//   '415': 'Unsupported Media Type',
//   '416': 'Range Not Satisfiable',
//   '417': 'Expectation Failed',
//   '418': "I'm a Teapot",
//   '421': 'Misdirected Request',
//   '422': 'Unprocessable Entity',
//   '423': 'Locked',
//   '424': 'Failed Dependency',
//   '425': 'Too Early',
//   '426': 'Upgrade Required',
//   '428': 'Precondition Required',
//   '429': 'Too Many Requests',
//   '431': 'Request Header Fields Too Large',
//   '451': 'Unavailable For Legal Reasons',
//   '500': 'Internal Server Error',
//   '501': 'Not Implemented',
//   '502': 'Bad Gateway',
//   '503': 'Service Unavailable',
//   '504': 'Gateway Timeout',
//   '505': 'HTTP Version Not Supported',
//   '506': 'Variant Also Negotiates',
//   '507': 'Insufficient Storage',
//   '508': 'Loop Detected',
//   '509': 'Bandwidth Limit Exceeded',
//   '510': 'Not Extended',
//   '511': 'Network Authentication Required'
// }

// console.log(__filename);
// // C:\Users\xxx\source\nodejs\file\test.js
// console.log(__dirname);
// // C:\Users\xxx\source\nodejs\file

// import fs, { readFileSync } from 'node:fs';
// import { syncBuiltinESMExports } from 'node:module';
// import { Buffer } from 'node:buffer';

// fs.readFileSync = () => Buffer.from('Hello, ESM');
// syncBuiltinESMExports();
// console.log(fs.readFileSync === readFileSync);
// // true

// import os from 'node:os';
// console.log(os.platform());
// // win32
// console.log(os.release());
// // 10.0.19044
// console.log(os.EOL);
// // \r\n
// console.log(os.arch());
// // x64
// console.log(os.tmpdir());
// // C:\Users\sunji\AppData\Local\Temp
// console.log(os.totalmem());
// // 8424386560
// console.log(os.type());
// // Windows_NT
// console.log(os.uptime());
// 334498
// console.log(os.userInfo());
// console.log(os.version());

// import { report } from 'process';
// console.log(report);
// console.log(report.writeReport('../testReport.json'));
// console.log(report.resourceUsage());

// import process from 'node:process';

// if (process.getegid && process.setegid) {
//   console.log(`Current gid: ${process.getegid()}`);
//   try {
//     process.setegid(501);
//     console.log(`New gid: ${process.getegid()}`);
//   } catch (err) {
//     console.log(`Failed to set gid: ${err}`);
//   }
// }
// console.log(process.title);
// C:\Windows\System32\cmd.exe - node  test.js
// process.title = 'qwer';
// console.log(process.title);
// qwer

// console.log(process.uptime());
// // 0.0754413
// console.log(process.version);
// // v18.12.1
// console.log(process.versions.node);
// // 18.12.1
// console.log(process.versions);
// {
//  node: '18.12.1',
//  v8: '10.2.154.15-node.12',
//  uv: '1.43.0',
//  zlib: '1.2.11',
//  brotli: '1.0.9',
//  ares: '1.18.1',
//  modules: '108',
//  nghttp2: '1.47.0',
//  napi: '8',
//  llhttp: '6.0.10',
//  openssl: '3.0.7+quic',
//  cldr: '41.0',
//  icu: '71.1',
//  tz: '2022b',
//  unicode: '14.0',
//  ngtcp2: '0.8.1',
//  nghttp3: '0.7.0'
// }

// import readline from 'node:readline';
// import process from 'node:process';
// var rl = readline.createInterface(process.stdin, process.stdout);
// // rl.setPrompt('Test');
// // rl.prompt();
// // rl.question('What is your favorite food? ', (answer) => {
// //   console.log(`Oh, so your favorite food is ${answer}`);
// //   process.exit(0);
// // });
// const ac = new AbortController();
// const signal = ac.signal;

// rl.question('What is your favorite food? ', { signal }, (answer) => {
//   console.log(`Oh, so your favorite food is ${answer}`);
// });

// signal.addEventListener(
//   'abort',
//   () => {
//     console.log('The food question timed out');
//   },
//   { once: true }
// );

// setTimeout(() => ac.abort(), 10000);

// import test from 'node:test';
// import assert from 'assert';
// test('top level test', async (t) => {
//   await t.test('subtest 1', (t) => {
//     assert.strictEqual(1, 1);
//   });

//   await t.test('subtest 2', (t) => {
//     assert.strictEqual(2, 2);
//   });
// });

// test('top level test', { skip: true }, (t) => {
//   assert.strictEqual(1, 1);
// });
// test('top level test', { skip: 'skip message' }, (t) => {
//   assert.strictEqual(1, 1);
// });
// test('top level test', (t) => {
//   assert.strictEqual(1, 1);
//   t.skip();
//   assert.strictEqual(2, 2);
// });
// test('top level test', (t) => {
//   assert.strictEqual(1, 1);
//   t.skip('skip message');
//   assert.strictEqual(2, 2);
// });

// import test from 'node:test';
// import assert from 'node:assert';
// describe('test parent', () => {
//   it('first test', () => {
//     assert.strictEqual(1, 1);
//   });

//   it('second test', () => {
//     assert.strictEqual(2, 2);
//   });

//   describe('child test', () => {
//     it('grand test', () => {
//       assert.strictEqual(3, 3);
//     });
//   });
// });
// describe('test parent', { only: true }, () => {
//   it('first test', () => {
//     assert.strictEqual(1, 1);
//   });

//   it('second test', async (t) => {
//     assert.strictEqual(2, 2);
//   });
//   describe('child test', () => {
//     it('grand test', () => {
//       assert.strictEqual(3, 3);
//     });
//   });
// });
// describe('qwe123', () => {
//   it('first test', () => {
//     assert.strictEqual(1, 1);
//   });

//   it('second test', () => {
//     assert.strictEqual(2, 2);
//   });

//   describe('child test', () => {
//     it('grand test', () => {
//       assert.strictEqual(3, 3);
//     });
//   });
// });
// test('this test is run', { only: true }, async (t) => {
//   // 在此测试中，默认运行所有子测试。
//   await t.test('running subtest');

//   // 可以使用 'only' 选项更新测试上下文以运行子测试。
//   t.runOnly(true);
//   await t.test('this subtest is now skipped');
//   await t.test('this subtest is run', { only: true });

//   // 切换上下文以执行所有测试。
//   t.runOnly(false);
//   await t.test('this subtest is now run');

//   // 显式地不要运行这些测试。
//   await t.test('skipped subtest 3', { only: false });
//   await t.test('skipped subtest 4', { skip: true });
// });

// // 未设置 'only' 选项，因此跳过此测试。
// test('this test is not run', () => {
//   // 此代码未运行。
//   throw new Error('fail');
// });

// test('a test that creates asynchronous activity', (t) => {
//   setImmediate(() => {
//     t.test('subtest that is created too late', (t) => {
//       throw new Error('error1');
//     });
//   });

//   setImmediate(() => {
//     throw new Error('error2');
//   });

//   // 此行之后测试结束。
// });

// import url from 'node:url';
// console.log(url.URL === globalThis.URL);

// const myURL = new URL('https://example.org:8888');
// console.log(myURL.port);
// // 打印 8888

// // 默认端口自动转换为空字符串
// //（HTTPS 协议的默认端口是 443）
// myURL.port = '443';
// console.log(myURL.port);
// // 打印空字符串
// console.log(myURL.href);
// // 打印 https://example.org/

// myURL.port = 1234;
// console.log(myURL.port);
// // 打印 1234
// console.log(myURL.href);
// // 打印 https://example.org:1234/

// // 完全无效的端口字符串被忽略
// myURL.port = 'abcd';
// console.log(myURL.port);
// // 打印 1234

// // 前导数字被视为端口号
// myURL.port = '5678abcd';
// console.log(myURL.port);
// // 打印 5678

// // 非整数被截断
// myURL.port = 1234.5678;
// console.log(myURL.port);
// // 打印 1234

// // 未用科学计数法表示的超出范围的数字将被忽略。
// myURL.port = 1e10; // 10000000000，将按如下所述进行范围检查
// console.log(myURL.port);
// // 打印 1234

// myURL.port = 4.567e21;
// console.log(myURL.port);
// // 打印 4（因为它是字符串 '4.567e21' 中的前导数字）

// const u = new URL('http://example.org');
// u.protocol = 'https';
// console.log(u.href);
// https://example.org

// const u = new URL('http://example.org');
// u.protocol = 'fish';
// console.log(u.href);
// http://example.org

// const u = new URL('fish://example.org');
// u.protocol = 'http';
// console.log(u.href);
// fish://example.org

// const myURLs = [
//   new URL('https://www.example.com'),
//   new URL('https://test.example.org'),
// ];
// console.log(JSON.stringify(myURLs));
// console.log(new URL('https://www.example.com').toJSON());

// let params;

// // 使用数组
// params = new URLSearchParams([
//   ['user', 'abc'],
//   ['query', 'first'],
//   ['query', 'second'],
// ]);
// console.log(params.toString());
// // 打印 'user=abc&query=first&query=second'

// // 使用 Map 对象
// const map = new Map();
// map.set('user', 'abc');
// map.set('query', 'xyz');
// params = new URLSearchParams(map);
// console.log(params.toString());
// // 打印 'user=abc&query=xyz'

// // 使用生成器函数
// function* getQueryPairs() {
//   yield ['user', 'abc'];
//   yield ['query', 'first'];
//   yield ['query', 'second'];
// }
// params = new URLSearchParams(getQueryPairs());
// console.log(params.toString());
// // 打印 'user=abc&query=first&query=second'

// // 每个键值对必须恰好有两个元素
// param = new URLSearchParams([['user', 'abc', 'error']]);
// console.log(params.toString());
// // 抛出 TypeError [ERR_INVALID_TUPLE]:
// //        Each query pair must be an iterable [name, value] tuple

import { urlToHttpOptions } from 'node:url';
const myURL = new URL('https://a:b@測試?abc#foo');

console.log(urlToHttpOptions(myURL));
