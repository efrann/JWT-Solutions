On the previous writing, I mentioned what the JWT but now Portswigger comes for practising.
Before the solutions, I think it is crucial to understan the symmetric and asymmetric algorithms

### Symmetric algorithms
In the symmetric algorithm, a single key is used to encrypt the data. When encrypted with the key, the data can be decrypted with the same key.

### Asymmetric algorithms
In the asymmetric algorithm, two keys are responsible for the encrypt and decrypt messages. Private key is for signin the message and public key for veriyfing.

### JOSE headers - https://datatracker.ietf.org/doc/html/rfc7515#section-4.1

##### alg: algorithm header parameter value  

 
## LAB1:   JWT authentication bypass via unverified signature

Lab Description: This lab uses a JWT-based mechanism for handling sessions. Due to implementation flaws, the server doesn't verify the signature of any JWTs that it receives. To solve the lab, modify your session token to gain access to the admin panel at `/admin`, then delete the user `carlos`.

**Attack Vectors 1: What if developer forgot to verify the signature.**

Beklenildiği gibi /admin sayfasına erişim kısıtlamasından dolayı erişemiyoruz. 401 Unauthorized.

İlgili istekteki JWT token decode edildiğinde ve içerisindeki sub parametresinin değeri administrator ile değiştirilip, request tekrar gönderildiğinde /admin paneline erişim sağlamış oluyoruz. Yani  developer tokeni decode etti fakat signature kontrolü yapmayı unutmuş ve bu sebeple gelen her türlü signature kabul edilmiş olacaktır. 
Aynı lab için none type attack da başarılı olacaktır ama lab'ın asıl amacı bu değildir.

The developer must verify the token before decode it.

![[Pasted image 20231116154608.png]]

Ardından /admin/delete?username=carlos endpointine gidilirse de lab çözülmüş olacaktır.
![[Pasted image 20231116154733.png]]



Developer'lar gelen tokeni verify etmeyi unuttuğu zaman, yani token geldi ve direkt decode edildiği zaman signature kontrolü yapılmamış oluyor ve gelen her türlü signature kabul edilmiş oluyor. Bu sebeple bu saldırıda none type attack da başarılı olacaktır ama temel sebep bu değildir.

wiener:peter kullanıcı adı ile login olundu ve my account kısmına gidildi. JWT token içerisinde kullanıcı adı parametresi geçtiği tespit edildi.
`https://<LAB_ID>.web-security-academy.net/my-account/admin` 

`https://<LAB_ID>.web-security-academy.net/my-account?id=administrator` olarak değiştirildi ve JWT token içerisindeki wiener adı da administrator ile değiştirilerek istek tekrar gönderildi.
Ve başarılı olundu

________________________

## LAB2: JWT authentication bypass via flawed signature verification

wiener:peter kullanıcı adı ile login olundu ve my account kısmına gidildi. JWT token içerisinde kullanıcı adı parametresi geçtiği tespit edildi.
`https://<LAB_ID>.web-security-academy.net/my-account?id=wiener` 

`https://0a9d004b031168b1801ec6d1005400ed.web-security-academy.net/my-account?id=administrator` olarak değiştirildi ve JWT token içerisindeki wiener adı da administrator ile değiştirilerek istek tekrar gönderildi.
Başarısız olundu. 

Ardından istek eski haline getirilerek (wiener endpointine wiener kullanıcı adı içeren JWT token ) ile ve alg none  ile değiştirilerek istek iletildi. İstek gitti. Atak vektörümüz hazır. Yazılımcı imza kontrolü yapmıyor. JWT token çeşitli algoritmalar ile imzalanabilir ama hiçbir algoritma ile de imzalanabilir. Bu örnekte de bunu deneyimlemiş olduk.
Yine de JWT token yapısı bozulmamalıdır.

![[Pasted image 20231116160602.png]]

1. `https://0a9d004b031168b1801ec6d1005400ed.web-security-academy.net/my-account?id=administrator` olarak değiştirildi 
2. JWT token içerisindeki wiener adı da administrator ile değiştirildi.
3. alg none olarak değiştirildi.
 İstek gönderildi.
Artık adminiz.
 Kullanıcı silinerek LAB çözülür.

___________________



**Attack Vectors 2: Use Strong Secret Keys**
## LAB3:  JWT authentication bypass via weak signing key

/admin kısmına gitmeyi denedik ve beklenildiği gibi 401 Unauthorized hatası aldık. 
none type ve unverified signature saldırıları denen ve başarılı olunamadı. Yani developer bizden aldığı token'i verify ediyor ve JWT token mekanizması istenildiği gibi çalışıyor diyebiliriz.

Peki ilgili secret key gerçekten güvenli mi? Eğer ilgili secret key bilinirse, yeni bir valid token sign edebiliriz.
Deneyelim.
`https://github.com/wallarm/jwt-secrets/` ile bir wordlist indirelim ve bunu hashcat aracılığı ile kırmayı deneyelim. Umarım wordlistimiz yeterli olur ve başarılı bir şekilde kırmayı başarabiliriz.

`hashcat -m 16500 <jwttoken> <wordlist>`

![[Pasted image 20231117104924.png]]

secret key'e ulaştık. Yani biz artık kendi verified  jwt tokenımızı üretebiliriz.

![[Pasted image 20231117105057.png]]
ardından isteği göndeririz ve admin paneline erişim sağlayabiliriz. Bundan sonra da carlos kullanıcısını sileriz ve lab'ı çözmüş oluruz.

Kısaca özetlemek gerekirse:

1. secret key cracked
2. jwt web tokens extension burp extension ile
3. wiener administrator ile değiştir
4. recalculare signature
5. secret/key for signature recalculation -> `<secret key>`
6. gönder ve saldırı tamam.

____________
Bundan önce JWT parametrelerini açıklayalım.
alg is mandatory but the others are not.
jwk: json web key; provides an embedded JSON object representing the key.
jku: json web key set url; provides an URL from which server can fetch a set of keys containing the correct key.
kid: KEY ID; 1 den fazla key varsa, doğru anahtarı tanımlamak için kullanılan parametredir.
________

## LAB4: JWT authentication bypass via jwk header injection

Öncelikle jwk'nin ne olduğunu öğrenelim, diğer JOSE headerleri ile ilgili ataklara diğer lablarda değineceğiz. 

jku : json web key
Doğru yapılandırılmamış sunucularda, jwk parametresiyle gömülen veri anahtar olarak kullanabilir. Yani saldırgan kendi tokenini, ekledikleri parametre ile imzalayabilir ve doğrulayabilir. 
**JWT headeri içerisinde jwk parametresi yazmasa bile biz kendimizin elle ekleyebileceğini unutmayalım.**

Her zamanki gibi, none type ve unverified signature saldırılarını en başta deniyoruz. Fakat başarılı olunamadı ve bu sebeple farklı atak vektörlerini test etmeliyiz.

-- Zafiyetin keşfi
**We can directly embed the jwk in our jwk parameter.**
 Örnek bir jwk li JWT örneği:
 ```{
  "kid": "40f548ed-1d62-435e-8a2d-a769386279c7",
  "typ": "JWT",
  "alg": "RS256",
  "jwk": {
    "p": "xxxxx",
    "kty": "xxxxx",
    "q": "xxxxx",
    "d": "xxxxx",
    "e": "xxxxx",
    "kid": "xxxxx",
    "qi": "xxxxx",
    "dp": "xxxxx",
    "dq": "xxxxx",
    "n": "xxxxx"
  }
}
```

Test etmek amacı ile JWT Editor ile bir RSA key üretelim. 
![[Pasted image 20231025150628.png]]

- Ardından bunu kopyalayıp JWT içerisine, yukarıdaki örneğe göre yapıştıralım.
- JSON Web Token extension aracılığı ile bu token'i sign edelim.

- ya da json web token burp suit extension'u ile otomatik olarak ekleyelim. Fakat imzalarken kendi ürettiğimiz signing key'i seçmeyi unutmayalım.
![[Pasted image 20231025151330.png]]

- Ardından imzaladığımız token ile isteği gönderelim. Eğer istek gidiyor ise, kendi tokenimizi imzalandı ve verify edildi demektir. Ve evet başarıyla isteğimizi gönderdik.
![[Pasted image 20231025151447.png]]


Exploit - Lab'ın çözülmesi

Token içerisindeki wiener'i administrator ile değiştirerek token'i yeniden sign edelim ve isteği gönderelim. 

![[Pasted image 20231025151651.png]]
![[Pasted image 20231025151747.png]]

____________________

## LAB5: # JWT authentication bypass via jku header injection

Sunucunun jku parametresi desteklediği bilinmektedir. Buna ait ilgili testler gerçeklenecektir.
JKU: JSON Web Key Set URL

Öncelikle jku parametresinin ne olduğundan bahsedelim. jku parametresi, JWK formatında olan public anahtarların tutulduğu yeri URL ile gösterir. 

Bizim uygulamamızda biz bunu exploit sunucusunda depolayacağız.

Saldırgan, jku değerini başka bir URL ile değiştirerek kendi JWK seti ile tokenini doğrulayabilir.

URL kontrolü yapmadan ilgili URL'e gidiyorsa da SSRF ve Open Redirect zafiyetleri de düşünülmelidir.

Giden JWT token içerisinde jku parametresi bulunmasa bile bunu ekleyerek test edebiliriz. Etmeliyiz.

TEST:

- RSA anahtarı oluştur.
- Anahtarı jwk formatında kopyala ve exploit sunucusuna yükle.
- Eğer jku kabul edilirse, token doğrulamak için bizim sunucuya gidip jwk seti kullanılacaktır.
- Sunucuya anahtar jwk formatında anahtar yüklendikten sonra "kid" parametrelerini eşleştirmeliyiz.
- Bu test başarılı geçer ise zafiyet tespit edilmiş olur.

EXPLOIT
- administrator'e ait bir token üret ve işlemleri gerçekleştir. 

>jku parametresine verilen değer **kabul edilmiyor** ise, bazı bypass teknikleri uygulanmalıdır.
> `"jku":"https://example@saldirgan.com/keys"`
> `"jku":"https://example#saldirgan.com/keys"`
> `"jku":"https://example.saldirgan.com/keys"`

teknikleri denenebilir.

```
{
 "keys":[
	{
    "p": "xxxxx",
    "kty": "RSA",
    "q": "xxxxx",
    "d": "xxxxx",
    "e": "AQAB",
    "kid": "xxxxx",
    "qi": "xxxxx",
    "dp": "xxxxx",
    "dq": "xxxxx",
    "n": "xxxxx"
	}
	]
}
```
![[Pasted image 20231025162954.png]]

Kendi jwk mızı kendi sunucumuza(exploit sunucusu) kaydettikten sonra,
bu key'i point eden url yani jku parametresini ekleyerlim ve tokeni sign edelim ve kid parametresini güncelleyelim.
Eğer test başarılı olursa suncuya gidip doğrulama(validating,verifying) yapacaktır ve loglardan yakalayabileceğiz.

![[Pasted image 20231117122845.png]]

![[Pasted image 20231117122918.png]]

Zafiyetin varlığı kanıtlanmış oldu. Şimdi ise admin kullanıcı ile carlos kullanıcısını silmek için tekrar bir **sign** işlemi gerçekleştirelim ama bu sefer administrator hesabı için bir token sign ederek /admin endpointine gitmeyi deneyelim.


![[Pasted image 20231117123426.png]]

![[Pasted image 20231117123508.png]]

Administrator hesabına yönelik bir key ürettik ve carlos kullanıcısını silerek labı tamamlayalım.

![[Pasted image 20231117123611.png]]

_______________

## LAB6: # JWT authentication bypass via kid header path traversal

Her zamanki gibi yine header'in ne olduğundan ve ilgili atak vektörleri hakkında bilgi vererek başlayalım.

Sunucuda birdan fazla anahtar olduğu durumda, imzayı doğrulamak için hangi anahtarın kullanılacağına keyID yani kid karar verir.
kid değeri bir stringe, bir dosyaya, dizine ve url'e ait olabilir. 

**Eğer PATH belirtiliyor ise, directory traversal zafiyeti akıldan çıkmamalıdır.** 
**Aynı şekilde URL belirtiliyor ise de SSRF ve Open Redirection zafiyetleri de akılda bulundurulmalıdır.**

```
"kid":"key123"
"kid":"/keys/key.key"
"kid":"https://example.com/keys/key.key
"kid":"1232-123-123-213-12"
```

>Eğer directory traversal zafiyeti tespit edildiyse, farklı bir dizin belirtilerek başka bir dosya anahtar olarak gösterilebilir ve bu dosyanın içeriği ile imza doğrulanabilir.

Depolanan anahtarlar genellikle JWK formatındadır.

TEST
RSA : asimetrik anahtarlamadır.
- Bir anahtar üreteceğiz (RSA değil) Symmetric bir key üreteceğiz. Simetrik anahtarlarda secret anahtar hem doğrulamada hem imzalamada kullanılır.
  
  Asimetrik algoritmalarda ise örneğin RSA, public private kullanır. Private anahtarlar ile token imzalanır, public anahtar ile de doğrulama işlemi yapılır.

**Ek Bilgi: Symmetrik anahtar üretirken, üretilen k parametresi, bizim secret değerimizin base64 halidir.**

- Sistemde bir dosyanın içeriği okunabilirse, onun içeriği k parametresine verilebilir ya da **/dev/null** dosyasının boş olduğu bilindiği için bu dosya kullanılabilir.


O zaman başlayalım. Sistem içerisinde bir keşif yapmadığımız için önerildiği gibi /dev/null aracılığı ile ilerleyelim.
Let's generate  a new symmetric key and change the k parameter with a null value.
![[Pasted image 20231118103255.png]]
Then get back to the  /admin request. change the sub parameter to administrator.
And change the kid parameter in case of the null value as we assigned when generating the key and increase the path traversal make it sure to point the dev null file
../../../../../../../../../../../../../dev/null
And let's sign the token but do not modify the headers because kid parameter must point to the dev/null file
![[Pasted image 20231118103633.png]]
Send the yenilenmiş request again.
![[Pasted image 20231118103715.png]]

As it is seen, we can erişmek to the /admin endpoint. And we can delete the carlos user to solve the lab.

| |

Aynı işlemleri jwt_tool ile de yapabiliriz. 

```
sudo python3 jwt_tool.py <JWTTOKEN> -I -hc kid -hv '../../../../../../../../../../dev/null' -pc sub -pv administrator -S hs256 -p ''

-I :  inject new claims and update existing claims with new values
-hc:HEADERCLAIM
-hv: HEADER VALUE
-pc: PAYLOADCLAIM
-pv: PAYLOAD VALUE
-S: SIGN
-p: password

-hc kid -hc 'aaa' mevcut tokendaki kid yerine aaa yaz
-pc sub -pv 'bbb' mevcut tokendaki sub yerine bbb yaz 
-S hs256 imzalamak için kullanılacak şifreleme algoritması
-p '' değeri de JWT'nin imzalanması için gerekli parolayı temsil eder biz parola belirtmeyeceğiz.
```

Ardından bize verilen jwt token'i browserdaki mevcut jwt ile değiştirerek admin hesabına erişim sağlarız. Ardından da ilgili işlemleri yaparak lab'ı tamamlayabiliriz.

![[Pasted image 20231025174741.png]]

__________________________
<h1> EXPERT ADVANCED LABS </h1>
## LAB7: LAB JWT authentication bypass via algorithm confusion 

RSA : asimetrik anahtarlamadır.
- Bir anahtar üreteceğiz (RSA değil) Symmetric bir key üreteceğiz. Simetrik anahtarlarda secret anahtar hem doğrulamada hem imzalamada kullanılır.
  
  Asimetrik algoritmalarda ise örneğin RSA, public private kullanır. Private anahtarlar ile token imzalanır, public anahtar ile de doğrulama işlemi yapılır.


Eğer algoritma parametresi, belirlenen algoritmanın deiştirilip değiştirilmediğini kontrol etmiyorsa, saldırgan bu algoritmayı manipule ederek kendi kendi tokenini doğrulatabilir.
Saldırgan, public anahtara ya da anahtar setine erişebiliyorsa da algoritmayı değiştirerek saldırıyı gerçekleştirebilir.

HS256(HMAC + SHA256) use a symmetric key. Yani server uses a single key to both sign and verify the token.
RS256(RSA + SHA256) use an asmmetric keys, private key to sign the token and public key to verify the signature.

RS256 algoritması HS256(HMAC + SHA256) ile değiştirilirse, verify() public anahtarı, HS256 secret anahtarı yerine kullanıp tokeni imzalar ve ardından aynı anahtar ile imzayı doğrulayacaktır.
## LAB8 JWT authentication bypass via algorithm confusion with no exposed key.