import { Component } from '@angular/core';
import{CipherKey} from 'crypto';
import * as sha from 'object-sha';
import * as rsa from '../../../../../uni/BIGDATACIBER/ciberseguridad/rsa2/rsa-cybersecurity';
import * as bigconv from 'bigint-conversion'
import {MensajeService} from './service'

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  title = 'alice';
key: any;
publicKey: rsa.PublicKey;
privateKey: rsa.PrivateKey;
serverPublicKey: rsa.PublicKey;
ttpPublicKey: rsa.PublicKey;
keyExport:any;
iv: any;

constructor(private mensajeService: MensajeService) {

}

async ngOnInit() {
 
  await this.claves();
  this.dameClave();
  this.dameClaveTTP();
}

  async enviarMensaje(mensaje: any)
  {
    
    var k;
    var encrypt;
    var iv = window.crypto.getRandomValues(new Uint8Array(16));
    this.iv = iv;
    var des;

    console.log(mensaje);
    var messageBuffer = this.str2ab(mensaje);


      await crypto.subtle.generateKey({
      name: "AES-CBC",
      length: 256, //can be  128, 192, or 256
  },
  true, //whether the key is extractable (i.e. can be used in exportKey)
  ["encrypt", "decrypt"] //can "encrypt", "decrypt" or  "wrapKey", or "unwrapKey"
).then(function(key) {
  console.log(key);
  k = key;
});

console.log(k);
const exportKeyData = await crypto.subtle.exportKey("jwk", k)

this.key = k;
this.keyExport = exportKeyData;

await crypto.subtle.encrypt(
  {
      name: "AES-CBC",
      //Don't re-use initialization vectors!
      //Always generate a new iv every time your encrypt!
      iv,
  },
  this.key, //from generateKey or importKey above
  messageBuffer //ArrayBuffer of data you want to encrypt
)
.then(function(encrypted){
  //returns an ArrayBuffer containing the encrypted data
  console.log(new Uint8Array(encrypted));
  encrypt = new Uint8Array(encrypted);

});

// await crypto.subtle.decrypt(
//   {
//       name: "AES-CBC",
//       iv, //The initialization vector you used to encrypt
//   },
//   this.key, //from generateKey or importKey above
//   encrypt //ArrayBuffer of the data
// )
// .then(function(decrypted){
//   //returns an ArrayBuffer containing the decrypted data
//   console.log(new Uint8Array(decrypted));
//  des =   new Uint8Array(decrypted);
// })

// var as = this.ab2str(des);
// console.log(as);
var myDate = new Date();
var body = {src: 'A', dest: 'B', msg : encrypt, type : 1, timestamp: myDate};
const hash = await this.hashBody(body);

const po = bigconv.bigintToHex(this.privateKey.sign(bigconv.textToBigint(hash)));
const e = bigconv.bigintToHex(this.publicKey.e);
const n = bigconv.bigintToHex(this.publicKey.n);

this.mensajeService.enviarmensaje1({body, po, e, n})
.subscribe(async (res: any) => {
  const hashBody = await sha.digest(res.body, 'SHA-256');

  if (hashBody == bigconv.bigintToText(this.serverPublicKey.verify(bigconv.hexToBigint(res.pr)))) {
    console.log(res.body)
    //await this.enviarKeyTTPnoRepudio();
    await this.mensajetTTP();
  } else {
    console.log("No se ha podido verificar al servidor B")
    //this.res = "No se ha podido verificar al servidor B"
  }
});  }



async mensajetTTP()
{
  var myDate = new Date();

  var body = {src: 'A', ttp: 'TTP',dest: 'B', msg: this.keyExport, type : 4, timestamp: myDate};

  const hash = await this.hashBody(body);

const pko = bigconv.bigintToHex(this.privateKey.sign(bigconv.textToBigint(hash)));
const e = bigconv.bigintToHex(this.publicKey.e);
const n = bigconv.bigintToHex(this.publicKey.n);
const iv = bigconv.bigintToHex(this.iv);
this.mensajeService.enviarmensaje3({body, pko, e, n , iv})
.subscribe(async (res: any) => {
  const hashBody = await sha.digest(res.body, 'SHA-256');

  if (hashBody == bigconv.bigintToText(this.ttpPublicKey.verify(bigconv.hexToBigint(res.pkp)))) {
    console.log(res.body);
    this.avisoBob();
    
  } else {
    console.log("No se ha podido verificar al servidor TTP")
  }
});

}


avisoBob()
{
  this.mensajeService.avisoBob()
  .subscribe((res: any)=>{

    console.log("enviado mensaje bien a bob");
  })
}
   str2ab(str) {
    var buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
    var bufView = new Uint16Array(buf);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  }

   ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint16Array(buf));
  
  }

  async hashBody(body)
  {
    const hash = await sha.digest(body, 'SHA-256');
    return hash;

  }

  async claves() {
    const { publicKey, privateKey } = await rsa.generateRandomKeys(3072);
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  
  dameClave() {
    this.mensajeService.dameClave().subscribe((res: any) => {
      this.serverPublicKey = new rsa.PublicKey(bigconv.hexToBigint(res.e), bigconv.hexToBigint(res.n))
    })
  }
  dameClaveTTP() {
    this.mensajeService.dameClaveTTP().subscribe((res: any) => {
      this.ttpPublicKey = new rsa.PublicKey(bigconv.hexToBigint(res.e), bigconv.hexToBigint(res.n))
    })
  }

}


