import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class MensajeService {

  constructor(private http: HttpClient) { }

  readonly URLBob = 'http://localhost:4000';
  readonly URLTTP = 'http://localhost:2000';


  enviarmensaje1(mensaje : any){

    return this.http.post(this.URLBob + '/mensaje1' , {mensaje})
  };

  dameClave() {
    return this.http.get(this.URLBob + '/key');
  }

  dameClaveTTP()
  {
    return this.http.get(this.URLTTP + '/key');

  }

  enviarmensaje3(mensaje : any)
  {
    return this.http.post(this.URLTTP + '/mensaje3' , {mensaje})

  }

  avisoBob()
  {
return this.http.get(this.URLBob + '/avisobob');

  }
}
